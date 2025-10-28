package main

import (
    "bytes"
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "crypto/tls"
    "crypto/x509"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "strconv"
    "strings"
    "time"
)

type KeySummary struct {
    ID         string   `json:"id"`
    Algorithm  string   `json:"algorithm"`
    Version    int      `json:"version"`
    State      string   `json:"state"`
    Usage      []string `json:"usage"`
    PolicyTags []string `json:"policy_tags"`
}

type CreateKeyRequest struct {
    Algorithm   string   `json:"algorithm"`
    Usage       []string `json:"usage"`
    PolicyTags  []string `json:"policy_tags"`
    Description string   `json:"description,omitempty"`
}

type SignRequest struct {
    PayloadB64 string `json:"payload_b64"`
}

type SignResponse struct {
    SignatureB64 string `json:"signature_b64"`
}

type ErrorResponse struct {
    Error string `json:"error"`
}

type Approval struct {
    ID         string  `json:"id"`
    Action     string  `json:"action"`
    Subject    string  `json:"subject"`
    Requester  string  `json:"requester"`
    ApprovedBy *string `json:"approved_by"`
    ApprovedAt *string `json:"approved_at"`
    CreatedAt  string  `json:"created_at"`
}

type MetricsSummary struct {
    RateAllowed int
    RateBlocked int
    CacheHits   int
    CacheMisses int
    CacheStores int
}

func main() {
    client := buildMutualTLSClient("client.pem", "client.key.pem", "ca.pem")
    endpoint := "https://localhost:8443"
    secret := mustJWTSecret()
    token := mustMakeJWT(secret, "go-sdk", []string{"operator"}, 5*time.Minute)

    key := createKey(client, endpoint, token, CreateKeyRequest{
        Algorithm:  "Aes256Gcm",
        Usage:      []string{"Encrypt", "Decrypt"},
        PolicyTags: []string{"cicd"},
    })
    fmt.Printf("created key %s (%s)\n", key.ID, key.Algorithm)

    signature := signPayload(client, endpoint, token, key.ID, []byte("build artifact"))
    fmt.Printf("signature: %s\n", signature)

    approvals, err := listApprovals(client, endpoint, token)
    if err != nil {
        log.Printf("approvals unavailable: %v\n", err)
    } else if len(approvals) == 0 {
        fmt.Println("no pending approvals")
    } else {
        fmt.Printf("%d approvals pending:\n", len(approvals))
        for _, approval := range approvals {
            fmt.Printf("- %s %s requested by %s\n", approval.Action, approval.Subject, approval.Requester)
        }
    }

    metrics, err := fetchMetrics(client, endpoint, token)
    if err != nil {
        log.Printf("metrics unavailable: %v\n", err)
    } else {
        fmt.Printf(
            "metrics: rate_allowed=%d rate_blocked=%d cache_hits=%d cache_misses=%d cache_stores=%d\n",
            metrics.RateAllowed,
            metrics.RateBlocked,
            metrics.CacheHits,
            metrics.CacheMisses,
            metrics.CacheStores,
        )
    }
}

func buildMutualTLSClient(certFile, keyFile, caFile string) *http.Client {
    cert, err := tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        log.Fatalf("loading client identity: %v", err)
    }
    caPool := x509.NewCertPool()
    caData, err := os.ReadFile(caFile)
    if err != nil {
        log.Fatalf("reading ca bundle: %v", err)
    }
    if !caPool.AppendCertsFromPEM(caData) {
        log.Fatalf("invalid ca bundle")
    }
    transport := &http.Transport{
        TLSClientConfig: &tls.Config{
            Certificates: []tls.Certificate{cert},
            RootCAs:      caPool,
        },
    }
    return &http.Client{Timeout: 10 * time.Second, Transport: transport}
}

func createKey(client *http.Client, endpoint, token string, payload CreateKeyRequest) KeySummary {
    body, _ := json.Marshal(payload)
    req, _ := http.NewRequest(http.MethodPost, endpoint+"/api/v1/keys", bytes.NewReader(body))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer "+token)
    resp, err := client.Do(req)
    if err != nil {
        log.Fatalf("create key: %v", err)
    }
    defer resp.Body.Close()
    if resp.StatusCode == http.StatusAccepted {
        var respErr ErrorResponse
        if err := json.NewDecoder(resp.Body).Decode(&respErr); err != nil {
            log.Fatalf("key creation pending dual-control approval (unable to decode response): %v", err)
        }
        log.Fatalf("key creation awaiting approval: %s", respErr.Error)
    }
    if resp.StatusCode >= 300 {
        data, _ := io.ReadAll(resp.Body)
        log.Fatalf("create failed: %s", data)
    }
    var result KeySummary
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        log.Fatalf("decode response: %v", err)
    }
    return result
}

func signPayload(client *http.Client, endpoint, token, keyID string, payload []byte) string {
    reqBody, _ := json.Marshal(SignRequest{PayloadB64: base64.StdEncoding.EncodeToString(payload)})
    req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/api/v1/keys/%s/sign", endpoint, keyID), bytes.NewReader(reqBody))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer "+token)
    resp, err := client.Do(req)
    if err != nil {
        log.Fatalf("sign: %v", err)
    }
    defer resp.Body.Close()
    if resp.StatusCode == http.StatusAccepted {
        var respErr ErrorResponse
        if err := json.NewDecoder(resp.Body).Decode(&respErr); err != nil {
            log.Fatalf("sign pending approval (decode error): %v", err)
        }
        log.Fatalf("signature request awaiting approval: %s", respErr.Error)
    }
    if resp.StatusCode >= 300 {
        data, _ := io.ReadAll(resp.Body)
        log.Fatalf("sign failed: %s", data)
    }
    var result SignResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        log.Fatalf("decode sign: %v", err)
    }
    return result.SignatureB64
}

func listApprovals(client *http.Client, endpoint, token string) ([]Approval, error) {
    req, _ := http.NewRequest(http.MethodGet, endpoint+"/api/v1/approvals", nil)
    req.Header.Set("Authorization", "Bearer "+token)
    resp, err := client.Do(req)
    if err != nil {
        return nil, fmt.Errorf("list approvals: %w", err)
    }
    defer resp.Body.Close()
    if resp.StatusCode == http.StatusForbidden {
        return nil, fmt.Errorf("forbidden: ensure token grants operator or auditor role")
    }
    if resp.StatusCode >= 300 {
        data, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("list approvals failed: %s", data)
    }
    var approvals []Approval
    if err := json.NewDecoder(resp.Body).Decode(&approvals); err != nil {
        return nil, fmt.Errorf("decode approvals: %w", err)
    }
    return approvals, nil
}

func fetchMetrics(client *http.Client, endpoint, token string) (MetricsSummary, error) {
    req, _ := http.NewRequest(http.MethodGet, endpoint+"/metrics", nil)
    req.Header.Set("Authorization", "Bearer "+token)
    resp, err := client.Do(req)
    if err != nil {
        return MetricsSummary{}, fmt.Errorf("fetch metrics: %w", err)
    }
    defer resp.Body.Close()
    if resp.StatusCode >= 300 {
        data, _ := io.ReadAll(resp.Body)
        return MetricsSummary{}, fmt.Errorf("metrics request failed: %s", data)
    }
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return MetricsSummary{}, fmt.Errorf("read metrics body: %w", err)
    }
    text := string(body)
    return MetricsSummary{
        RateAllowed: parseCounter(text, "ferrohsm_rate_limit_allowed_total"),
        RateBlocked: parseCounter(text, "ferrohsm_rate_limit_blocked_total"),
        CacheHits:   parseCounter(text, "ferrohsm_key_cache_hit_total"),
        CacheMisses: parseCounter(text, "ferrohsm_key_cache_miss_total"),
        CacheStores: parseCounter(text, "ferrohsm_key_cache_store_total"),
    }, nil
}

func parseCounter(metrics, name string) int {
    for _, line := range strings.Split(metrics, "\n") {
        if strings.HasPrefix(line, name) {
            parts := strings.Fields(line)
            if len(parts) == 2 {
                if val, err := strconv.ParseFloat(parts[1], 64); err == nil {
                    return int(val)
                }
            }
        }
    }
    return 0
}

func mustJWTSecret() []byte {
    secret := os.Getenv("FERROHSM_JWT_SECRET")
    if secret == "" {
        log.Fatal("FERROHSM_JWT_SECRET environment variable is required")
    }
    if decoded, err := base64.StdEncoding.DecodeString(secret); err == nil {
        return decoded
    }
    return []byte(secret)
}

func mustMakeJWT(secret []byte, actor string, roles []string, ttl time.Duration) string {
    header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
    now := time.Now().Unix()
    payloadMap := map[string]interface{}{
        "sub": actor,
        "roles": roles,
        "iat": now,
        "exp": now + int64(ttl/time.Second),
        "sid": randomID(),
    }
    payloadBytes, err := json.Marshal(payloadMap)
    if err != nil {
        log.Fatalf("marshal jwt payload: %v", err)
    }
    payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
    unsigned := header + "." + payload
    mac := hmac.New(sha256.New, secret)
    if _, err := mac.Write([]byte(unsigned)); err != nil {
        log.Fatalf("sign token: %v", err)
    }
    signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
    return unsigned + "." + signature
}

func randomID() string {
    buf := make([]byte, 16)
    if _, err := rand.Read(buf); err != nil {
        return fmt.Sprintf("%d", time.Now().UnixNano())
    }
    return hex.EncodeToString(buf)
}
