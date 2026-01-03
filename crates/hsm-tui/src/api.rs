//! API client for communicating with FerroHSM server

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;
use uuid::Uuid;

use hsm_core::{
    AuthContext, KeyAlgorithm, KeyMetadata, KeyState, KeyUsage, OperationContext, PendingApprovalInfo,
};

/// API client for FerroHSM server communication
#[derive(Clone)]
pub struct ApiClient {
    client: Client,
    base_url: String,
    auth_token: Option<String>,
}

impl ApiClient {
    /// Create a new API client
    pub fn new(base_url: String, client_cert: Option<String>, client_key: Option<String>, ca_bundle: Option<String>) -> Result<Self> {
        let mut client_builder = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("ferrohsm-tui/1.0");

        // Configure TLS
        if let Some(cert) = client_cert {
            let key = client_key.ok_or_else(|| anyhow::anyhow!("client certificate provided but no key"))?;
            let cert = reqwest::Certificate::from_pem(cert.as_bytes())?;
            let key = reqwest::Identity::from_pem(&format!("{}\n{}", cert.as_pem()?, key))?;
            client_builder = client_builder.identity(key);
        }

        if let Some(ca) = ca_bundle {
            let ca_cert = reqwest::Certificate::from_pem(ca.as_bytes())?;
            client_builder = client_builder.add_root_certificate(ca_cert);
        }

        let client = client_builder.build()?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            auth_token: None,
        })
    }

    /// Set the authentication token
    pub fn set_auth_token(&mut self, token: String) {
        self.auth_token = Some(token);
    }

    /// Clear the authentication token
    pub fn clear_auth_token(&mut self) {
        self.auth_token = None;
    }

    /// Check if authenticated
    pub fn is_authenticated(&self) -> bool {
        self.auth_token.is_some() && !self.is_token_expired()
    }

    /// Check if the current token is expired
    pub fn is_token_expired(&self) -> bool {
        if let Some(token) = &self.auth_token {
            // Decode JWT without verification to check expiration
            if let Ok(token_data) = decode::<serde_json::Value>(
                token,
                &DecodingKey::from_secret(&[]), // Empty key for unverified decode
                &Validation::new(Algorithm::HS256).insecure_disable_signature_validation(),
            ) {
                if let Some(exp) = token_data.claims.get("exp").and_then(|v| v.as_u64()) {
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                    return exp <= now;
                }
            }
        }
        false
    }

    /// Get user information from the current token
    pub fn get_user_info(&self) -> Option<UserInfo> {
        if let Some(token) = &self.auth_token {
            if let Ok(token_data) = decode::<serde_json::Value>(
                token,
                &DecodingKey::from_secret(&[]),
                &Validation::new(Algorithm::HS256).insecure_disable_signature_validation(),
            ) {
                let claims = token_data.claims;
                let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let roles = claims.get("roles").and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
                    .unwrap_or_default();
                let exp = claims.get("exp").and_then(|v| v.as_u64());
                Some(UserInfo { sub, roles, exp })
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Make an authenticated request
    fn authenticated_request(&self, method: reqwest::Method, path: &str) -> RequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.client.request(method, url);

        if let Some(token) = &self.auth_token {
            req = req.bearer_auth(token);
        }

        req
    }

    /// Handle API response and extract JSON
    async fn handle_response<T: for<'de> Deserialize<'de>>(&self, response: Response) -> Result<T> {
        let status = response.status();
        let text = response.text().await?;

        if !status.is_success() {
            return Err(anyhow::anyhow!("API error {}: {}", status, text));
        }

        serde_json::from_str(&text).map_err(|e| anyhow::anyhow!("JSON parse error: {}", e))
    }

    // ===== KEY MANAGEMENT =====

    /// List keys with optional filtering
    pub async fn list_keys(&self, query: &KeyListQuery) -> Result<PaginatedKeys> {
        let mut url = "/api/v1/keys".to_string();

        let mut params = Vec::new();
        if let Some(page) = query.page {
            params.push(format!("page={}", page));
        }
        if let Some(per_page) = query.per_page {
            params.push(format!("per_page={}", per_page));
        }
        if let Some(algorithm) = &query.algorithm {
            params.push(format!("algorithm={}", algorithm));
        }
        if let Some(state) = &query.state {
            params.push(format!("state={}", state));
        }
        if let Some(tags) = &query.tags {
            params.push(format!("tags={}", tags));
        }

        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }

        let response = self.authenticated_request(reqwest::Method::GET, &url).send().await?;
        self.handle_response(response).await
    }

    /// Create a new key
    pub async fn create_key(&self, request: CreateKeyRequest) -> Result<KeySummary> {
        let response = self
            .authenticated_request(reqwest::Method::POST, "/api/v1/keys")
            .json(&request)
            .send()
            .await?;
        self.handle_response(response).await
    }

    /// Get key details
    pub async fn describe_key(&self, key_id: &str) -> Result<KeySummary> {
        let url = format!("/api/v1/keys/{}", key_id);
        let response = self.authenticated_request(reqwest::Method::GET, &url).send().await?;
        self.handle_response(response).await
    }

    /// Rotate a key
    pub async fn rotate_key(&self, key_id: &str) -> Result<KeySummary> {
        let url = format!("/api/v1/keys/{}/rotate", key_id);
        let response = self.authenticated_request(reqwest::Method::POST, &url).send().await?;
        self.handle_response(response).await
    }

    /// List key versions
    pub async fn list_key_versions(&self, key_id: &str) -> Result<Vec<KeySummary>> {
        let url = format!("/api/v1/keys/{}/versions", key_id);
        let response = self.authenticated_request(reqwest::Method::GET, &url).send().await?;
        self.handle_response(response).await
    }

    /// Rollback key to specific version
    pub async fn rollback_key(&self, key_id: &str, version: u32) -> Result<KeySummary> {
        let url = format!("/api/v1/keys/{}/rollback", key_id);
        let request = RollbackRequest { version };
        let response = self
            .authenticated_request(reqwest::Method::POST, &url)
            .json(&request)
            .send()
            .await?;
        self.handle_response(response).await
    }

    // ===== CRYPTOGRAPHIC OPERATIONS =====

    /// Sign data with a key
    pub async fn sign(&self, key_id: &str, payload_b64: String) -> Result<SignResponse> {
        let url = format!("/api/v1/keys/{}/sign", key_id);
        let request = SignRequest { payload_b64 };
        let response = self
            .authenticated_request(reqwest::Method::POST, &url)
            .json(&request)
            .send()
            .await?;
        self.handle_response(response).await
    }

    /// Encrypt data with a key
    pub async fn encrypt(&self, key_id: &str, plaintext_b64: String, associated_data_b64: Option<String>) -> Result<EncryptResponse> {
        let url = format!("/api/v1/keys/{}/encrypt", key_id);
        let request = EncryptRequest {
            plaintext_b64,
            associated_data_b64,
        };
        let response = self
            .authenticated_request(reqwest::Method::POST, &url)
            .json(&request)
            .send()
            .await?;
        self.handle_response(response).await
    }

    /// Decrypt data with a key
    pub async fn decrypt(&self, key_id: &str, ciphertext_b64: String, nonce_b64: String, associated_data_b64: Option<String>) -> Result<DecryptResponse> {
        let url = format!("/api/v1/keys/{}/decrypt", key_id);
        let request = DecryptRequest {
            ciphertext_b64,
            nonce_b64,
            associated_data_b64,
        };
        let response = self
            .authenticated_request(reqwest::Method::POST, &url)
            .json(&request)
            .send()
            .await?;
        self.handle_response(response).await
    }

    // ===== APPROVALS MANAGEMENT =====

    /// List pending approvals
    pub async fn list_approvals(&self) -> Result<Vec<ApprovalResponse>> {
        let response = self.authenticated_request(reqwest::Method::GET, "/api/v1/approvals").send().await?;
        self.handle_response(response).await
    }

    /// Approve a pending approval
    pub async fn approve_approval(&self, approval_id: &str) -> Result<serde_json::Value> {
        let url = format!("/api/v1/approvals/{}/approve", approval_id);
        let response = self.authenticated_request(reqwest::Method::POST, &url).send().await?;
        self.handle_response(response).await
    }

    /// Deny a pending approval
    pub async fn deny_approval(&self, approval_id: &str) -> Result<serde_json::Value> {
        let url = format!("/api/v1/approvals/{}/deny", approval_id);
        let response = self.authenticated_request(reqwest::Method::POST, &url).send().await?;
        self.handle_response(response).await
    }

    // ===== AUDIT LOGS =====

    /// List audit logs with optional filtering
    pub async fn list_audit_logs(&self, query: &AuditLogQuery) -> Result<PaginatedAuditLogs> {
        let mut url = "/api/v1/audit/logs".to_string();

        let mut params = Vec::new();
        if let Some(page) = query.page {
            params.push(format!("page={}", page));
        }
        if let Some(per_page) = query.per_page {
            params.push(format!("per_page={}", per_page));
        }
        if let Some(user) = &query.user {
            params.push(format!("user={}", user));
        }
        if let Some(action) = &query.action {
            params.push(format!("action={}", action));
        }
        if let Some(from) = &query.from {
            params.push(format!("from={}", from));
        }
        if let Some(to) = &query.to {
            params.push(format!("to={}", to));
        }

        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }

        let response = self.authenticated_request(reqwest::Method::GET, &url).send().await?;
        self.handle_response(response).await
    }

    // ===== HEALTH CHECK =====

    /// Check server health
    pub async fn health_check(&self) -> Result<HealthResponse> {
        let response = self.client.get(format!("{}/healthz", self.base_url)).send().await?;
        self.handle_response(response).await
    }
}

// ===== USER INFO =====

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub sub: String,
    pub roles: Vec<String>,
    pub exp: Option<u64>,
}

// ===== REQUEST/RESPONSE STRUCTS =====

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyListQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub algorithm: Option<String>,
    pub state: Option<String>,
    pub tags: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedKeys {
    pub items: Vec<KeySummary>,
    pub total: usize,
    pub page: u32,
    pub per_page: u32,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySummary {
    pub id: String,
    pub algorithm: KeyAlgorithm,
    pub version: u32,
    pub state: KeyState,
    pub usage: KeyUsage,
    pub description: Option<String>,
    pub policy_tags: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub tamper_status: String,
}

#[derive(Debug, Serialize)]
pub struct CreateKeyRequest {
    pub algorithm: KeyAlgorithm,
    pub usage: KeyUsage,
    pub policy_tags: Vec<String>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SignRequest {
    pub payload_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct SignResponse {
    pub signature_b64: String,
}

#[derive(Debug, Serialize)]
pub struct EncryptRequest {
    pub plaintext_b64: String,
    pub associated_data_b64: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EncryptResponse {
    pub ciphertext_b64: String,
    pub nonce_b64: String,
}

#[derive(Debug, Serialize)]
pub struct DecryptRequest {
    pub ciphertext_b64: String,
    pub nonce_b64: String,
    pub associated_data_b64: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DecryptResponse {
    pub plaintext_b64: String,
}

#[derive(Debug, Serialize)]
pub struct RollbackRequest {
    pub version: u32,
}

#[derive(Debug, Deserialize)]
pub struct ApprovalResponse {
    pub id: String,
    pub action: String,
    pub subject: String,
    pub requester: String,
    pub created_at: String,
    pub approved_by: Option<String>,
    pub approved_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuditLogQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub user: Option<String>,
    pub action: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PaginatedAuditLogs {
    pub items: Vec<AuditLogEntry>,
    pub total: usize,
    pub page: u32,
    pub per_page: u32,
    pub has_more: bool,
}

#[derive(Debug, Deserialize)]
pub struct AuditLogEntry {
    pub id: String,
    pub timestamp: String,
    pub user: String,
    pub action: String,
    pub resource: String,
    pub details: serde_json::Value,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub uptime_seconds: u64,
    pub cache_entries: usize,
    pub rate_limit_per_second: u64,
    pub rate_limit_burst: u64,
    pub active_rate_limiters: usize,
}