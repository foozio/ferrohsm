#!/usr/bin/env bash
set -euo pipefail

# FerroHSM End-to-End Test Script
# Tests the full integration of hsm-server and hsm-cli components

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_DIR="$ROOT_DIR/test_tmp"
SERVER_PID=""
JWT_SECRET=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

cleanup() {
    log_info "Cleaning up test environment..."

    # Kill server if still running
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        log_info "Stopping server (PID: $SERVER_PID)"
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi

    # Remove test directory
    if [[ -d "$TEST_DIR" ]]; then
        rm -rf "$TEST_DIR"
        log_info "Removed test directory: $TEST_DIR"
    fi
}

trap cleanup EXIT

generate_jwt_secret() {
    log_info "Generating secure JWT secret..."
    
    # Generate a cryptographically secure random secret (32 bytes base64 encoded)
    JWT_SECRET=$(openssl rand -base64 32)
    if [[ -z "$JWT_SECRET" ]]; then
        log_error "Failed to generate JWT secret"
        exit 1
    fi
    log_info "JWT secret generated successfully"
}

generate_test_certs() {
    log_info "Generating test certificates..."

    mkdir -p "$TEST_DIR/certs"

    # Generate CA private key and certificate
    openssl genrsa -out "$TEST_DIR/certs/ca.key" 2048
    openssl req -new -x509 -days 1 -key "$TEST_DIR/certs/ca.key" -sha256 -out "$TEST_DIR/certs/ca.pem" \
        -subj "/C=US/ST=Test/L=Test/O=Test/CN=TestCA"

    # Generate server private key and certificate
    openssl genrsa -out "$TEST_DIR/certs/server.key" 2048
    openssl req -subj "/C=US/ST=Test/L=Test/O=Test/CN=localhost" -new -key "$TEST_DIR/certs/server.key" \
        -out "$TEST_DIR/certs/server.csr"
    openssl x509 -req -days 1 -in "$TEST_DIR/certs/server.csr" -CA "$TEST_DIR/certs/ca.pem" \
        -CAkey "$TEST_DIR/certs/ca.key" -sha256 -out "$TEST_DIR/certs/server.pem" \
        -CAcreateserial -extfile <(echo "subjectAltName=DNS:localhost,IP:127.0.0.1")

    # Generate client private key and certificate
    openssl genrsa -out "$TEST_DIR/certs/client.key" 2048
    openssl req -subj "/C=US/ST=Test/L=Test/O=Test/CN=client" -new -key "$TEST_DIR/certs/client.key" \
        -out "$TEST_DIR/certs/client.csr"
    openssl x509 -req -days 1 -in "$TEST_DIR/certs/client.csr" -CA "$TEST_DIR/certs/ca.pem" \
        -CAkey "$TEST_DIR/certs/ca.key" -sha256 -out "$TEST_DIR/certs/client.pem" \
        -CAcreateserial

    log_info "Test certificates generated successfully"
}

start_server() {
    log_info "Starting FerroHSM server..."

    mkdir -p "$TEST_DIR/data"

    # Start server in background with test configuration
    pushd "$ROOT_DIR" >/dev/null
    cargo run -p hsm-server -- \
        --tls-mode manual \
        --cert "$TEST_DIR/certs/server.pem" \
        --key "$TEST_DIR/certs/server.key" \
        --client-ca "$TEST_DIR/certs/ca.pem" \
        --key-dir "$TEST_DIR/data/keys" \
        --audit-log "$TEST_DIR/data/audit.log" \
        --auth-jwt-secret "$JWT_SECRET" \
        --auth-jwt-algorithm hs256 \
        --retention-config /dev/null \
        --retention-ledger "$TEST_DIR/data/retention-ledger.log" \
        --retention-interval-secs 3600 \
        --retention-grace-secs 86400 \
        --bind 127.0.0.1:8443 \
        > "$TEST_DIR/server.log" 2>&1 &
    SERVER_PID=$!
    popd >/dev/null

    log_info "Server started with PID: $SERVER_PID"

    # Wait for server to be ready
    log_info "Waiting for server to be ready..."
    for i in {1..30}; do
        if curl -sk --cert "$TEST_DIR/certs/client.pem" --key "$TEST_DIR/certs/client.key" \
                --cacert "$TEST_DIR/certs/ca.pem" \
                "https://localhost:8443/healthz" >/dev/null 2>&1; then
            log_info "Server is ready"
            return 0
        fi
        sleep 1
    done

    log_error "Server failed to start within 30 seconds"
    cat "$TEST_DIR/server.log"
    return 1
}

run_cli_tests() {
    log_info "Running CLI integration tests..."

    CLI_CMD="cargo run -p hsm-cli -- --endpoint https://localhost:8443 \
        --client-cert $TEST_DIR/certs/client.pem \
        --client-key $TEST_DIR/certs/client.key \
        --ca-bundle $TEST_DIR/certs/ca.pem \
        --jwt-secret $JWT_SECRET \
        --jwt-algorithm hs256"

    # Test 1: List keys (should be empty initially)
    log_info "Test 1: Listing keys (should be empty)"
    KEYS_OUTPUT=$($CLI_CMD list 2>&1)
    if echo "$KEYS_OUTPUT" | grep -q "No keys found"; then
        log_info "✓ Initial key list is empty"
    else
        log_error "Expected empty key list, got: $KEYS_OUTPUT"
        return 1
    fi

    # Test 2: Create an AES key
    log_info "Test 2: Creating AES key"
    CREATE_OUTPUT=$($CLI_CMD create --algorithm aes256gcm --usage encrypt,decrypt --tags test.e2e)
    if echo "$CREATE_OUTPUT" | grep -q "Created key"; then
        KEY_ID=$(echo "$CREATE_OUTPUT" | grep "Created key" | sed 's/.*Created key //' | cut -d' ' -f1)
        log_info "✓ Created AES key: $KEY_ID"
    else
        log_error "Failed to create AES key: $CREATE_OUTPUT"
        return 1
    fi

    # Test 3: List keys (should show the created key)
    log_info "Test 3: Listing keys (should show created key)"
    LIST_OUTPUT=$($CLI_CMD list)
    if echo "$LIST_OUTPUT" | grep -q "$KEY_ID"; then
        log_info "✓ Key appears in list"
    else
        log_error "Key not found in list: $LIST_OUTPUT"
        return 1
    fi

    # Test 4: Encrypt some data
    log_info "Test 4: Encrypting data"
    TEST_DATA="Hello, FerroHSM E2E Test!"
    ENCRYPT_OUTPUT=$($CLI_CMD encrypt --key-id "$KEY_ID" --data "$TEST_DATA")
    if echo "$ENCRYPT_OUTPUT" | grep -q "Encrypted data"; then
        ENCRYPTED_B64=$(echo "$ENCRYPT_OUTPUT" | grep "Encrypted data" | sed 's/.*Encrypted data //' | cut -d' ' -f1)
        log_info "✓ Data encrypted successfully"
    else
        log_error "Failed to encrypt data: $ENCRYPT_OUTPUT"
        return 1
    fi

    # Test 5: Decrypt the data
    log_info "Test 5: Decrypting data"
    DECRYPT_OUTPUT=$($CLI_CMD decrypt --key-id "$KEY_ID" --data "$ENCRYPTED_B64")
    if echo "$DECRYPT_OUTPUT" | grep -q "$TEST_DATA"; then
        log_info "✓ Data decrypted successfully and matches original"
    else
        log_error "Decryption failed or data mismatch: $DECRYPT_OUTPUT"
        return 1
    fi

    # Test 6: Create an RSA key for signing
    log_info "Test 6: Creating RSA key for signing"
    RSA_CREATE_OUTPUT=$($CLI_CMD create --algorithm rsa2048 --usage sign,verify --tags test.signing)
    if echo "$RSA_CREATE_OUTPUT" | grep -q "Created key"; then
        RSA_KEY_ID=$(echo "$RSA_CREATE_OUTPUT" | grep "Created key" | sed 's/.*Created key //' | cut -d' ' -f1)
        log_info "✓ Created RSA key: $RSA_KEY_ID"
    else
        log_error "Failed to create RSA key: $RSA_CREATE_OUTPUT"
        return 1
    fi

    # Test 7: Sign some data
    log_info "Test 7: Signing data"
    SIGN_DATA="Data to be signed for E2E test"
    SIGN_OUTPUT=$($CLI_CMD sign --key-id "$RSA_KEY_ID" --data "$SIGN_DATA")
    if echo "$SIGN_OUTPUT" | grep -q "Signature"; then
        SIGNATURE_B64=$(echo "$SIGN_OUTPUT" | grep "Signature" | sed 's/.*Signature //' | cut -d' ' -f1)
        log_info "✓ Data signed successfully"
    else
        log_error "Failed to sign data: $SIGN_OUTPUT"
        return 1
    fi

    # Test 8: Verify the signature
    log_info "Test 8: Verifying signature"
    VERIFY_OUTPUT=$($CLI_CMD verify --key-id "$RSA_KEY_ID" --data "$SIGN_DATA" --signature "$SIGNATURE_B64")
    if echo "$VERIFY_OUTPUT" | grep -q "Signature is valid"; then
        log_info "✓ Signature verification successful"
    else
        log_error "Signature verification failed: $VERIFY_OUTPUT"
        return 1
    fi

    # Test 9: Check audit log
    log_info "Test 9: Checking audit log"
    if [[ -f "$TEST_DIR/data/audit.log" ]]; then
        AUDIT_ENTRIES=$(wc -l < "$TEST_DIR/data/audit.log")
        if [[ $AUDIT_ENTRIES -gt 0 ]]; then
            log_info "✓ Audit log contains $AUDIT_ENTRIES entries"
        else
            log_error "Audit log is empty"
            return 1
        fi
    else
        log_error "Audit log file not found"
        return 1
    fi

    # Test 10: Health check
    log_info "Test 10: Health check"
    HEALTH_OUTPUT=$(curl -sk --cert "$TEST_DIR/certs/client.pem" --key "$TEST_DIR/certs/client.key" \
        --cacert "$TEST_DIR/certs/ca.pem" \
        "https://localhost:8443/healthz")
    if echo "$HEALTH_OUTPUT" | grep -q "ok"; then
        log_info "✓ Health check passed"
    else
        log_error "Health check failed: $HEALTH_OUTPUT"
        return 1
    fi

    # Test 11: Approvals list via CLI (should report none pending)
    log_info "Test 11: Listing approvals"
    APPROVALS_OUTPUT=$($CLI_CMD approvals list)
    if echo "$APPROVALS_OUTPUT" | grep -q "No pending approvals"; then
        log_info "✓ Approvals list reports no pending items"
    else
        log_error "Unexpected approvals output: $APPROVALS_OUTPUT"
        return 1
    fi

    # Test 12: Metrics endpoint exposes cache counters
    log_info "Test 12: Verifying metrics endpoint"
    METRICS_OUTPUT=$(curl -sk --cert "$TEST_DIR/certs/client.pem" --key "$TEST_DIR/certs/client.key" \
        --cacert "$TEST_DIR/certs/ca.pem" \
        "https://localhost:8443/metrics")
    if echo "$METRICS_OUTPUT" | grep -q "ferrohsm_key_cache_hit_total"; then
        log_info "✓ Metrics include key cache counters"
    else
        log_error "Metrics output missing cache counters"
        return 1
    fi

    # Test 13: Deny endpoint returns not found for unknown approvals
    log_info "Test 13: Hitting deny endpoint for unknown approval"
    UNKNOWN_ID=$(python3 -c 'import uuid; print(uuid.uuid4())')
    HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --cert "$TEST_DIR/certs/client.pem" \
        --key "$TEST_DIR/certs/client.key" --cacert "$TEST_DIR/certs/ca.pem" \
        -X POST "https://localhost:8443/api/v1/approvals/$UNKNOWN_ID/deny")
    if [[ "$HTTP_CODE" == "404" ]]; then
        log_info "✓ Deny endpoint responds with 404 for unknown approval"
    else
        log_error "Unexpected status from deny endpoint: $HTTP_CODE"
        return 1
    fi

    # Test 14: Post-quantum cryptography operations
    log_info "Test 14: Testing post-quantum cryptographic operations"
    PQC_OUTPUT=$($CLI_CMD create --algorithm dilithium5 --usage sign,verify --tags pqc,quantum_resistant)
    if echo "$PQC_OUTPUT" | grep -q "Created key"; then
        PQC_KEY_ID=$(echo "$PQC_OUTPUT" | grep "Created key" | sed 's/.*Created key //' | cut -d' ' -f1)
        log_info "✓ Created PQC key: $PQC_KEY_ID"
        
        # Test PQC signing
        PQC_SIGN_DATA="Post-quantum cryptography test message"
        PQC_SIGN_OUTPUT=$($CLI_CMD sign --key-id "$PQC_KEY_ID" --data "$PQC_SIGN_DATA")
        if echo "$PQC_SIGN_OUTPUT" | grep -q "Signature"; then
            PQC_SIGNATURE_B64=$(echo "$PQC_SIGN_OUTPUT" | grep "Signature" | sed 's/.*Signature //' | cut -d' ' -f1)
            log_info "✓ PQC signing successful"
            
            # Verify PQC signature
            PQC_VERIFY_OUTPUT=$($CLI_CMD verify --key-id "$PQC_KEY_ID" --data "$PQC_SIGN_DATA" --signature "$PQC_SIGNATURE_B64")
            if echo "$PQC_VERIFY_OUTPUT" | grep -q "Signature is valid"; then
                log_info "✓ PQC signature verification successful"
            else
                log_error "PQC signature verification failed: $PQC_VERIFY_OUTPUT"
                return 1
            fi
        else
            log_error "Failed to sign with PQC key: $PQC_SIGN_OUTPUT"
            return 1
        fi
    else
        log_info "✓ PQC operations skipped (not supported in this build)"
    fi

    log_info "All CLI integration tests passed!"
    return 0
}

main() {
    log_info "Starting FerroHSM End-to-End Tests"

    # Check if required tools are available
    if ! command -v openssl >/dev/null 2>&1; then
        log_error "openssl is required but not installed"
        exit 1
    fi

    if ! command -v curl >/dev/null 2>&1; then
        log_error "curl is required but not installed"
        exit 1
    fi

    if ! command -v python3 >/dev/null 2>&1; then
        log_error "python3 is required but not installed"
        exit 1
    fi

    # Build the project first
    log_info "Building project..."
    pushd "$ROOT_DIR" >/dev/null
    cargo build
    popd >/dev/null

    # Run tests
    generate_jwt_secret
    generate_test_certs
    start_server
    run_cli_tests

    log_info "All end-to-end tests completed successfully!"
}

main "$@"