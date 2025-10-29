#!/bin/bash

cd /Users/foozio/Downloads/Codes/ferrohsm

# Create temp directory
TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t ferrohsm)
echo "Using temp directory: $TMP_DIR"

# Create subdirectories
mkdir -p "$TMP_DIR/keys" "$TMP_DIR/approvals"
echo "Created subdirectories"

# Generate credentials
MASTER_KEY=$(openssl rand -base64 32)
HMAC_KEY=$(openssl rand -base64 32)
JWT_SECRET=$(openssl rand -base64 32)

echo "Generated credentials"

# Try to generate certificate
if openssl req -x509 -newkey rsa:2048 -keyout "$TMP_DIR/key.pem" -out "$TMP_DIR/cert.pem" -days 1 -nodes -subj "/CN=localhost" 2>/dev/null; then
    echo "Certificate generated successfully"
    ls -la "$TMP_DIR/cert.pem" "$TMP_DIR/key.pem"
    
    # Run server with certificate
    echo "Starting server with certificate..."
    cargo run -p hsm-server -- \
        --cert "$TMP_DIR/cert.pem" \
        --key "$TMP_DIR/key.pem" \
        --master-key "$MASTER_KEY" \
        --hmac-key "$HMAC_KEY" \
        --auth-jwt-secret "$JWT_SECRET" \
        --key-dir "$TMP_DIR/keys" \
        --approval-dir "$TMP_DIR/approvals" \
        --audit-log "$TMP_DIR/audit.log" \
        --retention-ledger "$TMP_DIR/retention.log" \
        --list-cache-ttl-secs 1
else
    echo "Failed to generate certificate"
fi