#!/bin/bash

cd /Users/foozio/Downloads/Codes/ferrohsm

# Create temp directory
TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t ferrohsm)
echo "Using temp directory: $TMP_DIR"

# Create subdirectories
mkdir -p "$TMP_DIR/keys" "$TMP_DIR/approvals"

# Generate credentials
MASTER_KEY=$(openssl rand -base64 32)
HMAC_KEY=$(openssl rand -base64 32)
JWT_SECRET=$(openssl rand -base64 32)

echo "Generated credentials:"
echo "  MASTER_KEY: $MASTER_KEY"
echo "  HMAC_KEY: $HMAC_KEY"
echo "  JWT_SECRET: $JWT_SECRET"

# Generate certificate
openssl req -x509 -newkey rsa:2048 -keyout "$TMP_DIR/key.pem" -out "$TMP_DIR/cert.pem" -days 1 -nodes -subj "/CN=localhost" 2>/dev/null

# Run server in background
SERVER_LOG="$TMP_DIR/server.log"
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
    --list-cache-ttl-secs 1 > "$SERVER_LOG" 2>&1 &

SERVER_PID=$!
echo "Server started with PID: $SERVER_PID"

# Wait for server to be ready
sleep 5

# Test key creation
echo "Creating AES key..."
CREATE_OUTPUT=$(cargo run -p hsm-cli -- --endpoint https://localhost:8443 --insecure --jwt-secret "$JWT_SECRET" create aes256-gcm --usage encrypt,decrypt --tags poc 2>&1)
echo "$CREATE_OUTPUT"
KEY_ID=$(echo "$CREATE_OUTPUT" | awk '/Created key/{print $3}')
echo "Key ID: $KEY_ID"

# Test encryption
echo "Testing encryption..."
ENCRYPT_OUTPUT=$(cargo run -p hsm-cli -- --endpoint https://localhost:8443 --insecure --jwt-secret "$JWT_SECRET" encrypt "$KEY_ID" "test message" 2>&1)
echo "$ENCRYPT_OUTPUT"

# Check if encryption was successful
if echo "$ENCRYPT_OUTPUT" | grep -q "ciphertext:"; then
    echo "Encryption successful!"
    
    # Extract ciphertext and nonce
    CIPHERTEXT=$(echo "$ENCRYPT_OUTPUT" | awk -F': ' '/^ciphertext:/{print $2}')
    NONCE=$(echo "$ENCRYPT_OUTPUT" | awk -F': ' '/^nonce:/{print $2}')
    
    echo "Ciphertext: $CIPHERTEXT"
    echo "Nonce: $NONCE"
    
    # Test decryption
    echo "Testing decryption..."
    DECRYPT_OUTPUT=$(cargo run -p hsm-cli -- --endpoint https://localhost:8443 --insecure --jwt-secret "$JWT_SECRET" decrypt "$KEY_ID" "$CIPHERTEXT" "$NONCE" 2>&1)
    echo "$DECRYPT_OUTPUT"
else
    echo "Encryption failed"
    echo "Server logs:"
    cat "$SERVER_LOG"
fi

# Clean up
kill "$SERVER_PID" 2>/dev/null || true
rm -rf "$TMP_DIR"