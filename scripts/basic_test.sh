#!/bin/bash

# Simple test script to verify basic FerroHSM functionality

set -e

echo "=== FerroHSM Basic Functionality Test ==="

# Create test directory
TEST_DIR="/tmp/ferrohsm_test"
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

echo "Test directory: $TEST_DIR"

# Generate test keys
echo "Generating test keys..."
JWT_SECRET=$(openssl rand -base64 32)
MASTER_KEY=$(openssl rand -base64 32)
HMAC_KEY=$(openssl rand -base64 32)

echo "Keys generated successfully"

# Generate test certificates
echo "Generating test certificates..."
mkdir -p "$TEST_DIR/certs"

# Generate CA
openssl genrsa -out "$TEST_DIR/certs/ca.key" 2048 >/dev/null 2>&1
openssl req -new -x509 -days 1 -key "$TEST_DIR/certs/ca.key" -sha256 -out "$TEST_DIR/certs/ca.pem" \
    -subj "/C=US/ST=Test/L=Test/O=Test/CN=TestCA" >/dev/null 2>&1

# Generate server certificate
openssl genrsa -out "$TEST_DIR/certs/server.key" 2048 >/dev/null 2>&1
openssl req -subj "/C=US/ST=Test/L=Test/O=Test/CN=localhost" -new -key "$TEST_DIR/certs/server.key" \
    -out "$TEST_DIR/certs/server.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -in "$TEST_DIR/certs/server.csr" -CA "$TEST_DIR/certs/ca.pem" \
    -CAkey "$TEST_DIR/certs/ca.key" -sha256 -out "$TEST_DIR/certs/server.pem" \
    -CAcreateserial -extfile <(echo "subjectAltName=DNS:localhost,IP:127.0.0.1") >/dev/null 2>&1

# Generate client certificate
openssl genrsa -out "$TEST_DIR/certs/client.key" 2048 >/dev/null 2>&1
openssl req -subj "/C=US/ST=Test/L=Test/O=Test/CN=client" -new -key "$TEST_DIR/certs/client.key" \
    -out "$TEST_DIR/certs/client.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -in "$TEST_DIR/certs/client.csr" -CA "$TEST_DIR/certs/ca.pem" \
    -CAkey "$TEST_DIR/certs/ca.key" -sha256 -out "$TEST_DIR/certs/client.pem" \
    -CAcreateserial >/dev/null 2>&1

echo "Certificates generated successfully"

# Start server in background
echo "Starting server..."
mkdir -p "$TEST_DIR/data"

# Use a random port to avoid conflicts
PORT=$((8444 + RANDOM % 1000))

./target/release/hsm-server \
    --tls-mode manual \
    --cert "$TEST_DIR/certs/server.pem" \
    --key "$TEST_DIR/certs/server.key" \
    --client-ca "$TEST_DIR/certs/ca.pem" \
    --key-dir "$TEST_DIR/data/keys" \
    --audit-log "$TEST_DIR/data/audit.log" \
    --master-key "$MASTER_KEY" \
    --hmac-key "$HMAC_KEY" \
    --auth-jwt-secret "$JWT_SECRET" \
    --bind 127.0.0.1:$PORT \
    > "$TEST_DIR/server.log" 2>&1 &

SERVER_PID=$!

echo "Server started with PID: $SERVER_PID on port $PORT"

# Wait for server to start
echo "Waiting for server to be ready..."
sleep 5

# Check if server is running
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "ERROR: Server failed to start"
    cat "$TEST_DIR/server.log"
    exit 1
fi

echo "Server is running"

# Define CLI command
CLI_CMD="./target/release/hsm-cli --endpoint https://localhost:$PORT \
    --client-cert $TEST_DIR/certs/client.pem \
    --client-key $TEST_DIR/certs/client.key \
    --ca-bundle $TEST_DIR/certs/ca.pem \
    --jwt-secret $JWT_SECRET \
    --jwt-algorithm hs256"

# Test 1: List keys (should be empty)
echo "Test 1: Listing keys (should be empty)"
KEYS_OUTPUT=$($CLI_CMD list 2>&1)
echo "CLI output: $KEYS_OUTPUT"
if echo "$KEYS_OUTPUT" | grep -q "No keys found"; then
    echo "✓ Test 1 passed: Initial key list is empty"
else
    echo "✗ Test 1 failed: Expected empty key list"
    echo "Output was: $KEYS_OUTPUT"
    kill $SERVER_PID 2>/dev/null || true
    exit 1
fi

# Test 2: Create an AES key
echo "Test 2: Creating AES key"
CREATE_OUTPUT=$($CLI_CMD create --algorithm aes256gcm --usage encrypt,decrypt --tags test.basic)
if echo "$CREATE_OUTPUT" | grep -q "Created key"; then
    KEY_ID=$(echo "$CREATE_OUTPUT" | grep "Created key" | sed 's/.*Created key //' | cut -d' ' -f1)
    echo "✓ Test 2 passed: Created AES key: $KEY_ID"
else
    echo "✗ Test 2 failed: Failed to create AES key: $CREATE_OUTPUT"
    kill $SERVER_PID 2>/dev/null || true
    exit 1
fi

# Test 3: List keys (should show the created key)
echo "Test 3: Listing keys (should show created key)"
LIST_OUTPUT=$($CLI_CMD list)
if echo "$LIST_OUTPUT" | grep -q "$KEY_ID"; then
    echo "✓ Test 3 passed: Key appears in list"
else
    echo "✗ Test 3 failed: Key not found in list: $LIST_OUTPUT"
    kill $SERVER_PID 2>/dev/null || true
    exit 1
fi

# Test 4: Encrypt some data
echo "Test 4: Encrypting data"
TEST_DATA="Hello, FerroHSM Basic Test!"
ENCRYPT_OUTPUT=$($CLI_CMD encrypt --key-id "$KEY_ID" --data "$TEST_DATA")
if echo "$ENCRYPT_OUTPUT" | grep -q "Encrypted data"; then
    ENCRYPTED_B64=$(echo "$ENCRYPT_OUTPUT" | grep "Encrypted data" | sed 's/.*Encrypted data //' | cut -d' ' -f1)
    echo "✓ Test 4 passed: Data encrypted successfully"
else
    echo "✗ Test 4 failed: Failed to encrypt data: $ENCRYPT_OUTPUT"
    kill $SERVER_PID 2>/dev/null || true
    exit 1
fi

# Test 5: Decrypt the data
echo "Test 5: Decrypting data"
DECRYPT_OUTPUT=$($CLI_CMD decrypt --key-id "$KEY_ID" --data "$ENCRYPTED_B64")
if echo "$DECRYPT_OUTPUT" | grep -q "$TEST_DATA"; then
    echo "✓ Test 5 passed: Data decrypted successfully and matches original"
else
    echo "✗ Test 5 failed: Decryption failed or data mismatch: $DECRYPT_OUTPUT"
    kill $SERVER_PID 2>/dev/null || true
    exit 1
fi

# Test 6: Health check
echo "Test 6: Health check"
HEALTH_OUTPUT=$(curl -sk --cert "$TEST_DIR/certs/client.pem" --key "$TEST_DIR/certs/client.key" \
    --cacert "$TEST_DIR/certs/ca.pem" \
    "https://localhost:$PORT/healthz")
if echo "$HEALTH_OUTPUT" | grep -q "ok"; then
    echo "✓ Test 6 passed: Health check passed"
else
    echo "✗ Test 6 failed: Health check failed: $HEALTH_OUTPUT"
    kill $SERVER_PID 2>/dev/null || true
    exit 1
fi

# Stop server
echo "Stopping server..."
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

# Clean up
echo "Cleaning up..."
rm -rf "$TEST_DIR"

echo "=== All tests passed! ==="
echo "FerroHSM basic functionality is working correctly."