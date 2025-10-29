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

# Wait a bit for server to start
sleep 5

# Check if server is still running
if kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "Server is running"
    
    # Test connection
    echo "Testing connection..."
    if nc -z localhost 8443; then
        echo "Port 8443 is open"
        
        # Test CLI with insecure option
        echo "Testing CLI..."
        cargo run -p hsm-cli -- --endpoint https://localhost:8443 --insecure --jwt-secret "$JWT_SECRET" list
    else
        echo "Port 8443 is not open"
    fi
else
    echo "Server has exited"
    cat "$SERVER_LOG"
fi

# Clean up
kill "$SERVER_PID" 2>/dev/null || true
rm -rf "$TMP_DIR"