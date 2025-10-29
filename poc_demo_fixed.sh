#!/bin/bash

# FerroHSM Proof of Concept Demo Script
# Demonstrates classical workflows against a local server instance.

set -euo pipefail

if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl is required to run this demo" >&2
    exit 1
fi

echo "=== FerroHSM Proof of Concept Demo ==="
echo ""

TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t ferrohsm)
SERVER_LOG="$TMP_DIR/server.log"
SERVER_PID=""

cleanup() {
    if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        echo "Stopping server (pid ${SERVER_PID})..."
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

MASTER_KEY=$(openssl rand -base64 32)
HMAC_KEY=$(openssl rand -base64 32)
JWT_SECRET=$(openssl rand -base64 32)

echo "Generated credentials:"
echo "  MASTER_KEY: ${MASTER_KEY}"
echo "  HMAC_KEY:   ${HMAC_KEY}"
echo "  JWT_SECRET: ${JWT_SECRET}"
echo ""

# Generate certificate
openssl req -x509 -newkey rsa:2048 -keyout "${TMP_DIR}/key.pem" -out "${TMP_DIR}/cert.pem" -days 1 -nodes -subj "/CN=localhost" 2>/dev/null

mkdir -p "${TMP_DIR}/keys" "${TMP_DIR}/approvals"

echo "Starting FerroHSM server with self-signed TLS certificate..."
cargo run -p hsm-server -- \
    --cert "${TMP_DIR}/cert.pem" \
    --key "${TMP_DIR}/key.pem" \
    --master-key "${MASTER_KEY}" \
    --hmac-key "${HMAC_KEY}" \
    --auth-jwt-secret "${JWT_SECRET}" \
    --key-dir "${TMP_DIR}/keys" \
    --approval-dir "${TMP_DIR}/approvals" \
    --audit-log "${TMP_DIR}/audit.log" \
    --retention-ledger "${TMP_DIR}/retention.log" \
    --list-cache-ttl-secs 1 \
    >"${SERVER_LOG}" 2>&1 &

SERVER_PID=$!
echo "Server started (pid ${SERVER_PID}). Logs: ${SERVER_LOG}"
echo ""

# Wait for server to be ready by checking if it responds to requests
echo "Waiting for server to be ready..."
SERVER_READY=false
for i in {1..30}; do
    # Try to connect to the server
    if nc -z localhost 8443 2>/dev/null; then
        echo "Server is ready!"
        SERVER_READY=true
        break
    fi
    echo "Server not ready yet, waiting... ($i/30)"
    sleep 2
done

if [ "$SERVER_READY" = "false" ]; then
    echo "Error: Server failed to start within timeout period"
    cat "${SERVER_LOG}" >&2
    exit 1
fi

# Function to run CLI commands with insecure option
run_cli() {
    >&2 echo "Running: cargo run -p hsm-cli -- --endpoint https://localhost:8443 --insecure --jwt-secret \"${JWT_SECRET}\" $*"
    cargo run -p hsm-cli -- \
        --endpoint https://localhost:8443 \
        --insecure \
        --jwt-secret "${JWT_SECRET}" \
        "$@"
    local exit_code=$?
    >&2 echo ""
    return $exit_code
}

echo "=== Creating Keys ==="

create_aes_output=$(run_cli create aes256-gcm --usage encrypt,decrypt --tags poc)
if [ $? -ne 0 ]; then
    echo "Failed to create AES key"
    cat "${SERVER_LOG}" >&2
    exit 1
fi
AES_KEY_ID=$(echo "${create_aes_output}" | awk '/Created key/{print $3}')
echo "AES key ID: ${AES_KEY_ID}"
echo ""

create_rsa_output=$(run_cli create rsa2048 --usage sign,verify --tags poc)
if [ $? -ne 0 ]; then
    echo "Failed to create RSA key"
    cat "${SERVER_LOG}" >&2
    exit 1
fi
RSA_KEY_ID=$(echo "${create_rsa_output}" | awk '/Created key/{print $3}')
echo "RSA key ID: ${RSA_KEY_ID}"
echo ""

echo "=== Testing Key Listing ==="
run_cli list
if [ $? -ne 0 ]; then
    echo "Failed to list keys"
    cat "${SERVER_LOG}" >&2
    exit 1
fi

echo ""
echo "=== Demo Status ==="
echo "Key creation and listing are working correctly."
echo "NOTE: There is a known issue with the server where encryption operations"
echo "cause a stack overflow and crash the server. This is a bug in the"
echo "server implementation that needs to be fixed."
echo ""
echo "The script has successfully demonstrated:"
echo "1. Server startup with TLS"
echo "2. Key creation (AES and RSA)"
echo "3. Key listing"
echo ""
echo "=== Demo Complete ==="
echo "Server logs are available at ${SERVER_LOG}"
echo ""
echo "FerroHSM demo completed successfully (with known server bug)."