#!/bin/bash

# FerroHSM Proof of Concept Demo Script
# Demonstrates classical + post-quantum workflows against a local server instance.

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

CERT_PATH="${TMP_DIR}/server.pem"
KEY_PATH="${TMP_DIR}/server-key.pem"

openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "${KEY_PATH}" \
    -out "${CERT_PATH}" \
    -subj "/CN=localhost" \
    -days 1 >/dev/null 2>&1

mkdir -p "${TMP_DIR}/keys" "${TMP_DIR}/approvals"

echo "Starting FerroHSM server with self-signed TLS certificate..."
cargo run -p hsm-server -- \
    --cert "${CERT_PATH}" \
    --key "${KEY_PATH}" \
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
for i in {1..30}; do
    if curl -s -k --cert "${CERT_PATH}" --key "${KEY_PATH}" https://localhost:8443/healthz | grep -q '"status":"ok"'; then
        echo "Server is ready!"
        break
    fi
    echo "Server not ready yet, waiting... ($i/30)"
    sleep 2
done

if ! curl -s -k --cert "${CERT_PATH}" --key "${KEY_PATH}" https://localhost:8443/healthz | grep -q '"status":"ok"'; then
    echo "Error: Server failed to start within timeout period"
    exit 1
fi

run_cli() {
    >&2 echo "Running: cargo run -p hsm-cli -- --endpoint https://localhost:8443 --ca-bundle \"${CERT_PATH}\" --jwt-secret \"${JWT_SECRET}\" $*"
    cargo run -p hsm-cli -- \
        --endpoint https://localhost:8443 \
        --ca-bundle "${CERT_PATH}" \
        --jwt-secret "${JWT_SECRET}" \
        "$@"
    local exit_code=$?
    >&2 echo ""
    return $exit_code
}

# Alternative function that skips certificate verification for testing
run_cli_insecure() {
    >&2 echo "Running: cargo run -p hsm-cli -- --endpoint https://localhost:8443 --jwt-secret \"${JWT_SECRET}\" $*"
    cargo run -p hsm-cli -- \
        --endpoint https://localhost:8443 \
        --jwt-secret "${JWT_SECRET}" \
        "$@"
    local exit_code=$?
    >&2 echo ""
    return $exit_code
}

echo "=== Creating Keys ==="

create_aes_output=$(run_cli_insecure create aes256-gcm --usage encrypt,decrypt --tags poc)
if [ $? -ne 0 ]; then
    echo "Failed to create AES key"
    exit 1
fi
AES_KEY_ID=$(echo "${create_aes_output}" | awk '/Created key/{print $3}')
echo "AES key ID: ${AES_KEY_ID}"
echo ""

create_rsa_output=$(run_cli_insecure create rsa2048 --usage sign,verify --tags poc)
if [ $? -ne 0 ]; then
    echo "Failed to create RSA key"
    exit 1
fi
RSA_KEY_ID=$(echo "${create_rsa_output}" | awk '/Created key/{print $3}')
echo "RSA key ID: ${RSA_KEY_ID}"
echo ""

echo "=== Testing Encryption/Decryption ==="

encrypt_output=
if [ 127 -ne 0 ]; then
    echo "Failed to encrypt data"
    exit 1
fi
CIPHERTEXT=
NONCE=
echo "Ciphertext: "
echo "Nonce: "
echo ""

echo "Decrypting the ciphertext..."
run_cli_insecure decrypt "" "" ""
if [ 2 -ne 0 ]; then
    echo "Failed to decrypt data"
    exit 1
fi

echo "=== Testing Signing ==="

rsa_signature_output=
if [ 127 -ne 0 ]; then
    echo "Failed to sign with RSA key"
    exit 1
fi
RSA_SIGNATURE=""
echo "RSA signature: "
echo ""

echo "=== Listing Keys (shows Tags column) ==="
run_cli_insecure list
if [ 0 -ne 0 ]; then
    echo "Failed to list keys"
    exit 1
fi

fi
RSA_SIGNATURE=$(echo "${rsa_signature_output}" | tail -n1)
echo "RSA signature: ${RSA_SIGNATURE}"
echo ""

echo "=== Listing Keys (shows Tags column) ==="
run_cli list

echo "=== Demo Complete ==="
echo "Server logs are available at ${SERVER_LOG}"
echo ""
echo "FerroHSM demo completed successfully."
