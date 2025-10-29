#!/bin/bash

echo "=== FerroHSM CLI Demo ==="
echo ""

echo "1. Show available commands:"
echo "   cargo run -p hsm-cli -- --help"
echo ""

echo "2. Show help for creating keys:"
echo "   cargo run -p hsm-cli -- create --help"
echo ""

echo "3. Show help for encryption:"
echo "   cargo run -p hsm-cli -- encrypt --help"
echo ""

echo "4. Show help for decryption:"
echo "   cargo run -p hsm-cli -- decrypt --help"
echo ""

echo "5. Show help for signing:"
echo "   cargo run -p hsm-cli -- sign --help"
echo ""

echo "=== Available Algorithms ==="
echo "The CLI supports these algorithms:"
echo "  - aes256-gcm"
echo "  - rsa2048"
echo "  - rsa4096"
echo "  - p256"
echo "  - p384"
echo ""

echo "=== Usage Examples (requires running server) ==="
echo "1. Create an AES key:"
echo "   cargo run -p hsm-cli -- --jwt-secret \$(openssl rand -base64 32) create aes256-gcm --usage encrypt,decrypt --tags demo"
echo ""

echo "2. Encrypt data with an AES key:"
echo "   cargo run -p hsm-cli -- --jwt-secret \$(openssl rand -base64 32) encrypt <key-id> 'Hello, FerroHSM!'"
echo ""

echo "3. Decrypt data with an AES key:"
echo "   cargo run -p hsm-cli -- --jwt-secret \$(openssl rand -base64 32) decrypt <key-id> <ciphertext-b64> <nonce-b64>"
echo ""

echo "4. Create an RSA key for signing:"
echo "   cargo run -p hsm-cli -- --jwt-secret \$(openssl rand -base64 32) create rsa2048 --usage sign,verify --tags signing"
echo ""

echo "5. Sign data with an RSA key:"
echo "   cargo run -p hsm-cli -- --jwt-secret \$(openssl rand -base64 32) sign <key-id> 'Data to sign'"
echo ""

echo "Note: These commands require a running FerroHSM server to work."