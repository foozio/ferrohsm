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
echo "  - aes256-gcm (symmetric encryption)"
echo "  - rsa2048 (RSA signing/verification)"
echo "  - rsa4096 (RSA signing/verification)"
echo "  - p256 (ECDSA signing/verification)"
echo "  - p384 (ECDSA signing/verification)"
echo "  - ml-dsa-44 (Post-quantum signing - Dilithium)"
echo "  - ml-dsa-65 (Post-quantum signing - Dilithium)"
echo "  - ml-dsa-87 (Post-quantum signing - Dilithium)"
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

echo "6. Create a post-quantum ML-DSA key for signing:"
echo "   cargo run -p hsm-cli -- --jwt-secret \$(openssl rand -base64 32) create ml-dsa-44 --usage sign,verify --tags pqc"
echo ""

echo "7. Sign data with an ML-DSA key:"
echo "   cargo run -p hsm-cli -- --jwt-secret \$(openssl rand -base64 32) sign <key-id> 'Post-quantum signed data'"
echo ""

echo "8. List keys (the output now includes a Tags column so policy annotations are visible):"
echo "   cargo run -p hsm-cli -- --jwt-secret \$(openssl rand -base64 32) list --tags demo"
echo ""

echo "=== Running the Demo ==="
echo "To run a full demo:"
echo "1. Start the server in one terminal (supply TLS material plus master & HMAC keys):"
echo "   export FERROHSM_MASTER_KEY=\$(openssl rand -base64 32)"
echo "   export FERROHSM_HMAC_KEY=\$(openssl rand -base64 32)"
echo "   cargo run -p hsm-server -- \\"
echo "     --cert certs/server.pem \\"
echo "     --key certs/server-key.pem \\"
echo "     --master-key \"\$FERROHSM_MASTER_KEY\" \\"
echo "     --hmac-key \"\$FERROHSM_HMAC_KEY\" \\"
echo "     --auth-jwt-secret \$(openssl rand -base64 32)"
echo ""
echo "2. In another terminal, run the CLI commands as shown above."
echo ""
echo "Note: These commands require a running FerroHSM server to work."
