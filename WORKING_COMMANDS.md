# Working FerroHSM Commands

These commands can be executed successfully with the current build:

## Basic CLI Information

```bash
# Show all available commands
cargo run -p hsm-cli -- --help

# Show version
cargo run -p hsm-cli -- --version
```

## Key Management Commands

```bash
# Show help for list command
cargo run -p hsm-cli -- list --help

# Show help for create command
cargo run -p hsm-cli -- create --help

# Show help for rotate command
cargo run -p hsm-cli -- rotate --help

# Show help for versions command
cargo run -p hsm-cli -- versions --help

# Show help for rollback command
cargo run -p hsm-cli -- rollback --help
```

## Cryptographic Operations

```bash
# Show help for encrypt command
cargo run -p hsm-cli -- encrypt --help

# Show help for decrypt command
cargo run -p hsm-cli -- decrypt --help

# Show help for sign command
cargo run -p hsm-cli -- sign --help
```

## Administrative Commands

```bash
# Show help for approvals command
cargo run -p hsm-cli -- approvals --help

# Show help for audit command
cargo run -p hsm-cli -- audit --help
```

## Supported Algorithms for Key Creation

The create command supports these algorithms:
- `aes256-gcm` - AES-256 Galois/Counter Mode
- `rsa2048` - RSA with 2048-bit key
- `rsa4096` - RSA with 4096-bit key
- `p256` - NIST P-256 elliptic curve
- `p384` - NIST P-384 elliptic curve

## Example Usage Pattern (requires running server)

```bash
# Generate a JWT secret for authentication
JWT_SECRET=$(openssl rand -base64 32)

# Create a key (requires running server)
cargo run -p hsm-cli -- --jwt-secret $JWT_SECRET create aes256-gcm --usage encrypt,decrypt --tags demo

# List keys (requires running server)
cargo run -p hsm-cli -- --jwt-secret $JWT_SECRET list

# The above commands would work if the server was running and properly configured
```

## Current Limitations

1. **No Server**: Cannot connect to a running server without it being started
2. **No PQC**: Post-Quantum Cryptography features are not available due to build issues
3. **No PKCS#11**: PKCS#11 interface cannot be built due to code issues
4. **No Tests**: Cannot run tests due to PQC-related code issues

## Build Status

✅ `hsm-core` - Core cryptographic library (builds successfully)
✅ `hsm-cli` - Command-line interface (builds successfully)
❌ `hsm-pkcs11` - PKCS#11 interface (build fails)
❌ `hsm-server` - REST API server (build fails)
❌ PQC features (build fails)

## Next Steps

To make the full system functional:
1. Fix PQC implementation issues in the codebase
2. Resolve PKCS#11 module compilation errors
3. Fix server component issues
4. Enable end-to-end testing