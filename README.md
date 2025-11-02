# FerroHSM v0.3.0

FerroHSM is a software-based Hardware Security Module implemented in Rust with Secure by Design principles. It offers cryptographic key management, tamper-evident storage, role-based access control, and multiple interfaces for integration with modern platforms.

## What's New in v0.3.0

- **PKCS#11 Interface**: Full PKCS#11 v2.40 compliant interface for legacy application compatibility
- **Enhanced TUI**: Advanced text-based user interface with ATAC-inspired modular architecture, syntax highlighting, customizable themes, and comprehensive interactive management
- **Homebrew Distribution**: One-command installation for macOS and Linux users
- **Comprehensive Documentation**: Complete API reference and user guides

## Crate Overview

- `hsm-core`: memory-safe cryptographic core featuring AES-256-GCM, RSA-2048/4096, P-256/P-384, post-quantum cryptography (ML-KEM, ML-DSA, SLH-DSA), hybrid cryptography, policy enforcement, and audit logging.
- `hsm-server`: Axum-based HTTPS service delivering REST APIs and a management UI surfacing approvals, audit trails, and live metrics with JWT authentication and optional mutual TLS support.
- `hsm-cli`: administrative client for day-to-day operations built on top of the REST API with built-in JWT issuance.
- `hsm-pkcs11`: PKCS#11 interface implementation providing compatibility with legacy applications and hardware security modules.
- `hsm-tui`: advanced text-based user interface with ATAC-inspired modular design, syntax highlighting, customizable themes, and comprehensive key management capabilities.

## Post-Quantum Cryptography Support

FerroHSM includes support for NIST-standardized post-quantum cryptographic algorithms:

- **ML-KEM** (formerly Kyber): Key Encapsulation Mechanism at security levels 512, 768, and 1024
- **ML-DSA** (formerly Dilithium): Digital Signature Algorithm at security levels 65, 87, and 135
- **SLH-DSA** (formerly SPHINCS+): Hash-based Digital Signature Algorithm with various parameter sets

Hybrid cryptography options are also available, combining traditional elliptic curve cryptography with post-quantum algorithms:
- P-256 + ML-KEM-768
- P-384 + ML-KEM-1024
- P-256 + ML-DSA variants

Enhanced policy controls ensure proper governance of post-quantum operations, with configurable dual-control requirements and role-based restrictions for higher security levels.

## Installation

### Homebrew (macOS & Linux)

The easiest way to install FerroHSM on macOS or Linux is via Homebrew:

**macOS:**
```bash
brew tap foozio/ferrohsm
brew install ferrohsm
```

**Linux:**
```bash
brew install ./dist/homebrew-linux/ferrohsm.rb
```

See [Homebrew Installation](docs/homebrew/installation.md) for detailed instructions.

### Manual Installation

1. Install Rust (1.75+ recommended).
2. Clone this repository and build with `cargo build --release`
3. The binaries will be available in `target/release/`

## Getting Started

1. Install Rust (1.75+ recommended).
2. Choose a TLS provisioning mode:
   - **Manual (default)** – supply your own `--cert`/`--key` pair; FerroHSM will automatically fetch and staple live OCSP responses when `--ocsp-response` is omitted and refresh them using `--ocsp-refresh-interval-secs` alongside hot-reloading cert/key material.
   - **ACME automation** – let FerroHSM obtain and renew certificates from Let's Encrypt (or another ACME directory) with `--tls-mode acme` and one or more `--acme-domain` values; cached certs are stapled with periodically refreshed OCSP responses and served via a hybrid resolver that also handles ACME challenge traffic.
3. Launch the server (supply 32-byte base64 values for both the sealing master key and audit HMAC key, plus a 256-bit JWT secret via flag/env var or a config file describing rotating keys):

   ```bash
   export FERROHSM_MASTER_KEY=$(openssl rand -base64 32)
   export FERROHSM_HMAC_KEY=$(openssl rand -base64 32)
   export FERROHSM_JWT_SECRET=$(openssl rand -base64 32)
   ```

   ```bash
   cargo run -p hsm-server -- \
     --tls-mode manual \
     --cert certs/server.pem \
     --key certs/server-key.pem \
     --client-ca certs/ca.pem \
     --key-dir data/keys \
     --audit-log data/audit.log \
     --master-key "$FERROHSM_MASTER_KEY" \
     --hmac-key "$FERROHSM_HMAC_KEY" \
     --auth-jwt-secret "$FERROHSM_JWT_SECRET" \
     --list-cache-ttl-secs 5 \
     --retention-config config/retention.yaml \
     --retention-ledger data/retention-ledger.log \
     --retention-interval-secs 3600 \
     --retention-grace-secs 86400
   ```

4. Use the CLI (supply an existing token or mint one locally with the desired algorithm):

   ```bash
   cargo run -p hsm-cli -- \
     --endpoint https://localhost:8443 \
     --client-cert certs/client.pem \
     --client-key certs/client-key.pem \
     --ca-bundle certs/ca.pem \
     --jwt-secret $(cat jwt-secret.txt) \
     --jwt-algorithm hs256 \
     list
   ```

5. Use the TUI interface:

   ```bash
   cargo run -p hsm-tui
   ```

## Interfaces

FerroHSM provides multiple interfaces for different use cases:

1. **REST API**: JSON-based endpoints for programmatic access
2. **CLI**: Command-line interface for administrative tasks
3. **TUI**: Text-based user interface for interactive management with menu-based navigation
4. **PKCS#11**: Standard cryptographic token interface for legacy application compatibility
5. **Web UI**: Browser-based management interface (coming soon)

### TUI Features
The enhanced TUI provides:
- Intuitive menu-based navigation
- Key management interface with full CRUD operations
- Cryptographic operations (sign, encrypt, decrypt)
- Audit log viewing and verification
- Approval workflow management
- Settings configuration
- Comprehensive help system

## Tests

Unit and integration tests live under `tests/`, including lifecycle coverage for AES, RSA, and P-256 keys, rotation/rollback, revoke/destroy, and RBAC policy denials. Execute them with:

```bash
cargo test
```

## SDK Examples

- `examples/go-sdk`: demonstrates Go integration with mutual TLS.
- `examples/python-sdk`: demonstrates Python usage with requests.

See `docs/architecture.md` for the full design document, threat model, and security considerations.
See `docs/key_retention_policy.md` for key material retention and purge strategy details.
See [PLAN.md](PLAN.md) for the comprehensive development plan.
See [docs/tui/](docs/tui/) for TUI development plans and documentation.

## Maintainer

- Nuzli L. Hernawan (<nuzlilatief@gmail.com>, [@foozio](https://github.com/foozio))

## License

Released under the [MIT License](./LICENSE).