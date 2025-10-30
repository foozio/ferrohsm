# FerroHSM

FerroHSM is a software-based Hardware Security Module implemented in Rust with Secure by Design principles. It offers cryptographic key management, tamper-evident storage, role-based access control, and multiple interfaces for integration with modern platforms.

## Crate Overview

- `hsm-core`: memory-safe cryptographic core featuring AES-256-GCM, RSA-2048/4096, P-256/P-384, post-quantum cryptography (ML-KEM, ML-DSA, SLH-DSA), hybrid cryptography, policy enforcement, and audit logging.
- `hsm-server`: Axum-based HTTPS service delivering REST APIs and a management UI surfacing approvals, audit trails, and live metrics with JWT authentication and optional mutual TLS support.
- `hsm-cli`: administrative client for day-to-day operations built on top of the REST API with built-in JWT issuance.
- `hsm-pkcs11`: PKCS#11 interface implementation providing compatibility with legacy applications and hardware security modules.
- `hsm-tui`: text-based user interface for interactive HSM management directly from the terminal.

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
3. **TUI**: Text-based user interface for interactive management
4. **PKCS#11**: Standard cryptographic token interface for legacy application compatibility
5. **Web UI**: Browser-based management interface (coming soon)

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

## Maintainer

- Nuzli L. Hernawan (<nuzlilatief@gmail.com>, [@foozio](https://github.com/foozio))

## License

Released under the [MIT License](./LICENSE).

## Crate Overview

- `hsm-core`: memory-safe cryptographic core featuring AES-256-GCM, RSA-2048/4096, P-256/P-384, post-quantum cryptography (ML-KEM, ML-DSA, SLH-DSA), hybrid cryptography, policy enforcement, and audit logging.
- `hsm-server`: Axum-based HTTPS service delivering REST APIs and a management UI surfacing approvals, audit trails, and live metrics with JWT authentication and optional mutual TLS support.
- `hsm-cli`: administrative client for day-to-day operations built on top of the REST API with built-in JWT issuance.

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

### PQC REST API surface

When the `pqc` feature flag is enabled, the server now wires dedicated REST endpoints for managing post-quantum material and hybrid workflows alongside the classical APIs:

- `POST /api/v1/keys/pqc` – create ML-KEM, ML-DSA, or SLH-DSA key material at the requested security level.
- `POST /api/v1/keys/hybrid` – mint hybrid elliptic-curve + PQC key pairs (ECDH+ML-KEM or ECDSA+ML-DSA).
- `POST /api/v1/keys/:id/encapsulate` – run ML-KEM encapsulation and return the ciphertext + shared secret (Base64).
- `POST /api/v1/keys/:id/decapsulate` – accept a Base64 ciphertext and derive the shared secret via ML-KEM decapsulation.

These routes are registered automatically when building or running `hsm-server` with `--features pqc`, and they inherit the same RBAC, policy, audit, and dual-control protections as the classical endpoints.

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

   Swap `--auth-jwt-secret` for `--auth-jwt-config` if you manage verification keys via YAML/JSON; HS256 entries in that file must still decode to at least 32 bytes.

   To enable automatic certificate issuance with Let's Encrypt staging (default), supply domains and contacts instead of static PEMs:

   ```bash
   cargo run -p hsm-server -- \
     --tls-mode acme \
     --acme-domain hsm.example.com \
     --acme-contact ops@example.com \
     --acme-cache-dir data/acme \
     --acme-use-production \
     --client-ca certs/ca.pem \
     --key-dir data/keys \
     --audit-log data/audit.log \
     --master-key "$FERROHSM_MASTER_KEY" \
     --hmac-key "$FERROHSM_HMAC_KEY" \
     --auth-jwt-config config/jwt.yaml \
     --retention-config config/retention.yaml \
     --retention-ledger data/retention-ledger.log
   ```

   Example `config/jwt.yaml`:

   ```yaml
   algorithm: RS256
   issuer: https://issuer.example.com
   leeway_seconds: 120
   keys:
     - kid: primary-2025-10
       public_key_pem: |
         -----BEGIN PUBLIC KEY-----
         ...
         -----END PUBLIC KEY-----
     - kid: fallback-2025-09
       public_key_pem: |
         -----BEGIN PUBLIC KEY-----
         ...
         -----END PUBLIC KEY-----
   ```

   Retention policies are configured via `config/retention.yaml` and map policy tags or explicit key versions to retention windows (days). The scheduler scans hourly (configurable), creates dual-control purge approvals, enforces a 24h grace period after approval, and emits attestation records to `data/retention-ledger.log` with wipe metadata and hashes.

   Example `config/retention.yaml`:

   ```yaml
   default_days: 180
   tags:
     operational.default: 180
     operational.critical: 365
     compliance.sox: 2555
     test.ephemeral: 30
   overrides:
     - key_id: release-signer
       version: 1
       days: 730
   ```

   Storage backends are pluggable via the `KeyStore` trait. The default filesystem store persists sealed blobs under `--key-dir`. To back FerroHSM with SQLite instead, start the server with `--key-store sqlite --sqlite-path data/keys.sqlite`. Cloud or HSM-backed vaults can integrate by implementing `RemoteKeyVault` and wiring it through `RemoteKeyStore`.

   Audit logs and dual-control approvals may also leverage SQLite for durability: launch with `--audit-store sqlite --audit-sqlite-path data/audit.sqlite` and `--approval-store sqlite --approval-sqlite-path data/approvals.sqlite`. When running in SQLite mode, background tasks enforce retention windows configured via `--audit-retention-days` and `--approval-retention-days`, purging stale events on the intervals defined by their respective `--*-retention-interval-secs` flags.

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

   The tabular output now includes a `Tags` column so you can confirm policy annotations at a glance. Combine it with the existing `--tags` filter to scope results to specific retention or approval policies.

   The CLI expects the JWT material to align with the server configuration. When using `--jwt-secret` with HS256, provide a base64 or UTF-8 value that is at least 32 bytes after decoding so it passes server validation. For asymmetric issuers:

   ```bash
   cargo run -p hsm-cli -- \
     --endpoint https://localhost:8443 \
     --client-cert certs/client.pem \
     --client-key certs/client-key.pem \
     --ca-bundle certs/ca.pem \
     --jwt-algorithm rs256 \
     --jwt-private-key config/jwt-signing-key.pem \
     --jwt-issuer https://issuer.example.com \
     --jwt-kid primary-2025-10 \
     list
   ```

   Dual-control approvals can be inspected and granted from the CLI when sensitive operations require quorum:

   ```bash
   cargo run -p hsm-cli -- approvals list
   cargo run -p hsm-cli -- approvals approve --approval-id <UUID>
   cargo run -p hsm-cli -- approvals deny --approval-id <UUID>
   ```

   Paginated listings and filtering are supported when querying the key inventory:

   ```bash
   cargo run -p hsm-cli -- list --per-page 20 --page 1 --algorithm rsa2048 --state active --tags operational.critical,beta
   ```

   Key version history, rotation, and rollback are available directly from the CLI:

   ```bash
   cargo run -p hsm-cli -- rotate --key-id <KEY_ID>
   cargo run -p hsm-cli -- versions --key-id <KEY_ID>
   cargo run -p hsm-cli -- rollback --key-id <KEY_ID> --version 2
   ```

5. Explore the web interface at `https://localhost:8443/ui` (requires presenting a valid client certificate when mTLS is enabled and a valid Authorization header). The dashboard combines pending approvals with approve/deny controls, recent audit events with integrity hashes, uptime, rate limiter statistics, and Prometheus-derived cache metrics.

6. Verify audit log integrity (hash chain + optional HMAC signature) with:

   ```bash
   cargo run -p hsm-cli -- audit verify --audit-path data/audit.log --hmac-key $(cat audit-hmac.txt)
   ```

7. Monitor health and metrics:

   ```bash
   curl -sk https://localhost:8443/healthz | jq
   curl -sk https://localhost:8443/metrics | head
   ```

   Metrics include `ferrohsm_rate_limit_allowed_total`, `ferrohsm_rate_limit_blocked_total`, `ferrohsm_auth_jwt_failure_total`, key cache hit/miss/store counters, and retention gauges/counters (`ferrohsm_retention_queue_length`, `ferrohsm_retention_purge_scheduled_total`, `ferrohsm_retention_purge_completed_total`). The web dashboard renders these counters directly in its cards; scrape via Prometheus or bridge to OpenTelemetry collectors.

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

## Maintainer

- Nuzli L. Hernawan (<nuzlilatief@gmail.com>, [@foozio](https://github.com/foozio))

## License

Released under the [MIT License](./LICENSE).
