# FerroHSM 0.4.0

## Highlights
- Added comprehensive post-quantum cryptography (PQC) support with NIST-standardized algorithms:
  - ML-KEM (formerly Kyber) at security levels 512, 768, and 1024
  - ML-DSA (formerly Dilithium) at security levels 65, 87, and 135
  - SLH-DSA (formerly SPHINCS+) hash-based signatures
- Implemented hybrid cryptography combining traditional and post-quantum algorithms:
  - P-256 + ML-KEM-768
  - P-384 + ML-KEM-1024
  - P-256 + ML-DSA variants
- Enhanced policy controls for PQC operations with configurable dual-control requirements and role-based restrictions
- **PKCS#11 Interface**: Full PKCS#11 v2.40 compliant interface for legacy application compatibility
- **Enhanced TUI**: Improved text-based user interface with menu-based navigation
- **Homebrew Distribution**: One-command installation for macOS and Linux users
- **Comprehensive Documentation**: Complete API reference and user guides for all interfaces
- Updated SDK examples and test scripts to demonstrate PQC functionality

## Bug Fixes
- Fixed compilation errors in the cryptographic core module related to missing braces in match statements
- Resolved type annotation issues in the signing code path

# FerroHSM 0.3.0

## Highlights
- Added comprehensive post-quantum cryptography (PQC) support with NIST-standardized algorithms:
  - ML-KEM (formerly Kyber) at security levels 512, 768, and 1024
  - ML-DSA (formerly Dilithium) at security levels 65, 87, and 135
  - SLH-DSA (formerly SPHINCS+) hash-based signatures
- Implemented hybrid cryptography combining traditional and post-quantum algorithms:
  - P-256 + ML-KEM-768
  - P-384 + ML-KEM-1024
  - P-256 + ML-DSA variants
- Enhanced policy controls for PQC operations with configurable dual-control requirements and role-based restrictions
- **PKCS#11 Interface**: Full PKCS#11 v2.40 compliant interface for legacy application compatibility
- **Enhanced TUI**: Improved text-based user interface with menu-based navigation
- **Homebrew Distribution**: One-command installation for macOS and Linux users
- **Comprehensive Documentation**: Complete API reference and user guides for all interfaces
- Updated SDK examples and test scripts to demonstrate PQC functionality

## Bug Fixes
- Fixed compilation errors in the cryptographic core module related to missing braces in match statements
- Resolved type annotation issues in the signing code path

# FerroHSM 0.2.0

## Highlights
- Hardened authentication with reloadable JWT configuration supporting HS256, RS256, and ES256 algorithms plus issuer enforcement and key rotation.
- Enforced dual-control governance via persistent approvals, quorum checks, and CLI/server workflows.
- Added token-bucket rate limiting, mutual TLS binding support, and TLS 1.3 termination updates.
- Upgraded the TLS stack to `rustls` 0.23 with the `ring` crypto provider, refreshed `axum-server`/`rustls-acme` integrations, and enabled automatic OCSP fetching/stapling (including background refresh for ACME-cached certificates).
- Introduced `--tls-mode` runtime provisioning with manual PEM reload + OCSP stapling and automated Let's Encrypt issuance via `rustls-acme` (staging/production directories, cached account keys).
- Implemented hash-chained audit logging with optional HMAC signatures and a CLI verification utility.
- Expanded CLI capabilities for asymmetric JWT minting, approval management, and audit verification.
- Introduced approval denial workflow across REST (`POST /api/v1/approvals/:id/deny`), CLI, and web UI, with the dashboard surfacing approvals, audit tails, and Prometheus-backed metrics cards.
- Refreshed Go/Python SDK examples and end-to-end tests to cover approvals listing, denial, and metrics telemetry.
- Updated documentation (architecture, security evaluation, README, PRD) to reflect the secure MVP feature set.
- Added Homebrew packaging assets (`scripts/package_homebrew.sh`, `dist/homebrew/ferrohsm.rb`) for distributing the CLI via `brew`.
- Refactored key storage to retain immutable per-version history and added API/CLI support for rotation history and rollback workflows.
- Authored retention & archival policy (`docs/key_retention_policy.md`) defining purge windows and secure wipe procedures for versioned key material.
- Introduced paginated, filterable key listings with short-lived caching plus CLI flags for inventory navigation.
- Integrated Prometheus-compatible metrics (`/metrics`) and structured health checks reporting rate limiting, JWT auth failures, and cache telemetry.
- Expanded integration test suite to exercise RSA/P-256 signing flows, rotation and rollback lifecycles, revoke/destroy operations, and RBAC policy denials.
- Implemented retention scheduler with configurable policy/interval/grace flags, dual-control purge approvals, secure wipe attestation ledger, and retention metrics.
- Added SQLite-backed audit log and approval stores with configurable retention sweeps, enabling durable governance data without unbounded growth.

## Bug Fixes
- Fixed critical compilation errors in the cryptographic core module that prevented successful builds

## Homebrew Installation

```bash
# package and upload release artifact, then host formula in a tap
./scripts/package_homebrew.sh

# install locally using the generated formula (for testing)
brew install --formula ./dist/homebrew/ferrohsm.rb
```

