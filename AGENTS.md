# AGENTS.md

This file provides guidance to Qoder (qoder.com) when working with code in this repository.

## Build/Lint/Test Commands
- **Build all crates**: `cargo build`
- **Build specific crate**: `cargo build -p hsm-core` (or hsm-server, hsm-cli)
- **Run all tests**: `cargo test`
- **Run single test**: `cargo test test_name` or `cargo test -- --exact test_name`
- **Run tests for specific crate**: `cargo test -p hsm-core`
- **Run end-to-end tests**: `./scripts/e2e_test.sh`
- **Lint**: `cargo clippy`
- **Format**: `cargo fmt`
- **Verify compilation after changes**: Always run `cargo build -p hsm-core` to ensure cryptographic core compiles successfully

## Code Style Guidelines
- **Imports**: Group std imports first, then external crates, then local crates. Use explicit imports over glob imports.
- **Formatting**: Use `cargo fmt` for consistent formatting. Follow standard Rust formatting conventions.
- **Types**: Use strong typing with enums for constrained values. Implement Serialize/Deserialize for API types.
- **Naming**: snake_case for functions/variables, PascalCase for types/enums, SCREAMING_SNAKE_CASE for constants.
- **Error handling**: Use `thiserror` for custom error types. Return `Result<T, HsmError>` for fallible operations.
- **Documentation**: Add comprehensive doc comments for public APIs using `//!` for modules and `///` for items.
- **Async**: Use `tokio` runtime. Prefer async traits with `async-trait` crate.
- **Security**: Never log sensitive data. Use constant-time operations for crypto. Validate all inputs.

## High-Level Architecture

FerroHSM is a software-based Hardware Security Module implemented in Rust with Secure by Design principles. It offers cryptographic key management, tamper-evident storage, role-based access control, and both REST + CLI interfaces.

### Crate Overview
- `hsm-core`: Memory-safe cryptographic core featuring AES-256-GCM, RSA-2048/4096, P-256/P-384, post-quantum cryptography (ML-KEM, ML-DSA, SLH-DSA), hybrid cryptography, policy enforcement, and audit logging.
- `hsm-server`: Axum-based HTTPS service delivering REST APIs and a management UI surfacing approvals, audit trails, and live metrics with JWT authentication and optional mutual TLS support.
- `hsm-cli`: Administrative client for day-to-day operations built on top of the REST API with built-in JWT issuance.
- `hsm-pkcs11`: PKCS#11 interface implementation (adapter layer).
- `hsm-tui`: Advanced text-based user interface with ATAC-inspired modular design, syntax highlighting, customizable themes, and comprehensive interactive management.

### Architecture Layers
```
+--------------------------+        +------------------+
|   Management Surfaces    |        |  Integration SDK |
|  (CLI, TUI, Web UI,      |        |  (Go, Python)    |
|   REST, PKCS#11 facade)  |        +------------------+
+-------------+------------+
              |
              v
+-------------+------------+
| AuthN/AuthZ Gateway      |  -> JWT/RBAC validation, rate limiting, TLS mTLS termination
+-------------+------------+
              |
              v
+-------------+------------+
|  Policy & Session Layer  |  -> Policy evaluation, dual control, workflow engine
+-------------+------------+
              |
       Trusted Channel
              |
+-------------+------------+
|    Cryptographic Core    |  -> Key manager, crypto operations, tamper store
|  (hsm-core crate)        |
+-------------+------------+
              |
              v
+-------------+------------+
| Secure Storage Providers |  -> Encrypted file store, SQLite-backed store, in-memory/dev store, remote KMS/HSM backends via `RemoteKeyStore`
+--------------------------+
```

### Trust Boundaries
1. **Network Boundary**: TLS 1.3 with optional mutual authentication
2. **Gateway Boundary**: Authentication layer validates JWTs with reloadable keysets
3. **Policy & Session Boundary**: Policy evaluation and session management
4. **Core Boundary**: `hsm-core` is the sole module with direct access to key material
5. **Storage Boundary**: Keys are encrypted-at-rest using operator-provisioned secrets

### Key Components in hsm-core
- **Crypto**: Cryptographic operations (AES, RSA, ECC, Post-Quantum)
- **Storage**: Key storage with tamper-evident mechanisms
- **Audit**: Audit logging with hash-chain integrity
- **Policy**: RBAC and custom policy enforcement
- **Approvals**: Dual-control workflow system
- **Session**: Session management
- **Retention**: Key retention and purge scheduling

### Integration Points
- **REST API**: JSON-based endpoints for key management operations
- **CLI**: Command-line interface for administrative tasks
- **Web UI**: Browser-based management interface
- **PKCS#11** (future): Standard cryptographic token interface
- **SDKs**: Go and Python integration examples