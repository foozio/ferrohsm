# FerroHSM Architecture

## Secure by Design Objectives
- **Minimal attack surface:** every exposed interface is authenticated, authorized, and rate limited; optional features are off by default.
- **Defense in depth:** layered isolation between the front end, policy engine, and cryptographic services with explicit trust boundaries; sensitive data is never exposed outside trusted contexts.
- **Memory safety:** 100% Rust codebase with no `unsafe` blocks in the critical path; cryptography delegated to vetted crates (`aes-gcm`, `rsa`, `p256`, `p384`).
- **Reproducibility:** deterministic build pipeline (`cargo --locked`, reproducible artefact hashes, SBOM metadata) with signed release bundles and provenance.
- **FIPS 140-3 inspired design:** module separation (cryptographic boundary, logical boundary, physical boundary analogue), power-up self-tests, startup entropy validation, detailed audit trail, dual-control for critical actions.

## High-Level Component Model
```
+--------------------------+        +------------------+
|   Management Surfaces    |        |  Integration SDK |
|  (CLI, Web UI, REST,     |        |  (Go, Python)    |
|   PKCS#11 facade)        |        +------------------+
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

### Crate Overview
- **`hsm-core`**: implements key lifecycle management, PKCS#11-aligned attribute storage (`AttributeSet`) with per-backend indexes, algorithm providers (AES-256-GCM, RSA-2048/4096, P-256/P-384, post-quantum algorithms), authorization policies, tamper-evident storage (HMAC over sealed blobs), audit logging, and extensibility hooks.
- **`hsm-server`**: exposes REST endpoints via Axum, performs TLS 1.3 termination with the `rustls` ring provider (manual PEM reloads with automatic OCSP retrieval/stapling or automated ACME lifecycle via `rustls-acme`), validates JWT bearer tokens using reloadable keysets (HS256/RS256/ES256), applies per-actor rate limiting, persists dual-control approvals, hosts the web UI (Tera templated dashboard with approvals queue, audit tail, and metrics cards), and orchestrates policy enforcement. When built with the `pqc` feature it also wires dedicated routes for PQC key creation, hybrid workflows, and ML-KEM encapsulation/decapsulation so post-quantum operations receive the same policy, audit, and approval guarantees as classical algorithms.
- **`hsm-cli`**: secure administrative CLI that authenticates using mutual TLS and/or short-lived JWTs it can mint locally, supporting workflows (initialize, rotate, approve, audit).
- **`hsm-pkcs11`**: implements the PKCS#11 v2.40 standard interface as a C-compatible shared library, providing session management, object handling, cryptographic operations, and key management for legacy application compatibility.
- **`hsm-tui`**: advanced text-based user interface built with Ratatui and ATAC-inspired modular design, featuring syntax highlighting, customizable themes, advanced key bindings, and comprehensive interactive management with full CLI feature parity.
- **`web/static`**: static assets for the embedded management UI (progressive enhancement, CSP enforced via headers).

## Trust Boundaries & Isolation Layers
1. **Network Boundary:** TLS 1.3 with optional mutual authentication. Operators may pin static PEMs while FerroHSM auto-fetches and staples OCSP responses on configurable intervals, or delegate issuance/renewal to Let's Encrypt via ACME (staging/production directories cached under `--acme-cache-dir`) with the same OCSP refresh guarantees. Rustls enforces modern cipher suites (ECDHE + AES-GCM/CHACHA20-POLY1305).
2. **Gateway Boundary:** Authentication layer validates JWTs (HS256, RS256, ES256) issued by trusted tooling, auto-reloads keysets for rotation, enforces issuer claims, and optionally binds identities to presented client certificates. Requests are mapped to RBAC roles (`Administrator`, `Operator`, `Auditor`, `Service`) and throttled via a token-bucket rate limiter per actor backed by a bounded LRU store (4096 actors with 5-minute idle eviction) to mitigate cache-amplified DoS attempts.
3. **Policy & Session Boundary:** Policy evaluation occurs before invoking cryptographic primitives. Session state is managed by the new `SessionManager`, which tracks PKCS#11-style slots, search cursors, and hardware adapters without exposing raw key material. Policy scripts are sandboxed (Wasm/Lua hooks) with timeouts and capability restrictions.
4. **Core Boundary:** `hsm-core` is the sole module with direct access to key material. All responses pass through a zeroisation boundary that wipes memory after use.
5. **Storage Boundary:** Keys are encrypted-at-rest using operator-provisioned 32-byte secrets (`--master-key` and `--hmac-key`) supplied at startup. Every blob includes integrity metadata (HMAC, version counter, monotonic clock) to detect tampering.

## Secure Key Lifecycle
1. **Creation:** Operator requests key creation (algorithm, usage policy). Policy engine validates request; key is generated using `rand::rngs::OsRng` seeded from OS entropy. Key metadata is recorded in the audit log.
2. **Activation:** Dual control can be enforced: second operator approval before keys transition from `Staged` to `Active` state.
3. **Usage:** API clients request operations (sign, decrypt, wrap). Requests pass through RBAC, rate limiting, and policy verification before the key manager performs the cryptographic operation in-memory.
4. **Rotation:** Scheduled or manual rotation writes immutable version files (`vNNNNNNNN.json`), preserving historical material while marking prior versions revoked; operators can promote (rollback) any historical version, which records a new generation and audit event. Retention classes (see `docs/key_retention_policy.md`) govern when revoked versions progress to purge workflows.
5. **Revocation/Destruction:** Secure wipe uses in-memory zeroisation and deletion of sealed blobs. Optional `shred --iterations` for filesystem-level sanitisation is orchestrated but not destructive by default.
6. **Audit:** Every lifecycle transition emits an HMAC-authenticated audit event with hash-chain integrity, appended to an append-only log and optionally forwarded to SIEM via syslog. A CLI verification tool validates signatures and chain continuity.

## Policy & RBAC
- RBAC matrix stored in signed configuration with fine-grained actions (e.g., `key:create`, `key:use:rsa`, `policy:update`).
- Sessions are issued as short-lived JWTs (5 minutes) referencing role grants and contextual constraints (client IP, mTLS certificate fingerprint).
- Policy scripts (Luau sandbox) can enforce custom business logic (e.g., time-based restrictions, geofencing).
- Administrative operations require dual control: actions remain `Pending` until quorum is met.

## Audit Logging & Tamper Evident Storage
- Audit entries structure: timestamp, actor, action, key_id, result, payload hash, sequence number, signature.
- Logs stored in an append-only file with fs2 advisory locks; periodic checkpoint hashed (SHA-512) and compared against previous anchor.
- Tamper-evident storage stores the sealed key blob per version (`keys/<id>/vNNNNNNNN.json`) with `version || algorithm || usage || ciphertext || nonce || mac`. HMAC (SHA-384) computed from master key ensures modification detection while `current.json` serves as a pointer to the active version and retention scheduler drives transition to secure wipe.

## Web & CLI Management
- CLI: built with Clap, supports mutual TLS and HS256/RS256/ES256 JWTs (minted locally) for authentication. Supports offline bootstrap (initial admin creation), key commands (create, rotate, rollback, history), audit verification, policy updates, and dual-control approval workflows (list/approve/deny) alongside metrics inspection helpers.
- Web UI: server-side rendered pages (Tera templates) behind JWT authentication (and client certificates when enabled); the dashboard renders key inventory, pending approvals with approve/deny controls, a hash-linked audit timeline, uptime, rate limiter statistics, and Prometheus-derived cache counters. Strict CSP, CSRF tokens, session cookies with `HttpOnly` & `Secure` flags.

## Integration Interfaces
- **REST API:** JSON-based endpoints following RESTful naming (`/api/v1/keys`, `/api/v1/keys/:id/rotate`, `/api/v1/keys/:id/versions`, `/api/v1/keys/:id/rollback`). Listing endpoints support pagination (`page`, `per_page`), filtering (`algorithm`, `state`, `tags`), and are backed by a TTL-bound, LRU-capped cache per actor (2048 unique queries) to keep memory usage predictable. Requires Bearer JWT tokens backed by reloadable keysets, is rate limited per client identity, persists dual-control approvals via `/api/v1/approvals`, and exposes explicit `POST /api/v1/approvals/:id/{approve|deny}` actions; responses are validated with Serde.
- **PKCS#11:** C-compatible shared library (`libhsm_pkcs11.so`/`libhsm_pkcs11.dylib`) implementing PKCS#11 v2.40 standard for legacy application integration, supporting session management, object operations, cryptographic functions, and key management with full attribute mapping.
- **TUI:** Interactive terminal interface for direct HSM management without network dependencies, featuring menu-based navigation, key operations, audit inspection, and approval handling.
- **SDK Examples:** Provided for Go and Python showing TLS-authenticated REST usage, error handling, and audit correlation IDs.

## Operational Controls & Deployment
- Designed for Linux target with systemd service file template. Uses `ambient_capabilities` to drop privileges, `PrivateTmp` and `ProtectHome` hardening.
- Container image (future) built with distroless base, `ro` filesystem, seccomp profile.
- Data directory separated from application binary; backup guidance includes encrypted snapshots and integrity checks.
- Deployment selects storage backend at runtime via `--key-store {filesystem,sqlite}` with `--sqlite-path` for database deployment; remote vault adapters reuse the same trait surface.
- Startup self-tests: RNG health, HMAC verification of sealed master key, configuration signature validation.
- Audit logs and approval workflows can be backed by SQLite (`--audit-store sqlite`, `--approval-store sqlite`), enabling on-disk durability with automated retention sweeps driven by configurable day-based windows.
- Retention scheduler executes hourly, loading `config/retention.yaml`, issuing purge approvals, enforcing a 24h post-approval grace, and recording attestation entries in `data/retention-ledger.log` once secure wipes complete.
- Metrics & Health: `/healthz` returns structured JSON (uptime, cache/load statistics) and `/metrics` exposes Prometheus-formatted counters (rate limiting, JWT failures, cache hits/misses) via the `metrics` exporter, compatible with Prometheus and OpenTelemetry collectors; the management UI consumes the same metrics feed to render dashboard telemetry.

## Threat Model Summary
- **Adversaries:** remote attackers, malicious insiders, stolen backups, compromised integration clients.
- **Key Risks & Mitigations:**
  - API Exploitation → TLS mTLS + RBAC + rate limiting.
  - Key Exfiltration → Keys never leave core; only operations; audit logging ensures traceability.
  - Tampering at Rest → HMAC + version counters + append-only log.
  - Side Channel (timing) → Constant-time primitives from RustCrypto suites, uniform error messages.
  - Supply Chain → Reproducible builds, dependency auditing (`cargo audit`), signature verification.
  - DoS → Tokio tower + request limits + circuit breakers.

## Extensibility Hooks
- Provider trait for storage backends ships with `FileKeyStore`, `SqliteKeyStore`, and `MemoryKeyStore`, plus a `RemoteKeyStore` adapter that accepts any cloud/HSM integration implementing `RemoteKeyVault`.
- Policy hook trait allowing different scripting engines (e.g., WASI modules).
- Event subscribers for audit streaming (Kafka, NATS, SIEM).
- CI/CD integration sample: CLI plugin executes signing operation as pipeline step using short-lived service role.

## Future Work
- FIPS 140-3 certification alignment (formal self-test harness, entropy source validation).
- Hardware-rooted key sealing with TPM or AWS Nitro Enclaves.
- Web UI: Browser-based management interface with real-time dashboards.
- Support for threshold cryptography (Shamir, MPC) to reduce single point of failure.
- Hardware HSM integration for commercial security modules.
