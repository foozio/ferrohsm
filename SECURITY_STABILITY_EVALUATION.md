# Security & Stability Evaluation

## 1. Security Posture
### Strengths
- **Memory safety:** Core logic implemented in safe Rust; cryptographic primitives delegated to vetted crates (`aes-gcm`, `rsa`, `p256`, `p384`).
- **Sealed storage:** Key material encrypted with AES-256-GCM and authenticated with HMAC-SHA256 prior to persistence, reducing tampering risk.
- **Audit logging:** Append-only file sink with optional HMAC signing and file locking to prevent concurrent corruption.
- **Strict CSP for UI:** Web templates enforce Content-Security-Policy forbidding inline scripts.
- **Authenticated ingress:** REST and UI requests require HS256 JWT bearer tokens with expiry validation; optional mutual TLS adds channel binding. TLS certificates can be hot-reloaded from PEM/OCSP bundles or provisioned automatically via ACME (Let's Encrypt staging/production).
- **Rate limiting:** Token-bucket limiter keyed by actor throttles abusive clients across REST and UI surfaces using a bounded LRU store to cap memory impact.
- **Dual-control enforcement:** Sensitive operations now persist approvals on disk and require distinct operators to satisfy quorum before execution.
- **Versioned key history:** Rotations write immutable per-version artifacts with rollback and newly defined retention/secure purge policy.
- **Responsive inventory:** Key listings support pagination/filtering with a TTL-bound, LRU-capped per-actor cache, lowering I/O pressure during dashboard access without risking unbounded growth.
- **Observability hooks:** Structured `/healthz` JSON and Prometheus `/metrics` counters highlight rate limiting, JWT authentication failures, and cache telemetry.
- **Retention automation:** Scheduler enforces tag-based lifetimes, dual-control approvals with 24h grace, secure overwrites, and attestation ledger entries for purge events.
- **Pluggable storage:** `KeyStore` trait now ships with filesystem, SQLite, and in-memory implementations plus a `RemoteKeyStore` adapter for cloud/HSM vaults implementing `RemoteKeyVault`.
- **Durable governance data:** Audit logs and approval records can be routed to SQLite with configurable retention windows and background purges, preventing unbounded disk growth while preserving long-lived evidence.

### Gaps & Risks
1. **JWT secret management:** HS256 secret (now enforced to be >=32 bytes) is sourced from environment variables without automated rotation or hardware-backed storage; compromise enables token forgery.
2. **Dual-control flexibility:** Current quorum model enforces a single approval token with implicit two-party flow; lacks configurable quorum sizes and richer policy scopes.
3. **Audit signature management:** `FileAuditLog` accepts signing key but never verifies signatures or rotates keys; no log chain anchoring implemented.
4. **Retention ledger assurance:** While purges now execute automatically, ledger files remain local; loss or tampering of attestation records could go undetected without off-host replication.
5. **Error handling:** REST API collapses multiple internal errors into generic 500 responses, obscuring root cause analysis and complicating monitoring.

### Recommendations
- Integrate KMS-managed key rotation for JWT signing secrets and add JWK endpoint support for future asymmetric issuers.
- Enforce dual-control by persisting `PendingApproval` records and blocking operations until quorum met.
- Implement log chaining (hash of previous record) and periodic remote anchoring for audit logs.
- Replicate the retention ledger to hardened storage (encrypted) and anchor purge attestations with the audit hash chain to detect tampering.
- Harden TLS automation by monitoring ACME renewal failures and protecting cached account keys (e.g., encrypt `--acme-cache-dir` at rest, alert on repeated order errors).
- Expand error taxonomy returned by API while preserving non-leaky messages.

## 2. Stability & Reliability
### Strengths
- Uses `parking_lot` locks for lightweight synchronization and `fs2` for file locking, improving concurrency safety.
- Tokio async runtime with graceful shutdown ensures in-flight requests complete before exit.
- Unit tests cover symmetric key lifecycle end-to-end, exercising storage, audit, and crypto layers.

### Risks
1. **Backend profiling:** Filesystem store still scans per-record sequentially; while SQLite backend mitigates this, load/performance baselines for each backend remain unverified.
2. **No background maintenance:** Lacks compaction, log rotation, or health monitoring for storage and audit files.
3. **Mutable global state:** `DefaultPolicyEngine` maintains approvals in-memory (`RwLock<HashMap>`); restarts will drop pending approvals.
4. **Metrics coverage:** Counters are emitted for rate limiting, auth failures, and cache usage, but latency histograms and error gauges remain absent, limiting SLO monitoring.

### Recommendations
- Benchmark filesystem vs. SQLite vs. remote vault adapters under expected load and tune pagination/streaming APIs to ensure predictable latency; validate audit/approval retention sweeps against compliance evidence needs before pruning.
- Add maintenance tasks (audit log rotation, integrity verification) and extend telemetry with latency histograms plus SLO-driven alerting derived from the `/metrics` endpoint.
- Persist policy approvals in durable store or distributed cache to survive restarts.
- Integrate tracing spans with `tracing` subscriber to emit structured metrics compatible with OpenTelemetry.

## 3. Testing & Tooling
- [COMPLETED] Integration tests now cover RSA/EC operations, rotation, rollback, revoke/destroy flows, and RBAC policy denials.
- [COMPLETED] GitHub Actions `Secret Scan` workflow runs `gitleaks` against full Git history to detect leaked credentials.
- Add property-based tests (e.g., using `proptest`) for crypto operation round-trips.
- Run `cargo audit` and `cargo clippy --all-targets --all-features` in CI to catch dependency vulnerabilities and lint issues.
- Add end-to-end tests hitting REST API via hyper client exercising JWT issuance/validation, rate limiting responses, dual-control approval flows, and TLS handshakes.
