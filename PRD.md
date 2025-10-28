# FerroHSM Product Requirements Document (PRD)

## 1. Overview
FerroHSM is a software hardware security module that offers secure key lifecycle management, cryptographic operations, and auditable governance for cloud-native workloads. The platform exposes a REST API, CLI, and embedded web console, backed by a Rust core that handles key generation, sealing, authorization, and audit logging. This PRD captures the business objectives, user needs, and functional scope for the MVP release (v0.1).

## 2. Goals & Non-Goals
### Goals
1. Provide secure storage and lifecycle management for symmetric (AES-256-GCM) and asymmetric (RSA-2048/4096, P-256, P-384) keys.
2. Offer authenticated and authorized access to cryptographic operations (encrypt/decrypt, sign/verify, wrap/unwrap) with detailed audit trails.
3. Ship an operator-focused CLI and minimal web dashboard for observability and manual workflows.
4. Support deployment as a self-hosted service with TLS, optional mutual TLS, and runtime-selectable storage backends (filesystem by default, SQLite optional).
5. Establish extensibility points for alternative storage backends, policy engines, and audit sinks.

### Non-Goals
- FIPS certification, hardware-backed key sealing, or threshold cryptography.
- High availability clustering or cross-region replication.
- PKCS#11 compatibility (out of scope for MVP).
- Multi-tenant isolation and billing features.

## 3. Personas & User Journeys
### Security Operator (Primary)
- Needs to create, rotate, revoke, and inspect keys via CLI.
- Requires audit visibility and policy enforcement.

### DevOps Engineer
- Automates CI/CD signing via REST or SDK examples.
- Integrates with mutual TLS and service role identities.

### Auditor
- Consumes append-only audit logs for compliance.
- Verifies cryptographic controls and access decisions.

### Core Journeys
1. Operator authenticates via CLI, creates a symmetric key with policy tags, and verifies presence in dashboard.
2. DevOps pipeline invokes REST API to sign build artefacts using a designated key and records correlation ID.
3. Auditor extracts audit log, verifies HMAC signatures, and cross-checks for suspicious activity.

## 4. Functional Requirements
1. **Key Lifecycle**
   - Create keys with configurable algorithm, usage, policy tags, and description.
   - List and describe keys with version, state, usage, and tags, supporting pagination, filtering, and cached responses for responsive dashboards.
   - Rotate keys while preserving identifiers and immutable metadata history, support promoting historical versions (rollback), and enforce retention/archival windows defined per policy tag.
   - Revoke and destroy keys with tamper-evident audit entries.
2. **Cryptographic Operations**
   - Perform encrypt/decrypt (AES-256-GCM) with optional associated data.
   - Sign/verify payloads for RSA and EC keys (DER signatures).
   - Wrap/unwrap key material using symmetric keys.
3. **Access Control & Policy**
   - Enforce RBAC roles (Administrator, Operator, Auditor, Service).
   - Require short-lived JWT bearer tokens with config-driven keysets (HS256 or RS/ES algorithms), automated reload, and issuer validation; optionally bind sessions to mutual TLS client certificates.
   - Apply configurable per-actor rate limiting to all REST and UI surfaces.
   - Persist dual-control approvals tied to policy tags; block sensitive operations until quorum reached across distinct operators.
   - Propagate context (actor, session, client fingerprint, source IP).
4. **Audit Logging**
    - Emit append-only records with UUID, timestamp, actor, action, key_id, message, optional signature, and chained integrity hashes.
    - Support file-based audit sink with HMAC signing key and provide verification tooling for tamper detection.
    - Offer durable persistence for audit events via SQLite with configurable retention windows and automated pruning.
    - Record dual-control approvals (requested, approved, expired) with traceable identifiers.
    - Persist approval workflow state in durable storage (SQLite option) with retention policies for completed approvals.
5. **Interfaces**
   - REST API via Axum with TLS and optional mutual TLS.
   - CLI using Reqwest with mutual TLS and table-rendered outputs.
   - Web UI dashboard listing keys.
   - Example SDKs (Go, Python) demonstrating authenticated usage.
   - Runtime-selectable TLS provisioning: manual PEMs with hot reload/OCSP stapling or automated ACME issuance/renewal with cache-backed key retention.
6. **Storage Backends**
   - `KeyStore` trait must allow multiple implementations shipped in-tree (filesystem, SQLite, in-memory) with consistent semantics for versioning, purge, and rollback.
   - Provide adapter interface (`RemoteKeyVault` + `RemoteKeyStore`) enabling future cloud KMS/HSM integrations without altering policy or audit layers.

## 5. Non-Functional Requirements
1. **Security**
   - TLS 1.3 enforced; authenticated via JWT + optional mutual TLS with strict header rejection.
   - JWT verification uses server-held secret with exp validation; secrets sourced from secure environment variables.
   - Policy engine must prevent unauthorized actions and flag dual-control requirements.
   - Automated certificate lifecycle: manual deployments support periodic PEM/OCSP reload, while ACME mode obtains and rotates certs from Let's Encrypt (staging/production) using cached account material.
2. **Performance**
   - Single-node throughput target: 200 crypto ops/sec with median latency < 50 ms for symmetric operations.
   - Key listing must handle 5k keys with response time < 500 ms.
3. **Reliability**
   - Graceful shutdown handling; audit log writes must be durable.
   - Integrity check on sealed key material before usage.
   - Automated retention scheduler enforces tag-based lifetimes, dual-control purge approvals, 24h grace periods, and attestation logging.
   - Storage backend selectable via CLI flags (`--key-store {filesystem,sqlite}`) with consistent behavior across implementations.
    - Audit and approval stores expose retention knobs (`--audit-retention-days`, `--approval-retention-days`) to cap growth while maintaining compliance evidence.
4. **Observability**
   - Structured tracing (OpenTelemetry ready) for REST endpoints and core operations.
   - Expose `/metrics` (Prometheus exposition via `metrics` exporter) and `/healthz` JSON payloads capturing rate limiting, JWT auth failures, and cache statistics for integration with Prometheus/OpenTelemetry collectors.

## 6. Delivery Plan
| Milestone | Scope | Target |
| --- | --- | --- |
| Alpha (M1) | Core key lifecycle, AES-256-GCM operations, CLI list/create, audit logging | +4 weeks |
| Beta (M2) | RSA/EC support, REST API hardening, web dashboard, dual-control scaffolding | +8 weeks |
| GA (M3) | Policy enforcement refinements, SDK examples, security hardening review, docs | +12 weeks |

## 7. Success Metrics
- >95% automated test coverage for core key lifecycle paths.
- Zero critical security findings in third-party penetration testing.
- Operator satisfaction score ≥ 4/5 in pilot cohort.
- Mean time to rotate a key via CLI < 30 seconds end-to-end.

## 8. Open Questions
1. How should remote/cloud HSM adapters using `RemoteKeyVault` be prioritized relative to database deployments in future milestones?
2. Should audit signatures use asymmetric keys to enable non-repudiation across services?
3. How will dual-control approvals be surfaced in the UI and enforced end-to-end?
4. What SLAs are expected for production deployments (uptime, RPO/RTO)?
