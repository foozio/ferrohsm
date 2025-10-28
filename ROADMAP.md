# FerroHSM Roadmap

## 0. Guiding Principles
- **Security First:** Every milestone must improve or preserve cryptographic assurances, access controls, and auditability.
- **Operational Readiness:** Emphasize observability, automation, and predictable upgrades.
- **Incremental Delivery:** Ship value in releasable slices with backwards-compatible migration paths.

## 1. H1 2026 — Security Hardening & Governance
### Objectives
- Eliminate single points of failure in authentication and key custody.
- Provide auditable controls suitable for regulated environments.

### Major Initiatives
1. **JWT Secret Lifecycle Automation**
   - Integrate with cloud KMS or HSM for secret generation and rotation.
   - Support asymmetric JWT verification (EdDSA/ECDSA) with JWK discovery endpoint.
   - Deliver migration tooling for clients to adopt rotating issuers.
2. **Dual-Control Enforcement**
   - Persist `PendingApproval` records in durable storage (SQLite/Postgres feature flag).
   - Extend REST/UI/CLI with approval workflows and quorum rules per policy tag.
   - Emit audit entries for approval requests, approvals, denials, and expirations.
3. **Audit Log Integrity**
   - Chain audit records via hash pointers; publish periodic checkpoints to external anchor (e.g., S3, blockchain, notarization service).
   - Provide verification CLI that rebuilds the chain and validates HMAC signatures.

### Deliverables
- `v0.2` release with KMS-backed JWT rotation, approval APIs, and audit verification tooling.
- Updated runbooks and deployment manifests for new secrets and databases.

## 2. H2 2026 — Scalability & Reliability
### Objectives
- Scale beyond single-node file storage while maintaining tamper evidence.
- Improve performance observability and operational automation.

### Major Initiatives
1. **Storage Abstractions**
   - Build on the shipped SQLite `KeyStore`/`RemoteKeyStore` adapters to add Postgres support and managed cloud KMS connectors.
   - Add sealed blob garbage collection and archival policies.
2. **Distributed Deployment Support**
   - Introduce stateless server mode with shared storage and distributed coordinator for approvals.
   - Build Helm charts/Terraform modules with secure defaults and automated certificate provisioning (ACME).
3. **Observability Suite**
   - Expose Prometheus metrics (auth failures, rate limit hits, latency buckets).
   - Integrate OpenTelemetry tracing with service tags correlating audit IDs.
   - Add health probes and self-check endpoints (crypto self-tests, storage integrity).

### Deliverables
- `v0.3` release certified for clustered deployments with documented scale test results.
- Operations dashboard (Grafana) and alerting rules templates.

## 3. 2027 — Ecosystem Expansion & Compliance
### Objectives
- Broaden integration surface (SDKs, PKCS#11) and align with compliance standards.

### Major Initiatives
1. **API & SDK Enhancements**
   - GA Go/Python SDKs with auto-refresh tokens and circuit breaker patterns.
   - Add Java/.NET SDKs and Terraform provider for key management automation.
   - Publish OpenAPI spec with conformance tests.
2. **PKCS#11 Compatibility Layer**
   - Implement PKCS#11 shim backed by `hsm-core`, enabling legacy clients.
   - Run interoperability tests with major vendor suites (SafeNet, Thales).
3. **Compliance Readiness**
   - Map controls to SOC 2/FIPS 140-3 readiness checklist.
   - Provide evidence collection scripts (audit log exports, configuration snapshots).
   - Engage external assessment for cryptographic module validation planning.

### Deliverables
- `v1.0` release featuring PKCS#11 support, multi-language SDKs, and compliance documentation pack.

## 4. Future Horizons (Post-2027)
- **Threshold Cryptography:** Integrate MPC-based signing or Shamir key shards to remove single custodians.
- **Secure Enclaves:** Offer optional Nitro Enclave/TEE deployment mode for master key operations.
- **Policy Scripting Engine:** Host WASM policy sandbox with deterministic execution and attestation.
- **Zero-Knowledge Auditing:** Explore zk-proof summaries for audit logs to share evidence without sensitive details.

## 5. Dependencies & Risks
- Reliance on external KMS/HSM providers may introduce vendor lock-in—maintain abstraction layers.
- Database introduction requires migration tooling and HA guidance; risk of misconfiguration impacting tamper evidence.
- PKCS#11 compliance demands rigorous testing; schedule buffer for certification feedback.
- Secure enclave roadmap contingent on hardware availability and cloud provider features.

## 6. Reporting & Review Cadence
- Quarterly roadmap reviews with security, operations, and product stakeholders.
- Bi-weekly progress demos covering completed milestones and upcoming blockers.
- Maintain living roadmap in version control; update with post-mortems and scope adjustments.
