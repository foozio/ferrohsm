# FerroHSM Follow-Up Task List

## Immediate (Blocking)
1. [COMPLETED] Hardened JWT authentication with config-driven rotation, issuer validation, and asymmetric (RS/ES) verification support.
2. [COMPLETED] Persist dual-control approvals and enforce quorum for sensitive actions (landed in current iteration).
3. [COMPLETED] Added audit log chaining with hash linking and CLI verification utility to detect tampering.

## Near-Term (Next 1–2 Sprints)
1. [COMPLETED] Refactored key rotation to preserve historical versions and support rollback.
2. [COMPLETED] Designed retention and archival policy for versioned key material with purge windows and secure wipe confirmations.
3. [COMPLETED] Added pagination, filtering, and caching to key listing endpoints.
4. [COMPLETED] Integrated structured metrics and health checks (Prometheus/OpenTelemetry), including rate limiting counters and JWT auth failures.
5. [COMPLETED] Expanded integration tests to cover RSA/EC operations, rotation, rollback, revoke/destroy, and policy failures.
6. [COMPLETED] Implemented retention scheduler and purge attestation workflow described in `docs/key_retention_policy.md`.

## Medium-Term (Quarterly)
1. [COMPLETED] Support alternative key stores (database, cloud KMS) via `KeyStore` trait implementations.
2. [COMPLETED] Persist audit logs and approvals in durable backend with retention policies.
3. [COMPLETED] Harden TLS provisioning with `rustls` 0.23 (ring provider), automated ACME rotation, and proactive OCSP stapling/refresh.
4. [COMPLETED] Extend web UI to surface approvals (including approve/deny actions), audit trails, and live metrics.

## Long-Term
1. Implement PKCS#11 compatibility layer and hardware security integrations.
   - [x] Phase 0 discovery deliverables (ADR, attribute model, session manager prototype).
2. Explore threshold cryptography and secure enclaves for master key protection.
3. Formalize compliance artifacts (FIPS readiness, SOC2 controls) and security assurance processes.
