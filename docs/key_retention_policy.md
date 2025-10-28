# Key Material Retention & Archival Policy

## Objectives
- Maintain an immutable history of key material for forensic analysis and restoration.
- Apply configurable retention windows aligned with key classification and regulatory mandates.
- Ensure secure destruction (logical and physical) of superseded key material after retention expiry.

## Classification & Retention Windows
| Key Class | Typical Usage | Retention Window | Rationale |
| --- | --- | --- | --- |
| `operational.default` | Service-to-service encryption/signing | 180 days (rolling) | Balances rollback needs with storage footprint; covers quarterly compliance audits. |
| `operational.critical` | Release signing, database master keys | 365 days | Supports yearly audits and rollback of long-lived credentials. |
| `compliance.sox` | SOX/SOC2 governed keys | 7 years | Mirrors financial record retention; required for audit defense. |
| `test.ephemeral` | Integration / QA environments | 30 days | Minimizes exposure for non-production keys. |

Retention classes map to policy tags. Multiple tags -> longest retention wins.

## Lifecycle States
1. **Active** – current generation pointed to by `current.json`.
2. **Revoked** – superseded by rotation or rollback, awaiting retention expiry.
3. **PurgeScheduled** – retention window elapsed, pending secure wipe.
4. **Destroyed** – removed from disk after wipe confirmation, audit event recorded.

## Secure Wipe Procedure
1. Verify key version is not referenced by approvals or active operations.
2. Generate audit event (`key.purge`) including version, actor, timestamp, wipe method.
3. Overwrite sealed file with cryptographically random data (`rand::rngs::OsRng` stream) matching file size, perform `sync_all`.
4. Remove file, update `current.json` if it pointed at purged version (should not happen—protect via guard).
5. Append retention ledger entry (JSON lines file) capturing purge metadata and hash of wiped data for attestation.

## Operational Controls
- **Scheduler:** Background task runs on the server (`RetentiveScheduler`) at a configurable interval (`--retention-interval-secs`, default 3600). It scans `keys/<id>` directories, evaluates retention deadlines using the configured policy, and creates purge approvals when windows expire.
- **Policy Config:** YAML/JSON (`--retention-config`, default `config/retention.yaml`) mapping tags to durations in days with optional overrides per key/version. The longest applicable duration is enforced.
- **Grace Period:** After approval, the scheduler enforces a configurable 24h grace (`--retention-grace-secs`, default 86400) before executing purges.
- **Ledger & Attestation:** Successful purges append JSONL entries to `--retention-ledger` (default `data/retention-ledger.log`) capturing wipe metadata, approval identifiers, and SHA-256 hashes of the overwrite stream for audit attestation.
- **Manual Overrides:** CLI command `retention extend --key-id <id> --version <n> --days <m>` to defer purge (requires Administrator + Auditor approval).
- **Cross-Checks:** Before purge, compare against audit anchoring checkpoints; abort if hash chain verification fails.

## Implementation Roadmap
1. **Config Loader (Sprint +1):** Parse retention YAML, expose via `RetentionPolicy` in `hsm-core` with lookup by tags.
2. **Scheduler (Sprint +1):** Tokio task in `hsm-server` evaluating purge candidates, generating approvals for dual-control confirmation prior to destructive wipe.
3. **Secure Wipe Engine (Sprint +2):** Implement file overwrite + attestation log, integrate with audit chain.
4. **CLI Enhancements (Sprint +2):** Commands for viewing retention status and approving purges.
5. **Monitoring (Sprint +3):** Metrics for purge queue length, last successful wipe, and retention violations.

## Compliance Considerations
- Ensure purge approvals require dual-control (Operator + Auditor) with 24h grace period.
- Maintain off-site backups of retention ledger for audit; encrypt ledger with operational KMS.
- Document RTO/RPO impact—restoring purged versions is impossible; communicate policy to stakeholders.
