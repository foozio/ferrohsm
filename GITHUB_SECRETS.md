# GitHub Secrets Inventory

| Secret Name | Purpose | Scope | Notes |
| --- | --- | --- | --- |
| `FERROHSM_MASTER_KEY` | 32-byte base64 master key for sealing data during integration tests | Actions workflows needing end-to-end tests | Mandatory at startup; use ephemeral value and never store production keys in GitHub. |
| `FERROHSM_HMAC_KEY` | 32-byte base64 HMAC key for audit log signatures in CI | Actions workflows | Mandatory at startup; rotate per workflow run. |
| `FERROHSM_JWT_SECRET` | Shared secret for HS256 JWT validation during integration tests | Actions workflows running `hsm-server` | Provide base64 or UTF-8 value **at least 32 bytes long**; rotate on every workflow run to avoid replay. |
| `TLS_CERT_PEM` | Self-signed certificate for integration testing | Actions workflows | Non-sensitive test certificate; consider using environment provisioning instead. |
| `TLS_KEY_PEM` | Private key paired with `TLS_CERT_PEM` | Actions workflows | Restrict access to CI runners; replace with short-lived keys regularly. |
| `CARGO_REGISTRY_TOKEN` | Publish token for crates.io (optional) | Release workflow | Store only if publishing; require least-privilege token. |
| `GH_PAGES_DEPLOY_TOKEN` | Deploy documentation to GitHub Pages (optional) | Docs workflow | Needed only if web docs deployment is enabled. |
| `SIEM_WEBHOOK_URL` | Forward audit logs during tests | Actions workflows | Use mock endpoint in CI; real URL should live in production secrets manager. |

## Handling Guidelines
1. Grant workflow access to secrets on an as-needed basis using environment-level permissions.
2. Prefer GitHub OpenID Connect federation with cloud secret stores when possible to avoid long-lived secrets.
3. Monitor GitHub audit logs for access to sensitive secrets and rotate quarterly at minimum.
