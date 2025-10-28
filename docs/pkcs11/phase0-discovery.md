# Phase 0 — PKCS#11 Discovery & Architecture Notes

## 1. `hsm-core` Capability Audit

| Capability Area | Relevant APIs / Types | Notes for PKCS#11 Bridging |
| --- | --- | --- |
| Session / Authentication context | `AuthContext`, policy engine (`PolicyEngine::evaluate`, approvals) | PKCS#11 sessions map to authenticated contexts. Need lightweight session objects decoupled from policy approvals; dual-control remains server-side. |
| Key lifecycle | `KeyManager::generate_key`, `rotate_key`, `rollback_key`, `revoke_key`, `destroy_key`, `list_key_versions` | Aligns with `C_GenerateKey`, `C_DestroyObject`, `C_CopyObject`, and versioning. Rollback can back `C_SetAttributeValue` + version clones. |
| Key storage | `KeyStore` trait, `KeyRecord`, `SealedKeyMaterial` | Objects persisted per version; PBKDF-sealed. Need mapping from PKCS#11 handles to `(KeyId, version)` tuples plus in-memory handle table. |
| Crypto operations | `CryptoOperation::{Encrypt,Decrypt,Sign,Verify,WrapKey,UnwrapKey}`, `CryptoEngine::perform` | Satisfies mechanisms for AES-GCM (encrypt/decrypt), RSA (PKCS#1 v1.5 sign/verify), P-256/P-384 ECDSA. Lacks digest-only operations, C_Digest*, random generation (except `OsRng` usage). |
| Randomness | `CryptoEngine::random_nonce`, `OsRng` usage | Need to expose `C_GenerateRandom` wrapper around `OsRng`. |
| Policy & approvals | `PolicyEngine`, `PolicyDecision`, approval workflows | PKCS#11 login roles map to FerroHSM roles (User/SO). Dual-control mostly orthogonal but must surface as CKR_USER_NOT_LOGGED_IN / CKR_ACTION_PROHIBITED equivalents when pending. |
| Audit logging | `AuditLog` trait, `AuditRecord`, `compute_event_hash` | PKCS#11 events must emit audit entries with CK operation metadata. |
| Metrics | Prometheus counters (rate limiting, cache) | Extend to PKCS#11-specific metrics (sessions, op latency, CKR error counts). |

Gaps identified:

- Attribute model: `KeyMetadata` lacks PKCS#11 attribute sets (e.g., `CKA_CLASS`, `CKA_LABEL`, per-mechanism flags). Need extensible metadata store.
- Session state machine: no abstraction for R/W vs R/O sessions, SO vs user login, or per-session object handles.
- Mechanism coverage: missing key agreement (ECDH), AES-CBC/CTR, digest-only operations; to prioritise after core flows.
- Object visibility: need search/index API supporting attribute templates (wrap existing `list_keys` with filters + soft objects).

## 2. PKCS#11 Function Coverage Mapping

| PKCS#11 Function | Priority | Proposed Mapping | Notes |
| --- | --- | --- | --- |
| `C_Initialize` / `C_Finalize` | P0 | New entry points initializing adapter registry and loading configuration. | Should reuse existing config loader; initialization returns fake slot for default token. |
| `C_GetInfo`, `C_GetSlotList`, `C_GetSlotInfo`, `C_GetTokenInfo` | P0 | Static metadata derived from server configuration + hardware adapters. | Provide per-adapter descriptors (manufacturer, flags). |
| `C_OpenSession`, `C_CloseSession`, `C_CloseAllSessions` | P0 | Wraps session manager storing `{session_handle, auth_context, capabilities}`. | Implement session pooling to reuse authenticated contexts. |
| `C_Login`, `C_Logout` | P0 | Maps to JWT-authenticated roles via `AuthVerifier`; maintain session state. | Support USER (operator) and SO (administrator). |
| `C_GenerateKey`, `C_GenerateKeyPair` | P0 | Delegate to `KeyManager::generate_key`; extend to return handles + attribute templates. | For RSA/ECC pair generation, re-use existing algorithms. |
| `C_DestroyObject` | P0 | Maps to `KeyManager::destroy_key`. | Need handle-to-key resolution and policy enforcement. |
| `C_FindObjectsInit/FindObjects/FindObjectsFinal` | P0 | Attribute filtering against `KeyMetadata` + new attribute store. | Support label, class, key type at minimum. |
| `C_Sign` / `C_Verify` | P0 | Use `CryptoOperation::Sign/Verify`. | Format conversion for DER signatures vs raw; parameter handling per mechanism. |
| `C_Encrypt` / `C_Decrypt` | P1 | Use `CryptoOperation::Encrypt/Decrypt`. | Need mechanism-specific IV handling (AES-GCM). |
| `C_WrapKey` / `C_UnwrapKey` | P1 | Leverage `CryptoOperation::WrapKey/UnwrapKey`. | Extended attribute propagation for wrapped keys. |
| `C_GenerateRandom` | P1 | Expose `OsRng` helper. | Thread-safe RNG via `rand` crate. |
| `C_GetAttributeValue` / `C_SetAttributeValue` | P1 | Backed by metadata store; enforce read-only attributes. | Some attributes configurable only during key creation. |
| `C_InitPIN` / `C_SetPIN` | P2 | Map to policy-managed credentials or mark not supported initially. |
| `C_Digest*` | P2 | Need direct hashing support if required; optional for interop MVP. |

## 3. Hardware Adapter Trait Proposal

```rust
pub enum HardwareCapability {
    Generate(KeyAlgorithm),
    Sign { mechanism: Mechanism },
    Verify { mechanism: Mechanism },
    Wrap { mechanism: Mechanism },
    Unwrap { mechanism: Mechanism },
    Import(KeyAlgorithm),
    ExportPublic,
}

#[async_trait::async_trait]
pub trait HardwareKeyStore: Send + Sync {
    fn id(&self) -> &'static str;
    async fn capabilities(&self) -> HashSet<HardwareCapability>;
    async fn list(&self) -> HsmResult<Vec<HardwareKeyInfo>>;
    async fn generate(&self, request: KeyGenerationRequest) -> HsmResult<HardwareKeyInfo>;
    async fn import(&self, material: KeyMaterial, attrs: AttributeSet) -> HsmResult<HardwareKeyInfo>;
    async fn destroy(&self, handle: HardwareHandle) -> HsmResult<()>;
}

#[async_trait::async_trait]
pub trait HardwareSigner: Send + Sync {
    async fn sign(&self, handle: HardwareHandle, mechanism: Mechanism, payload: &[u8]) -> HsmResult<Vec<u8>>;
    async fn verify(&self, handle: HardwareHandle, mechanism: Mechanism, payload: &[u8], signature: &[u8]) -> HsmResult<bool>;
}
```

Capability matrix draft:

| Adapter | Generate | Sign/Verify | Wrap/Unwrap | Notes |
| --- | --- | --- | --- | --- |
| Software fallback (existing `KeyStore`) | AES, RSA, EC | pkcs1v15, ECDSA | AES-GCM | Default CI path. |
| SoftHSM | AES, RSA, EC | pkcs1v15, ECDSA | AES-CBC, AES-KW | Use PKCS#11 bridge for regression. |
| Cloud HSM (AWS) | RSA, EC | pkcs1v15, ECDSA | AES-KWP (subset) | Requires async network adapter + credential refresh. |
| YubiHSM 2 | EC (EdDSA), wrap/unwrap | Ed25519, ECDSA | Derived via `WrapData` | Serial channel command framing required. |

## 4. Object Handle & Attribute Storage Plan

- **Handle Model:** Map PKCS#11 `CK_OBJECT_HANDLE` to `u64` generated per session, backed by a global registry: `{handle -> ObjectDescriptor}` where descriptor stores `(key_id, version, object_class, template_hash, visibility)`.
- **Persistent Attributes:** Extend `KeyMetadata` with an `AttributeSet` (serde-encoded map). Store label, key type, allowed mechanisms, sensitivity flags (`CKA_SENSITIVE`, `CKA_EXTRACTABLE`).
- **Session Objects:** Maintain per-session collections for transient objects (generated during session, not persisted). Use `HashMap<SessionHandle, Vec<ObjectHandle>>` to clean on logout.
- **Search Index:** Build secondary index keyed by (class, label, mechanism constraints) to accelerate `C_FindObjects*`. Reuse existing cache infrastructure with TTL.
- **Concurrency:** Rely on `parking_lot::RwLock` for registries; ensure handle invalidation on key destroy/rotate.

## 5. ADR Outline (PKCS#11 Shim Architecture)

- **Context:** Need C ABI shim delivering PKCS#11 compatibility without compromising security posture.
- **Decision:** Introduce new crate `hsm-pkcs11` compiling to a `cdylib`. The crate hosts FFI boundary, converts PKCS#11 structs (`cryptoki::types`) into internal commands dispatched over an async channel to a background runtime co-located with `hsm-server` core logic. Leverage IPC (Unix socket) when running as sidecar; in embedded mode, link directly to `hsm-core`. See ADR 0001 (`docs/adr/0001-pkcs11-shim-architecture.md`) for the formal record.
- **Threading Model:** FFI exports remain synchronous (per spec) but delegate to an async runtime via `tokio::runtime::Handle::block_on`. Session state stored in `Arc<SessionManager>` guarded by `RwLock`. Hardware adapters register with manager at init.
- **Error Translation:** Map `HsmError` to `CKR_*` codes (e.g., `PolicyDenied` -> `CKR_ACTION_PROHIBITED`, `TamperDetected` -> `CKR_DEVICE_ERROR`). Unknown errors map to `CKR_FUNCTION_FAILED` with audit entry. Ensure no internal debug strings leak past CKR mapping.
- **Security Controls:** Enforce zeroisation on buffers crossing FFI boundary via `zeroize` crate wrappers. Add fuzz tests for request parsing. Maintain audit correlation by embedding session ID + operation in `AuditRecord`.
- **Alternatives Considered:** Running PKCS#11 as standalone process communicating over REST (rejected: high latency, credential exposure). Directly modifying `hsm-server` to expose C ABI (rejected: bloats binary, complicates TLS-laden runtime).
- **Consequences:** Additional crate increases build targets; need CI for Linux/macOS shared library outputs. Requires public API stability commitment for PKCS#11 wrapper.

Next deliverables: formal ADR document (`docs/adr/000X-pkcs11-shim.md`), attribute schema design proposal, and prototype session manager API sketches.

**Update:** Drafts available — refer to:
- `docs/adr/0001-pkcs11-shim-architecture.md`
- `docs/pkcs11/attribute-model.md`
- `docs/pkcs11/session-manager.md`
