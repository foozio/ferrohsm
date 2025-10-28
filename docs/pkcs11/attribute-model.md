# PKCS#11 Attribute Model Proposal

## Goals
- Persist the minimum viable set of PKCS#11 attributes required for interoperability with SoftHSM and commercial vendors.
- Preserve backward compatibility for existing FerroHSM metadata consumers.
- Support session-scoped attributes without persisting them to disk.
- Enable efficient lookup of objects via `C_FindObjects*` templates.

## Attribute Storage Strategy

### Persistent Objects
- Extend `KeyMetadata` with a new `AttributeSet` field (serde map) stored alongside existing metadata.
- Attributes persisted by default:
  - `CKA_CLASS`
  - `CKA_KEY_TYPE`
  - `CKA_LABEL`
  - `CKA_ID`
  - `CKA_TOKEN`
  - `CKA_SENSITIVE`
  - `CKA_EXTRACTABLE`
  - `CKA_WRAP`, `CKA_UNWRAP`, `CKA_ENCRYPT`, `CKA_DECRYPT`, `CKA_SIGN`, `CKA_VERIFY`
  - `CKA_ALLOWED_MECHANISMS` (subset per capability)
- Attributes computed on the fly to avoid duplication:
  - `CKA_MODULUS_BITS`, `CKA_EC_PARAMS` derived from key material.
  - `CKA_ALWAYS_AUTHENTICATE` (driven by policy tags).

### Session Objects
- Maintain a per-session in-memory store keyed by `SessionHandle`.
- Only transient templates (e.g., generated wrapping keys, search results) are kept; they are dropped automatically on logout or `C_CloseSession`.

### Serialization
- Represent attributes as `HashMap<AttributeId, AttributeValue>` where `AttributeValue` supports the common PKCS#11 primitive types (bool, usize, byte array, mechanism list).
- Use a compact binary encoding (bincode) for storage; convert to/from JSON when exposing via management APIs.
- Attribute updates are versioned with the underlying key metadata to retain auditability.

## Indexing & Lookup
- Maintain secondary indexes to accelerate searches. The initial prototype is implemented in `MemoryKeyStore` and tracks `HashMap<AttributeId, HashMap<AttributeValue, Vec<(KeyId, version)>>`, allowing quick candidate lookup for `C_FindObjects*`.
- Disk-backed stores fall back to a linear scan during Phase 0; indexes will be extended as we integrate PKCS#11 persistence.
- Session-specific objects rely on the session manager’s search cursor (see `docs/pkcs11/session-manager.md`) and are not persisted.

## Attribute Mutability Rules
- Immutable after creation: `CKA_CLASS`, `CKA_KEY_TYPE`, `CKA_TOKEN`, `CKA_SENSITIVE`, `CKA_ID`.
- Mutable with policy check: `CKA_LABEL`, usage flags (e.g., `CKA_ENCRYPT`) if policy allows.
- Not supported in Phase 0: `CKA_WRAP_TEMPLATE`, `CKA_UNWRAP_TEMPLATE`, `CKA_ALWAYS_SENSITIVE`.

## Validation
- `AttributeSet` exposes helpers (`validate_required`, `ensure_allowed`, `matches_template`) that enforce required keys, reject unsupported identifiers, and evaluate search templates.
- Attribute templates provided by clients are validated before object creation; unsupported or conflicting attributes yield `CKR_TEMPLATE_INCOMPLETE` / `CKR_TEMPLATE_INCONSISTENT`.
- Persisted attributes are included in audit records for key lifecycle operations.

## Next Steps
1. [x] Add `AttributeSet` struct and serialization helpers to `hsm-core`.
2. [x] Implement attribute validation API referenced by the forthcoming session manager.
3. Prototype index structures and benchmark common `C_FindObjects*` queries (MemoryKeyStore implementation completed; benchmark work pending).
