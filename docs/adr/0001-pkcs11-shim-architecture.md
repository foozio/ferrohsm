# ADR 0001 — PKCS#11 Shim Architecture

## Status
Draft — pending platform sign-off

## Context
- FerroHSM must expose a PKCS#11 interface without regressing the security posture or deprecating existing REST/CLI clients.
- The `hsm-core` crate already encapsulates key management, crypto operations, audit, and policy enforcement; the new interface should reuse these capabilities.
- Customers expect a drop-in shared library (`libpkcs11.so`/`pkcs11.dll`) that satisfies the OASIS PKCS#11 specification while allowing deployment next to the existing server runtime.
- We must accommodate multiple hardware backends (software, SoftHSM, commercial HSMs) via a pluggable abstraction layer.
- The PKCS#11 specification is synchronous and C ABI–based, whereas FerroHSM is asynchronous Rust. Bridging them cleanly requires deliberate boundary management.

## Decision
We will build a dedicated `hsm-pkcs11` crate that compiles to a `cdylib` and implements the PKCS#11 entry points using the `cryptoki` type definitions. The crate will:

- Provide `#[no_mangle]` exports conforming to the standard function signatures.
- Maintain an in-process session manager that tracks slots, sessions, and object handles.
- Delegate key management and crypto operations to `hsm-core` over an internal async interface.
- Load hardware adapters (software fallback, SoftHSM bridge, commercial HSMs) through a trait-based registry.
- Optionally run as a sidecar by connecting to `hsm-server` over a local IPC channel when embedding is not desirable.

Key structural elements:

1. **Runtime Bridge:** A dedicated Tokio runtime is created during `C_Initialize`. FFI functions call into async handlers using `Handle::block_on`, preserving synchronous semantics.
2. **Session Manager:** Stores session metadata (`SessionState`, authenticated role, capabilities) and exposes thread-safe operations. Handles slot enumeration and login state transitions.
3. **Object Registry:** Maps PKCS#11 object handles to persistent `KeyMetadata` identifiers plus attribute templates. Session-scoped objects are tracked separately to support clean-up on logout.
4. **Hardware Adapter Layer:** Each adapter implements `HardwareKeyStore` and `HardwareSigner` traits. Capabilities are advertised at init to drive mechanism availability per slot.
5. **Error Translation:** `HsmError` variants are mapped to PKCS#11 `CKR_*` codes. Unknown errors fall back to `CKR_FUNCTION_FAILED` after auditing.

## Alternatives Considered
1. **Expose PKCS#11 directly from `hsm-server`:** Rejected due to tight coupling between TLS HTTP stack and C ABI requirements, increasing binary size and complicating deployment.
2. **REST Gateway for PKCS#11:** Rejected because it violates spec expectations, introduces latency, and forces clients to embed HTTP credentials.
3. **Dedicated proxy process:** Considered, but embedding in-process keeps latency low and reduces deployment surface. Sidecar mode remains an option via IPC for constrained environments.

## Consequences
### Positive
- Clear separation of concerns: FFI boundary isolated from core logic.
- Adapter trait makes it straightforward to add new hardware providers.
- Sidecar mode enables multi-host deployments without replicating business logic.
- Error and audit mapping controlled in one place, easing compliance review.

### Negative
- Additional crate increases build targets and CI matrix (Linux/macOS shared libraries).
- Maintaining the runtime bridge introduces complexity around async blocking semantics.
- Need to harden the FFI boundary (memory safety, zeroization) beyond typical Rust-only code.

### Follow-up Actions
1. Implement the session manager and object registry APIs (see `docs/pkcs11/session-manager.md`).
2. Finalize attribute storage schema shared with `hsm-core` (see `docs/pkcs11/attribute-model.md`).
3. Define IPC transport (Unix domain socket + mTLS) for sidecar mode and document operational guidance.
4. Update CI to build and package `hsm-pkcs11` shared libraries.

