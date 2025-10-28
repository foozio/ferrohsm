# Session Manager & Slot Registry Sketch

## Objectives
- Provide a spec-compliant implementation of PKCS#11 slots, tokens, and sessions that can sit behind the FFI layer.
- Integrate FerroHSM authentication (JWT + policy roles) with PKCS#11 login states (Public, User, Security Officer).
- Offer a clean API for the `hsm-pkcs11` crate to manage handles, searches, and hardware adapter selection.

## Core Types

```rust
pub type SlotId = u64;
pub type SessionHandle = u64;
pub type ObjectHandle = u64;

#[derive(Clone, Debug)]
pub struct SlotDescriptor {
    pub slot_id: SlotId,
    pub label: String,
    pub manufacturer: String,
    pub hardware_id: String,
}

pub trait HardwareAdapter: Send + Sync {
    fn id(&self) -> &'static str;
    fn supports_mechanism(&self, mechanism: &str) -> bool;
}

#[derive(Clone, Debug)]
pub enum SessionState {
    Public,
    User(AuthContext),
    SecurityOfficer(AuthContext),
}

#[derive(Clone, Debug)]
pub struct SessionInfo {
    pub slot_id: SlotId,
    pub read_only: bool,
    pub state: SessionState,
    pub opened_at: Instant,
    pub objects: Vec<ObjectHandle>,
    pub search: Option<SearchCursor>,
}

#[derive(Clone, Debug)]
pub struct ObjectDescriptor {
    pub handle: ObjectHandle,
    pub slot_id: SlotId,
    pub attributes: AttributeSet,
    pub token_object: bool,
    pub key_id: Option<String>,
}

pub struct SessionManager {
    slots: HashMap<SlotId, SlotEntry>,
    sessions: RwLock<HashMap<SessionHandle, SessionInfo>>,
    objects: RwLock<HashMap<ObjectHandle, ObjectDescriptor>>,
    next_session: AtomicU64,
    next_object: AtomicU64,
}
```

## Key Responsibilities
1. **Slot Enumeration**
   - Build the slot list during initialization from configuration + registered hardware adapters.
   - Expose metadata for `C_GetSlotList`, `C_GetSlotInfo`, `C_GetTokenInfo`.

2. **Session Lifecycle**
   - `open_session(slot_id, flags) -> SessionHandle`
   - `close_session(handle)` / `close_all_sessions(slot_id)`
   - Track R/O vs R/W flags and enforce concurrency limits per spec.

3. **Authentication**
   - `login(handle, user_type, pin)` delegates to `AuthVerifier`, producing an `AuthContext` when successful.
   - `logout(handle)` clears session state and destroys session objects.
   - Map PKCS#11 user types:
     - `CKU_USER` → FerroHSM roles `Operator`, `Service`.
     - `CKU_SO` → roles `Administrator`.

4. **Object Management**
   - Allocate handles via `handles.issue(ObjectDescriptor)`; associate with session scope or token scope.
   - Provide lookup helpers for operations (sign, encrypt, destroy).
   - Enforce attribute visibility based on session state (`CKA_PRIVATE` objects require authenticated session).

5. **Search API**
   - `find_objects_init(handle, template)` compiles attribute filters and snapshots candidate handles into a `VecDeque`.
   - `find_objects(handle, max_objects)` drains the cursor, returning handles visible to the session and matching the template.
   - `find_objects_final(handle)` clears search state to free memory.

6. **Hardware Routing**
   - Slots register an `Arc<dyn HardwareAdapter>`; lookups for a given object resolve the slot and retrieve the adapter.
   - Fallback to software implementation remains the default when an adapter lacks the requested mechanism.

## Thread Safety & Concurrency
- `SessionManager` is wrapped in `Arc<RwLock<...>>`.
- Handle issuance uses an atomic counter per slot to avoid collisions.
- Long-running operations (e.g., hardware sign) release read locks after resolving the descriptor to minimize contention.

## Error Mapping
- Define `SessionError` enum (`InvalidHandle`, `NotLoggedIn`, `ReadOnlySession`, etc.) with conversion to `CKR_*`.
- Propagate hardware adapter errors through structured variants to aid diagnostics.

## Metrics & Audit
- Produce counters: open sessions, login failures, handle allocation failures.
- Emit audit records for login/logout, object creation/destruction, and cryptographic operations (using existing `AuditLog` APIs).

## Next Steps
1. [x] Implement `SessionManager` skeleton with slot registration and basic session lifecycle.
2. Wire authentication to reuse the new rate-limited `AuthVerifier::authenticate` (pending FFI integration).
3. Prototype `C_Login`/`C_OpenSession` mappings in `hsm-pkcs11` using the skeleton.
4. [x] Add unit tests covering session state transitions, object registration, search cursors, and adapter routing.
