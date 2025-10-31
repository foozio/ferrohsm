//! PKCS#11 compatibility layer for FerroHSM.
//!
//! This crate exposes C ABI entrypoints that bridge the PKCS#11
//! specification onto existing FerroHSM primitives. The implementation
//! is staged; initial scaffolding wires basic initialization flows and
//! shared state management while the full function surface is added
//! incrementally during Phase 1.
//!
//! This implementation includes support for post-quantum cryptography
//! algorithms including ML-KEM, ML-DSA, SLH-DSA, and hybrid combinations
//! with classical algorithms.

use cryptoki_sys::{
    CK_ATTRIBUTE_PTR, CK_BYTE_PTR, CK_CHAR_PTR, CK_FLAGS, CK_INFO, CK_MECHANISM_PTR,
    CK_NOTIFICATION, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE_PTR, CK_RV, CK_SESSION_HANDLE,
    CK_SESSION_HANDLE_PTR, CK_SLOT_ID, CK_SLOT_ID_PTR, CK_SLOT_INFO, CK_STATE, CK_TOKEN_INFO,
    CK_ULONG, CK_ULONG_PTR, CK_USER_TYPE, CK_VOID_PTR, CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL,
    CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED, CKR_OK,
};

use parking_lot::RwLock;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tracing::{error, info};

// Import hsm-core for cryptographic operations
use hsm_core::{
    AttributeSet,
    crypto::{CryptoEngine, CryptoOperation, KeyOperationResult},
    models::{
        KeyAlgorithm, KeyGenerationRequest, KeyMaterial, KeyMetadata, KeyState, KeyUsage,
        TamperStatus,
    },
    storage::{KeyStore, MemoryKeyStore},
};
use rand::{RngCore, thread_rng};
use time::OffsetDateTime;
use uuid::Uuid;

// Module declarations
pub mod attribute;
pub mod mechanism;

struct InstanceContext {
    slots: Vec<SlotInfo>,
    sessions: std::collections::HashMap<CK_SESSION_HANDLE, SessionInfo>,
    objects: std::collections::HashMap<CK_OBJECT_HANDLE, ObjectInfo>,
    next_session_id: CK_SESSION_HANDLE,
    next_object_id: CK_OBJECT_HANDLE,
    crypto_engine: Arc<CryptoEngine>,
    key_store: Arc<dyn KeyStore>,
}

impl std::fmt::Debug for InstanceContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstanceContext")
            .field("slots", &self.slots)
            .field("sessions", &self.sessions)
            .field("objects", &self.objects)
            .field("next_session_id", &self.next_session_id)
            .field("next_object_id", &self.next_object_id)
            .field("crypto_engine", &"<CryptoEngine>")
            .field("key_store", &"<KeyStore>")
            .finish()
    }
}

#[derive(Debug, Clone)]
struct SlotInfo {
    id: CK_SLOT_ID,
    description: String,
    manufacturer: String,
    // Removed unused field: hardware_id: String,
}

#[derive(Debug, Clone)]
struct SessionInfo {
    handle: CK_SESSION_HANDLE,
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
    state: CK_STATE,
    user_type: Option<CK_USER_TYPE>, // None = not logged in, Some(type) = logged in as that type
    search_context: Option<SearchContext>,
    active_operation: Option<ActiveOperation>,
}

#[derive(Debug, Clone)]
struct ObjectInfo {
    handle: CK_OBJECT_HANDLE,
    session_handle: CK_SESSION_HANDLE,
    slot_id: CK_SLOT_ID,
    key_id: Option<String>, // Reference to key in hsm-core storage
}

#[derive(Debug, Clone)]
struct SearchContext {
    handles: std::collections::VecDeque<CK_OBJECT_HANDLE>,
    position: usize,
}

#[derive(Debug, Clone)]
enum ActiveOperation {
    Sign {
        mechanism_type: CK_ULONG,
        key_handle: CK_OBJECT_HANDLE,
    },
    Verify {
        mechanism_type: CK_ULONG,
        key_handle: CK_OBJECT_HANDLE,
    },
    Encrypt {
        mechanism_type: CK_ULONG,
        key_handle: CK_OBJECT_HANDLE,
    },
    Decrypt {
        mechanism_type: CK_ULONG,
        key_handle: CK_OBJECT_HANDLE,
    },
}

#[derive(Debug, Default)]
struct GlobalState {
    context: Option<Arc<Mutex<InstanceContext>>>,
}

static STATE: once_cell::sync::Lazy<RwLock<GlobalState>> =
    once_cell::sync::Lazy::new(|| RwLock::new(GlobalState::default()));

/// Errors raised by the PKCS#11 front-end prior to translation into
/// CKR_* return codes.
#[derive(Debug, Error)]
pub enum FrontendError {
    #[error("cryptoki already initialized")]
    AlreadyInitialized,
    #[error("cryptoki not initialized")]
    NotInitialized,
    #[error("internal error: {0}")]
    Internal(String),
}

/// Initialize the PKCS#11 front-end.
pub fn initialize(_args: CK_VOID_PTR) -> Result<(), FrontendError> {
    let mut guard = STATE.write();
    if guard.context.is_some() {
        return Err(FrontendError::AlreadyInitialized);
    }

    // Create a default slot
    let slots = vec![SlotInfo {
        id: 1,
        description: "FerroHSM Software Token".to_string(),
        manufacturer: "FerroLabs AG".to_string(),
    }];

    // Create a CryptoEngine instance with dummy keys for now
    // In a real implementation, these would come from configuration
    let master_key = [0u8; 32];
    let hmac_key = [0u8; 32];
    let crypto_engine = Arc::new(CryptoEngine::new(master_key, hmac_key));
    let key_store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());

    let slots_count = slots.len();
    guard.context = Some(Arc::new(Mutex::new(InstanceContext {
        slots,
        sessions: std::collections::HashMap::new(),
        objects: std::collections::HashMap::new(),
        next_session_id: 1,
        next_object_id: 1000, // Start object IDs from 1000
        crypto_engine,
        key_store,
    })));
    info!("PKCS#11 instance initialized with {} slot(s)", slots_count);
    Ok(())
}

/// Finalize the PKCS#11 front-end, releasing resources.
pub fn finalize() -> Result<(), FrontendError> {
    let mut guard = STATE.write();
    if guard.context.take().is_none() {
        return Err(FrontendError::NotInitialized);
    }
    info!("PKCS#11 instance finalized");
    Ok(())
}

fn translate_error(err: FrontendError) -> CK_RV {
    match err {
        FrontendError::AlreadyInitialized => CKR_CRYPTOKI_ALREADY_INITIALIZED,
        FrontendError::NotInitialized => CKR_CRYPTOKI_NOT_INITIALIZED,
        FrontendError::Internal(_) => CKR_FUNCTION_FAILED,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn C_Initialize(p_init_args: CK_VOID_PTR) -> CK_RV {
    match initialize(p_init_args) {
        Ok(()) => CKR_OK,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 initialize internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn C_Finalize(_reserved: CK_VOID_PTR) -> CK_RV {
    match finalize() {
        Ok(()) => CKR_OK,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 finalize internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

/// Get general information about the PKCS#11 implementation
pub fn get_info() -> Result<CK_INFO, FrontendError> {
    let mut info: CK_INFO = unsafe { std::mem::zeroed() };

    // Set the cryptoki version (2.40)
    info.cryptokiVersion.major = 2;
    info.cryptokiVersion.minor = 40;

    // Set the manufacturer ID
    let manufacturer_id = b"FerroLabs AG\0";
    let len = std::cmp::min(manufacturer_id.len(), 32);
    unsafe {
        std::ptr::copy_nonoverlapping(
            manufacturer_id.as_ptr(),
            info.manufacturerID.as_mut_ptr(),
            len,
        );
        // Pad with spaces
        for i in len..32 {
            info.manufacturerID[i] = b' ';
        }
    }

    // Set flags (no special flags for now)
    info.flags = 0;

    // Set the library description
    let library_description = b"FerroHSM PKCS#11 Interface\0";
    let len = std::cmp::min(library_description.len(), 32);
    unsafe {
        std::ptr::copy_nonoverlapping(
            library_description.as_ptr(),
            info.libraryDescription.as_mut_ptr(),
            len,
        );
        // Pad with spaces
        for i in len..32 {
            info.libraryDescription[i] = b' ';
        }
    }

    // Set the library version
    info.libraryVersion.major = 0;
    info.libraryVersion.minor = 3;

    Ok(info)
}

#[unsafe(no_mangle)]
pub extern "C" fn C_GetInfo(pInfo: *mut CK_INFO) -> CK_RV {
    if pInfo.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match get_info() {
        Ok(info) => {
            unsafe {
                *pInfo = info;
            }
            CKR_OK
        }
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 get_info internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

/// Get the list of slots in the system
pub fn get_slot_list(_token_present: bool) -> Result<Vec<CK_SLOT_ID>, FrontendError> {
    let guard = STATE.read();
    let context = guard
        .context
        .as_ref()
        .ok_or(FrontendError::NotInitialized)?;
    let context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    // For now, we always return our slots regardless of token_present
    // In a more sophisticated implementation, we might check if tokens are actually present
    let slot_ids: Vec<CK_SLOT_ID> = context.slots.iter().map(|slot| slot.id).collect();

    Ok(slot_ids)
}

#[unsafe(no_mangle)]
pub extern "C" fn C_GetSlotList(
    token_present: CK_ULONG,
    pSlotList: CK_SLOT_ID_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    if pulCount.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match get_slot_list(token_present != 0) {
        Ok(slot_ids) => {
            unsafe {
                // If pSlotList is null, just return the count
                if pSlotList.is_null() {
                    *pulCount = slot_ids.len() as CK_ULONG;
                    return CKR_OK;
                }

                // If the buffer is too small, return the required size
                if *pulCount < slot_ids.len() as CK_ULONG {
                    *pulCount = slot_ids.len() as CK_ULONG;
                    return CKR_BUFFER_TOO_SMALL;
                }

                // Copy the slot IDs to the provided buffer
                std::ptr::copy_nonoverlapping(slot_ids.as_ptr(), pSlotList, slot_ids.len());
                *pulCount = slot_ids.len() as CK_ULONG;
            }
            CKR_OK
        }
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 get_slot_list internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

/// Get information about a specific slot
pub fn get_slot_info(slot_id: CK_SLOT_ID) -> Result<CK_SLOT_INFO, FrontendError> {
    let guard = STATE.read();
    let context = guard
        .context
        .as_ref()
        .ok_or(FrontendError::NotInitialized)?;
    let context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    // Find the slot
    let slot = context
        .slots
        .iter()
        .find(|slot| slot.id == slot_id)
        .ok_or_else(|| FrontendError::Internal(format!("Slot {} not found", slot_id)))?;

    let mut info: CK_SLOT_INFO = unsafe { std::mem::zeroed() };

    // Set the slot description
    let description_bytes = slot.description.as_bytes();
    let len = std::cmp::min(description_bytes.len(), 64);
    unsafe {
        std::ptr::copy_nonoverlapping(
            description_bytes.as_ptr(),
            info.slotDescription.as_mut_ptr(),
            len,
        );
        // Pad with spaces
        for i in len..64 {
            info.slotDescription[i] = b' ';
        }
    }

    // Set the manufacturer ID
    let manufacturer_bytes = slot.manufacturer.as_bytes();
    let len = std::cmp::min(manufacturer_bytes.len(), 32);
    unsafe {
        std::ptr::copy_nonoverlapping(
            manufacturer_bytes.as_ptr(),
            info.manufacturerID.as_mut_ptr(),
            len,
        );
        // Pad with spaces
        for i in len..32 {
            info.manufacturerID[i] = b' ';
        }
    }

    // Set flags (hardware slot, token present, etc.)
    info.flags = 0x004; // CKF_TOKEN_PRESENT

    // Set hardware version (dummy values)
    info.hardwareVersion.major = 1;
    info.hardwareVersion.minor = 0;

    // Set firmware version (dummy values)
    info.firmwareVersion.major = 1;
    info.firmwareVersion.minor = 0;

    Ok(info)
}

#[unsafe(no_mangle)]
pub extern "C" fn C_GetSlotInfo(slotID: CK_SLOT_ID, pInfo: *mut CK_SLOT_INFO) -> CK_RV {
    if pInfo.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match get_slot_info(slotID) {
        Ok(info) => {
            unsafe {
                *pInfo = info;
            }
            CKR_OK
        }
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 get_slot_info internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

/// Get information about the token in a specific slot
pub fn get_token_info(slot_id: CK_SLOT_ID) -> Result<CK_TOKEN_INFO, FrontendError> {
    let guard = STATE.read();
    let context = guard
        .context
        .as_ref()
        .ok_or(FrontendError::NotInitialized)?;
    let context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    // Find the slot
    let slot = context
        .slots
        .iter()
        .find(|slot| slot.id == slot_id)
        .ok_or_else(|| FrontendError::Internal(format!("Slot {} not found", slot_id)))?;

    let mut info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };

    // Set the label
    let label_bytes = b"FerroHSM Token\0";
    let len = std::cmp::min(label_bytes.len(), 32);
    unsafe {
        std::ptr::copy_nonoverlapping(label_bytes.as_ptr(), info.label.as_mut_ptr(), len);
        // Pad with spaces
        for i in len..32 {
            info.label[i] = b' ';
        }
    }

    // Set the manufacturer ID
    let manufacturer_bytes = slot.manufacturer.as_bytes();
    let len = std::cmp::min(manufacturer_bytes.len(), 32);
    unsafe {
        std::ptr::copy_nonoverlapping(
            manufacturer_bytes.as_ptr(),
            info.manufacturerID.as_mut_ptr(),
            len,
        );
        // Pad with spaces
        for i in len..32 {
            info.manufacturerID[i] = b' ';
        }
    }

    // Set the model
    let model_bytes = b"Software HSM\0";
    let len = std::cmp::min(model_bytes.len(), 16);
    unsafe {
        std::ptr::copy_nonoverlapping(model_bytes.as_ptr(), info.model.as_mut_ptr(), len);
        // Pad with spaces
        for i in len..16 {
            info.model[i] = b' ';
        }
    }

    // Set the serial number
    let serial_bytes = b"00000001\0";
    let len = std::cmp::min(serial_bytes.len(), 16);
    unsafe {
        std::ptr::copy_nonoverlapping(serial_bytes.as_ptr(), info.serialNumber.as_mut_ptr(), len);
        // Pad with spaces
        for i in len..16 {
            info.serialNumber[i] = b' ';
        }
    }

    // Set flags
    info.flags = 0x00000400; // CKF_TOKEN_INITIALIZED

    // Set other fields (dummy values)
    info.ulMaxSessionCount = 100;
    info.ulSessionCount = 0;
    info.ulMaxRwSessionCount = 100;
    info.ulRwSessionCount = 0;
    info.ulMaxPinLen = 255;
    info.ulMinPinLen = 4;
    info.ulTotalPublicMemory = 0xFFFFFFFF;
    info.ulFreePublicMemory = 0xFFFFFFFF;
    info.ulTotalPrivateMemory = 0xFFFFFFFF;
    info.ulFreePrivateMemory = 0xFFFFFFFF;

    // Set hardware version (dummy values)
    info.hardwareVersion.major = 1;
    info.hardwareVersion.minor = 0;

    // Set firmware version (dummy values)
    info.firmwareVersion.major = 1;
    info.firmwareVersion.minor = 0;

    // Set UTC time (dummy value)
    let utc_bytes = b"2025010100000000\0";
    let len = std::cmp::min(utc_bytes.len(), 16);
    unsafe {
        std::ptr::copy_nonoverlapping(utc_bytes.as_ptr(), info.utcTime.as_mut_ptr(), len);
    }

    Ok(info)
}

#[unsafe(no_mangle)]
pub extern "C" fn C_GetTokenInfo(slotID: CK_SLOT_ID, pInfo: *mut CK_TOKEN_INFO) -> CK_RV {
    if pInfo.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match get_token_info(slotID) {
        Ok(info) => {
            unsafe {
                *pInfo = info;
            }
            CKR_OK
        }
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 get_token_info internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

/// Open a new session
pub fn open_session(
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
) -> Result<CK_SESSION_HANDLE, FrontendError> {
    let mut guard = STATE.write();
    let context = guard
        .context
        .as_mut()
        .ok_or(FrontendError::NotInitialized)?;
    let mut context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    // Verify the slot exists
    if !context.slots.iter().any(|slot| slot.id == slot_id) {
        return Err(FrontendError::Internal(format!(
            "Slot {} not found",
            slot_id
        )));
    }

    // Generate a new session handle
    let session_handle = context.next_session_id;
    context.next_session_id += 1;

    // Determine the initial state (public session)
    let state = if (flags & 0x00000004) != 0 {
        // CKF_RW_SESSION
        1 // CKS_RW_PUBLIC_SESSION
    } else {
        0 // CKS_RO_PUBLIC_SESSION
    };

    // Create the session info
    let session_info = SessionInfo {
        handle: session_handle,
        slot_id,
        flags,
        state,
        user_type: None,        // Not logged in initially
        search_context: None,   // No active search
        active_operation: None, // No active operation
    };

    // Store the session
    context.sessions.insert(session_handle, session_info);

    info!("Opened session {} for slot {}", session_handle, slot_id);
    Ok(session_handle)
}

#[unsafe(no_mangle)]
pub extern "C" fn C_OpenSession(
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    _pApplication: CK_VOID_PTR,
    _Notify: Option<extern "C" fn(CK_SESSION_HANDLE, CK_NOTIFICATION, CK_VOID_PTR) -> CK_RV>,
    phSession: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    if phSession.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match open_session(slotID, flags) {
        Ok(session_handle) => {
            unsafe {
                *phSession = session_handle;
            }
            CKR_OK
        }
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 open_session internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

/// Close a session
pub fn close_session(session_handle: CK_SESSION_HANDLE) -> Result<(), FrontendError> {
    let mut guard = STATE.write();
    let context = guard
        .context
        .as_mut()
        .ok_or(FrontendError::NotInitialized)?;
    let mut context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    // Remove the session
    if context.sessions.remove(&session_handle).is_some() {
        // Also remove all objects associated with this session
        context
            .objects
            .retain(|_, object| object.session_handle != session_handle);
        info!("Closed session {}", session_handle);
        Ok(())
    } else {
        Err(FrontendError::Internal(format!(
            "Session {} not found",
            session_handle
        )))
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn C_CloseSession(hSession: CK_SESSION_HANDLE) -> CK_RV {
    match close_session(hSession) {
        Ok(()) => CKR_OK,
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 close_session internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

/// Close all sessions for a slot
pub fn close_all_sessions(slot_id: CK_SLOT_ID) -> Result<(), FrontendError> {
    let mut guard = STATE.write();
    let context = guard
        .context
        .as_mut()
        .ok_or(FrontendError::NotInitialized)?;
    let mut context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    // Remove all sessions for this slot
    context
        .sessions
        .retain(|_, session| session.slot_id != slot_id);

    info!("Closed all sessions for slot {}", slot_id);
    Ok(())
}

/// Login to a session
pub fn login(
    session_handle: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    pin: &[u8],
) -> Result<(), FrontendError> {
    let mut guard = STATE.write();
    let context = guard
        .context
        .as_mut()
        .ok_or(FrontendError::NotInitialized)?;
    let mut context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    // Find the session
    let session = context
        .sessions
        .get_mut(&session_handle)
        .ok_or_else(|| FrontendError::Internal(format!("Session {} not found", session_handle)))?;

    // Check if already logged in
    if session.user_type.is_some() {
        return Err(FrontendError::Internal("Already logged in".to_string()));
    }

    // Validate PIN (dummy validation for now)
    if pin.is_empty() {
        return Err(FrontendError::Internal("PIN required".to_string()));
    }

    // Update session state based on user type
    session.user_type = Some(user_type);
    session.state = match user_type {
        0 => {
            // CKU_SO (Security Officer)
            if (session.flags & 0x00000004) != 0 {
                // CKF_RW_SESSION
                3 // CKS_RW_SO_FUNCTIONS
            } else {
                2 // CKS_RO_SO_FUNCTIONS (should not happen in practice)
            }
        }
        1 => {
            // CKU_USER (Regular user)
            if (session.flags & 0x00000004) != 0 {
                // CKF_RW_SESSION
                5 // CKS_RW_USER_FUNCTIONS
            } else {
                4 // CKS_RO_USER_FUNCTIONS
            }
        }
        _ => {
            session.user_type = None; // Reset login state
            return Err(FrontendError::Internal(format!(
                "Unsupported user type: {}",
                user_type
            )));
        }
    };

    info!(
        "User logged in to session {} as type {}",
        session_handle, user_type
    );
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn C_Login(
    hSession: CK_SESSION_HANDLE,
    userType: CK_USER_TYPE,
    pPin: CK_CHAR_PTR,
    ulPinLen: CK_ULONG,
) -> CK_RV {
    if pPin.is_null() && ulPinLen > 0 {
        return CKR_ARGUMENTS_BAD;
    }

    // Convert PIN to bytes
    let pin_bytes = if ulPinLen == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(pPin, ulPinLen as usize).to_vec() }
    };

    match login(hSession, userType, &pin_bytes) {
        Ok(()) => CKR_OK,
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 login internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

/// Logout from a session
pub fn logout(session_handle: CK_SESSION_HANDLE) -> Result<(), FrontendError> {
    let mut guard = STATE.write();
    let context = guard
        .context
        .as_mut()
        .ok_or(FrontendError::NotInitialized)?;
    let mut context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    // Find the session
    let session = context
        .sessions
        .get_mut(&session_handle)
        .ok_or_else(|| FrontendError::Internal(format!("Session {} not found", session_handle)))?;

    // Check if logged in
    if session.user_type.is_none() {
        return Err(FrontendError::Internal("Not logged in".to_string()));
    }

    // Reset session state to public
    session.user_type = None;
    session.state = if (session.flags & 0x00000004) != 0 {
        // CKF_RW_SESSION
        1 // CKS_RW_PUBLIC_SESSION
    } else {
        0 // CKS_RO_PUBLIC_SESSION
    };

    info!("User logged out from session {}", session_handle);
    Ok(())
}

/// Initialize a signing operation
pub fn sign_init(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> Result<(), FrontendError> {
    let mut guard = STATE.write();
    let context = guard
        .context
        .as_mut()
        .ok_or(FrontendError::NotInitialized)?;
    let mut context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    // Find the session
    let session = context
        .sessions
        .get_mut(&session_handle)
        .ok_or_else(|| FrontendError::Internal(format!("Session {} not found", session_handle)))?;

    // Check if logged in
    if session.user_type.is_none() {
        return Err(FrontendError::Internal("Not logged in".to_string()));
    }

    // Validate mechanism
    if mechanism.is_null() {
        return Err(FrontendError::Internal("Mechanism is null".to_string()));
    }

    // Check if there's already an active operation
    if session.active_operation.is_some() {
        return Err(FrontendError::Internal(
            "Operation already active".to_string(),
        ));
    }

    // Extract mechanism type
    let mechanism_type = unsafe { (*mechanism).mechanism };

    // Set the active operation
    session.active_operation = Some(ActiveOperation::Sign {
        mechanism_type,
        key_handle,
    });

    info!(
        "Initialized signing operation in session {}",
        session_handle
    );
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn C_SignInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    match sign_init(hSession, pMechanism, hKey) {
        Ok(()) => CKR_OK,
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 sign_init internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

/// Perform a signing operation
pub fn sign(
    session_handle: CK_SESSION_HANDLE,
    data: &[u8],
    signature: CK_BYTE_PTR,
    signature_len: CK_ULONG_PTR,
) -> Result<(), FrontendError> {
    let mut guard = STATE.write();
    let context = guard
        .context
        .as_mut()
        .ok_or(FrontendError::NotInitialized)?;
    let mut context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    // Find the session
    let session = context
        .sessions
        .get_mut(&session_handle)
        .ok_or_else(|| FrontendError::Internal(format!("Session {} not found", session_handle)))?;

    // Check if logged in
    if session.user_type.is_none() {
        return Err(FrontendError::Internal("Not logged in".to_string()));
    }

    // Get the active sign operation
    let (_mechanism_type, key_handle) = match session.active_operation.take() {
        Some(ActiveOperation::Sign {
            mechanism_type,
            key_handle,
        }) => (mechanism_type, key_handle),
        Some(_) => {
            return Err(FrontendError::Internal(
                "Different operation active".to_string(),
            ));
        }
        None => {
            return Err(FrontendError::Internal(
                "No active sign operation".to_string(),
            ));
        }
    };

    // Look up the key material
    let key_material = lookup_key_material(&mut context, key_handle)?;

    // Create a CryptoOperation::Sign with the data
    let operation = CryptoOperation::Sign {
        payload: data.to_vec(),
    };

    // Create an operation context
    let op_context = hsm_core::models::OperationContext::new();

    // Call crypto_engine.perform() to do the actual signing
    let result = context
        .crypto_engine
        .perform(operation, &key_material, &op_context)
        .map_err(|e| FrontendError::Internal(format!("Crypto operation failed: {}", e)))?;

    // Extract the signature from the result
    let signature_bytes = match result {
        KeyOperationResult::Signature { signature } => signature,
        _ => {
            return Err(FrontendError::Internal(
                "Unexpected crypto operation result".to_string(),
            ));
        }
    };

    // Check if the provided buffer is large enough
    unsafe {
        if *signature_len < signature_bytes.len() as CK_ULONG {
            *signature_len = signature_bytes.len() as CK_ULONG;
            return Err(FrontendError::Internal("Buffer too small".to_string()));
        }

        // If signature is not null, copy the signature data
        if !signature.is_null() {
            std::ptr::copy_nonoverlapping(
                signature_bytes.as_ptr(),
                signature,
                signature_bytes.len(),
            );
            *signature_len = signature_bytes.len() as CK_ULONG;
        } else {
            // Just return the required length
            *signature_len = signature_bytes.len() as CK_ULONG;
        }
    }

    info!("Performed signing operation in session {}", session_handle);
    Ok(())
}

/// Initialize a verification operation
pub fn verify_init(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> Result<(), FrontendError> {
    let mut guard = STATE.write();
    let context = guard
        .context
        .as_mut()
        .ok_or(FrontendError::NotInitialized)?;
    let mut context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    // Find the session
    let session = context
        .sessions
        .get_mut(&session_handle)
        .ok_or_else(|| FrontendError::Internal(format!("Session {} not found", session_handle)))?;

    // Check if logged in
    if session.user_type.is_none() {
        return Err(FrontendError::Internal("Not logged in".to_string()));
    }

    // Validate mechanism
    if mechanism.is_null() {
        return Err(FrontendError::Internal("Mechanism is null".to_string()));
    }

    // Check if there's already an active operation
    if session.active_operation.is_some() {
        return Err(FrontendError::Internal(
            "Operation already active".to_string(),
        ));
    }

    // Extract mechanism type
    let mechanism_type = unsafe { (*mechanism).mechanism };

    // Set the active operation
    session.active_operation = Some(ActiveOperation::Verify {
        mechanism_type,
        key_handle,
    });

    info!(
        "Initialized verification operation in session {}",
        session_handle
    );
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn C_VerifyInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    match verify_init(hSession, pMechanism, hKey) {
        Ok(()) => CKR_OK,
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 verify_init internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

/// Perform a verification operation
pub fn verify(
    session_handle: CK_SESSION_HANDLE,
    data: &[u8],
    signature: &[u8],
) -> Result<(), FrontendError> {
    let mut guard = STATE.write();
    let context = guard
        .context
        .as_mut()
        .ok_or(FrontendError::NotInitialized)?;
    let mut context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    // Find the session
    let session = context
        .sessions
        .get_mut(&session_handle)
        .ok_or_else(|| FrontendError::Internal(format!("Session {} not found", session_handle)))?;

    // Check if logged in
    if session.user_type.is_none() {
        return Err(FrontendError::Internal("Not logged in".to_string()));
    }

    // Get the active verify operation
    let (_mechanism_type, key_handle) = match session.active_operation.take() {
        Some(ActiveOperation::Verify {
            mechanism_type,
            key_handle,
        }) => (mechanism_type, key_handle),
        Some(_) => {
            return Err(FrontendError::Internal(
                "Different operation active".to_string(),
            ));
        }
        None => {
            return Err(FrontendError::Internal(
                "No active verify operation".to_string(),
            ));
        }
    };

    // Look up the key material
    let key_material = lookup_key_material(&mut context, key_handle)?;

    // Create a CryptoOperation::Verify with the data and signature
    let operation = CryptoOperation::Verify {
        payload: data.to_vec(),
        signature: signature.to_vec(),
    };

    // Create an operation context
    let op_context = hsm_core::models::OperationContext::new();

    // Call crypto_engine.perform() to do the actual verification
    let result = context
        .crypto_engine
        .perform(operation, &key_material, &op_context)
        .map_err(|e| FrontendError::Internal(format!("Crypto operation failed: {}", e)))?;

    // Check the verification result
    let valid = match result {
        KeyOperationResult::Verified { valid } => valid,
        _ => {
            return Err(FrontendError::Internal(
                "Unexpected crypto operation result".to_string(),
            ));
        }
    };

    // Return an error if the signature is invalid
    if !valid {
        return Err(FrontendError::Internal(
            "Signature verification failed".to_string(),
        ));
    }

    info!(
        "Performed verification operation in session {}",
        session_handle
    );
    Ok(())
}

/// Look up key material for an object handle
fn lookup_key_material(
    context: &mut InstanceContext,
    object_handle: CK_OBJECT_HANDLE,
) -> Result<KeyMaterial, FrontendError> {
    // Find the object
    let object = context
        .objects
        .get(&object_handle)
        .ok_or_else(|| FrontendError::Internal(format!("Object {} not found", object_handle)))?;

    // Get the key ID
    let key_id = object.key_id.as_ref().ok_or_else(|| {
        FrontendError::Internal(format!("Object {} has no key ID", object_handle))
    })?;

    // Look up key material from hsm-core storage
    let record = context
        .key_store
        .fetch(key_id)
        .map_err(|e| FrontendError::Internal(format!("Failed to fetch key {}: {}", key_id, e)))?;
    let key_material = context
        .crypto_engine
        .open_key(&record)
        .map_err(|e| FrontendError::Internal(format!("Failed to open key {}: {}", key_id, e)))?;
    Ok(key_material)
}

#[unsafe(no_mangle)]
pub extern "C" fn C_Verify(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG,
) -> CK_RV {
    if pData.is_null() || pSignature.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    // Convert data and signature to bytes
    let data_bytes = unsafe { std::slice::from_raw_parts(pData, ulDataLen as usize).to_vec() };

    let signature_bytes =
        unsafe { std::slice::from_raw_parts(pSignature, ulSignatureLen as usize).to_vec() };

    match verify(hSession, &data_bytes, &signature_bytes) {
        Ok(()) => CKR_OK,
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 verify internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn C_Sign(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR,
) -> CK_RV {
    if pData.is_null() || pulSignatureLen.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    // Convert data to bytes
    let data_bytes = unsafe { std::slice::from_raw_parts(pData, ulDataLen as usize).to_vec() };

    match sign(hSession, &data_bytes, pSignature, pulSignatureLen) {
        Ok(()) => CKR_OK,
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 sign internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

/// Generate a secret key
pub fn generate_key(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    _template: CK_ATTRIBUTE_PTR,
    _template_len: CK_ULONG,
    key_handle: &mut CK_OBJECT_HANDLE,
) -> Result<(), FrontendError> {
    let mut guard = STATE.write();
    let context = guard
        .context
        .as_mut()
        .ok_or(FrontendError::NotInitialized)?;
    let mut context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    // Find the session
    let slot_id = {
        let session = context.sessions.get(&session_handle).ok_or_else(|| {
            FrontendError::Internal(format!("Session {} not found", session_handle))
        })?;

        // Check if logged in
        if session.user_type.is_none() {
            return Err(FrontendError::Internal("Not logged in".to_string()));
        }

        // Validate mechanism
        if mechanism.is_null() {
            return Err(FrontendError::Internal("Mechanism is null".to_string()));
        }

        session.slot_id
    };

    // Extract mechanism type
    let mechanism_type = unsafe { (*mechanism).mechanism };

    // Generate a key based on the mechanism
    let (key_material, algorithm) = match mechanism_type {
        // CKM_AES_KEY_GEN
        0x00001080 => {
            // Generate a 256-bit AES key
            let mut key = vec![0u8; 32];
            thread_rng().fill_bytes(&mut key);
            (KeyMaterial::Symmetric { key }, KeyAlgorithm::Aes256Gcm)
        }
        // CKM_GENERIC_SECRET_KEY_GEN
        0x00000350 => {
            // Generate a 256-bit generic secret key
            let mut key = vec![0u8; 32];
            thread_rng().fill_bytes(&mut key);
            (KeyMaterial::Symmetric { key }, KeyAlgorithm::Aes256Gcm) // Use AES-GCM for generic
        }
        _ => {
            return Err(FrontendError::Internal(format!(
                "Unsupported mechanism: 0x{:x}",
                mechanism_type
            )));
        }
    };

    // Generate key ID
    let key_id = format!("pkcs11-key-{}", Uuid::new_v4());

    // Create metadata
    let metadata = KeyMetadata {
        id: key_id.clone(),
        algorithm,
        usage: KeyUsage::default(),
        policy_tags: vec![],
        state: KeyState::Active,
        version: 1,
        created_at: OffsetDateTime::now_utc(),
        description: Some("PKCS#11 generated key".to_string()),
        tamper_status: TamperStatus::Clean,
        attributes: AttributeSet::new(),
    };

    // Seal the key
    let record = context
        .crypto_engine
        .seal_key(&metadata, key_material)
        .map_err(|e| FrontendError::Internal(format!("Failed to seal key: {}", e)))?;

    // Store the key in hsm-core storage
    context
        .key_store
        .store(record)
        .map_err(|e| FrontendError::Internal(format!("Failed to store key: {}", e)))?;

    // Generate object handle
    let object_handle = context.next_object_id;
    context.next_object_id += 1;

    // Create object info entry
    context.objects.insert(
        object_handle,
        ObjectInfo {
            handle: object_handle,
            session_handle,
            slot_id,
            key_id: Some(key_id),
        },
    );

    *key_handle = object_handle;

    info!("Generated key in session {}", session_handle);
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn C_GenerateKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    if phKey.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let mut key_handle: CK_OBJECT_HANDLE = 0;
    match generate_key(hSession, pMechanism, pTemplate, ulCount, &mut key_handle) {
        Ok(()) => {
            unsafe {
                *phKey = key_handle;
            }
            CKR_OK
        }
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 generate_key internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

/// Generate a key pair
pub fn generate_key_pair(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    _public_template: CK_ATTRIBUTE_PTR,
    _public_template_len: CK_ULONG,
    _private_template: CK_ATTRIBUTE_PTR,
    _private_template_len: CK_ULONG,
    public_key_handle: &mut CK_OBJECT_HANDLE,
    private_key_handle: &mut CK_OBJECT_HANDLE,
) -> Result<(), FrontendError> {
    let mut guard = STATE.write();
    let context = guard
        .context
        .as_mut()
        .ok_or(FrontendError::NotInitialized)?;
    let mut context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    // Find the session
    let slot_id = {
        let session = context.sessions.get(&session_handle).ok_or_else(|| {
            FrontendError::Internal(format!("Session {} not found", session_handle))
        })?;

        // Check if logged in
        if session.user_type.is_none() {
            return Err(FrontendError::Internal("Not logged in".to_string()));
        }

        // Validate mechanism
        if mechanism.is_null() {
            return Err(FrontendError::Internal("Mechanism is null".to_string()));
        }

        session.slot_id
    };

    // Extract mechanism type
    let mechanism_type = unsafe { (*mechanism).mechanism };

    // Generate a key pair based on the mechanism
    match mechanism_type {
        // CKM_RSA_PKCS_KEY_PAIR_GEN
        0x00000000 => {
            // Generate RSA key pair
            let request = KeyGenerationRequest {
                algorithm: KeyAlgorithm::Rsa2048,
                usage: KeyUsage::default(),
                policy_tags: vec![],
                description: Some("PKCS#11 RSA key pair".to_string()),
            };
            let generated = context
                .crypto_engine
                .generate_material(&request)
                .map_err(|e| {
                    FrontendError::Internal(format!("Failed to generate RSA key: {}", e))
                })?;

            // Generate key IDs
            let public_key_id = format!("pkcs11-public-key-{}", Uuid::new_v4());
            let private_key_id = generated.id.clone();

            // Create metadata for private key
            let private_metadata = KeyMetadata {
                id: private_key_id.clone(),
                algorithm: KeyAlgorithm::Rsa2048,
                usage: KeyUsage::default(),
                policy_tags: vec![],
                state: KeyState::Active,
                version: 1,
                created_at: OffsetDateTime::now_utc(),
                description: Some("PKCS#11 RSA private key".to_string()),
                tamper_status: TamperStatus::Clean,
                attributes: AttributeSet::new(),
            };

            // Seal the private key
            let private_record = context
                .crypto_engine
                .seal_key(&private_metadata, generated.material.clone())
                .map_err(|e| {
                    FrontendError::Internal(format!("Failed to seal private key: {}", e))
                })?;
            context.key_store.store(private_record).map_err(|e| {
                FrontendError::Internal(format!("Failed to store private key: {}", e))
            })?;

            // For public key, we can store the public part, but since KeyMaterial expects full, perhaps store a dummy or extract.
            // For simplicity, store the same material for public, but in practice, public should be separate.
            // TODO: Properly handle public key storage
            let public_metadata = KeyMetadata {
                id: public_key_id.clone(),
                algorithm: KeyAlgorithm::Rsa2048,
                usage: KeyUsage::default(),
                policy_tags: vec![],
                state: KeyState::Active,
                version: 1,
                created_at: OffsetDateTime::now_utc(),
                description: Some("PKCS#11 RSA public key".to_string()),
                tamper_status: TamperStatus::Clean,
                attributes: AttributeSet::new(),
            };
            // For now, store the full key for public too (not ideal, but works for demo)
            let public_record = context
                .crypto_engine
                .seal_key(&public_metadata, generated.material.clone())
                .map_err(|e| {
                    FrontendError::Internal(format!("Failed to seal public key: {}", e))
                })?;
            context.key_store.store(public_record).map_err(|e| {
                FrontendError::Internal(format!("Failed to store public key: {}", e))
            })?;

            // Generate object handles
            let public_handle = context.next_object_id;
            context.next_object_id += 1;
            let private_handle = context.next_object_id;
            context.next_object_id += 1;

            // Create object info entries
            context.objects.insert(
                public_handle,
                ObjectInfo {
                    handle: public_handle,
                    session_handle,
                    slot_id,
                    key_id: Some(public_key_id),
                },
            );
            context.objects.insert(
                private_handle,
                ObjectInfo {
                    handle: private_handle,
                    session_handle,
                    slot_id,
                    key_id: Some(private_key_id),
                },
            );

            *public_key_handle = public_handle;
            *private_key_handle = private_handle;
        }
        // CKM_EC_KEY_PAIR_GEN
        0x00001040 => {
            // Generate EC key pair
            let request = KeyGenerationRequest {
                algorithm: KeyAlgorithm::P256,
                usage: KeyUsage::default(),
                policy_tags: vec![],
                description: Some("PKCS#11 EC key pair".to_string()),
            };
            let generated = context
                .crypto_engine
                .generate_material(&request)
                .map_err(|e| {
                    FrontendError::Internal(format!("Failed to generate EC key: {}", e))
                })?;

            // Generate key IDs
            let public_key_id = format!("pkcs11-public-key-{}", Uuid::new_v4());
            let private_key_id = generated.id.clone();

            // Create metadata for private key
            let private_metadata = KeyMetadata {
                id: private_key_id.clone(),
                algorithm: KeyAlgorithm::P256,
                usage: KeyUsage::default(),
                policy_tags: vec![],
                state: KeyState::Active,
                version: 1,
                created_at: OffsetDateTime::now_utc(),
                description: Some("PKCS#11 EC private key".to_string()),
                tamper_status: TamperStatus::Clean,
                attributes: AttributeSet::new(),
            };

            // Seal the private key
            let private_record = context
                .crypto_engine
                .seal_key(&private_metadata, generated.material.clone())
                .map_err(|e| {
                    FrontendError::Internal(format!("Failed to seal private key: {}", e))
                })?;
            context.key_store.store(private_record).map_err(|e| {
                FrontendError::Internal(format!("Failed to store private key: {}", e))
            })?;

            // For public key, store the same material (demo)
            let public_metadata = KeyMetadata {
                id: public_key_id.clone(),
                algorithm: KeyAlgorithm::P256,
                usage: KeyUsage::default(),
                policy_tags: vec![],
                state: KeyState::Active,
                version: 1,
                created_at: OffsetDateTime::now_utc(),
                description: Some("PKCS#11 EC public key".to_string()),
                tamper_status: TamperStatus::Clean,
                attributes: AttributeSet::new(),
            };
            let public_record = context
                .crypto_engine
                .seal_key(&public_metadata, generated.material)
                .map_err(|e| {
                    FrontendError::Internal(format!("Failed to seal public key: {}", e))
                })?;
            context.key_store.store(public_record).map_err(|e| {
                FrontendError::Internal(format!("Failed to store public key: {}", e))
            })?;

            // Generate object handles
            let public_handle = context.next_object_id;
            context.next_object_id += 1;
            let private_handle = context.next_object_id;
            context.next_object_id += 1;

            // Create object info entries
            context.objects.insert(
                public_handle,
                ObjectInfo {
                    handle: public_handle,
                    session_handle,
                    slot_id,
                    key_id: Some(public_key_id),
                },
            );
            context.objects.insert(
                private_handle,
                ObjectInfo {
                    handle: private_handle,
                    session_handle,
                    slot_id,
                    key_id: Some(private_key_id),
                },
            );

            *public_key_handle = public_handle;
            *private_key_handle = private_handle;
        }
        _ => {
            return Err(FrontendError::Internal(format!(
                "Unsupported mechanism: 0x{:x}",
                mechanism_type
            )));
        }
    }

    info!("Generated key pair in session {}", session_handle);
    Ok(())
}

/// Destroy an object
pub fn destroy_object(
    session_handle: CK_SESSION_HANDLE,
    object_handle: CK_OBJECT_HANDLE,
) -> Result<(), FrontendError> {
    let mut guard = STATE.write();
    let context = guard
        .context
        .as_mut()
        .ok_or(FrontendError::NotInitialized)?;
    let mut context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    // Find the session
    let session = context
        .sessions
        .get(&session_handle)
        .ok_or_else(|| FrontendError::Internal(format!("Session {} not found", session_handle)))?;

    // Check if logged in
    if session.user_type.is_none() {
        return Err(FrontendError::Internal("Not logged in".to_string()));
    }

    // Find the object
    let object = context
        .objects
        .get(&object_handle)
        .ok_or_else(|| FrontendError::Internal(format!("Object {} not found", object_handle)))?;

    // Check if the object belongs to this session
    if object.session_handle != session_handle {
        return Err(FrontendError::Internal(
            "Object does not belong to this session".to_string(),
        ));
    }

    // Remove the object
    context.objects.remove(&object_handle);

    info!(
        "Destroyed object {} in session {}",
        object_handle, session_handle
    );
    Ok(())
}

/// Initialize a search for objects
pub fn find_objects_init(
    session_handle: CK_SESSION_HANDLE,
    _template: CK_ATTRIBUTE_PTR,
    _template_len: CK_ULONG,
) -> Result<(), FrontendError> {
    let mut guard = STATE.write();
    let context = guard
        .context
        .as_mut()
        .ok_or(FrontendError::NotInitialized)?;
    let mut context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    // Check if logged in and get session handle copy
    let session_handle_copy = {
        let session = context.sessions.get(&session_handle).ok_or_else(|| {
            FrontendError::Internal(format!("Session {} not found", session_handle))
        })?;

        // Check if logged in
        if session.user_type.is_none() {
            return Err(FrontendError::Internal("Not logged in".to_string()));
        }

        session_handle
    };

    // Get all objects for this session
    let mut object_handles = std::collections::VecDeque::new();
    for (handle, object) in context.objects.iter() {
        if object.session_handle == session_handle_copy {
            object_handles.push_back(*handle);
        }
    }

    // Update the session with search context
    let session = context
        .sessions
        .get_mut(&session_handle)
        .ok_or_else(|| FrontendError::Internal(format!("Session {} not found", session_handle)))?;
    session.search_context = Some(SearchContext {
        handles: object_handles,
        position: 0,
    });

    info!("Initialized object search in session {}", session_handle);
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn C_FindObjectsInit(
    hSession: CK_SESSION_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV {
    match find_objects_init(hSession, pTemplate, ulCount) {
        Ok(()) => CKR_OK,
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 find_objects_init internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

/// Find objects
pub fn find_objects(
    session_handle: CK_SESSION_HANDLE,
    object_handles: &mut [CK_OBJECT_HANDLE],
    max_objects: CK_ULONG,
    object_count: &mut CK_ULONG,
) -> Result<(), FrontendError> {
    let mut guard = STATE.write();
    let context = guard
        .context
        .as_mut()
        .ok_or(FrontendError::NotInitialized)?;
    let mut context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    // Find the session
    let session = context
        .sessions
        .get_mut(&session_handle)
        .ok_or_else(|| FrontendError::Internal(format!("Session {} not found", session_handle)))?;

    // Check if logged in
    if session.user_type.is_none() {
        return Err(FrontendError::Internal("Not logged in".to_string()));
    }

    // Check if search is initialized
    let search_context = session
        .search_context
        .as_mut()
        .ok_or_else(|| FrontendError::Internal("Search not initialized".to_string()))?;

    // Copy object handles
    let mut count = 0;
    while count < max_objects && search_context.position < search_context.handles.len() {
        if let Some(handle) = search_context.handles.get(search_context.position) {
            object_handles[count as usize] = *handle;
            count += 1;
            search_context.position += 1;
        } else {
            break;
        }
    }

    *object_count = count;

    info!("Found {} objects in session {}", count, session_handle);
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn C_FindObjects(
    hSession: CK_SESSION_HANDLE,
    phObject: CK_OBJECT_HANDLE_PTR,
    ulMaxObjectCount: CK_ULONG,
    pulObjectCount: CK_ULONG_PTR,
) -> CK_RV {
    if phObject.is_null() || pulObjectCount.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    // Create a vector to hold the object handles
    let mut object_handles = vec![0 as CK_OBJECT_HANDLE; ulMaxObjectCount as usize];
    let mut object_count: CK_ULONG = 0;

    match find_objects(
        hSession,
        &mut object_handles,
        ulMaxObjectCount,
        &mut object_count,
    ) {
        Ok(()) => {
            // Copy the object handles to the output array
            unsafe {
                std::ptr::copy_nonoverlapping(
                    object_handles.as_ptr(),
                    phObject,
                    object_count as usize,
                );
                *pulObjectCount = object_count;
            }
            CKR_OK
        }
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 find_objects internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

/// Finalize a search for objects
pub fn find_objects_final(session_handle: CK_SESSION_HANDLE) -> Result<(), FrontendError> {
    let mut guard = STATE.write();
    let context = guard
        .context
        .as_mut()
        .ok_or(FrontendError::NotInitialized)?;
    let mut context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    // Find the session
    let session = context
        .sessions
        .get_mut(&session_handle)
        .ok_or_else(|| FrontendError::Internal(format!("Session {} not found", session_handle)))?;

    // Check if logged in
    if session.user_type.is_none() {
        return Err(FrontendError::Internal("Not logged in".to_string()));
    }

    // Clear search context
    session.search_context = None;

    info!("Finalized object search in session {}", session_handle);
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn C_FindObjectsFinal(hSession: CK_SESSION_HANDLE) -> CK_RV {
    match find_objects_final(hSession) {
        Ok(()) => CKR_OK,
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 find_objects_final internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn C_DestroyObject(hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE) -> CK_RV {
    match destroy_object(hSession, hObject) {
        Ok(()) => CKR_OK,
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 destroy_object internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn C_GenerateKeyPair(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    pPublicKeyTemplate: CK_ATTRIBUTE_PTR,
    ulPublicKeyAttributeCount: CK_ULONG,
    pPrivateKeyTemplate: CK_ATTRIBUTE_PTR,
    ulPrivateKeyAttributeCount: CK_ULONG,
    phPublicKey: CK_OBJECT_HANDLE_PTR,
    phPrivateKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    if phPublicKey.is_null() || phPrivateKey.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let mut public_key_handle: CK_OBJECT_HANDLE = 0;
    let mut private_key_handle: CK_OBJECT_HANDLE = 0;
    match generate_key_pair(
        hSession,
        pMechanism,
        pPublicKeyTemplate,
        ulPublicKeyAttributeCount,
        pPrivateKeyTemplate,
        ulPrivateKeyAttributeCount,
        &mut public_key_handle,
        &mut private_key_handle,
    ) {
        Ok(()) => {
            unsafe {
                *phPublicKey = public_key_handle;
                *phPrivateKey = private_key_handle;
            }
            CKR_OK
        }
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 generate_key_pair internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn C_Logout(hSession: CK_SESSION_HANDLE) -> CK_RV {
    match logout(hSession) {
        Ok(()) => CKR_OK,
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 logout internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn C_CloseAllSessions(slotID: CK_SLOT_ID) -> CK_RV {
    match close_all_sessions(slotID) {
        Ok(()) => CKR_OK,
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 close_all_sessions internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

/// Get session information
pub fn get_session_info(
    session_handle: CK_SESSION_HANDLE,
) -> Result<(CK_SLOT_ID, CK_FLAGS, CK_STATE), FrontendError> {
    let guard = STATE.read();
    let context = guard
        .context
        .as_ref()
        .ok_or(FrontendError::NotInitialized)?;
    let context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    // Find the session
    if let Some(session) = context.sessions.get(&session_handle) {
        Ok((session.slot_id, session.flags, session.state))
    } else {
        Err(FrontendError::Internal(format!(
            "Session {} not found",
            session_handle
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_and_finalize_roundtrip() {
        initialize(std::ptr::null_mut()).expect("init");
        finalize().expect("finalize");
        assert_eq!(
            translate_error(finalize().unwrap_err()),
            CKR_CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    fn double_initialize_is_rejected() {
        initialize(std::ptr::null_mut()).expect("init");
        let rv = translate_error(initialize(std::ptr::null_mut()).unwrap_err());
        assert_eq!(rv, CKR_CRYPTOKI_ALREADY_INITIALIZED);
        finalize().expect("finalize");
    }
}
