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

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use cryptoki_sys::{
    CK_ATTRIBUTE_PTR, CK_BYTE_PTR, CK_FLAGS, CK_MECHANISM_INFO, CK_MECHANISM_TYPE,
    CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_SESSION_HANDLE_PTR,
    CK_SESSION_INFO, CK_SLOT_ID, CK_SLOT_ID_PTR, CK_SLOT_INFO, CK_SLOT_INFO_PTR, CK_STATE, CK_TOKEN_INFO, CK_TOKEN_INFO_PTR,
    CK_UNAVAILABLE_INFORMATION, CK_ULONG, CK_ULONG_PTR, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_VOID_PTR, CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL,
    CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED, CKR_OK,
};
use hsm_core::{
    crypto::CryptoEngine,
    storage::{KeyStore, MemoryKeyStore},
};

use parking_lot::RwLock;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tracing::{error, info};

// Module declarations
pub mod attribute;
pub mod mechanism;

struct InstanceContext {
    slots: Vec<SlotInfo>,
    sessions: std::collections::HashMap<CK_SESSION_HANDLE, SessionInfo>,
    objects: std::collections::HashMap<CK_OBJECT_HANDLE, ObjectInfo>,
    next_session_id: CK_SESSION_HANDLE,
    next_object_id: CK_OBJECT_HANDLE,
    #[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
struct ObjectInfo {
    handle: CK_OBJECT_HANDLE,
    session_handle: CK_SESSION_HANDLE,
    slot_id: CK_SLOT_ID,
    key_id: Option<String>, // Reference to key in hsm-core storage
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SearchContext {
    handles: std::collections::VecDeque<CK_OBJECT_HANDLE>,
    position: usize,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
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

/// Translate FrontendError into PKCS#11 CKR_* return codes
fn translate_error(err: FrontendError) -> CK_RV {
    match err {
        FrontendError::AlreadyInitialized => CKR_CRYPTOKI_ALREADY_INITIALIZED,
        FrontendError::NotInitialized => CKR_CRYPTOKI_NOT_INITIALIZED,
        FrontendError::Internal(_) => CKR_FUNCTION_FAILED,
    }
}

pub fn initialize(_init_args: *mut cryptoki_sys::CK_C_INITIALIZE_ARGS) -> Result<(), FrontendError> {
    let mut guard = STATE.write();
    if guard.context.is_some() {
        return Err(FrontendError::AlreadyInitialized);
    }
    let slots = vec![SlotInfo {
        id: 1,
        description: "FerroHSM Software Token".to_string(),
        manufacturer: "FerroLabs AG".to_string(),
    }];

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
        next_object_id: 1000,
        crypto_engine,
        key_store,
    })));

    info!("PKCS#11 instance initialized with {} slot(s)", slots_count);
    Ok(())
}

/// Finalize the PKCS#11 front-end.
pub fn finalize() -> Result<(), FrontendError> {
    let mut guard = STATE.write();
    if guard.context.is_none() {
        return Err(FrontendError::NotInitialized);
    }
    guard.context = None;
    info!("PKCS#11 instance finalized");
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn C_Initialize(p_init_args: CK_VOID_PTR) -> CK_RV {
    let init_args = p_init_args as *mut cryptoki_sys::CK_C_INITIALIZE_ARGS;
    match initialize(init_args) {
        Ok(()) => CKR_OK,
        Err(err) => translate_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn C_Finalize(p_reserved: CK_VOID_PTR) -> CK_RV {
    if !p_reserved.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match finalize() {
        Ok(()) => CKR_OK,
        Err(err) => translate_error(err),
    }
}

/// Initialize a verification operation
pub fn verify_init(
    session_handle: CK_SESSION_HANDLE,
    mechanism: *mut cryptoki_sys::CK_MECHANISM,
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

    {
        let session = context
            .sessions
            .get(&session_handle)
            .ok_or_else(|| FrontendError::Internal(format!("Session {} not found", session_handle)))?;

        if session.user_type.is_none() {
            return Err(FrontendError::Internal("Not logged in".to_string()));
        }
    }

    {
        let object = context
            .objects
            .get(&key_handle)
            .ok_or_else(|| FrontendError::Internal(format!("Object {} not found", key_handle)))?;

        if object.session_handle != session_handle {
            return Err(FrontendError::Internal(
                "Object does not belong to this session".to_string(),
            ));
        }
    }

    let mechanism_type = unsafe { (*mechanism).mechanism };

    let session = context
        .sessions
        .get_mut(&session_handle)
        .ok_or_else(|| FrontendError::Internal(format!("Session {} not found", session_handle)))?;
    session.active_operation = Some(ActiveOperation::Verify {
        mechanism_type,
        key_handle,
    });

    Ok(())
}

/// Perform a verification operation
pub fn verify(
    session_handle: CK_SESSION_HANDLE,
    _data: CK_BYTE_PTR,
    _data_len: CK_ULONG,
    _signature: CK_BYTE_PTR,
    _signature_len: CK_ULONG,
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

    // Get active operation
    let active_op = session.active_operation.take().ok_or_else(|| FrontendError::Internal("No active operation".to_string()))?;

    match active_op {
        ActiveOperation::Verify { mechanism_type: _, key_handle: _ } => {}
        _ => {
            return Err(FrontendError::Internal("Wrong active operation".to_string()));
        }
    }

    // For dummy implementation, always return success
    Ok(())
}

/// Initialize an encryption operation
pub fn encrypt_init(
    session_handle: CK_SESSION_HANDLE,
    mechanism: *mut cryptoki_sys::CK_MECHANISM,
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

    {
        let session = context
            .sessions
            .get(&session_handle)
            .ok_or_else(|| FrontendError::Internal(format!("Session {} not found", session_handle)))?;

        if session.user_type.is_none() {
            return Err(FrontendError::Internal("Not logged in".to_string()));
        }
    }

    {
        let object = context
            .objects
            .get(&key_handle)
            .ok_or_else(|| FrontendError::Internal(format!("Object {} not found", key_handle)))?;

        if object.session_handle != session_handle {
            return Err(FrontendError::Internal(
                "Object does not belong to this session".to_string(),
            ));
        }
    }

    let mechanism_type = unsafe { (*mechanism).mechanism };

    let session = context
        .sessions
        .get_mut(&session_handle)
        .ok_or_else(|| FrontendError::Internal(format!("Session {} not found", session_handle)))?;
    session.active_operation = Some(ActiveOperation::Encrypt {
        mechanism_type,
        key_handle,
    });

    Ok(())
}

/// Perform an encryption operation
pub fn encrypt(
    session_handle: CK_SESSION_HANDLE,
    data: CK_BYTE_PTR,
    data_len: CK_ULONG,
    encrypted_data: CK_BYTE_PTR,
    encrypted_data_len: CK_ULONG_PTR,
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

    // Get active operation
    let active_op = session.active_operation.take().ok_or_else(|| FrontendError::Internal("No active operation".to_string()))?;

    match active_op {
        ActiveOperation::Encrypt { mechanism_type: _, key_handle: _ } => {}
        _ => {
            return Err(FrontendError::Internal("Wrong active operation".to_string()));
        }
    }

    // For dummy implementation, assume AES, output same size
    let output_size = data_len as usize;
    unsafe {
        if encrypted_data.is_null() {
            *encrypted_data_len = output_size as CK_ULONG;
        } else {
            if *encrypted_data_len < output_size as CK_ULONG {
                return Err(FrontendError::Internal("Encrypted data buffer too small".to_string()));
            }
            // Copy data as dummy encryption
            std::ptr::copy_nonoverlapping(data, encrypted_data, output_size);
            *encrypted_data_len = output_size as CK_ULONG;
        }
    }

    Ok(())
}

/// Initialize a decryption operation
pub fn decrypt_init(
    session_handle: CK_SESSION_HANDLE,
    mechanism: *mut cryptoki_sys::CK_MECHANISM,
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

    {
        let session = context
            .sessions
            .get(&session_handle)
            .ok_or_else(|| FrontendError::Internal(format!("Session {} not found", session_handle)))?;

        if session.user_type.is_none() {
            return Err(FrontendError::Internal("Not logged in".to_string()));
        }
    }

    {
        let object = context
            .objects
            .get(&key_handle)
            .ok_or_else(|| FrontendError::Internal(format!("Object {} not found", key_handle)))?;

        if object.session_handle != session_handle {
            return Err(FrontendError::Internal(
                "Object does not belong to this session".to_string(),
            ));
        }
    }

    let mechanism_type = unsafe { (*mechanism).mechanism };

    let session = context
        .sessions
        .get_mut(&session_handle)
        .ok_or_else(|| FrontendError::Internal(format!("Session {} not found", session_handle)))?;
    session.active_operation = Some(ActiveOperation::Decrypt {
        mechanism_type,
        key_handle,
    });

    Ok(())
}

/// Perform a decryption operation
pub fn decrypt(
    session_handle: CK_SESSION_HANDLE,
    encrypted_data: CK_BYTE_PTR,
    encrypted_data_len: CK_ULONG,
    data: CK_BYTE_PTR,
    data_len: CK_ULONG_PTR,
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

    // Get active operation
    let active_op = session.active_operation.take().ok_or_else(|| FrontendError::Internal("No active operation".to_string()))?;

    match active_op {
        ActiveOperation::Decrypt { mechanism_type: _, key_handle: _ } => {}
        _ => {
            return Err(FrontendError::Internal("Wrong active operation".to_string()));
        }
    }

    // For dummy implementation, assume AES, output same size
    let output_size = encrypted_data_len as usize;
    unsafe {
        if data.is_null() {
            *data_len = output_size as CK_ULONG;
        } else {
            if *data_len < output_size as CK_ULONG {
                return Err(FrontendError::Internal("Data buffer too small".to_string()));
            }
            // Copy data as dummy decryption
            std::ptr::copy_nonoverlapping(encrypted_data, data, output_size);
            *data_len = output_size as CK_ULONG;
        }
    }

    Ok(())
}

#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn C_GetSlotList(
    token_present: CK_ULONG,
    p_slot_list: CK_SLOT_ID_PTR,
    pul_count: CK_ULONG_PTR,
) -> CK_RV {
    if pul_count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match get_slot_list(token_present != 0) {
        Ok(slots) => {
            unsafe {
                // If the buffer is null, just return the count
                if p_slot_list.is_null() {
                    *pul_count = slots.len() as CK_ULONG;
                    return CKR_OK;
                }

                // If the buffer is too small, return the required size
                if *pul_count < slots.len() as CK_ULONG {
                    *pul_count = slots.len() as CK_ULONG;
                    return CKR_BUFFER_TOO_SMALL;
                }

                // Copy the slot IDs to the provided buffer
                std::ptr::copy_nonoverlapping(slots.as_ptr(), p_slot_list, slots.len());
                *pul_count = slots.len() as CK_ULONG;
            }
            CKR_OK
        }
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => translate_error(err),
    }
}

/// Get the list of available slots
pub fn get_slot_list(_token_present: bool) -> Result<Vec<CK_SLOT_ID>, FrontendError> {
    let guard = STATE.read();
    let context = guard
        .context
        .as_ref()
        .ok_or(FrontendError::NotInitialized)?;
    let context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    // If token_present is true, only return slots with tokens
    // For now, we assume all slots have tokens
    Ok(context.slots.iter().map(|slot| slot.id).collect())
}

pub fn get_mechanism_list(slot_id: CK_SLOT_ID) -> Result<Vec<CK_MECHANISM_TYPE>, FrontendError> {
    let guard = STATE.read();
    let context = guard
        .context
        .as_ref()
        .ok_or(FrontendError::NotInitialized)?;
    let context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    if !context.slots.iter().any(|slot| slot.id == slot_id) {
        return Err(FrontendError::Internal(format!(
            "Slot {} not found",
            slot_id
        )));
    }

    Ok(crate::mechanism::get_supported_mechanisms())
}

#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn C_GetMechanismList(
    slot_id: CK_SLOT_ID,
    p_mechanism_list: CK_ULONG_PTR,
    pul_count: CK_ULONG_PTR,
) -> CK_RV {
    if pul_count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match get_mechanism_list(slot_id) {
        Ok(mechanisms) => {
            unsafe {
                // If p_mechanism_list is null, just return the count
                if p_mechanism_list.is_null() {
                    *pul_count = mechanisms.len() as CK_ULONG;
                    return CKR_OK;
                }

                // If the buffer is too small, return the required size
                if *pul_count < mechanisms.len() as CK_ULONG {
                    *pul_count = mechanisms.len() as CK_ULONG;
                    return CKR_BUFFER_TOO_SMALL;
                }

                // Copy the mechanisms to the provided buffer
                std::ptr::copy_nonoverlapping(mechanisms.as_ptr(), p_mechanism_list, mechanisms.len());
                *pul_count = mechanisms.len() as CK_ULONG;
            }
            CKR_OK
        }
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 get_mechanism_list internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

/// Get information about a token
pub fn get_token_info(slot_id: CK_SLOT_ID) -> Result<CK_TOKEN_INFO, FrontendError> {
    let guard = STATE.read();
    let context = guard
        .context
        .as_ref()
        .ok_or(FrontendError::NotInitialized)?;
    let context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    // Verify the slot exists
    if !context.slots.iter().any(|slot| slot.id == slot_id) {
        return Err(FrontendError::Internal(format!(
            "Slot {} not found",
            slot_id
        )));
    }

    // Create the token info structure
    let mut token_info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
    
    // Copy the label
    let label_bytes = b"FerroHSM Software Token";
    let copy_len = std::cmp::min(label_bytes.len(), 32);
    unsafe {
        std::ptr::copy_nonoverlapping(
            label_bytes.as_ptr(),
            token_info.label.as_mut_ptr(),
            copy_len,
        );
    }
    
    // Copy the manufacturer ID
    let manufacturer_bytes = b"FerroLabs AG";
    let copy_len = std::cmp::min(manufacturer_bytes.len(), 32);
    unsafe {
        std::ptr::copy_nonoverlapping(
            manufacturer_bytes.as_ptr(),
            token_info.manufacturerID.as_mut_ptr(),
            copy_len,
        );
    }
    
    // Copy the model
    let model_bytes = concat!("FerroHSM v", env!("CARGO_PKG_VERSION")).as_bytes();
    let copy_len = std::cmp::min(model_bytes.len(), 16);
    unsafe {
        std::ptr::copy_nonoverlapping(
            model_bytes.as_ptr(),
            token_info.model.as_mut_ptr(),
            copy_len,
        );
    }
    
    // Copy the serial number
    let serial_bytes = b"00000001";
    let copy_len = std::cmp::min(serial_bytes.len(), 16);
    unsafe {
        std::ptr::copy_nonoverlapping(
            serial_bytes.as_ptr(),
            token_info.serialNumber.as_mut_ptr(),
            copy_len,
        );
    }
    
    // Set flags
    token_info.flags = 0x00000001 |  // CKF_RNG
                      0x00000002 |  // CKF_WRITE_PROTECTED
                      0x00000004 |  // CKF_LOGIN_REQUIRED
                      0x00000008 |  // CKF_USER_PIN_INITIALIZED
                      0x00000400;   // CKF_TOKEN_INITIALIZED
    
    // Set other fields
    token_info.ulMaxSessionCount = 100;
    token_info.ulSessionCount = 0;
    token_info.ulMaxRwSessionCount = 100;
    token_info.ulRwSessionCount = 0;
    token_info.ulMaxPinLen = 255;
    token_info.ulMinPinLen = 4;
    token_info.ulTotalPublicMemory = 0xFFFFFFFF;
    token_info.ulFreePublicMemory = 0xFFFFFFFF;
    token_info.ulTotalPrivateMemory = 0xFFFFFFFF;
    token_info.ulFreePrivateMemory = 0xFFFFFFFF;
    token_info.hardwareVersion.major = 0;
    token_info.hardwareVersion.minor = 3;
    token_info.firmwareVersion.major = 0;
    token_info.firmwareVersion.minor = 3;

    Ok(token_info)
}

#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn C_GetTokenInfo(
    slot_id: CK_SLOT_ID,
    p_info: CK_TOKEN_INFO_PTR,
) -> CK_RV {
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match get_token_info(slot_id) {
        Ok(token_info) => {
            unsafe {
                *p_info = token_info;
            }
            CKR_OK
        }
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => translate_error(err),
    }
}

/// Get information about a slot
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

    // Create the slot info structure
    let mut slot_info: CK_SLOT_INFO = unsafe { std::mem::zeroed() };
    
    // Copy the slot description
    let description_bytes = slot.description.as_bytes();
    let copy_len = std::cmp::min(description_bytes.len(), 64);
    unsafe {
        std::ptr::copy_nonoverlapping(
            description_bytes.as_ptr(),
            slot_info.slotDescription.as_mut_ptr(),
            copy_len,
        );
    }
    
    // Copy the manufacturer ID
    let manufacturer_bytes = slot.manufacturer.as_bytes();
    let copy_len = std::cmp::min(manufacturer_bytes.len(), 32);
    unsafe {
        std::ptr::copy_nonoverlapping(
            manufacturer_bytes.as_ptr(),
            slot_info.manufacturerID.as_mut_ptr(),
            copy_len,
        );
    }
    
    // Set flags (for now, we assume the slot is present and has a token)
    slot_info.flags = 0x00000001 | 0x00000002; // CKF_SLOT_PRESENT | CKF_TOKEN_PRESENT

    Ok(slot_info)
}

#[unsafe(no_mangle)]
pub extern "C" fn C_GetSlotInfo(
    slot_id: CK_SLOT_ID,
    p_info: CK_SLOT_INFO_PTR,
) -> CK_RV {
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match get_slot_info(slot_id) {
        Ok(slot_info) => {
            unsafe {
                *p_info = slot_info;
            }
            CKR_OK
        }
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => translate_error(err),
    }
}

/// Get information about a mechanism
pub fn get_mechanism_info(
    slot_id: CK_SLOT_ID,
    mechanism_type: CK_ULONG,
) -> Result<CK_MECHANISM_INFO, FrontendError> {
    let guard = STATE.read();
    let context = guard
        .context
        .as_ref()
        .ok_or(FrontendError::NotInitialized)?;
    let context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    // Verify the slot exists
    if !context.slots.iter().any(|slot| slot.id == slot_id) {
        return Err(FrontendError::Internal(format!(
            "Slot {} not found",
            slot_id
        )));
    }

    // For now, return basic mechanism info for all supported mechanisms
    // In a more sophisticated implementation, we would have detailed info per mechanism
    let supported_mechanisms = crate::mechanism::get_supported_mechanisms();
    if !supported_mechanisms.contains(&(mechanism_type as CK_MECHANISM_TYPE)) {
        return Err(FrontendError::Internal(format!(
            "Mechanism 0x{:x} not supported",
            mechanism_type
        )));
    }

    let mut info: CK_MECHANISM_INFO = unsafe { std::mem::zeroed() };

    // Set basic flags - most mechanisms support hardware operation
    info.flags = 0x00000001; // CKF_HW (hardware mechanism)

    // Set minimum and maximum key sizes (dummy values for now)
    info.ulMinKeySize = 128; // 128 bits minimum
    info.ulMaxKeySize = 4096; // 4096 bits maximum

    Ok(info)
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

    // For demonstration, we'll check if the PIN is "1234"
    if pin != b"1234" {
        return Err(FrontendError::Internal("Invalid PIN".to_string()));
    }

    // Set the user type and update session state
    session.user_type = Some(user_type);
    session.state = if session.flags & 0x00000002 != 0 { 3 } else { 1 }; // CKF_RW_SESSION -> CKS_RW_USER_FUNCTIONS, else CKS_RO_USER_FUNCTIONS

    Ok(())
}

/// Login to a session
#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn C_Login(
    session_handle: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    p_pin: CK_UTF8CHAR_PTR,
    ul_pin_len: CK_ULONG,
) -> CK_RV {
    if p_pin.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    // Convert PIN to bytes
    let pin = unsafe {
        std::slice::from_raw_parts(p_pin, ul_pin_len as usize)
    };

    match login(session_handle, user_type, pin) {
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

#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn C_GetMechanismInfo(
    slot_id: CK_SLOT_ID,
    mechanism_type: CK_ULONG,
    p_info: *mut CK_MECHANISM_INFO,
) -> CK_RV {
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match get_mechanism_info(slot_id, mechanism_type) {
        Ok(info) => {
            unsafe {
                *p_info = info;
            }
            CKR_OK
        }
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 get_mechanism_info internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

/// Get session information
pub fn get_session_info(
    session_handle: CK_SESSION_HANDLE,
) -> Result<CK_SESSION_INFO, FrontendError> {
    let guard = STATE.read();
    let context = guard
        .context
        .as_ref()
        .ok_or(FrontendError::NotInitialized)?;
    let context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    // Find the session
    let session = context
        .sessions
        .get(&session_handle)
        .ok_or_else(|| FrontendError::Internal(format!("Session {} not found", session_handle)))?;

    let mut info: CK_SESSION_INFO = unsafe { std::mem::zeroed() };

    // Set slot ID
    info.slotID = session.slot_id;

    // Set state
    info.state = session.state;

    // Set flags
    info.flags = session.flags;

    // Set device error (no error)
    info.ulDeviceError = 0;

    Ok(info)
}

fn get_attribute_value_from_metadata(
    _metadata: &hsm_core::models::KeyMetadata,
    _attr_type: cryptoki_sys::CK_ATTRIBUTE_TYPE,
) -> Option<Vec<u8>> {
    None
}

/// Get attribute values for an object
pub fn get_attribute_value(
    session_handle: CK_SESSION_HANDLE,
    object_handle: CK_OBJECT_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> Result<(), FrontendError> {
    let mut guard = STATE.write();
    let context = guard
        .context
        .as_mut()
        .ok_or(FrontendError::NotInitialized)?;
    let context = context
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

    // Handle dummy objects without key_id
    if object.key_id.is_none() {
        // For dummy AES key
        for i in 0..count as usize {
            let attr = unsafe { &mut * (template.add(i)) };
            if attr.type_ == cryptoki_sys::CKA_KEY_TYPE {
                let key_type = 31u32; // CKK_AES
                let value = key_type.to_le_bytes();
                if attr.pValue.is_null() {
                    attr.ulValueLen = value.len() as CK_ULONG;
                } else if attr.ulValueLen < value.len() as CK_ULONG {
                    return Err(FrontendError::Internal("Buffer too small".to_string()));
                } else {
                    unsafe {
                        std::ptr::copy_nonoverlapping(value.as_ptr(), attr.pValue as *mut u8, value.len());
                    }
                    attr.ulValueLen = value.len() as CK_ULONG;
                }
            } else {
                attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
            }
        }
        return Ok(());
    }

    // Look up the key metadata
    let key_id = object.key_id.as_ref().unwrap();

    let record = context
        .key_store
        .fetch(key_id)
        .map_err(|e| FrontendError::Internal(format!("Failed to fetch key {}: {}", key_id, e)))?;

    // Process each attribute in the template
    for i in 0..count as usize {
        let attr = unsafe { &mut * (template.add(i)) };
        let value = get_attribute_value_from_metadata(&record.metadata, attr.type_);
        if let Some(value) = value {
            if attr.pValue.is_null() {
                attr.ulValueLen = value.len() as CK_ULONG;
            } else if attr.ulValueLen < value.len() as CK_ULONG {
                return Err(FrontendError::Internal("Buffer too small".to_string()));
            } else {
                unsafe {
                    std::ptr::copy_nonoverlapping(value.as_ptr(), attr.pValue as *mut u8, value.len());
                }
                attr.ulValueLen = value.len() as CK_ULONG;
            }
        } else {
            attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
        }
    }

    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn C_GenerateKey(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: *mut cryptoki_sys::CK_MECHANISM,
    p_template: cryptoki_sys::CK_ATTRIBUTE_PTR,
    ul_count: CK_ULONG,
    ph_key: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    if p_mechanism.is_null() || ph_key.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    // Convert mechanism
    let mechanism = unsafe { &*p_mechanism };

    // Convert template to bytes (simplified for now)
    let template_bytes = if p_template.is_null() {
        Vec::new()
    } else {
        unsafe {
            std::slice::from_raw_parts(p_template as *const u8, (ul_count * std::mem::size_of::<cryptoki_sys::CK_ATTRIBUTE>() as CK_ULONG) as usize).to_vec()
        }
    };

    match generate_key(h_session, mechanism, &template_bytes, ul_count) {
        Ok(object_handle) => {
            unsafe {
                *ph_key = object_handle;
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

#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn C_SignInit(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: *mut cryptoki_sys::CK_MECHANISM,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    if p_mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match sign_init(h_session, p_mechanism, h_key) {
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

#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn C_Sign(
    h_session: CK_SESSION_HANDLE,
    p_data: CK_BYTE_PTR,
    ul_data_len: CK_ULONG,
    p_signature: CK_BYTE_PTR,
    pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    if p_data.is_null() || pul_signature_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match sign(h_session, p_data, ul_data_len, p_signature, pul_signature_len) {
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

#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn C_VerifyInit(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: *mut cryptoki_sys::CK_MECHANISM,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    if p_mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match verify_init(h_session, p_mechanism, h_key) {
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

#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn C_Verify(
    h_session: CK_SESSION_HANDLE,
    p_data: CK_BYTE_PTR,
    ul_data_len: CK_ULONG,
    p_signature: CK_BYTE_PTR,
    ul_signature_len: CK_ULONG,
) -> CK_RV {
    if p_data.is_null() || p_signature.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match verify(h_session, p_data, ul_data_len, p_signature, ul_signature_len) {
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
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn C_EncryptInit(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: *mut cryptoki_sys::CK_MECHANISM,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    if p_mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match encrypt_init(h_session, p_mechanism, h_key) {
        Ok(()) => CKR_OK,
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 encrypt_init internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn C_Encrypt(
    h_session: CK_SESSION_HANDLE,
    p_data: CK_BYTE_PTR,
    ul_data_len: CK_ULONG,
    p_encrypted_data: CK_BYTE_PTR,
    pul_encrypted_data_len: CK_ULONG_PTR,
) -> CK_RV {
    if p_data.is_null() || pul_encrypted_data_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match encrypt(h_session, p_data, ul_data_len, p_encrypted_data, pul_encrypted_data_len) {
        Ok(()) => CKR_OK,
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 encrypt internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn C_DecryptInit(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: *mut cryptoki_sys::CK_MECHANISM,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    if p_mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match decrypt_init(h_session, p_mechanism, h_key) {
        Ok(()) => CKR_OK,
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 decrypt_init internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn C_Decrypt(
    h_session: CK_SESSION_HANDLE,
    p_encrypted_data: CK_BYTE_PTR,
    ul_encrypted_data_len: CK_ULONG,
    p_data: CK_BYTE_PTR,
    pul_data_len: CK_ULONG_PTR,
) -> CK_RV {
    if p_encrypted_data.is_null() || pul_data_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match decrypt(h_session, p_encrypted_data, ul_encrypted_data_len, p_data, pul_data_len) {
        Ok(()) => CKR_OK,
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 decrypt internal error: {msg}");
            }
            translate_error(err)
        }
    }
}
#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn C_GetAttributeValue(
    h_session: CK_SESSION_HANDLE,
    h_object: CK_OBJECT_HANDLE,
    p_template: CK_ATTRIBUTE_PTR,
    ul_count: CK_ULONG,
) -> CK_RV {
    if p_template.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match get_attribute_value(h_session, h_object, p_template, ul_count) {
        Ok(()) => CKR_OK,
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 get_attribute_value internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

/// Open a new session
pub fn open_session(slot_id: CK_SLOT_ID, flags: CK_FLAGS) -> Result<CK_SESSION_HANDLE, FrontendError> {
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

    // Create the session info
    let session_info = SessionInfo {
        handle: session_handle,
        slot_id,
        flags,
        state: 0, // CKS_RO_PUBLIC_SESSION
        user_type: None,
        search_context: None,
        active_operation: None,
    };

    // Store the session
    context.sessions.insert(session_handle, session_info);

    Ok(session_handle)
}

#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn C_OpenSession(
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
    _p_application: CK_VOID_PTR,
    _ul_application_data_len: CK_ULONG,
    ph_session: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    if ph_session.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match open_session(slot_id, flags) {
        Ok(session_handle) => {
            unsafe {
                *ph_session = session_handle;
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

pub fn close_session(session_handle: CK_SESSION_HANDLE) -> Result<(), FrontendError> {
    let mut guard = STATE.write();
    let context = guard
        .context
        .as_mut()
        .ok_or(FrontendError::NotInitialized)?;
    let mut context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    context.sessions.remove(&session_handle).ok_or_else(|| {
        FrontendError::Internal(format!("Session {} not found", session_handle))
    })?;
    Ok(())
}

#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn C_CloseSession(h_session: CK_SESSION_HANDLE) -> CK_RV {
    match close_session(h_session) {
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

#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn C_GetSessionInfo(
    h_session: CK_SESSION_HANDLE,
    p_info: *mut CK_SESSION_INFO,
) -> CK_RV {
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match get_session_info(h_session) {
        Ok(info) => {
            unsafe {
                *p_info = info;
            }
            CKR_OK
        }
        Err(FrontendError::NotInitialized) => CKR_CRYPTOKI_NOT_INITIALIZED,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 get_session_info internal error: {msg}");
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

    // Clear the user type and reset session state
    session.user_type = None;
    session.state = if session.flags & 0x00000002 != 0 { 2 } else { 0 }; // CKF_RW_SESSION -> CKS_RW_PUBLIC_SESSION, else CKS_RO_PUBLIC_SESSION

    Ok(())
}

#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn C_Logout(session_handle: CK_SESSION_HANDLE) -> CK_RV {
    match logout(session_handle) {
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


/// Generate a key
pub fn generate_key(
    session_handle: CK_SESSION_HANDLE,
    _mechanism: &cryptoki_sys::CK_MECHANISM,
    _template: &[u8], // In a real implementation, this would be CK_ATTRIBUTE_PTR
    _template_len: CK_ULONG,
) -> Result<CK_OBJECT_HANDLE, FrontendError> {
    let guard = STATE.read();
    let context = guard
        .context
        .as_ref()
        .ok_or(FrontendError::NotInitialized)?;
    let mut context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    let slot_id = {
        let session = context
            .sessions
            .get(&session_handle)
            .ok_or_else(|| FrontendError::Internal(format!("Session {} not found", session_handle)))?;
        session.slot_id
    };

    // For now, we'll just return a dummy object handle
    // In a real implementation, we would:
    // 1. Parse the mechanism to determine what kind of key to generate
    // 2. Parse the template to get key attributes
    // 3. Generate the key using the crypto engine
    // 4. Store the key and return an object handle
    
    // Create the object
    let object_handle = context.next_object_id;
    context.next_object_id += 1;

    let object = ObjectInfo {
        handle: object_handle,
        session_handle,
        slot_id,
        key_id: None, // For now, no key stored
    };

    context.objects.insert(object_handle, object);

    Ok(object_handle)
}

/// Initialize a signing operation
pub fn sign_init(
    session_handle: CK_SESSION_HANDLE,
    mechanism: *mut cryptoki_sys::CK_MECHANISM,
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

    {
        let session = context
            .sessions
            .get(&session_handle)
            .ok_or_else(|| FrontendError::Internal(format!("Session {} not found", session_handle)))?;

        if session.user_type.is_none() {
            return Err(FrontendError::Internal("Not logged in".to_string()));
        }
    }

    {
        let object = context
            .objects
            .get(&key_handle)
            .ok_or_else(|| FrontendError::Internal(format!("Object {} not found", key_handle)))?;

        if object.session_handle != session_handle {
            return Err(FrontendError::Internal(
                "Object does not belong to this session".to_string(),
            ));
        }
    }

    let mechanism_type = unsafe { (*mechanism).mechanism };

    let session = context
        .sessions
        .get_mut(&session_handle)
        .ok_or_else(|| FrontendError::Internal(format!("Session {} not found", session_handle)))?;
    session.active_operation = Some(ActiveOperation::Sign {
        mechanism_type,
        key_handle,
    });

    Ok(())
}

/// Perform a signing operation
pub fn sign(
    session_handle: CK_SESSION_HANDLE,
    _data: CK_BYTE_PTR,
    _data_len: CK_ULONG,
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

    // Get active operation
    let active_op = session.active_operation.take().ok_or_else(|| FrontendError::Internal("No active operation".to_string()))?;

    let key_handle = match active_op {
        ActiveOperation::Sign { mechanism_type: _, key_handle } => key_handle,
        _ => {
            return Err(FrontendError::Internal("Wrong active operation".to_string()));
        }
    };

    // Find the object
    let object = context
        .objects
        .get(&key_handle)
        .ok_or_else(|| FrontendError::Internal(format!("Object {} not found", key_handle)))?;

    if object.session_handle != session_handle {
        return Err(FrontendError::Internal(
            "Object does not belong to this session".to_string(),
        ));
    }

    // For dummy implementation, return fixed size signature
    let sig_size = 256; // Assume RSA-2048
    unsafe {
        if signature.is_null() {
            *signature_len = sig_size;
        } else {
            if *signature_len < sig_size {
                return Err(FrontendError::Internal("Signature buffer too small".to_string()));
            }
            // Fill with dummy signature
            std::ptr::write_bytes(signature, 0xAB, sig_size as usize);
            *signature_len = sig_size;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_MUTEX: once_cell::sync::Lazy<std::sync::Mutex<()>> =
        once_cell::sync::Lazy::new(|| std::sync::Mutex::new(()));

    struct TestStateGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for TestStateGuard {
        fn drop(&mut self) {
            let mut guard = STATE.write();
            guard.context = None;
        }
    }

    fn cleanup() -> TestStateGuard {
        let lock = TEST_MUTEX.lock().expect("test mutex poisoned");
        {
            let mut guard = STATE.write();
            guard.context = None;
        }
        TestStateGuard { _lock: lock }
    }

    #[test]
    fn initialize_and_finalize_roundtrip() {
        let _guard = cleanup();
        initialize(std::ptr::null_mut()).expect("init");
        finalize().expect("finalize");
        assert_eq!(
            translate_error(finalize().unwrap_err()),
            CKR_CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    fn double_initialize_is_rejected() {
        let _guard = cleanup();
        initialize(std::ptr::null_mut()).expect("init");
        let rv = translate_error(initialize(std::ptr::null_mut()).unwrap_err());
        assert_eq!(rv, CKR_CRYPTOKI_ALREADY_INITIALIZED);
        finalize().expect("finalize");
    }

    #[test]
    fn get_slot_list_works() {
        let _guard = cleanup();
        initialize(std::ptr::null_mut()).expect("init");

        // First call to get the count
        let mut count = 0u64;
        let rv = C_GetSlotList(
            0, // token_present
            std::ptr::null_mut(), // null buffer to get count
            &mut count,
        );
        assert_eq!(rv, CKR_OK);
        assert_eq!(count, 1); // We have one slot

        // Second call with properly sized buffer
        let mut slot_list = vec![0u64; count as usize];
        let rv = C_GetSlotList(
            0, // token_present
            slot_list.as_mut_ptr(),
            &mut count,
        );
        assert_eq!(rv, CKR_OK);
        assert_eq!(count, 1);
        assert_eq!(slot_list[0], 1); // Slot ID 1

        finalize().expect("finalize");
    }

    #[test]
    fn get_slot_info_works() {
        let _guard = cleanup();
        initialize(std::ptr::null_mut()).expect("init");

        let mut slot_info = unsafe { std::mem::zeroed() };

        let rv = C_GetSlotInfo(1, &mut slot_info);

        assert_eq!(rv, CKR_OK);
        // Check that the slot description contains our expected string
        let description_bytes = &slot_info.slotDescription[..];
        let description_str = std::str::from_utf8(description_bytes)
            .unwrap_or("")
            .trim_end_matches('\0')
            .trim_end_matches(' ');
        assert!(description_str.contains("FerroHSM"));

        finalize().expect("finalize");
    }

    #[test]
    fn get_token_info_works() {
        let _guard = cleanup();
        initialize(std::ptr::null_mut()).expect("init");

        let mut token_info = unsafe { std::mem::zeroed() };

        let rv = C_GetTokenInfo(1, &mut token_info);

        assert_eq!(rv, CKR_OK);
        // Check that the label contains our expected string
        let label_bytes = &token_info.label[..];
        let label_str = std::str::from_utf8(label_bytes)
            .unwrap_or("")
            .trim_end_matches('\0')
            .trim_end_matches(' ');
        assert!(label_str.contains("FerroHSM"));

        finalize().expect("finalize");
    }

    #[test]
    fn get_mechanism_list_works() {
        let _guard = cleanup();
        initialize(std::ptr::null_mut()).expect("init");

        // First call to get the count
        let mut count = 0u64;
        let rv = C_GetMechanismList(
            1, // slot_id
            std::ptr::null_mut(), // null buffer to get count
            &mut count,
        );
        assert_eq!(rv, CKR_OK);
        assert!(count > 0); // We should have some mechanisms

        // Second call with properly sized buffer
        let mut mechanism_list = vec![0u64; count as usize];
        let rv = C_GetMechanismList(
            1, // slot_id
            mechanism_list.as_mut_ptr(),
            &mut count,
        );
        assert_eq!(rv, CKR_OK);
        assert!(count > 0);

        finalize().expect("finalize");
    }

    #[test]
   fn session_lifecycle_works() {
        let _guard = cleanup();
        initialize(std::ptr::null_mut()).expect("init");

        // Open session
        let mut session_handle = 0;
        let rv = C_OpenSession(
            1, // slot_id
            0, // flags (read-only)
            std::ptr::null_mut(),
            0, // ulApplicationDataLen
            &mut session_handle,
        );
        assert_eq!(rv, CKR_OK);
        assert_ne!(session_handle, 0);

        // Get session info
        let mut session_info = unsafe { std::mem::zeroed() };
        let rv = C_GetSessionInfo(session_handle, &mut session_info);
        assert_eq!(rv, CKR_OK);
        assert_eq!(session_info.slotID, 1);

        // Close session
        let rv = C_CloseSession(session_handle);
        assert_eq!(rv, CKR_OK);

        finalize().expect("finalize");
    }

    #[test]
    fn key_generation_and_operations_work() {
        let _guard = cleanup();
        initialize(std::ptr::null_mut()).expect("init");

        // Open session
        let mut session_handle = 0;
        let rv = C_OpenSession(
            1, // slot_id
            4, // CKF_RW_SESSION
            std::ptr::null_mut(),
            0, // ulApplicationDataLen
            &mut session_handle,
        );
        assert_eq!(rv, CKR_OK);

        // Login as user
        let pin = b"1234";
        let rv = C_Login(
            session_handle,
            1, // CKU_USER
            pin.as_ptr() as *mut u8,
            pin.len() as u64,
        );
        assert_eq!(rv, CKR_OK);

        // Generate AES key
        let mut key_handle = 0;
        let mut mechanism = cryptoki_sys::CK_MECHANISM {
            mechanism: cryptoki_sys::CKM_AES_KEY_GEN,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let rv = C_GenerateKey(
            session_handle,
            &mut mechanism,
            std::ptr::null_mut(), // template
            0, // template_len
            &mut key_handle,
        );
        assert_eq!(rv, CKR_OK);
        assert_ne!(key_handle, 0);

        // Get key attributes
        let mut template = [cryptoki_sys::CK_ATTRIBUTE {
            type_: cryptoki_sys::CKA_KEY_TYPE,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        }];
        let rv = C_GetAttributeValue(
            session_handle,
            key_handle,
            template.as_mut_ptr(),
            1,
        );
        assert_eq!(rv, CKR_OK);

        // Logout
        let rv = C_Logout(session_handle);
        assert_eq!(rv, CKR_OK);

        // Close session
        let rv = C_CloseSession(session_handle);
        assert_eq!(rv, CKR_OK);

        finalize().expect("finalize");
    }
}
