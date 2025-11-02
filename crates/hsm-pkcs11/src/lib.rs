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
    CK_ATTRIBUTE_PTR, CK_FLAGS, CK_MECHANISM_INFO, CK_MECHANISM_TYPE,
    CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_SESSION_HANDLE_PTR,
    CK_SESSION_INFO, CK_SLOT_ID, CK_SLOT_ID_PTR, CK_SLOT_INFO, CK_SLOT_INFO_PTR, CK_STATE, CK_TOKEN_INFO, CK_TOKEN_INFO_PTR,
    CK_ULONG, CK_ULONG_PTR, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_VOID_PTR, CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL,
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
pub extern "C" fn C_Initialize(pInitArgs: CK_VOID_PTR) -> CK_RV {
    match initialize(pInitArgs) {
        Ok(()) => CKR_OK,
        Err(err) => translate_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn C_Finalize(pReserved: CK_VOID_PTR) -> CK_RV {
    if !pReserved.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    
    match finalize() {
        Ok(()) => CKR_OK,
        Err(err) => translate_error(err),
    }
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

    context.sessions.remove(&session_handle).ok_or_else(|| FrontendError::Internal(format!("Session {} not found", session_handle)))?;
    Ok(())
}

/// Get the list of mechanisms supported by a token
pub fn get_mechanism_list(slot_id: CK_SLOT_ID) -> Result<Vec<CK_ULONG>, FrontendError> {
    let guard = STATE.read();
    let context = guard
        .context
        .as_ref()
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

    // Return all supported mechanisms
    Ok(crate::mechanism::get_supported_mechanisms()
        .into_iter()
        .map(|m| m as CK_ULONG)
        .collect())
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
    let mut context = context
        .lock()
        .map_err(|_| FrontendError::Internal("Failed to lock context".to_string()))?;

    // If token_present is true, only return slots with tokens
    // For now, we assume all slots have tokens
    Ok(context.slots.iter().map(|slot| slot.id).collect())
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

    // Create the token info structure
    let mut token_info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
    
    // Copy the label
    let label_bytes = b"FerroHSM Software Token";
    let copy_len = std::cmp::min(label_bytes.len(), 32);
    unsafe {
        std::ptr::copy_nonoverlapping(
            label_bytes.as_ptr(),
            token_info.label.as_mut_ptr() as *mut u8,
            copy_len,
        );
    }
    
    // Copy the manufacturer ID
    let manufacturer_bytes = b"FerroLabs AG";
    let copy_len = std::cmp::min(manufacturer_bytes.len(), 32);
    unsafe {
        std::ptr::copy_nonoverlapping(
            manufacturer_bytes.as_ptr(),
            token_info.manufacturerID.as_mut_ptr() as *mut u8,
            copy_len,
        );
    }
    
    // Copy the model
    let model_bytes = b"FerroHSM v0.3.0";
    let copy_len = std::cmp::min(model_bytes.len(), 16);
    unsafe {
        std::ptr::copy_nonoverlapping(
            model_bytes.as_ptr(),
            token_info.model.as_mut_ptr() as *mut u8,
            copy_len,
        );
    }
    
    // Copy the serial number
    let serial_bytes = b"00000001";
    let copy_len = std::cmp::min(serial_bytes.len(), 16);
    unsafe {
        std::ptr::copy_nonoverlapping(
            serial_bytes.as_ptr(),
            token_info.serialNumber.as_mut_ptr() as *mut u8,
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
    let mut context = context
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
            slot_info.slotDescription.as_mut_ptr() as *mut u8,
            copy_len,
        );
    }
    
    // Copy the manufacturer ID
    let manufacturer_bytes = slot.manufacturer.as_bytes();
    let copy_len = std::cmp::min(manufacturer_bytes.len(), 32);
    unsafe {
        std::ptr::copy_nonoverlapping(
            manufacturer_bytes.as_ptr(),
            slot_info.manufacturerID.as_mut_ptr() as *mut u8,
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

    // For now, we'll just set the user type - in a real implementation, we would verify the PIN
    session.user_type = Some(user_type);
    
    // For demonstration, we'll check if the PIN is "1234"
    if pin != b"1234" {
        return Err(FrontendError::Internal("Invalid PIN".to_string()));
    }

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
    let mut context = context
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

    // Look up the key metadata
    let key_id = object.key_id.as_ref().ok_or_else(|| {
        FrontendError::Internal(format!("Object {} has no key ID", object_handle))
    })?;

    let record = context
        .key_store
        .fetch(key_id)
        .map_err(|e| FrontendError::Internal(format!("Failed to fetch key {}: {}", key_id, e)))?;

    // Process each attribute in the template
    for i in 0..count as usize {
        let attribute = unsafe { &mut *template.add(i) };

        // Use the attribute module to get the value
        match crate::attribute::get_attribute_value(&record.metadata, attribute.type_) {
            Some(value) => {
                unsafe {
                    if attribute.pValue.is_null() {
                        // Just set the length
                        attribute.ulValueLen = value.len() as CK_ULONG;
                    } else if attribute.ulValueLen < value.len() as CK_ULONG {
                        // Buffer too small
                        attribute.ulValueLen = value.len() as CK_ULONG;
                        return Err(FrontendError::Internal("Buffer too small".to_string()));
                    } else {
                        // Copy the value
                        std::ptr::copy_nonoverlapping(
                            value.as_ptr(),
                            attribute.pValue as *mut u8,
                            value.len(),
                        );
                        attribute.ulValueLen = value.len() as CK_ULONG;
                    }
                }
            }
            None => {
                // Attribute not found or not supported
                attribute.ulValueLen = std::u32::MAX as CK_ULONG; // CK_UNAVAILABLE_INFORMATION
            }
        }
    }

    Ok(())
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

    // Clear the user type
    session.user_type = None;

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

    // Find the session
    let _session = context
        .sessions
        .get(&session_handle)
        .ok_or_else(|| FrontendError::Internal(format!("Session {} not found", session_handle)))?;

    // For now, we'll just return a dummy object handle
    // In a real implementation, we would:
    // 1. Parse the mechanism to determine what kind of key to generate
    // 2. Parse the template to get key attributes
    // 3. Generate the key using the crypto engine
    // 4. Store the key and return an object handle
    
    // Create a dummy object handle
    let object_handle = context.next_object_id;
    // Note: In a real implementation, we would actually store the key

    Ok(object_handle)
}

#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cleanup() {
        // Force cleanup of global state
        let mut guard = STATE.write();
        guard.context = None;
    }

    #[test]
    fn initialize_and_finalize_roundtrip() {
        cleanup();
        initialize(std::ptr::null_mut()).expect("init");
        finalize().expect("finalize");
        assert_eq!(
            translate_error(finalize().unwrap_err()),
            CKR_CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    fn double_initialize_is_rejected() {
        cleanup();
        initialize(std::ptr::null_mut()).expect("init");
        let rv = translate_error(initialize(std::ptr::null_mut()).unwrap_err());
        assert_eq!(rv, CKR_CRYPTOKI_ALREADY_INITIALIZED);
        finalize().expect("finalize");
    }

    #[test]
    fn get_slot_list_works() {
        cleanup();
        initialize(std::ptr::null_mut()).expect("init");

        // First call to get the count
        let mut count = 0u64;
        let rv = unsafe {
            C_GetSlotList(
                0, // token_present
                std::ptr::null_mut(), // null buffer to get count
                &mut count,
            )
        };
        assert_eq!(rv, CKR_OK);
        assert_eq!(count, 1); // We have one slot

        // Second call with properly sized buffer
        let mut slot_list = vec![0u64; count as usize];
        let rv = unsafe {
            C_GetSlotList(
                0, // token_present
                slot_list.as_mut_ptr(),
                &mut count,
            )
        };
        assert_eq!(rv, CKR_OK);
        assert_eq!(count, 1);
        assert_eq!(slot_list[0], 1); // Slot ID 1

        finalize().expect("finalize");
    }

    #[test]
    fn get_slot_info_works() {
        cleanup();
        initialize(std::ptr::null_mut()).expect("init");

        let mut slot_info = unsafe { std::mem::zeroed() };

        let rv = unsafe { C_GetSlotInfo(1, &mut slot_info) };

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
        cleanup();
        initialize(std::ptr::null_mut()).expect("init");

        let mut token_info = unsafe { std::mem::zeroed() };

        let rv = unsafe { C_GetTokenInfo(1, &mut token_info) };

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
        cleanup();
        initialize(std::ptr::null_mut()).expect("init");

        // First call to get the count
        let mut count = 0u64;
        let rv = unsafe {
            C_GetMechanismList(
                1, // slot_id
                std::ptr::null_mut(), // null buffer to get count
                &mut count,
            )
        };
        assert_eq!(rv, CKR_OK);
        assert!(count > 0); // We should have some mechanisms

        // Second call with properly sized buffer
        let mut mechanism_list = vec![0u64; count as usize];
        let rv = unsafe {
            C_GetMechanismList(
                1, // slot_id
                mechanism_list.as_mut_ptr(),
                &mut count,
            )
        };
        assert_eq!(rv, CKR_OK);
        assert!(count > 0);

        finalize().expect("finalize");
    }

    #[test]
    fn session_lifecycle_works() {
        cleanup();
        initialize(std::ptr::null_mut()).expect("init");

        // Open session
        let mut session_handle = 0;
        let rv = unsafe {
            C_OpenSession(
                1, // slot_id
                0, // flags (read-only)
                std::ptr::null_mut(),
                0, // ulApplicationDataLen
                &mut session_handle,
            )
        };
        assert_eq!(rv, CKR_OK);
        assert_ne!(session_handle, 0);

        // Get session info
        let mut session_info = unsafe { std::mem::zeroed() };
        let rv = unsafe { C_GetSessionInfo(session_handle, &mut session_info) };
        assert_eq!(rv, CKR_OK);
        assert_eq!(session_info.slotID, 1);

        // Close session
        let rv = unsafe { C_CloseSession(session_handle) };
        assert_eq!(rv, CKR_OK);

        finalize().expect("finalize");
    }

    #[test]
    fn key_generation_and_operations_work() {
        cleanup();
        initialize(std::ptr::null_mut()).expect("init");

        // Open session
        let mut session_handle = 0;
        let rv = unsafe {
            C_OpenSession(
                1, // slot_id
                4, // CKF_RW_SESSION
                std::ptr::null_mut(),
                0, // ulApplicationDataLen
                &mut session_handle,
            )
        };
        assert_eq!(rv, CKR_OK);

        // Login as user
        let pin = b"1234";
        let rv = unsafe {
            C_Login(
                session_handle,
                1, // CKU_USER
                pin.as_ptr() as *mut u8,
                pin.len() as u64,
            )
        };
        assert_eq!(rv, CKR_OK);

        // Generate AES key
        let mut key_handle = 0;
        let mut mechanism = cryptoki_sys::CK_MECHANISM {
            mechanism: cryptoki_sys::CKM_AES_KEY_GEN,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let rv = unsafe {
            C_GenerateKey(
                session_handle,
                &mut mechanism,
                std::ptr::null_mut(), // template
                0, // template_len
                &mut key_handle,
            )
        };
        assert_eq!(rv, CKR_OK);
        assert_ne!(key_handle, 0);

        // Get key attributes
        let mut template = [cryptoki_sys::CK_ATTRIBUTE {
            type_: cryptoki_sys::CKA_KEY_TYPE,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        }];
        let rv = unsafe {
            C_GetAttributeValue(
                session_handle,
                key_handle,
                template.as_mut_ptr(),
                1,
            )
        };
        assert_eq!(rv, CKR_OK);

        // Logout
        let rv = unsafe { C_Logout(session_handle) };
        assert_eq!(rv, CKR_OK);

        // Close session
        let rv = unsafe { C_CloseSession(session_handle) };
        assert_eq!(rv, CKR_OK);

        finalize().expect("finalize");
    }
}
