//! PKCS#11 function implementations

use crate::session::SessionManager;
use crate::slot::SlotManager;
use crate::types::hsm_error_to_ckr;
use cryptoki::types::*;
use std::sync::Mutex;

// Global state managers
lazy_static::lazy_static! {
    static ref SLOT_MANAGER: Mutex<SlotManager> = Mutex::new(SlotManager::new());
    static ref SESSION_MANAGER: Mutex<SessionManager> = Mutex::new(SessionManager::new(SlotManager::new()));
}

/// Initialize the PKCS#11 library
#[no_mangle]
pub extern "C" fn C_Initialize(pInitArgs: CK_VOID_PTR) -> CK_RV {
    // In a real implementation, we would initialize the library here
    // For now, we'll just return OK
    CK_RV::CKR_OK
}

/// Finalize the PKCS#11 library
#[no_mangle]
pub extern "C" fn C_Finalize(pReserved: CK_VOID_PTR) -> CK_RV {
    // In a real implementation, we would finalize the library here
    // For now, we'll just return OK
    CK_RV::CKR_OK
}

/// Get information about the PKCS#11 library
#[no_mangle]
pub extern "C" fn C_GetInfo(pInfo: CK_INFO_PTR) -> CK_RV {
    if pInfo.is_null() {
        return CK_RV::CKR_ARGUMENTS_BAD;
    }

    // In a real implementation, we would fill in the library information
    // For now, we'll just return OK
    CK_RV::CKR_OK
}

/// Get the list of available slots
#[no_mangle]
pub extern "C" fn C_GetSlotList(
    tokenPresent: CK_BBOOL,
    pSlotList: CK_SLOT_ID_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    if pulCount.is_null() {
        return CK_RV::CKR_ARGUMENTS_BAD;
    }

    let slot_manager = SLOT_MANAGER.lock().unwrap();
    let slots = slot_manager.get_slots();
    let count = slots.len() as CK_ULONG;

    // If pSlotList is null, just return the count
    if pSlotList.is_null() {
        unsafe {
            *pulCount = count;
        }
        return CK_RV::CKR_OK;
    }

    // Check if the buffer is large enough
    unsafe {
        if *pulCount < count {
            *pulCount = count;
            return CK_RV::CKR_BUFFER_TOO_SMALL;
        }

        *pulCount = count;

        // Fill in the slot list
        for (i, slot) in slots.iter().enumerate() {
            *pSlotList.add(i) = slot.id;
        }
    }

    CK_RV::CKR_OK
}

/// Get information about a specific slot
#[no_mangle]
pub extern "C" fn C_GetSlotInfo(
    slotID: CK_SLOT_ID,
    pInfo: CK_SLOT_INFO_PTR,
) -> CK_RV {
    if pInfo.is_null() {
        return CK_RV::CKR_ARGUMENTS_BAD;
    }

    let slot_manager = SLOT_MANAGER.lock().unwrap();
    let slot = match slot_manager.get_slot(slotID) {
        Some(slot) => slot,
        None => return CK_RV::CKR_SLOT_ID_INVALID,
    };

    // In a real implementation, we would fill in the slot information
    // For now, we'll just return OK
    CK_RV::CKR_OK
}

/// Open a session with a token
#[no_mangle]
pub extern "C" fn C_OpenSession(
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    pApplication: CK_VOID_PTR,
    Notify: extern "C" fn(CK_SESSION_HANDLE, CK_NOTIFICATION, CK_VOID_PTR) -> CK_RV,
    phSession: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    if phSession.is_null() {
        return CK_RV::CKR_ARGUMENTS_BAD;
    }

    let mut session_manager = SESSION_MANAGER.lock().unwrap();
    match session_manager.open_session(slotID, flags) {
        Ok(session_handle) => {
            unsafe {
                *phSession = session_handle;
            }
            CK_RV::CKR_OK
        }
        Err(rv) => rv,
    }
}

/// Close a session
#[no_mangle]
pub extern "C" fn C_CloseSession(hSession: CK_SESSION_HANDLE) -> CK_RV {
    let mut session_manager = SESSION_MANAGER.lock().unwrap();
    match session_manager.close_session(hSession) {
        Ok(()) => CK_RV::CKR_OK,
        Err(rv) => rv,
    }
}

/// Close all sessions
#[no_mangle]
pub extern "C" fn C_CloseAllSessions(slotID: CK_SLOT_ID) -> CK_RV {
    // In a real implementation, we would close all sessions for the given slot
    // For now, we'll just return OK
    CK_RV::CKR_OK
}

/// Get information about a session
#[no_mangle]
pub extern "C" fn C_GetSessionInfo(
    hSession: CK_SESSION_HANDLE,
    pInfo: CK_SESSION_INFO_PTR,
) -> CK_RV {
    if pInfo.is_null() {
        return CK_RV::CKR_ARGUMENTS_BAD;
    }

    let session_manager = SESSION_MANAGER.lock().unwrap();
    let session = match session_manager.get_session(hSession) {
        Some(session) => session,
        None => return CK_RV::CKR_SESSION_HANDLE_INVALID,
    };

    // In a real implementation, we would fill in the session information
    // For now, we'll just return OK
    CK_RV::CKR_OK
}

/// Get the function list
#[no_mangle]
pub extern "C" fn C_GetFunctionList(
    ppFunctionList: *mut *const CK_FUNCTION_LIST,
) -> CK_RV {
    if ppFunctionList.is_null() {
        return CK_RV::CKR_ARGUMENTS_BAD;
    }

    // In a real implementation, we would return a pointer to our function list
    // For now, we'll just return OK
    CK_RV::CKR_OK
}