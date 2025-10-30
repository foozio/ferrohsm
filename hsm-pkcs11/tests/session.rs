//! Session management tests

use hsm_pkcs11::*;
use std::ptr;

#[test]
fn test_open_close_session() {
    // Initialize the library
    let rv = unsafe { C_Initialize(ptr::null_mut()) };
    assert_eq!(rv, CK_RV::CKR_OK);
    
    // Try to open a session with an invalid slot ID
    let mut session_handle: CK_SESSION_HANDLE = 0;
    let rv = unsafe {
        C_OpenSession(
            0, // Invalid slot ID
            CKF_SERIAL_SESSION,
            ptr::null_mut(),
            None,
            &mut session_handle,
        )
    };
    assert_eq!(rv, CK_RV::CKR_SLOT_ID_INVALID);
    
    // Finalize the library
    let rv = unsafe { C_Finalize(ptr::null_mut()) };
    assert_eq!(rv, CK_RV::CKR_OK);
}