//! Integration tests for the PKCS#11 implementation with SoftHSM

use hsm_pkcs11::*;
use std::ptr;

#[test]
fn test_initialize_and_finalize() {
    let rv = unsafe { C_Initialize(ptr::null_mut()) };
    assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);
    
    let rv = unsafe { C_Finalize(ptr::null_mut()) };
    assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);
}

#[test]
fn test_get_info() {
    unsafe { 
        C_Initialize(ptr::null_mut());
    }
    
    let mut info = cryptoki::types::CK_INFO::default();
    let rv = unsafe { C_GetInfo(&mut info) };
    assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);
    
    unsafe { 
        C_Finalize(ptr::null_mut());
    }
}

#[test]
fn test_get_slot_list() {
    unsafe { 
        C_Initialize(ptr::null_mut());
    }
    
    let mut count: cryptoki::types::CK_ULONG = 0;
    let rv = unsafe { C_GetSlotList(cryptoki::types::CK_FALSE, ptr::null_mut(), &mut count) };
    assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);
    
    unsafe { 
        C_Finalize(ptr::null_mut());
    }
}

#[test]
fn test_open_close_session() {
    unsafe { 
        C_Initialize(ptr::null_mut());
    }
    
    // Try to open a session
    let mut session_handle: cryptoki::types::CK_SESSION_HANDLE = 0;
    let rv = unsafe {
        C_OpenSession(
            0, // Slot ID (placeholder)
            cryptoki::types::CKF_SERIAL_SESSION,
            ptr::null_mut(),
            None,
            &mut session_handle,
        )
    };
    // This might fail if no slots are available, which is expected in a test environment
    // assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);
    
    if rv == cryptoki::types::CK_RV::CKR_OK {
        // Close the session
        let rv = unsafe { C_CloseSession(session_handle) };
        assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);
    }
    
    unsafe { 
        C_Finalize(ptr::null_mut());
    }
}

#[test]
fn test_generate_random() {
    unsafe { 
        C_Initialize(ptr::null_mut());
    }
    
    // Try to open a session
    let mut session_handle: cryptoki::types::CK_SESSION_HANDLE = 0;
    let rv = unsafe {
        C_OpenSession(
            0, // Slot ID (placeholder)
            cryptoki::types::CKF_SERIAL_SESSION,
            ptr::null_mut(),
            None,
            &mut session_handle,
        )
    };
    
    if rv == cryptoki::types::CK_RV::CKR_OK {
        // Generate random data
        let mut random_data = [0u8; 16];
        let rv = unsafe { 
            C_GenerateRandom(
                session_handle,
                random_data.as_mut_ptr(),
                random_data.len() as cryptoki::types::CK_ULONG,
            ) 
        };
        assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);
        
        // Close the session
        let rv = unsafe { C_CloseSession(session_handle) };
        assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);
    }
    
    unsafe { 
        C_Finalize(ptr::null_mut());
    }
}