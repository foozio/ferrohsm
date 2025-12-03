//! Integration tests for the PKCS#11 implementation with SoftHSM

use hsm_pkcs11::{*, hardware::SoftHsmAdapter};
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
    let mut adapter = SoftHsmAdapter::new();
    adapter.initialize().unwrap();

    unsafe {
        C_Initialize(ptr::null_mut());
    }

    let mut count: cryptoki::types::CK_ULONG = 0;
    let rv = unsafe { C_GetSlotList(cryptoki::types::CK_TRUE, ptr::null_mut(), &mut count) };
    assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);
    assert!(count > 0);

    let mut slots = vec![0; count as usize];
    let rv = unsafe { C_GetSlotList(cryptoki::types::CK_TRUE, slots.as_mut_ptr(), &mut count) };
    assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);

    // Try to open a session
    let mut session_handle: cryptoki::types::CK_SESSION_HANDLE = 0;
    let rv = unsafe {
        C_OpenSession(
            slots[0],
            cryptoki::types::CKF_SERIAL_SESSION,
            ptr::null_mut(),
            None,
            &mut session_handle,
        )
    };
    assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);
    
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
fn test_encrypt_decrypt() {
    let mut adapter = SoftHsmAdapter::new();
    adapter.initialize().unwrap();

    unsafe {
        C_Initialize(ptr::null_mut());
    }

    let mut count: cryptoki::types::CK_ULONG = 0;
    let rv = unsafe { C_GetSlotList(cryptoki::types::CK_TRUE, ptr::null_mut(), &mut count) };
    assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);
    assert!(count > 0);

    let mut slots = vec![0; count as usize];
    let rv = unsafe { C_GetSlotList(cryptoki::types::CK_TRUE, slots.as_mut_ptr(), &mut count) };
    assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);

    let mut session_handle: cryptoki::types::CK_SESSION_HANDLE = 0;
    let rv = unsafe {
        C_OpenSession(
            slots[0],
            cryptoki::types::CKF_SERIAL_SESSION,
            ptr::null_mut(),
            None,
            &mut session_handle,
        )
    };
    assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);

    let mut key_handle: CK_OBJECT_HANDLE = 0;
    let mut mechanism = CK_MECHANISM {
        mechanism: CK_MECHANISM_TYPE::CKM_AES_KEY_GEN,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };
    let template: Vec<CK_ATTRIBUTE> = Vec::new();
    let rv = unsafe {
        C_GenerateKey(
            session_handle,
            &mut mechanism,
            template.as_ptr(),
            template.len() as CK_ULONG,
            &mut key_handle,
        )
    };
    assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);

    let plaintext = b"some data to encrypt";
    let mut encrypted_data_len: CK_ULONG = 0;

    let rv = unsafe {
        C_EncryptInit(
            session_handle,
            &mut mechanism,
            key_handle,
        )
    };
    assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);

    let rv = unsafe {
        C_Encrypt(
            session_handle,
            plaintext.as_ptr(),
            plaintext.len() as CK_ULONG,
            ptr::null_mut(),
            &mut encrypted_data_len,
        )
    };
    assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);

    let mut encrypted_data = vec![0u8; encrypted_data_len as usize];
    let rv = unsafe {
        C_Encrypt(
            session_handle,
            plaintext.as_ptr(),
            plaintext.len() as CK_ULONG,
            encrypted_data.as_mut_ptr(),
            &mut encrypted_data_len,
        )
    };
    assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);

    let mut decrypted_data_len: CK_ULONG = 0;
    let rv = unsafe {
        C_DecryptInit(
            session_handle,
            &mut mechanism,
            key_handle,
        )
    };
    assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);

    let rv = unsafe {
        C_Decrypt(
            session_handle,
            encrypted_data.as_ptr(),
            encrypted_data.len() as CK_ULONG,
            ptr::null_mut(),
            &mut decrypted_data_len,
        )
    };
    assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);

    let mut decrypted_data = vec![0u8; decrypted_data_len as usize];
    let rv = unsafe {
        C_Decrypt(
            session_handle,
            encrypted_data.as_ptr(),
            encrypted_data.len() as CK_ULONG,
            decrypted_data.as_mut_ptr(),
            &mut decrypted_data_len,
        )
    };
    assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);

    assert_eq!(plaintext, &decrypted_data[..]);

    let rv = unsafe { C_CloseSession(session_handle) };
    assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);
    
    unsafe { 
        C_Finalize(ptr::null_mut());
    }
}

#[test]
fn test_generate_random() {
    let mut adapter = SoftHsmAdapter::new();
    adapter.initialize().unwrap();

    unsafe {
        C_Initialize(ptr::null_mut());
    }

    let mut count: cryptoki::types::CK_ULONG = 0;
    let rv = unsafe { C_GetSlotList(cryptoki::types::CK_TRUE, ptr::null_mut(), &mut count) };
    assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);
    assert!(count > 0);

    let mut slots = vec![0; count as usize];
    let rv = unsafe { C_GetSlotList(cryptoki::types::CK_TRUE, slots.as_mut_ptr(), &mut count) };
    assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);

    // Try to open a session
    let mut session_handle: cryptoki::types::CK_SESSION_HANDLE = 0;
    let rv = unsafe {
        C_OpenSession(
            slots[0],
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