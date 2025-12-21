//! PKCS#11 function implementations

use crate::session::SessionManager;
use crate::slot::SlotManager;
use crate::types::hsm_error_to_ckr;
use crate::object::ObjectManager;
use cryptoki::types::*;
use std::sync::Mutex;
use hsm_core::crypto::{CryptoEngine, CryptoOperation, KeyOperationResult};
use hsm_core::models::OperationContext;

use crate::hardware::SoftHsmAdapter;

// PKCS#11 Function List
lazy_static::lazy_static! {
    static ref FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
        version: CK_VERSION { major: 2, minor: 40 },
        C_Initialize: Some(C_Initialize),
        C_Finalize: Some(C_Finalize),
        C_GetInfo: Some(C_GetInfo),
        C_GetFunctionList: Some(C_GetFunctionList),
        C_GetSlotList: Some(C_GetSlotList),
        C_GetSlotInfo: Some(C_GetSlotInfo),
        C_GetTokenInfo: Some(C_GetTokenInfo),
        C_GetMechanismList: Some(C_GetMechanismList),
        C_GetMechanismInfo: Some(C_GetMechanismInfo),
        C_InitToken: Some(C_InitToken),
        C_InitPIN: Some(C_InitPIN),
        C_SetPIN: Some(C_SetPIN),
        C_OpenSession: Some(C_OpenSession),
        C_CloseSession: Some(C_CloseSession),
        C_CloseAllSessions: Some(C_CloseAllSessions),
        C_GetSessionInfo: Some(C_GetSessionInfo),
        C_GetOperationState: None,
        C_SetOperationState: None,
        C_Login: Some(C_Login),
        C_Logout: Some(C_Logout),
        C_CreateObject: None,
        C_CopyObject: None,
        C_DestroyObject: Some(C_DestroyObject),
        C_GetObjectSize: None,
        C_GetAttributeValue: Some(C_GetAttributeValue),
        C_SetAttributeValue: None,
        C_FindObjectsInit: Some(C_FindObjectsInit),
        C_FindObjects: Some(C_FindObjects),
        C_FindObjectsFinal: Some(C_FindObjectsFinal),
        C_EncryptInit: Some(C_EncryptInit),
        C_Encrypt: Some(C_Encrypt),
        C_EncryptUpdate: None,
        C_EncryptFinal: None,
        C_DecryptInit: Some(C_DecryptInit),
        C_Decrypt: Some(C_Decrypt),
        C_DecryptUpdate: None,
        C_DecryptFinal: None,
        C_DigestInit: None,
        C_Digest: None,
        C_DigestUpdate: None,
        C_DigestKey: None,
        C_DigestFinal: None,
        C_SignInit: Some(C_SignInit),
        C_Sign: Some(C_Sign),
        C_SignUpdate: None,
        C_SignFinal: None,
        C_SignRecoverInit: None,
        C_SignRecover: None,
        C_VerifyInit: Some(C_VerifyInit),
        C_Verify: Some(C_Verify),
        C_VerifyUpdate: None,
        C_VerifyFinal: None,
        C_VerifyRecoverInit: None,
        C_VerifyRecover: None,
        C_DigestEncryptUpdate: None,
        C_DecryptDigestUpdate: None,
        C_SignEncryptUpdate: None,
        C_DecryptVerifyUpdate: None,
        C_GenerateKey: Some(C_GenerateKey),
        C_GenerateKeyPair: None,
        C_WrapKey: None,
        C_UnwrapKey: None,
        C_DeriveKey: None,
        C_SeedRandom: None,
        C_GenerateRandom: Some(C_GenerateRandom),
        C_GetFunctionStatus: None,
        C_CancelFunction: None,
        C_WaitForSlotEvent: None,
    };
}

// Supported mechanisms
lazy_static::lazy_static! {
    static ref SUPPORTED_MECHANISMS: Vec<CK_MECHANISM_TYPE> = vec![
        CK_MECHANISM_TYPE::CKM_AES_KEY_GEN,
        CK_MECHANISM_TYPE::CKM_AES_GCM,
        CK_MECHANISM_TYPE::CKM_RSA_PKCS_KEY_PAIR_GEN,
        CK_MECHANISM_TYPE::CKM_RSA_PKCS,
        CK_MECHANISM_TYPE::CKM_EC_KEY_PAIR_GEN,
        CK_MECHANISM_TYPE::CKM_ECDSA,
    ];
}

// Global state managers
lazy_static::lazy_static! {
    static ref SLOT_MANAGER: Mutex<SlotManager> = {
        let mut manager = SlotManager::new();
        // Add a default slot
        manager.add_slot(crate::slot::Slot {
            id: 1,
            token: Some(crate::slot::Token {
                label: "FerroHSM Token".to_string(),
                serial_number: "00000001".to_string(),
                model: "HSM".to_string(),
                manufacturer: "FerroHSM".to_string(),
                flags: 0,
            }),
        });
        Mutex::new(manager)
    };
    static ref SESSION_MANAGER: Mutex<SessionManager> = {
        let slot_manager = SLOT_MANAGER.lock().unwrap().clone();
        Mutex::new(SessionManager::new(slot_manager))
    };
    static ref SOFT_HSM_ADAPTER: Mutex<Option<SoftHsmAdapter>> = Mutex::new(None);
    static ref OBJECT_MANAGER: Mutex<ObjectManager> = Mutex::new(ObjectManager::new());
    static ref CRYPTO_ENGINE: CryptoEngine = CryptoEngine::new([0u8; 32], [0u8; 32]);
}

/// Initialize the PKCS#11 library
#[no_mangle]
pub extern "C" fn C_Initialize(pInitArgs: CK_VOID_PTR) -> CK_RV {
    // Initialize the SoftHSM adapter
    let mut adapter = SoftHsmAdapter::new();
    match adapter.initialize() {
        Ok(()) => {
            // Store the initialized adapter
            let mut soft_hsm = SOFT_HSM_ADAPTER.lock().unwrap();
            *soft_hsm = Some(adapter);
    CK_RV::CKR_OK
}

/// Initialize a verification operation
#[no_mangle]
pub extern "C" fn C_VerifyInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    if pMechanism.is_null() {
        return CK_RV::CKR_ARGUMENTS_BAD;
    }

    let mut session_manager = SESSION_MANAGER.lock().unwrap();
    let session = match session_manager.get_mut_session(hSession) {
        Some(session) => session,
        None => return CK_RV::CKR_SESSION_HANDLE_INVALID,
    };

    let mechanism = unsafe { *pMechanism };
    session.active_mechanism = Some(mechanism.mechanism);
    session.active_key = Some(hKey);

    CK_RV::CKR_OK
}

/// Verify signature
#[no_mangle]
pub extern "C" fn C_Verify(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG,
) -> CK_RV {
    if pData.is_null() || pSignature.is_null() {
        return CK_RV::CKR_ARGUMENTS_BAD;
    }

    let session_manager = SESSION_MANAGER.lock().unwrap();
    let session = match session_manager.get_session(hSession) {
        Some(session) => session,
        None => return CK_RV::CKR_SESSION_HANDLE_INVALID,
    };

    let key_handle = match session.active_key {
        Some(handle) => handle,
        None => return CK_RV::CKR_OPERATION_NOT_INITIALIZED,
    };

    let object_manager = OBJECT_MANAGER.lock().unwrap();
    let object = match object_manager.get_object(key_handle) {
        Some(object) => object,
        None => return CK_RV::CKR_KEY_HANDLE_INVALID,
    };

    let key_material = match CRYPTO_ENGINE.open_key(&object.record) {
        Ok(material) => material,
        Err(e) => return hsm_error_to_ckr(e),
    };

    let data = unsafe { std::slice::from_raw_parts(pData, ulDataLen as usize) };
    let signature = unsafe { std::slice::from_raw_parts(pSignature, ulSignatureLen as usize) };

    let operation = CryptoOperation::Verify {
        message: data.to_vec(),
        signature: signature.to_vec(),
    };
    let op_ctx = OperationContext::new();

    match CRYPTO_ENGINE.perform(operation, &key_material, &op_ctx) {
        Ok(KeyOperationResult::Verified { valid }) => {
            if valid {
                CK_RV::CKR_OK
            } else {
                CK_RV::CKR_SIGNATURE_INVALID
            }
        }
        Ok(_) => CK_RV::CKR_GENERAL_ERROR,
        Err(e) => hsm_error_to_ckr(e),
    }
}

/// Destroy an object
#[no_mangle]
pub extern "C" fn C_DestroyObject(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
) -> CK_RV {
    // Get the session
    let session_manager = SESSION_MANAGER.lock().unwrap();
    let session = match session_manager.get_session(hSession) {
        Some(session) => session,
        None => return CK_RV::CKR_SESSION_HANDLE_INVALID,
    };
    
    // Try to use SoftHSM adapter
    let soft_hsm = SOFT_HSM_ADAPTER.lock().unwrap();
    if let Some(adapter) = soft_hsm.as_ref() {
        // For now, we'll just return OK
        // In a full implementation, we would use the SoftHSM adapter to destroy the object
        CK_RV::CKR_OK
    } else {
        // Fallback implementation - remove from object manager
        let mut object_manager = OBJECT_MANAGER.lock().unwrap();
        if object_manager.remove_object(hObject).is_some() {
            CK_RV::CKR_OK
        } else {
            CK_RV::CKR_OBJECT_HANDLE_INVALID
        }
    }
}

/// Get attribute values of an object
#[no_mangle]
pub extern "C" fn C_GetAttributeValue(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV {
    if pTemplate.is_null() || ulCount == 0 {
        return CK_RV::CKR_ARGUMENTS_BAD;
    }
    
    // Get the session
    let session_manager = SESSION_MANAGER.lock().unwrap();
    let session = match session_manager.get_session(hSession) {
        Some(session) => session,
        None => return CK_RV::CKR_SESSION_HANDLE_INVALID,
    };
    
    // Get the template
    let template = unsafe { std::slice::from_raw_parts_mut(pTemplate, ulCount as usize) };
    
    // Get the object
    let object_manager = OBJECT_MANAGER.lock().unwrap();
    let object = match object_manager.get_object(hObject) {
        Some(object) => object,
        None => return CK_RV::CKR_OBJECT_HANDLE_INVALID,
    };
    
    // Fill in the attribute values
    for attr in template {
        if let Some(value) = object.get_attribute_value(attr.type_) {
            if attr.pValue.is_null() {
                // Just return the required buffer size
                attr.ulValueLen = value.len() as CK_ULONG;
            } else {
                // Copy the attribute value to the output buffer
                if attr.ulValueLen < value.len() as CK_ULONG {
                    return CK_RV::CKR_BUFFER_TOO_SMALL;
                }
                
                unsafe {
                    std::ptr::copy_nonoverlapping(value.as_ptr(), attr.pValue as *mut u8, value.len());
                    attr.ulValueLen = value.len() as CK_ULONG;
                }
            }
        } else {
            // Attribute not found
            attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
        }
    }

    CK_RV::CKR_OK
}

/// Get the list of supported mechanisms
#[no_mangle]
pub extern "C" fn C_GetMechanismList(
    slotID: CK_SLOT_ID,
    pMechanismList: CK_MECHANISM_TYPE_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    if pulCount.is_null() {
        return CK_RV::CKR_ARGUMENTS_BAD;
    }

    let slot_manager = SLOT_MANAGER.lock().unwrap();
    let slots = slot_manager.get_slots();
    if !slots.iter().any(|s| s.id == slotID) {
        return CK_RV::CKR_SLOT_ID_INVALID;
    }

    let count = SUPPORTED_MECHANISMS.len() as CK_ULONG;

    unsafe {
        if pMechanismList.is_null() {
            *pulCount = count;
            return CK_RV::CKR_OK;
        }

        if *pulCount < count {
            *pulCount = count;
            return CK_RV::CKR_BUFFER_TOO_SMALL;
        }

        *pulCount = count;
        for (i, &mech) in SUPPORTED_MECHANISMS.iter().enumerate() {
            *pMechanismList.add(i) = mech;
        }
    }

    CK_RV::CKR_OK
}

/// Get information about a mechanism
#[no_mangle]
pub extern "C" fn C_GetMechanismInfo(
    slotID: CK_SLOT_ID,
    mechanism: CK_MECHANISM_TYPE,
    pInfo: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    if pInfo.is_null() {
        return CK_RV::CKR_ARGUMENTS_BAD;
    }

    let slot_manager = SLOT_MANAGER.lock().unwrap();
    if slot_manager.get_slot(slotID).is_none() {
        return CK_RV::CKR_SLOT_ID_INVALID;
    }

    if !SUPPORTED_MECHANISMS.contains(&mechanism) {
        return CK_RV::CKR_MECHANISM_INVALID;
    }

    unsafe {
        match mechanism {
            CK_MECHANISM_TYPE::CKM_AES_KEY_GEN => {
                (*pInfo).ulMinKeySize = 16;
                (*pInfo).ulMaxKeySize = 32;
                (*pInfo).flags = CKF_GENERATE;
            }
            CK_MECHANISM_TYPE::CKM_AES_GCM => {
                (*pInfo).ulMinKeySize = 16;
                (*pInfo).ulMaxKeySize = 32;
                (*pInfo).flags = CKF_ENCRYPT | CKF_DECRYPT;
            }
            CK_MECHANISM_TYPE::CKM_RSA_PKCS_KEY_PAIR_GEN => {
                (*pInfo).ulMinKeySize = 1024;
                (*pInfo).ulMaxKeySize = 4096;
                (*pInfo).flags = CKF_GENERATE_KEY_PAIR;
            }
            CK_MECHANISM_TYPE::CKM_RSA_PKCS => {
                (*pInfo).ulMinKeySize = 1024;
                (*pInfo).ulMaxKeySize = 4096;
                (*pInfo).flags = CKF_SIGN | CKF_VERIFY | CKF_ENCRYPT | CKF_DECRYPT;
            }
            CK_MECHANISM_TYPE::CKM_EC_KEY_PAIR_GEN => {
                (*pInfo).ulMinKeySize = 256;
                (*pInfo).ulMaxKeySize = 384;
                (*pInfo).flags = CKF_GENERATE_KEY_PAIR;
            }
            CK_MECHANISM_TYPE::CKM_ECDSA => {
                (*pInfo).ulMinKeySize = 256;
                (*pInfo).ulMaxKeySize = 384;
                (*pInfo).flags = CKF_SIGN | CKF_VERIFY;
            }
            _ => return CK_RV::CKR_MECHANISM_INVALID,
        }
    }

    CK_RV::CKR_OK
}

/// Login to a token
#[no_mangle]
pub extern "C" fn C_Login(
    hSession: CK_SESSION_HANDLE,
    userType: CK_USER_TYPE,
    pPin: CK_UTF8CHAR_PTR,
    ulPinLen: CK_ULONG,
) -> CK_RV {
    if pPin.is_null() {
        return CK_RV::CKR_ARGUMENTS_BAD;
    }
    
    // Get the PIN
    let pin = unsafe { std::slice::from_raw_parts(pPin, ulPinLen as usize) };
    
    // Login to the session
    let mut session_manager = SESSION_MANAGER.lock().unwrap();
    match session_manager.login(hSession, userType, pin) {
        Ok(()) => CK_RV::CKR_OK,
        Err(rv) => rv,
    }
}

/// Logout from a token
#[no_mangle]
pub extern "C" fn C_Logout(hSession: CK_SESSION_HANDLE) -> CK_RV {
    // Logout from the session
    let mut session_manager = SESSION_MANAGER.lock().unwrap();
    match session_manager.logout(hSession) {
        Ok(()) => CK_RV::CKR_OK,
        Err(rv) => rv,
    }
}

/// Initialize an encryption operation
#[no_mangle]
pub extern "C" fn C_EncryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    if pMechanism.is_null() {
        return CK_RV::CKR_ARGUMENTS_BAD;
    }

    let mut session_manager = SESSION_MANAGER.lock().unwrap();
    let session = match session_manager.get_mut_session(hSession) {
        Some(session) => session,
        None => return CK_RV::CKR_SESSION_HANDLE_INVALID,
    };

    let mechanism = unsafe { *pMechanism };
    session.active_mechanism = Some(mechanism.mechanism);
    session.active_key = Some(hKey);

    CK_RV::CKR_OK
}

/// Initialize a decryption operation
#[no_mangle]
pub extern "C" fn C_DecryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    if pMechanism.is_null() {
        return CK_RV::CKR_ARGUMENTS_BAD;
    }

    let mut session_manager = SESSION_MANAGER.lock().unwrap();
    let session = match session_manager.get_mut_session(hSession) {
        Some(session) => session,
        None => return CK_RV::CKR_SESSION_HANDLE_INVALID,
    };

    let mechanism = unsafe { *pMechanism };
    session.active_mechanism = Some(mechanism.mechanism);
    session.active_key = Some(hKey);

    CK_RV::CKR_OK
}

/// Encrypt data
#[no_mangle]
pub extern "C" fn C_Encrypt(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pEncryptedData: CK_BYTE_PTR,
    pulEncryptedDataLen: CK_ULONG_PTR,
) -> CK_RV {
    if pData.is_null() || pulEncryptedDataLen.is_null() {
        return CK_RV::CKR_ARGUMENTS_BAD;
    }

    let session_manager = SESSION_MANAGER.lock().unwrap();
    let session = match session_manager.get_session(hSession) {
        Some(session) => session,
        None => return CK_RV::CKR_SESSION_HANDLE_INVALID,
    };

    let key_handle = match session.active_key {
        Some(handle) => handle,
        None => return CK_RV::CKR_OPERATION_NOT_INITIALIZED,
    };

    let object_manager = OBJECT_MANAGER.lock().unwrap();
    let object = match object_manager.get_object(key_handle) {
        Some(object) => object,
        None => return CK_RV::CKR_KEY_HANDLE_INVALID,
    };

    let key_material = match CRYPTO_ENGINE.open_key(&object.record) {
        Ok(material) => material,
        Err(e) => return hsm_error_to_ckr(e),
    };

    let plaintext = unsafe { std::slice::from_raw_parts(pData, ulDataLen as usize) };

    let operation = CryptoOperation::Encrypt {
        plaintext: plaintext.to_vec(),
    };
    let op_ctx = OperationContext::new();

    match CRYPTO_ENGINE.perform(operation, &key_material, &op_ctx) {
        Ok(KeyOperationResult::Encrypted { ciphertext, .. }) => {
            unsafe {
                if pEncryptedData.is_null() {
                    *pulEncryptedDataLen = ciphertext.len() as CK_ULONG;
                    return CK_RV::CKR_OK;
                }
                if *pulEncryptedDataLen < ciphertext.len() as CK_ULONG {
                    *pulEncryptedDataLen = ciphertext.len() as CK_ULONG;
                    return CK_RV::CKR_BUFFER_TOO_SMALL;
                }
                std::ptr::copy_nonoverlapping(
                    ciphertext.as_ptr(),
                    pEncryptedData,
                    ciphertext.len(),
                );
                *pulEncryptedDataLen = ciphertext.len() as CK_ULONG;
            }
            CK_RV::CKR_OK
        }
        Ok(_) => CK_RV::CKR_GENERAL_ERROR,
        Err(e) => hsm_error_to_ckr(e),
    }
}

/// Decrypt data
#[no_mangle]
pub extern "C" fn C_Decrypt(
    hSession: CK_SESSION_HANDLE,
    pEncryptedData: CK_BYTE_PTR,
    ulEncryptedDataLen: CK_ULONG,
    pData: CK_BYTE_PTR,
    pulDataLen: CK_ULONG_PTR,
) -> CK_RV {
    if pEncryptedData.is_null() || pulDataLen.is_null() {
        return CK_RV::CKR_ARGUMENTS_BAD;
    }

    let session_manager = SESSION_MANAGER.lock().unwrap();
    let session = match session_manager.get_session(hSession) {
        Some(session) => session,
        None => return CK_RV::CKR_SESSION_HANDLE_INVALID,
    };

    let key_handle = match session.active_key {
        Some(handle) => handle,
        None => return CK_RV::CKR_OPERATION_NOT_INITIALIZED,
    };

    let object_manager = OBJECT_MANAGER.lock().unwrap();
    let object = match object_manager.get_object(key_handle) {
        Some(object) => object,
        None => return CK_RV::CKR_KEY_HANDLE_INVALID,
    };

    let key_material = match CRYPTO_ENGINE.open_key(&object.record) {
        Ok(material) => material,
        Err(e) => return hsm_error_to_ckr(e),
    };

    let ciphertext = unsafe { std::slice::from_raw_parts(pEncryptedData, ulEncryptedDataLen as usize) };

    // The nonce should be part of the mechanism parameters, but for now we'll assume it's prepended to the ciphertext
    if ciphertext.len() < 12 {
        return CK_RV::CKR_ENCRYPTED_DATA_INVALID;
    }
    let (nonce, ciphertext) = ciphertext.split_at(12);

    let operation = CryptoOperation::Decrypt {
        ciphertext: ciphertext.to_vec(),
        nonce: nonce.to_vec(),
        associated_data: None,
    };
    let op_ctx = OperationContext::new();

    match CRYPTO_ENGINE.perform(operation, &key_material, &op_ctx) {
        Ok(KeyOperationResult::Decrypted { plaintext }) => {
            unsafe {
                if pData.is_null() {
                    *pulDataLen = plaintext.len() as CK_ULONG;
                    return CK_RV::CKR_OK;
                }
                if *pulDataLen < plaintext.len() as CK_ULONG {
                    *pulDataLen = plaintext.len() as CK_ULONG;
                    return CK_RV::CKR_BUFFER_TOO_SMALL;
                }
                std::ptr::copy_nonoverlapping(
                    plaintext.as_ptr(),
                    pData,
                    plaintext.len(),
                );
                *pulDataLen = plaintext.len() as CK_ULONG;
            }
            CK_RV::CKR_OK
        }
        Ok(_) => CK_RV::CKR_GENERAL_ERROR,
        Err(e) => hsm_error_to_ckr(e),
    }
}

/// Generate random data
#[no_mangle]
pub extern "C" fn C_GenerateRandom(
    hSession: CK_SESSION_HANDLE,
    pRandomData: CK_BYTE_PTR,
    ulRandomLen: CK_ULONG,
) -> CK_RV {
    if pRandomData.is_null() {
        return CK_RV::CKR_ARGUMENTS_BAD;
    }
    
    // Get the session
    let session_manager = SESSION_MANAGER.lock().unwrap();
    let session = match session_manager.get_session(hSession) {
        Some(session) => session,
        None => return CK_RV::CKR_SESSION_HANDLE_INVALID,
    };
    
    // Try to use SoftHSM adapter
    let soft_hsm = SOFT_HSM_ADAPTER.lock().unwrap();
    if let Some(adapter) = soft_hsm.as_ref() {
        // For now, we'll just fill the buffer with placeholder random data
        // In a full implementation, we would use the SoftHSM adapter to generate random data
        unsafe {
            // Fill the buffer with placeholder random data
            for i in 0..ulRandomLen {
                *pRandomData.add(i as usize) = (i % 256) as u8;
            }
        }
        CK_RV::CKR_OK
    } else {
        // Fallback implementation
        unsafe {
            // Fill the buffer with placeholder random data
            for i in 0..ulRandomLen {
                *pRandomData.add(i as usize) = (i % 256) as u8;
            }
        }
        CK_RV::CKR_OK
    }
}