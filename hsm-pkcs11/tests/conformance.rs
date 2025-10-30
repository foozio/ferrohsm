//! Conformance tests for the PKCS#11 implementation

use hsm_pkcs11::*;

#[test]
fn test_initialize() {
    let rv = unsafe { C_Initialize(std::ptr::null_mut()) };
    assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);
}

#[test]
fn test_finalize() {
    let rv = unsafe { C_Finalize(std::ptr::null_mut()) };
    assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);
}

#[test]
fn test_get_info() {
    let mut info = cryptoki::types::CK_INFO::default();
    let rv = unsafe { C_GetInfo(&mut info) };
    assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);
}

#[test]
fn test_get_function_list() {
    let mut function_list_ptr: *const cryptoki::types::function::CK_FUNCTION_LIST = std::ptr::null();
    let rv = unsafe { C_GetFunctionList(&mut function_list_ptr as *mut _) };
    assert_eq!(rv, cryptoki::types::CK_RV::CKR_OK);
    assert!(!function_list_ptr.is_null());
}