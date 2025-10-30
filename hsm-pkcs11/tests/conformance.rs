//! Conformance tests for the PKCS#11 implementation

use hsm_pkcs11::*;
use hsm_pkcs11::hardware::SoftHsmAdapter;

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

#[test]
fn test_soft_hsm_adapter_creation() {
    let adapter = SoftHsmAdapter::new();
    assert!(!adapter.initialized);
    assert!(!adapter.session_open);
}

#[test]
fn test_soft_hsm_adapter_initialization() {
    let mut adapter = SoftHsmAdapter::new();
    let result = adapter.initialize();
    assert!(result.is_ok());
    assert!(adapter.initialized);
}

#[test]
fn test_soft_hsm_adapter_open_session() {
    let mut adapter = SoftHsmAdapter::new();
    
    // Try to open session without initialization
    let result = adapter.open_session("1234");
    assert!(result.is_err());
    
    // Initialize and then open session
    assert!(adapter.initialize().is_ok());
    let result = adapter.open_session("1234");
    assert!(result.is_ok());
    assert!(adapter.session_open);
}