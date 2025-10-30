//! Tests for the SoftHSM adapter

use hsm_pkcs11::hardware::SoftHsmAdapter;

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