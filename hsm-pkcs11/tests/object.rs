//! Object handling tests

use hsm_pkcs11::object::*;

#[test]
fn test_object_creation() {
    let mut object_manager = ObjectManager::new();
    assert_eq!(object_manager.objects.len(), 0);
}

#[test]
fn test_add_object() {
    let mut object_manager = ObjectManager::new();
    let object = Object {
        handle: 1,
        attributes: std::collections::HashMap::new(),
    };
    
    let handle = object_manager.add_object(object);
    assert_eq!(handle, 1);
    assert_eq!(object_manager.objects.len(), 1);
}