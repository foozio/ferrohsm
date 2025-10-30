//! PKCS#11 object handling

use crate::types::hsm_error_to_ckr;
use cryptoki::types::*;
use hsm_core::models::{KeyMetadata, KeyPurpose};
use std::collections::HashMap;

/// Represents a PKCS#11 object
#[derive(Debug, Clone)]
pub struct Object {
    pub handle: CK_OBJECT_HANDLE,
    pub attributes: HashMap<CK_ATTRIBUTE_TYPE, Vec<u8>>,
}

impl Object {
    /// Create a new object from key metadata
    pub fn from_key_metadata(metadata: &KeyMetadata, handle: CK_OBJECT_HANDLE) -> Self {
        let mut attributes = HashMap::new();
        
        // Map key metadata to PKCS#11 attributes
        attributes.insert(
            CK_ATTRIBUTE_TYPE::CKA_CLASS,
            Self::serialize_ck_ulong(Self::get_object_class(metadata)),
        );
        
        attributes.insert(
            CK_ATTRIBUTE_TYPE::CKA_KEY_TYPE,
            Self::serialize_ck_ulong(Self::get_key_type(metadata)),
        );
        
        attributes.insert(
            CK_ATTRIBUTE_TYPE::CKA_LABEL,
            metadata.id.as_bytes().to_vec(),
        );
        
        attributes.insert(
            CK_ATTRIBUTE_TYPE::CKA_ID,
            metadata.id.as_bytes().to_vec(),
        );
        
        // Add key usage attributes
        let allowed_mechanisms = Self::get_allowed_mechanisms(metadata);
        attributes.insert(
            CK_ATTRIBUTE_TYPE::CKA_ALLOWED_MECHANISMS,
            Self::serialize_mechanism_list(&allowed_mechanisms),
        );
        
        Self { handle, attributes }
    }
    
    /// Get the PKCS#11 object class for a key
    fn get_object_class(metadata: &KeyMetadata) -> CK_ULONG {
        // For now, we'll assume all keys are private keys
        // In a full implementation, we'd distinguish between public/private/secret keys
        CK_OBJECT_CLASS::CKO_PRIVATE_KEY as CK_ULONG
    }
    
    /// Get the PKCS#11 key type for a key
    fn get_key_type(metadata: &KeyMetadata) -> CK_ULONG {
        use hsm_core::models::KeyAlgorithm::*;
        
        match metadata.algorithm {
            Aes256Gcm => CK_KEY_TYPE::CKK_AES as CK_ULONG,
            Rsa2048 | Rsa4096 => CK_KEY_TYPE::CKK_RSA as CK_ULONG,
            P256 | P384 => CK_KEY_TYPE::CKK_EC as CK_ULONG,
            // Post-quantum and hybrid types would need custom mappings
            _ => CK_KEY_TYPE::CKK_VENDOR_DEFINED as CK_ULONG,
        }
    }
    
    /// Get the allowed mechanisms for a key based on its usage
    fn get_allowed_mechanisms(metadata: &KeyMetadata) -> Vec<CK_MECHANISM_TYPE> {
        let mut mechanisms = Vec::new();
        
        for purpose in &metadata.usage {
            match purpose {
                KeyPurpose::Encrypt => {
                    mechanisms.push(CK_MECHANISM_TYPE::CKM_AES_GCM);
                }
                KeyPurpose::Decrypt => {
                    mechanisms.push(CK_MECHANISM_TYPE::CKM_AES_GCM);
                }
                KeyPurpose::Sign => {
                    match metadata.algorithm {
                        P256 => mechanisms.push(CK_MECHANISM_TYPE::CKM_ECDSA),
                        P384 => mechanisms.push(CK_MECHANISM_TYPE::CKM_ECDSA),
                        Rsa2048 | Rsa4096 => mechanisms.push(CK_MECHANISM_TYPE::CKM_RSA_PKCS),
                        _ => {}
                    }
                }
                KeyPurpose::Verify => {
                    match metadata.algorithm {
                        P256 => mechanisms.push(CK_MECHANISM_TYPE::CKM_ECDSA),
                        P384 => mechanisms.push(CK_MECHANISM_TYPE::CKM_ECDSA),
                        Rsa2048 | Rsa4096 => mechanisms.push(CK_MECHANISM_TYPE::CKM_RSA_PKCS),
                        _ => {}
                    }
                }
                KeyPurpose::Wrap => {
                    mechanisms.push(CK_MECHANISM_TYPE::CKM_RSA_PKCS);
                }
                KeyPurpose::Unwrap => {
                    mechanisms.push(CK_MECHANISM_TYPE::CKM_RSA_PKCS);
                }
            }
        }
        
        mechanisms
    }
    
    /// Serialize a CK_ULONG value
    fn serialize_ck_ulong(value: CK_ULONG) -> Vec<u8> {
        value.to_le_bytes().to_vec()
    }
    
    /// Serialize a mechanism list
    fn serialize_mechanism_list(mechanisms: &[CK_MECHANISM_TYPE]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for mechanism in mechanisms {
            bytes.extend_from_slice(&mechanism.to_le_bytes());
        }
        bytes
    }
    
    /// Get attribute value
    pub fn get_attribute_value(&self, attr_type: CK_ATTRIBUTE_TYPE) -> Option<&Vec<u8>> {
        self.attributes.get(&attr_type)
    }
}

/// Manages PKCS#11 objects
pub struct ObjectManager {
    objects: HashMap<CK_OBJECT_HANDLE, Object>,
    next_handle: CK_OBJECT_HANDLE,
}

impl ObjectManager {
    pub fn new() -> Self {
        Self {
            objects: HashMap::new(),
            next_handle: 1,
        }
    }
    
    /// Add an object to the manager
    pub fn add_object(&mut self, object: Object) -> CK_OBJECT_HANDLE {
        let handle = object.handle;
        self.objects.insert(handle, object);
        handle
    }
    
    /// Create and add an object from key metadata
    pub fn add_key_object(&mut self, metadata: &KeyMetadata) -> CK_OBJECT_HANDLE {
        let handle = self.next_handle;
        self.next_handle += 1;
        
        let object = Object::from_key_metadata(metadata, handle);
        self.add_object(object)
    }
    
    /// Get an object by handle
    pub fn get_object(&self, handle: CK_OBJECT_HANDLE) -> Option<&Object> {
        self.objects.get(&handle)
    }
    
    /// Find objects matching a template
    pub fn find_objects(&self, template: &[CK_ATTRIBUTE]) -> Vec<CK_OBJECT_HANDLE> {
        let mut matches = Vec::new();
        
        for (handle, object) in &self.objects {
            if self.object_matches_template(object, template) {
                matches.push(*handle);
            }
        }
        
        matches
    }
    
    /// Check if an object matches a template
    fn object_matches_template(&self, object: &Object, template: &[CK_ATTRIBUTE]) -> bool {
        for attr in template {
            if let Some(value) = object.get_attribute_value(attr.type_) {
                // Compare the attribute value
                if value != unsafe { std::slice::from_raw_parts(attr.pValue as *const u8, attr.ulValueLen as usize) } {
                    return false;
                }
            } else {
                // Attribute not found
                return false;
            }
        }
        
        true
    }
}