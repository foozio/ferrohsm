//! PKCS#11 attribute handling for FerroHSM.
//!
//! This module defines the attribute handling for the PKCS#11 interface,
//! including mappings between PKCS#11 attributes and FerroHSM's internal
//! key metadata and material types.

use cryptoki_sys::{
    CK_ATTRIBUTE_TYPE, CK_OBJECT_CLASS, CK_ULONG, CKA_CLASS, CKA_DECRYPT, CKA_DERIVE, CKA_ENCRYPT,
    CKA_EXTRACTABLE, CKA_ID, CKA_KEY_TYPE, CKA_MODIFIABLE, CKA_PRIVATE, CKA_SENSITIVE, CKA_SIGN,
    CKA_TOKEN, CKA_UNWRAP, CKA_VALUE_LEN, CKA_VERIFY, CKA_WRAP, CKK_AES, CKK_EC, CKK_RSA,
    CKO_PRIVATE_KEY, CKO_SECRET_KEY,
};
use hsm_core::models::{KeyAlgorithm, KeyMaterial, KeyMaterialType, KeyMetadata, KeyPurpose};

#[cfg(feature = "pqc")]
use hsm_core::pqc::{MlDsaSecurityLevel, MlKemSecurityLevel, SlhDsaSecurityLevel};

use std::collections::HashMap;

// Define custom key types for post-quantum algorithms
// Note: These values are in the vendor-defined range (0x80000000 - 0xFFFFFFFF)
// as specified in the PKCS#11 standard

/// ML-KEM (Kyber) key type
pub const CKK_ML_KEM: CK_ULONG = 0x80000001;

/// ML-DSA (Dilithium) key type
pub const CKK_ML_DSA: CK_ULONG = 0x80000002;

/// SLH-DSA (SPHINCS+) key type
pub const CKK_SLH_DSA: CK_ULONG = 0x80000003;

/// Hybrid ECDH+ML-KEM key type
pub const CKK_HYBRID_ECDH_ML_KEM: CK_ULONG = 0x80000004;

/// Hybrid ECDSA+ML-DSA key type
pub const CKK_HYBRID_ECDSA_ML_DSA: CK_ULONG = 0x80000005;

// Define custom attributes for post-quantum algorithms
// Note: These values are in the vendor-defined range (0x80000000 - 0xFFFFFFFF)

/// ML-KEM security level attribute
pub const CKA_ML_KEM_SECURITY_LEVEL: CK_ATTRIBUTE_TYPE = 0x80000001;

/// ML-DSA security level attribute
pub const CKA_ML_DSA_SECURITY_LEVEL: CK_ATTRIBUTE_TYPE = 0x80000002;

/// SLH-DSA security level attribute
pub const CKA_SLH_DSA_SECURITY_LEVEL: CK_ATTRIBUTE_TYPE = 0x80000003;

/// Hybrid classical component algorithm attribute
pub const CKA_HYBRID_CLASSICAL_ALG: CK_ATTRIBUTE_TYPE = 0x80000004;

/// Hybrid post-quantum component algorithm attribute
pub const CKA_HYBRID_PQ_ALG: CK_ATTRIBUTE_TYPE = 0x80000005;

/// Represents a PKCS#11 attribute value
#[derive(Debug, Clone)]
pub enum AttributeValue {
    Bool(bool),
    Ulong(CK_ULONG),
    Bytes(Vec<u8>),
    String(String),
}

/// A collection of PKCS#11 attributes
#[derive(Debug, Clone, Default)]
pub struct AttributeSet {
    attributes: HashMap<CK_ATTRIBUTE_TYPE, AttributeValue>,
}

impl AttributeSet {
    /// Create a new empty attribute set
    pub fn new() -> Self {
        Self {
            attributes: HashMap::new(),
        }
    }

    /// Set an attribute value
    pub fn set(&mut self, attr_type: CK_ATTRIBUTE_TYPE, value: AttributeValue) {
        self.attributes.insert(attr_type, value);
    }

    /// Get an attribute value
    pub fn get(&self, attr_type: CK_ATTRIBUTE_TYPE) -> Option<&AttributeValue> {
        self.attributes.get(&attr_type)
    }

    /// Check if an attribute exists
    pub fn contains(&self, attr_type: CK_ATTRIBUTE_TYPE) -> bool {
        self.attributes.contains_key(&attr_type)
    }

    /// Remove an attribute
    pub fn remove(&mut self, attr_type: CK_ATTRIBUTE_TYPE) -> Option<AttributeValue> {
        self.attributes.remove(&attr_type)
    }
}

/// Maps a FerroHSM key material type to a PKCS#11 key type
/// Convert KeyAlgorithm to KeyMaterialType
fn key_algorithm_to_material_type(algorithm: &KeyAlgorithm) -> KeyMaterialType {
    match algorithm {
        KeyAlgorithm::Aes256Gcm => KeyMaterialType::Symmetric,
        KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => KeyMaterialType::Rsa,
        KeyAlgorithm::P256 => KeyMaterialType::EcP256,
        KeyAlgorithm::P384 => KeyMaterialType::EcP384,
        // Post-quantum algorithms
        KeyAlgorithm::MlKem512 => KeyMaterialType::MlKem512,
        KeyAlgorithm::MlKem768 => KeyMaterialType::MlKem768,
        KeyAlgorithm::MlKem1024 => KeyMaterialType::MlKem1024,
        KeyAlgorithm::MlDsa44 => KeyMaterialType::MlDsa44,
        KeyAlgorithm::MlDsa65 => KeyMaterialType::MlDsa65,
        KeyAlgorithm::MlDsa87 => KeyMaterialType::MlDsa87,
        KeyAlgorithm::SlhDsa128f => KeyMaterialType::SlhDsa128f,
        KeyAlgorithm::SlhDsa128s => KeyMaterialType::SlhDsa128s,
        KeyAlgorithm::SlhDsa192f => KeyMaterialType::SlhDsa192f,
        KeyAlgorithm::SlhDsa192s => KeyMaterialType::SlhDsa192s,
        KeyAlgorithm::SlhDsa256f => KeyMaterialType::SlhDsa256f,
        KeyAlgorithm::SlhDsa256s => KeyMaterialType::SlhDsa256s,
        // Hybrid algorithms
        KeyAlgorithm::HybridP256MlKem512 => KeyMaterialType::HybridP256MlKem512,
        KeyAlgorithm::HybridP256MlKem768 => KeyMaterialType::HybridP256MlKem768,
        KeyAlgorithm::HybridP384MlKem1024 => KeyMaterialType::HybridP384MlKem1024,
        KeyAlgorithm::HybridP256MlDsa44 => KeyMaterialType::HybridP256MlDsa44,
        KeyAlgorithm::HybridP256MlDsa65 => KeyMaterialType::HybridP256MlDsa65,
        KeyAlgorithm::HybridP384MlDsa87 => KeyMaterialType::HybridP384MlDsa87,
    }
}

pub fn key_material_type_to_key_type(material_type: &KeyMaterialType) -> CK_ULONG {
    match material_type {
        KeyMaterialType::Symmetric => CKK_AES,
        KeyMaterialType::Rsa => CKK_RSA,
        KeyMaterialType::EcP256 | KeyMaterialType::EcP384 => CKK_EC,

        // Post-quantum key types
        KeyMaterialType::MlKem512 | KeyMaterialType::MlKem768 | KeyMaterialType::MlKem1024 => {
            CKK_ML_KEM
        }
        KeyMaterialType::MlDsa44 | KeyMaterialType::MlDsa65 | KeyMaterialType::MlDsa87 => {
            CKK_ML_DSA
        }
        KeyMaterialType::SlhDsa128f
        | KeyMaterialType::SlhDsa128s
        | KeyMaterialType::SlhDsa192f
        | KeyMaterialType::SlhDsa192s
        | KeyMaterialType::SlhDsa256f
        | KeyMaterialType::SlhDsa256s => CKK_SLH_DSA,

        // Hybrid key types
        KeyMaterialType::HybridP256MlKem512
        | KeyMaterialType::HybridP256MlKem768
        | KeyMaterialType::HybridP384MlKem1024 => CKK_HYBRID_ECDH_ML_KEM,

        KeyMaterialType::HybridP256MlDsa44
        | KeyMaterialType::HybridP256MlDsa65
        | KeyMaterialType::HybridP384MlDsa87 => CKK_HYBRID_ECDSA_ML_DSA,
    }
}

/// Maps a FerroHSM key material to a PKCS#11 object class
pub fn key_material_to_object_class(material: &KeyMaterial) -> CK_OBJECT_CLASS {
    match material {
        KeyMaterial::Symmetric { .. } => CKO_SECRET_KEY,
        KeyMaterial::Rsa { .. } => CKO_PRIVATE_KEY,
        KeyMaterial::Ec { .. } => CKO_PRIVATE_KEY,
        KeyMaterial::PostQuantum { .. } => CKO_PRIVATE_KEY,
        KeyMaterial::Hybrid { .. } => CKO_PRIVATE_KEY,
    }
}

/// Creates a base attribute set for a key
pub fn create_base_key_attributes(metadata: &KeyMetadata, material: &KeyMaterial) -> AttributeSet {
    let mut attrs = AttributeSet::new();

    // Common attributes for all keys
    attrs.set(
        CKA_CLASS,
        AttributeValue::Ulong(key_material_to_object_class(material)),
    );
    attrs.set(
        CKA_KEY_TYPE,
        AttributeValue::Ulong(key_material_type_to_key_type(
            &key_algorithm_to_material_type(&metadata.algorithm),
        )),
    );
    // attrs.set(CKA_LABEL, AttributeValue::String(metadata.name.clone()));
    attrs.set(
        CKA_ID,
        AttributeValue::Bytes(metadata.id.as_bytes().to_vec()),
    );
    attrs.set(CKA_TOKEN, AttributeValue::Bool(true));
    attrs.set(CKA_PRIVATE, AttributeValue::Bool(true));
    attrs.set(CKA_MODIFIABLE, AttributeValue::Bool(false));

    // Set usage flags based on key algorithm
    match metadata.algorithm {
        KeyAlgorithm::Aes256Gcm => {
            attrs.set(CKA_ENCRYPT, AttributeValue::Bool(true));
            attrs.set(CKA_DECRYPT, AttributeValue::Bool(true));
            attrs.set(CKA_WRAP, AttributeValue::Bool(true));
            attrs.set(CKA_UNWRAP, AttributeValue::Bool(true));
        }
        KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => {
            attrs.set(CKA_SIGN, AttributeValue::Bool(true));
            attrs.set(CKA_VERIFY, AttributeValue::Bool(true));
            attrs.set(CKA_ENCRYPT, AttributeValue::Bool(true));
            attrs.set(CKA_DECRYPT, AttributeValue::Bool(true));
        }
        KeyAlgorithm::P256 | KeyAlgorithm::P384 => {
            attrs.set(CKA_SIGN, AttributeValue::Bool(true));
            attrs.set(CKA_VERIFY, AttributeValue::Bool(true));
            attrs.set(CKA_DERIVE, AttributeValue::Bool(true));
        }
        // Post-quantum algorithms
        KeyAlgorithm::MlKem512 | KeyAlgorithm::MlKem768 | KeyAlgorithm::MlKem1024 => {
            attrs.set(CKA_ENCRYPT, AttributeValue::Bool(true));
            attrs.set(CKA_DECRYPT, AttributeValue::Bool(true));
            attrs.set(CKA_DERIVE, AttributeValue::Bool(true));
        }
        KeyAlgorithm::MlDsa44 | KeyAlgorithm::MlDsa65 | KeyAlgorithm::MlDsa87 => {
            attrs.set(CKA_SIGN, AttributeValue::Bool(true));
            attrs.set(CKA_VERIFY, AttributeValue::Bool(true));
        }
        KeyAlgorithm::SlhDsa128f
        | KeyAlgorithm::SlhDsa128s
        | KeyAlgorithm::SlhDsa192f
        | KeyAlgorithm::SlhDsa192s
        | KeyAlgorithm::SlhDsa256f
        | KeyAlgorithm::SlhDsa256s => {
            attrs.set(CKA_SIGN, AttributeValue::Bool(true));
            attrs.set(CKA_VERIFY, AttributeValue::Bool(true));
        }
        // Hybrid algorithms
        KeyAlgorithm::HybridP256MlKem512
        | KeyAlgorithm::HybridP256MlKem768
        | KeyAlgorithm::HybridP384MlKem1024 => {
            attrs.set(CKA_ENCRYPT, AttributeValue::Bool(true));
            attrs.set(CKA_DECRYPT, AttributeValue::Bool(true));
            attrs.set(CKA_DERIVE, AttributeValue::Bool(true));
        }
        KeyAlgorithm::HybridP256MlDsa44
        | KeyAlgorithm::HybridP256MlDsa65
        | KeyAlgorithm::HybridP384MlDsa87 => {
            attrs.set(CKA_SIGN, AttributeValue::Bool(true));
            attrs.set(CKA_VERIFY, AttributeValue::Bool(true));
        }
    }

    // Add key material specific attributes
    match material {
        KeyMaterial::Symmetric { .. } => {
            attrs.set(CKA_SENSITIVE, AttributeValue::Bool(true));
            attrs.set(CKA_EXTRACTABLE, AttributeValue::Bool(false));
            attrs.set(CKA_VALUE_LEN, AttributeValue::Ulong(32)); // 256 bits = 32 bytes
        }
        KeyMaterial::Rsa { .. } => {
            // We don't have modulus_bits in the current structure
        }
        KeyMaterial::Ec { .. } => {
            // EC parameters would be added here in a real implementation
        }
        KeyMaterial::PostQuantum { .. } => {
            attrs.set(CKA_SENSITIVE, AttributeValue::Bool(true));
            attrs.set(CKA_EXTRACTABLE, AttributeValue::Bool(false));
        }
        KeyMaterial::Hybrid { .. } => {
            attrs.set(CKA_SENSITIVE, AttributeValue::Bool(true));
            attrs.set(CKA_EXTRACTABLE, AttributeValue::Bool(false));
        }
    }

    attrs
}

/// Convert ML-KEM security level to ULONG representation
#[cfg(feature = "pqc")]
fn ml_kem_security_level_to_ulong(level: MlKemSecurityLevel) -> CK_ULONG {
    match level {
        MlKemSecurityLevel::MlKem512 => 512,
        MlKemSecurityLevel::MlKem768 => 768,
        MlKemSecurityLevel::MlKem1024 => 1024,
    }
}

/// Convert ML-DSA security level to ULONG representation
#[cfg(feature = "pqc")]
fn ml_dsa_security_level_to_ulong(level: MlDsaSecurityLevel) -> CK_ULONG {
    match level {
        MlDsaSecurityLevel::MlDsa44 => 44,
        MlDsaSecurityLevel::MlDsa65 => 65,
        MlDsaSecurityLevel::MlDsa87 => 87,
    }
}

/// Convert SLH-DSA security level to ULONG representation
#[cfg(feature = "pqc")]
fn slh_dsa_security_level_to_ulong(level: SlhDsaSecurityLevel) -> CK_ULONG {
    match level {
        SlhDsaSecurityLevel::SlhDsa128f => 1281,
        SlhDsaSecurityLevel::SlhDsa128s => 1282,
        SlhDsaSecurityLevel::SlhDsa192f => 1921,
        SlhDsaSecurityLevel::SlhDsa192s => 1922,
        SlhDsaSecurityLevel::SlhDsa256f => 2561,
        SlhDsaSecurityLevel::SlhDsa256s => 2562,
    }
}

/// Convert KeyAlgorithm to ULONG representation for hybrid component tracking
#[cfg(feature = "pqc")]
fn key_algorithm_to_ulong(algorithm: KeyAlgorithm) -> CK_ULONG {
    match algorithm {
        KeyAlgorithm::Aes256Gcm => 1,
        KeyAlgorithm::Rsa2048 => 2,
        KeyAlgorithm::Rsa4096 => 3,
        KeyAlgorithm::P256 => 4,
        KeyAlgorithm::P384 => 5,
        KeyAlgorithm::MlKem512 => 10 + 512,
        KeyAlgorithm::MlKem768 => 10 + 768,
        KeyAlgorithm::MlKem1024 => 10 + 1024,
        KeyAlgorithm::MlDsa44 => 20 + 44,
        KeyAlgorithm::MlDsa65 => 20 + 65,
        KeyAlgorithm::MlDsa87 => 20 + 87,
        KeyAlgorithm::SlhDsa128f => 30 + 1281,
        KeyAlgorithm::SlhDsa128s => 30 + 1282,
        KeyAlgorithm::SlhDsa192f => 30 + 1921,
        KeyAlgorithm::SlhDsa192s => 30 + 1922,
        KeyAlgorithm::SlhDsa256f => 30 + 2561,
        KeyAlgorithm::SlhDsa256s => 30 + 2562,
        KeyAlgorithm::HybridP256MlKem512 => 40 + 512,
        KeyAlgorithm::HybridP256MlKem768 => 40 + 768,
        KeyAlgorithm::HybridP384MlKem1024 => 40 + 1024,
        KeyAlgorithm::HybridP256MlDsa44 => 50 + 44,
        KeyAlgorithm::HybridP256MlDsa65 => 50 + 65,
        KeyAlgorithm::HybridP384MlDsa87 => 50 + 87,
    }
}
    }
}

/// Get the value of a specific attribute for a key
pub fn get_attribute_value(
    metadata: &KeyMetadata,
    attribute_type: CK_ATTRIBUTE_TYPE,
) -> Option<Vec<u8>> {
    match attribute_type {
        CKA_CLASS => {
            // Determine object class based on algorithm
            let class = match metadata.algorithm {
                KeyAlgorithm::Aes256Gcm => CKO_SECRET_KEY,
                KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => CKO_PRIVATE_KEY, // For private keys
                KeyAlgorithm::P256 | KeyAlgorithm::P384 => CKO_PRIVATE_KEY, // For private keys
                #[cfg(feature = "pqc")]
                KeyAlgorithm::MlKem512 | KeyAlgorithm::MlKem768 | KeyAlgorithm::MlKem1024 => {
                    CKO_PRIVATE_KEY
                }
                #[cfg(feature = "pqc")]
                KeyAlgorithm::MlDsa44 | KeyAlgorithm::MlDsa65 | KeyAlgorithm::MlDsa87 => {
                    CKO_PRIVATE_KEY
                }
                #[cfg(feature = "pqc")]
                KeyAlgorithm::SlhDsa128f
                | KeyAlgorithm::SlhDsa128s
                | KeyAlgorithm::SlhDsa192f
                | KeyAlgorithm::SlhDsa192s
                | KeyAlgorithm::SlhDsa256f
                | KeyAlgorithm::SlhDsa256s => CKO_PRIVATE_KEY,
                #[cfg(feature = "pqc")]
                KeyAlgorithm::HybridP256MlKem512
                | KeyAlgorithm::HybridP256MlKem768
                | KeyAlgorithm::HybridP384MlKem1024
                | KeyAlgorithm::HybridP256MlDsa44
                | KeyAlgorithm::HybridP256MlDsa65
                | KeyAlgorithm::HybridP384MlDsa87 => CKO_PRIVATE_KEY,
                #[cfg(not(feature = "pqc"))]
                _ => CKO_PRIVATE_KEY,
            };
            Some((class as CK_ULONG).to_be_bytes().to_vec())
        }
        CKA_KEY_TYPE => {
            let key_type = algorithm_to_key_type(metadata.algorithm);
            Some((key_type as CK_ULONG).to_be_bytes().to_vec())
        }
        CKA_ID => {
            // Use the key ID as the CKA_ID
            Some(metadata.id.as_bytes().to_vec())
        }
        CKA_TOKEN => {
            // Keys are token objects (not session objects)
            Some(1u8.to_be_bytes().to_vec())
        }
        CKA_PRIVATE => {
            // Private keys are private objects
            Some(1u8.to_be_bytes().to_vec())
        }
        CKA_MODIFIABLE => {
            // Keys are not modifiable
            Some(0u8.to_be_bytes().to_vec())
        }
        CKA_ENCRYPT => {
            // Check if the key can be used for encryption
            let can_encrypt = metadata.usage.contains(&KeyPurpose::Encrypt);
            Some((can_encrypt as u8).to_be_bytes().to_vec())
        }
        CKA_DECRYPT => {
            // Check if the key can be used for decryption
            let can_decrypt = metadata.usage.contains(&KeyPurpose::Decrypt);
            Some((can_decrypt as u8).to_be_bytes().to_vec())
        }
        CKA_SIGN => {
            // Check if the key can be used for signing
            let can_sign = metadata.usage.contains(&KeyPurpose::Sign);
            Some((can_sign as u8).to_be_bytes().to_vec())
        }
        CKA_VERIFY => {
            // Check if the key can be used for verification
            let can_verify = metadata.usage.contains(&KeyPurpose::Verify);
            Some((can_verify as u8).to_be_bytes().to_vec())
        }
        CKA_WRAP => {
            // Check if the key can be used for wrapping
            let can_wrap = metadata.usage.contains(&KeyPurpose::Wrap);
            Some((can_wrap as u8).to_be_bytes().to_vec())
        }
        CKA_UNWRAP => {
            // Check if the key can be used for unwrapping
            let can_unwrap = metadata.usage.contains(&KeyPurpose::Unwrap);
            Some((can_unwrap as u8).to_be_bytes().to_vec())
        }
        CKA_SENSITIVE => {
            // All keys are sensitive
            Some(1u8.to_be_bytes().to_vec())
        }
        CKA_EXTRACTABLE => {
            // Keys are not extractable
            Some(0u8.to_be_bytes().to_vec())
        }
        CKA_VALUE_LEN => {
            // For symmetric keys, return the key length in bits
            match metadata.algorithm {
                KeyAlgorithm::Aes256Gcm => Some(256u32.to_be_bytes().to_vec()),
                _ => None,
            }
        }
        // Post-quantum specific attributes
        #[cfg(feature = "pqc")]
        CKA_ML_KEM_SECURITY_LEVEL => algorithm_to_ml_kem_security_level(metadata.algorithm)
            .map(|level| ml_kem_security_level_to_ulong(level).to_be_bytes().to_vec()),
        #[cfg(feature = "pqc")]
        CKA_ML_DSA_SECURITY_LEVEL => algorithm_to_ml_dsa_security_level(metadata.algorithm)
            .map(|level| ml_dsa_security_level_to_ulong(level).to_be_bytes().to_vec()),
        #[cfg(feature = "pqc")]
        CKA_SLH_DSA_SECURITY_LEVEL => algorithm_to_slh_dsa_security_level(metadata.algorithm)
            .map(|level| slh_dsa_security_level_to_ulong(level).to_be_bytes().to_vec()),
        _ => None, // Attribute not supported
    }
}

/// Convert KeyAlgorithm to PKCS#11 key type
fn algorithm_to_key_type(algorithm: KeyAlgorithm) -> CK_ULONG {
    match algorithm {
        KeyAlgorithm::Aes256Gcm => CKK_AES,
        KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => CKK_RSA,
        KeyAlgorithm::P256 | KeyAlgorithm::P384 => CKK_EC,
        #[cfg(feature = "pqc")]
        KeyAlgorithm::MlKem512 | KeyAlgorithm::MlKem768 | KeyAlgorithm::MlKem1024 => CKK_ML_KEM,
        #[cfg(feature = "pqc")]
        KeyAlgorithm::MlDsa44 | KeyAlgorithm::MlDsa65 | KeyAlgorithm::MlDsa87 => CKK_ML_DSA,
        #[cfg(feature = "pqc")]
        KeyAlgorithm::SlhDsa128f
        | KeyAlgorithm::SlhDsa128s
        | KeyAlgorithm::SlhDsa192f
        | KeyAlgorithm::SlhDsa192s
        | KeyAlgorithm::SlhDsa256f
        | KeyAlgorithm::SlhDsa256s => CKK_SLH_DSA,
        #[cfg(feature = "pqc")]
        KeyAlgorithm::HybridP256MlKem512
        | KeyAlgorithm::HybridP256MlKem768
        | KeyAlgorithm::HybridP384MlKem1024 => CKK_EC,
        #[cfg(feature = "pqc")]
        KeyAlgorithm::HybridP256MlDsa44
        | KeyAlgorithm::HybridP256MlDsa65
        | KeyAlgorithm::HybridP384MlDsa87 => CKK_EC,
        #[cfg(not(feature = "pqc"))]
        _ => CKK_EC,
    }
}

/// Convert KeyAlgorithm to ML-KEM security level
#[cfg(feature = "pqc")]
fn algorithm_to_ml_kem_security_level(algorithm: KeyAlgorithm) -> Option<MlKemSecurityLevel> {
    match algorithm {
        KeyAlgorithm::MlKem512 => Some(MlKemSecurityLevel::MlKem512),
        KeyAlgorithm::MlKem768 => Some(MlKemSecurityLevel::MlKem768),
        KeyAlgorithm::MlKem1024 => Some(MlKemSecurityLevel::MlKem1024),
        KeyAlgorithm::HybridP256MlKem512 => Some(MlKemSecurityLevel::MlKem512),
        KeyAlgorithm::HybridP256MlKem768 => Some(MlKemSecurityLevel::MlKem768),
        KeyAlgorithm::HybridP384MlKem1024 => Some(MlKemSecurityLevel::MlKem1024),
        _ => None,
    }
}

/// Convert KeyAlgorithm to ML-DSA security level
#[cfg(feature = "pqc")]
fn algorithm_to_ml_dsa_security_level(algorithm: KeyAlgorithm) -> Option<MlDsaSecurityLevel> {
    match algorithm {
        KeyAlgorithm::MlDsa44 => Some(MlDsaSecurityLevel::MlDsa44),
        KeyAlgorithm::MlDsa65 => Some(MlDsaSecurityLevel::MlDsa65),
        KeyAlgorithm::MlDsa87 => Some(MlDsaSecurityLevel::MlDsa87),
        KeyAlgorithm::HybridP256MlDsa44 => Some(MlDsaSecurityLevel::MlDsa44),
        KeyAlgorithm::HybridP256MlDsa65 => Some(MlDsaSecurityLevel::MlDsa65),
        KeyAlgorithm::HybridP384MlDsa87 => Some(MlDsaSecurityLevel::MlDsa87),
        _ => None,
    }
}

/// Convert KeyAlgorithm to SLH-DSA security level
#[cfg(feature = "pqc")]
fn algorithm_to_slh_dsa_security_level(algorithm: KeyAlgorithm) -> Option<SlhDsaSecurityLevel> {
    match algorithm {
        KeyAlgorithm::SlhDsa128f => Some(SlhDsaSecurityLevel::SlhDsa128f),
        KeyAlgorithm::SlhDsa128s => Some(SlhDsaSecurityLevel::SlhDsa128s),
        KeyAlgorithm::SlhDsa192f => Some(SlhDsaSecurityLevel::SlhDsa192f),
        KeyAlgorithm::SlhDsa192s => Some(SlhDsaSecurityLevel::SlhDsa192s),
        KeyAlgorithm::SlhDsa256f => Some(SlhDsaSecurityLevel::SlhDsa256f),
        KeyAlgorithm::SlhDsa256s => Some(SlhDsaSecurityLevel::SlhDsa256s),
        _ => None,
    }
}
