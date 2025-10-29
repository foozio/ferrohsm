//! PKCS#11 mechanism definitions and mappings for FerroHSM.
//!
//! This module defines the supported cryptographic mechanisms for the PKCS#11
//! interface, including mappings between PKCS#11 mechanism types and FerroHSM's
//! internal cryptographic operations.

use cryptoki_sys::{
    CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_AES_GCM, CKM_AES_KEY_GEN, CKM_ECDSA, CKM_ECDSA_SHA256,
    CKM_ECDSA_SHA384, CKM_EC_KEY_PAIR_GEN, CKM_RSA_PKCS, CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS, CK_MECHANISM_TYPE,
};
use hsm_core::{
    models::{KeyAlgorithm, KeyMaterialType},
};

#[cfg(feature = "pqc")]
use hsm_core::pqc::{MlDsaSecurityLevel, MlKemSecurityLevel, SlhDsaSecurityLevel};
use std::collections::HashMap;
use tracing::debug;

// Define custom mechanism types for post-quantum algorithms
// Note: These values are in the vendor-defined range (0x80000000 - 0xFFFFFFFF)
// as specified in the PKCS#11 standard

/// ML-KEM (Kyber) key generation mechanism
pub const CKM_ML_KEM_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x80000001;

/// ML-KEM-512 key encapsulation mechanism
pub const CKM_ML_KEM_512: CK_MECHANISM_TYPE = 0x80000002;

/// ML-KEM-768 key encapsulation mechanism
pub const CKM_ML_KEM_768: CK_MECHANISM_TYPE = 0x80000003;

/// ML-KEM-1024 key encapsulation mechanism
pub const CKM_ML_KEM_1024: CK_MECHANISM_TYPE = 0x80000004;

/// ML-DSA (Dilithium) key generation mechanism
pub const CKM_ML_DSA_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x80000005;

/// ML-DSA-44 signature mechanism
pub const CKM_ML_DSA_44: CK_MECHANISM_TYPE = 0x80000006;

/// ML-DSA-65 signature mechanism
pub const CKM_ML_DSA_65: CK_MECHANISM_TYPE = 0x80000007;

/// ML-DSA-87 signature mechanism
pub const CKM_ML_DSA_87: CK_MECHANISM_TYPE = 0x80000008;

/// SLH-DSA (SPHINCS+) key generation mechanism
pub const CKM_SLH_DSA_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x80000009;

/// SLH-DSA-SHA2-128f signature mechanism
pub const CKM_SLH_DSA_SHA2_128F: CK_MECHANISM_TYPE = 0x8000000A;

/// SLH-DSA-SHA2-128s signature mechanism
pub const CKM_SLH_DSA_SHA2_128S: CK_MECHANISM_TYPE = 0x8000000B;

/// SLH-DSA-SHA2-192f signature mechanism
pub const CKM_SLH_DSA_SHA2_192F: CK_MECHANISM_TYPE = 0x8000000C;

/// SLH-DSA-SHA2-192s signature mechanism
pub const CKM_SLH_DSA_SHA2_192S: CK_MECHANISM_TYPE = 0x8000000D;

/// SLH-DSA-SHA2-256f signature mechanism
pub const CKM_SLH_DSA_SHA2_256F: CK_MECHANISM_TYPE = 0x8000000E;

/// SLH-DSA-SHA2-256s signature mechanism
pub const CKM_SLH_DSA_SHA2_256S: CK_MECHANISM_TYPE = 0x8000000F;

/// Hybrid ECDH+ML-KEM key generation mechanism
pub const CKM_HYBRID_ECDH_ML_KEM_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x80000010;

/// Hybrid ECDH+ML-KEM-512 key encapsulation mechanism
pub const CKM_HYBRID_ECDH_ML_KEM_512: CK_MECHANISM_TYPE = 0x80000011;

/// Hybrid ECDH+ML-KEM-768 key encapsulation mechanism
pub const CKM_HYBRID_ECDH_ML_KEM_768: CK_MECHANISM_TYPE = 0x80000012;

/// Hybrid ECDH+ML-KEM-1024 key encapsulation mechanism
pub const CKM_HYBRID_ECDH_ML_KEM_1024: CK_MECHANISM_TYPE = 0x80000013;

/// Hybrid ECDSA+ML-DSA key generation mechanism
pub const CKM_HYBRID_ECDSA_ML_DSA_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x80000014;

/// Hybrid ECDSA+ML-DSA-44 signature mechanism
pub const CKM_HYBRID_ECDSA_ML_DSA_44: CK_MECHANISM_TYPE = 0x80000015;

/// Hybrid ECDSA+ML-DSA-65 signature mechanism
pub const CKM_HYBRID_ECDSA_ML_DSA_65: CK_MECHANISM_TYPE = 0x80000016;

/// Hybrid ECDSA+ML-DSA-87 signature mechanism
pub const CKM_HYBRID_ECDSA_ML_DSA_87: CK_MECHANISM_TYPE = 0x80000017;

/// Maps a PKCS#11 mechanism type to a FerroHSM key algorithm for key generation
pub fn mechanism_to_key_algorithm(mechanism: CK_MECHANISM_TYPE) -> Option<KeyAlgorithm> {
    match mechanism {
        CKM_RSA_PKCS_KEY_PAIR_GEN => Some(KeyAlgorithm::Rsa2048),
        CKM_EC_KEY_PAIR_GEN => Some(KeyAlgorithm::P256),
        CKM_AES_KEY_GEN => Some(KeyAlgorithm::Aes256Gcm),

        // Post-quantum key generation mechanisms
        CKM_ML_KEM_KEY_PAIR_GEN => Some(KeyAlgorithm::MlKem768),
        CKM_ML_DSA_KEY_PAIR_GEN => Some(KeyAlgorithm::MlDsa65),
        CKM_SLH_DSA_KEY_PAIR_GEN => Some(KeyAlgorithm::SlhDsa128f),

        // Hybrid key generation mechanisms
        CKM_HYBRID_ECDH_ML_KEM_KEY_PAIR_GEN => Some(KeyAlgorithm::HybridP256MlKem768),
        CKM_HYBRID_ECDSA_ML_DSA_KEY_PAIR_GEN => Some(KeyAlgorithm::HybridP256MlDsa65),
        _ => None,
    }
}

/// Maps a PKCS#11 mechanism type to a FerroHSM key material type
pub fn mechanism_to_key_material_type(mechanism: CK_MECHANISM_TYPE) -> Option<KeyMaterialType> {
    match mechanism {
        CKM_RSA_PKCS_KEY_PAIR_GEN => Some(KeyMaterialType::Rsa),
        CKM_EC_KEY_PAIR_GEN => Some(KeyMaterialType::EcP256),
        CKM_AES_KEY_GEN => Some(KeyMaterialType::Symmetric),

        // Post-quantum key material types
        CKM_ML_KEM_KEY_PAIR_GEN => Some(KeyMaterialType::MlKem768),
        CKM_ML_DSA_KEY_PAIR_GEN => Some(KeyMaterialType::MlDsa65),
        CKM_SLH_DSA_KEY_PAIR_GEN => Some(KeyMaterialType::SlhDsa128f),

        // Hybrid key material types
        CKM_HYBRID_ECDH_ML_KEM_KEY_PAIR_GEN => Some(KeyMaterialType::HybridP256MlKem768),
        CKM_HYBRID_ECDSA_ML_DSA_KEY_PAIR_GEN => Some(KeyMaterialType::HybridP256MlDsa65),
        _ => None,
    }
}

/// Returns a list of all supported mechanisms
pub fn get_supported_mechanisms() -> Vec<CK_MECHANISM_TYPE> {
    vec![
        // Classical algorithms
        CKM_RSA_PKCS_KEY_PAIR_GEN,
        CKM_RSA_PKCS,
        CKM_SHA256_RSA_PKCS,
        CKM_SHA384_RSA_PKCS,
        CKM_SHA512_RSA_PKCS,
        CKM_EC_KEY_PAIR_GEN,
        CKM_ECDSA,
        CKM_ECDSA_SHA256,
        CKM_ECDSA_SHA384,
        CKM_AES_KEY_GEN,
        CKM_AES_GCM,
        CKM_AES_CBC,
        CKM_AES_CBC_PAD,
        // Post-quantum algorithms
        CKM_ML_KEM_KEY_PAIR_GEN,
        CKM_ML_KEM_512,
        CKM_ML_KEM_768,
        CKM_ML_KEM_1024,
        CKM_ML_DSA_KEY_PAIR_GEN,
        CKM_ML_DSA_44,
        CKM_ML_DSA_65,
        CKM_ML_DSA_87,
        CKM_SLH_DSA_KEY_PAIR_GEN,
        CKM_SLH_DSA_SHA2_128F,
        CKM_SLH_DSA_SHA2_128S,
        CKM_SLH_DSA_SHA2_192F,
        CKM_SLH_DSA_SHA2_192S,
        CKM_SLH_DSA_SHA2_256F,
        CKM_SLH_DSA_SHA2_256S,
        // Hybrid algorithms
        CKM_HYBRID_ECDH_ML_KEM_KEY_PAIR_GEN,
        CKM_HYBRID_ECDH_ML_KEM_512,
        CKM_HYBRID_ECDH_ML_KEM_768,
        CKM_HYBRID_ECDH_ML_KEM_1024,
        CKM_HYBRID_ECDSA_ML_DSA_KEY_PAIR_GEN,
        CKM_HYBRID_ECDSA_ML_DSA_44,
        CKM_HYBRID_ECDSA_ML_DSA_65,
        CKM_HYBRID_ECDSA_ML_DSA_87,
    ]
}

/// Maps a specific ML-KEM mechanism to its security level
#[cfg(feature = "pqc")]
pub fn ml_kem_mechanism_to_security_level(
    mechanism: CK_MECHANISM_TYPE,
) -> Option<MlKemSecurityLevel> {
    match mechanism {
        CKM_ML_KEM_512 => Some(MlKemSecurityLevel::MlKem512),
        CKM_ML_KEM_768 => Some(MlKemSecurityLevel::MlKem768),
        CKM_ML_KEM_1024 => Some(MlKemSecurityLevel::MlKem1024),
        _ => None,
    }
}

/// Maps a specific ML-DSA mechanism to its security level
#[cfg(feature = "pqc")]
pub fn ml_dsa_mechanism_to_security_level(
    mechanism: CK_MECHANISM_TYPE,
) -> Option<MlDsaSecurityLevel> {
    match mechanism {
        CKM_ML_DSA_44 => Some(MlDsaSecurityLevel::MlDsa44),
        CKM_ML_DSA_65 => Some(MlDsaSecurityLevel::MlDsa65),
        CKM_ML_DSA_87 => Some(MlDsaSecurityLevel::MlDsa87),
        _ => None,
    }
}

/// Maps a specific SLH-DSA mechanism to its security level
#[cfg(feature = "pqc")]
pub fn slh_dsa_mechanism_to_security_level(
    mechanism: CK_MECHANISM_TYPE,
) -> Option<SlhDsaSecurityLevel> {
    match mechanism {
        CKM_SLH_DSA_SHA2_128F => Some(SlhDsaSecurityLevel::SlhDsa128f),
        CKM_SLH_DSA_SHA2_128S => Some(SlhDsaSecurityLevel::SlhDsa128s),
        CKM_SLH_DSA_SHA2_192F => Some(SlhDsaSecurityLevel::SlhDsa192f),
        CKM_SLH_DSA_SHA2_192S => Some(SlhDsaSecurityLevel::SlhDsa192s),
        CKM_SLH_DSA_SHA2_256F => Some(SlhDsaSecurityLevel::SlhDsa256f),
        CKM_SLH_DSA_SHA2_256S => Some(SlhDsaSecurityLevel::SlhDsa256s),
        _ => None,
    }
}

/// Maps a hybrid ECDH+ML-KEM mechanism to its components
#[cfg(feature = "pqc")]
pub fn hybrid_ecdh_ml_kem_mechanism_to_components(
    mechanism: CK_MECHANISM_TYPE,
) -> Option<(KeyAlgorithm, MlKemSecurityLevel)> {
    match mechanism {
        CKM_HYBRID_ECDH_ML_KEM_512 => Some((KeyAlgorithm::P256, MlKemSecurityLevel::MlKem512)),
        CKM_HYBRID_ECDH_ML_KEM_768 => Some((KeyAlgorithm::P256, MlKemSecurityLevel::MlKem768)),
        CKM_HYBRID_ECDH_ML_KEM_1024 => Some((KeyAlgorithm::P256, MlKemSecurityLevel::MlKem1024)),
        _ => None,
    }
}

/// Maps a hybrid ECDSA+ML-DSA mechanism to its components
#[cfg(feature = "pqc")]
pub fn hybrid_ecdsa_ml_dsa_mechanism_to_components(
    mechanism: CK_MECHANISM_TYPE,
) -> Option<(KeyAlgorithm, MlDsaSecurityLevel)> {
    match mechanism {
        CKM_HYBRID_ECDSA_ML_DSA_44 => Some((KeyAlgorithm::P256, MlDsaSecurityLevel::MlDsa44)),
        CKM_HYBRID_ECDSA_ML_DSA_65 => Some((KeyAlgorithm::P256, MlDsaSecurityLevel::MlDsa65)),
        CKM_HYBRID_ECDSA_ML_DSA_87 => Some((KeyAlgorithm::P256, MlDsaSecurityLevel::MlDsa87)),
        _ => None,
    }
}

/// Initialize the mechanism registry
pub fn init_mechanism_registry() {
    debug!("Initializing PKCS#11 mechanism registry with post-quantum support");
    // Additional initialization logic can be added here if needed
}
