use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    error::{HsmError, HsmResult},
    models::{GeneratedKey, KeyAlgorithm, KeyMaterial, KeyMaterialType, KeyMetadata},
};

/// Post-Quantum Cryptography provider trait
/// This trait allows for swapping different PQC implementations
pub trait CryptoProvider {
    fn generate_mlkem_keypair(&self, security_level: MlKemSecurityLevel) -> HsmResult<KeyMaterial>;
    fn generate_mldsa_keypair(&self, security_level: MlDsaSecurityLevel) -> HsmResult<KeyMaterial>;
    fn generate_slhdsa_keypair(&self, security_level: SlhDsaSecurityLevel) -> HsmResult<KeyMaterial>;
    
    fn mlkem_encapsulate(&self, public_key: &[u8], security_level: MlKemSecurityLevel) -> HsmResult<(Vec<u8>, Vec<u8>)>;
    fn mlkem_decapsulate(&self, ciphertext: &[u8], private_key: &[u8], security_level: MlKemSecurityLevel) -> HsmResult<Vec<u8>>;
    
    fn mldsa_sign(&self, message: &[u8], private_key: &[u8], security_level: MlDsaSecurityLevel) -> HsmResult<Vec<u8>>;
    fn mldsa_verify(&self, message: &[u8], signature: &[u8], public_key: &[u8], security_level: MlDsaSecurityLevel) -> HsmResult<bool>;
    
    fn slhdsa_sign(&self, message: &[u8], private_key: &[u8], security_level: SlhDsaSecurityLevel) -> HsmResult<Vec<u8>>;
    fn slhdsa_verify(&self, message: &[u8], signature: &[u8], public_key: &[u8], security_level: SlhDsaSecurityLevel) -> HsmResult<bool>;
    
    // Hybrid operations
    fn hybrid_ecdh_mlkem_encapsulate(&self, ec_public_key: &[u8], pq_public_key: &[u8], ec_type: KeyMaterialType, pq_level: MlKemSecurityLevel) -> HsmResult<(Vec<u8>, Vec<u8>)>;
    fn hybrid_ecdh_mlkem_decapsulate(&self, ciphertext: &[u8], ec_private_key: &[u8], pq_private_key: &[u8], ec_type: KeyMaterialType, pq_level: MlKemSecurityLevel) -> HsmResult<Vec<u8>>;
    
    fn hybrid_ecdsa_mldsa_sign(&self, message: &[u8], ec_private_key: &[u8], pq_private_key: &[u8], ec_type: KeyMaterialType, pq_level: MlDsaSecurityLevel) -> HsmResult<Vec<u8>>;
    fn hybrid_ecdsa_mldsa_verify(&self, message: &[u8], signature: &[u8], ec_public_key: &[u8], pq_public_key: &[u8], ec_type: KeyMaterialType, pq_level: MlDsaSecurityLevel) -> HsmResult<bool>;
}

/// ML-KEM (Kyber) security levels as defined in NIST FIPS 203
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MlKemSecurityLevel {
    /// ML-KEM-512 (security roughly equivalent to AES-128)
    MlKem512,
    /// ML-KEM-768 (security roughly equivalent to AES-192)
    MlKem768,
    /// ML-KEM-1024 (security roughly equivalent to AES-256)
    MlKem1024,
}

impl fmt::Display for MlKemSecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MlKemSecurityLevel::MlKem512 => write!(f, "ML-KEM-512"),
            MlKemSecurityLevel::MlKem768 => write!(f, "ML-KEM-768"),
            MlKemSecurityLevel::MlKem1024 => write!(f, "ML-KEM-1024"),
        }
    }
}

/// ML-DSA (Dilithium) security levels as defined in NIST FIPS 204
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MlDsaSecurityLevel {
    /// ML-DSA-44 (security roughly equivalent to AES-128)
    MlDsa44,
    /// ML-DSA-65 (security roughly equivalent to AES-192)
    MlDsa65,
    /// ML-DSA-87 (security roughly equivalent to AES-256)
    MlDsa87,
}

impl fmt::Display for MlDsaSecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MlDsaSecurityLevel::MlDsa44 => write!(f, "ML-DSA-44"),
            MlDsaSecurityLevel::MlDsa65 => write!(f, "ML-DSA-65"),
            MlDsaSecurityLevel::MlDsa87 => write!(f, "ML-DSA-87"),
        }
    }
}

/// SLH-DSA (SPHINCS+) security levels as defined in NIST FIPS 205
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlhDsaSecurityLevel {
    /// SLH-DSA-SHA2-128f (fast variant, security roughly equivalent to AES-128)
    SlhDsaSha2128f,
    /// SLH-DSA-SHA2-128s (small variant, security roughly equivalent to AES-128)
    SlhDsaSha2128s,
    /// SLH-DSA-SHA2-192f (fast variant, security roughly equivalent to AES-192)
    SlhDsaSha2192f,
    /// SLH-DSA-SHA2-192s (small variant, security roughly equivalent to AES-192)
    SlhDsaSha2192s,
    /// SLH-DSA-SHA2-256f (fast variant, security roughly equivalent to AES-256)
    SlhDsaSha2256f,
    /// SLH-DSA-SHA2-256s (small variant, security roughly equivalent to AES-256)
    SlhDsaSha2256s,
}

impl fmt::Display for SlhDsaSecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SlhDsaSecurityLevel::SlhDsaSha2128f => write!(f, "SLH-DSA-SHA2-128f"),
            SlhDsaSecurityLevel::SlhDsaSha2128s => write!(f, "SLH-DSA-SHA2-128s"),
            SlhDsaSecurityLevel::SlhDsaSha2192f => write!(f, "SLH-DSA-SHA2-192f"),
            SlhDsaSecurityLevel::SlhDsaSha2192s => write!(f, "SLH-DSA-SHA2-192s"),
            SlhDsaSecurityLevel::SlhDsaSha2256f => write!(f, "SLH-DSA-SHA2-256f"),
            SlhDsaSecurityLevel::SlhDsaSha2256s => write!(f, "SLH-DSA-SHA2-256s"),
        }
    }
}

/// Post-Quantum key material types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PqKeyMaterialType {
    /// ML-KEM key material
    MlKem(MlKemSecurityLevel),
    /// ML-DSA key material
    MlDsa(MlDsaSecurityLevel),
    /// SLH-DSA key material
    SlhDsa(SlhDsaSecurityLevel),
    /// Hybrid ECDH+ML-KEM key material
    HybridEcdhMlKem(KeyMaterialType, MlKemSecurityLevel),
    /// Hybrid ECDSA+ML-DSA key material
    HybridEcdsaMlDsa(KeyMaterialType, MlDsaSecurityLevel),
}

impl fmt::Display for PqKeyMaterialType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PqKeyMaterialType::MlKem(level) => write!(f, "{}", level),
            PqKeyMaterialType::MlDsa(level) => write!(f, "{}", level),
            PqKeyMaterialType::SlhDsa(level) => write!(f, "{}", level),
            PqKeyMaterialType::HybridEcdhMlKem(ec_type, pq_level) => {
                write!(f, "Hybrid-{}-{}", ec_type, pq_level)
            }
            PqKeyMaterialType::HybridEcdsaMlDsa(ec_type, pq_level) => {
                write!(f, "Hybrid-{}-{}", ec_type, pq_level)
            }
        }
    }
}

/// Post-Quantum key algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PqKeyAlgorithm {
    /// ML-KEM (Kyber) key encapsulation mechanism
    MlKem(MlKemSecurityLevel),
    /// ML-DSA (Dilithium) digital signature algorithm
    MlDsa(MlDsaSecurityLevel),
    /// SLH-DSA (SPHINCS+) digital signature algorithm
    SlhDsa(SlhDsaSecurityLevel),
    /// Hybrid ECDH+ML-KEM key encapsulation
    HybridEcdhMlKem(KeyAlgorithm, MlKemSecurityLevel),
    /// Hybrid ECDSA+ML-DSA digital signature
    HybridEcdsaMlDsa(KeyAlgorithm, MlDsaSecurityLevel),
}

impl fmt::Display for PqKeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PqKeyAlgorithm::MlKem(level) => write!(f, "{}", level),
            PqKeyAlgorithm::MlDsa(level) => write!(f, "{}", level),
            PqKeyAlgorithm::SlhDsa(level) => write!(f, "{}", level),
            PqKeyAlgorithm::HybridEcdhMlKem(ec_alg, pq_level) => {
                write!(f, "Hybrid-{}-{}", ec_alg, pq_level)
            }
            PqKeyAlgorithm::HybridEcdsaMlDsa(ec_alg, pq_level) => {
                write!(f, "Hybrid-{}-{}", ec_alg, pq_level)
            }
        }
    }
}

/// Post-Quantum cryptographic operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PqCryptoOperation {
    /// ML-KEM encapsulation operation
    MlKemEncapsulate {
        public_key: Vec<u8>,
        security_level: MlKemSecurityLevel,
    },
    /// ML-KEM decapsulation operation
    MlKemDecapsulate {
        ciphertext: Vec<u8>,
        security_level: MlKemSecurityLevel,
    },
    /// ML-DSA signing operation
    MlDsaSign {
        message: Vec<u8>,
        security_level: MlDsaSecurityLevel,
    },
    /// ML-DSA verification operation
    MlDsaVerify {
        message: Vec<u8>,
        signature: Vec<u8>,
        public_key: Vec<u8>,
        security_level: MlDsaSecurityLevel,
    },
    /// SLH-DSA signing operation
    SlhDsaSign {
        message: Vec<u8>,
        security_level: SlhDsaSecurityLevel,
    },
    /// SLH-DSA verification operation
    SlhDsaVerify {
        message: Vec<u8>,
        signature: Vec<u8>,
        public_key: Vec<u8>,
        security_level: SlhDsaSecurityLevel,
    },
    /// Hybrid ECDH+ML-KEM encapsulation
    HybridEncapsulate {
        ec_public_key: Vec<u8>,
        pq_public_key: Vec<u8>,
        ec_type: KeyMaterialType,
        pq_level: MlKemSecurityLevel,
    },
    /// Hybrid ECDH+ML-KEM decapsulation
    HybridDecapsulate {
        ciphertext: Vec<u8>,
        ec_type: KeyMaterialType,
        pq_level: MlKemSecurityLevel,
    },
    /// Hybrid ECDSA+ML-DSA signing
    HybridSign {
        message: Vec<u8>,
        ec_type: KeyMaterialType,
        pq_level: MlDsaSecurityLevel,
    },
    /// Hybrid ECDSA+ML-DSA verification
    HybridVerify {
        message: Vec<u8>,
        signature: Vec<u8>,
        ec_public_key: Vec<u8>,
        pq_public_key: Vec<u8>,
        ec_type: KeyMaterialType,
        pq_level: MlDsaSecurityLevel,
    },
}

/// Results of post-quantum cryptographic operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PqKeyOperationResult {
    /// Result of ML-KEM encapsulation
    MlKemEncapsulated {
        ciphertext: Vec<u8>,
        shared_secret: Vec<u8>,
    },
    /// Result of ML-KEM decapsulation
    MlKemDecapsulated {
        shared_secret: Vec<u8>,
    },
    /// Result of ML-DSA signing
    MlDsaSignature {
        signature: Vec<u8>,
    },
    /// Result of ML-DSA verification
    MlDsaVerified {
        valid: bool,
    },
    /// Result of SLH-DSA signing
    SlhDsaSignature {
        signature: Vec<u8>,
    },
    /// Result of SLH-DSA verification
    SlhDsaVerified {
        valid: bool,
    },
    /// Result of hybrid encapsulation
    HybridEncapsulated {
        ciphertext: Vec<u8>,
        shared_secret: Vec<u8>,
    },
    /// Result of hybrid decapsulation
    HybridDecapsulated {
        shared_secret: Vec<u8>,
    },
    /// Result of hybrid signing
    HybridSignature {
        signature: Vec<u8>,
    },
    /// Result of hybrid verification
    HybridVerified {
        valid: bool,
    },
}