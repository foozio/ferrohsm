use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    error::HsmResult,
    models::{KeyMaterial, KeyMaterialType},
};

/// Post-Quantum Cryptography provider trait
/// This trait allows for swapping different PQC implementations
pub trait CryptoProvider {
    fn generate_mlkem_keypair(&self, security_level: MlKemSecurityLevel) -> HsmResult<KeyMaterial>;
    fn generate_mldsa_keypair(&self, security_level: MlDsaSecurityLevel) -> HsmResult<KeyMaterial>;
    fn generate_slhdsa_keypair(
        &self,
        security_level: SlhDsaSecurityLevel,
    ) -> HsmResult<KeyMaterial>;

    fn mlkem_encapsulate(
        &self,
        public_key: &[u8],
        security_level: MlKemSecurityLevel,
    ) -> HsmResult<(Vec<u8>, Vec<u8>)>;
    fn mlkem_decapsulate(
        &self,
        ciphertext: &[u8],
        private_key: &[u8],
        security_level: MlKemSecurityLevel,
    ) -> HsmResult<Vec<u8>>;

    fn mldsa_sign(
        &self,
        message: &[u8],
        private_key: &[u8],
        security_level: MlDsaSecurityLevel,
    ) -> HsmResult<Vec<u8>>;
    fn mldsa_verify(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
        security_level: MlDsaSecurityLevel,
    ) -> HsmResult<bool>;

    fn slhdsa_sign(
        &self,
        message: &[u8],
        private_key: &[u8],
        security_level: SlhDsaSecurityLevel,
    ) -> HsmResult<Vec<u8>>;
    fn slhdsa_verify(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
        security_level: SlhDsaSecurityLevel,
    ) -> HsmResult<bool>;

    // Hybrid operations
    fn hybrid_ecdh_mlkem_encapsulate(
        &self,
        ec_public_key: &[u8],
        pq_public_key: &[u8],
        ec_type: KeyMaterialType,
        pq_level: MlKemSecurityLevel,
    ) -> HsmResult<(Vec<u8>, Vec<u8>)>;
    fn hybrid_ecdh_mlkem_decapsulate(
        &self,
        ciphertext: &[u8],
        ec_private_key: &[u8],
        pq_private_key: &[u8],
        ec_type: KeyMaterialType,
        pq_level: MlKemSecurityLevel,
    ) -> HsmResult<Vec<u8>>;

    fn hybrid_ecdsa_mldsa_sign(
        &self,
        message: &[u8],
        ec_private_key: &[u8],
        pq_private_key: &[u8],
        ec_type: KeyMaterialType,
        pq_level: MlDsaSecurityLevel,
    ) -> HsmResult<Vec<u8>>;
    fn hybrid_ecdsa_mldsa_verify(
        &self,
        message: &[u8],
        signature: &[u8],
        ec_public_key: &[u8],
        pq_public_key: &[u8],
        ec_type: KeyMaterialType,
        pq_level: MlDsaSecurityLevel,
    ) -> HsmResult<bool>;
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
    SlhDsa128f,
    /// SLH-DSA-SHA2-128s (small variant, security roughly equivalent to AES-128)
    SlhDsa128s,
    /// SLH-DSA-SHA2-192f (fast variant, security roughly equivalent to AES-192)
    SlhDsa192f,
    /// SLH-DSA-SHA2-192s (small variant, security roughly equivalent to AES-192)
    SlhDsa192s,
    /// SLH-DSA-SHA2-256f (fast variant, security roughly equivalent to AES-256)
    SlhDsa256f,
    /// SLH-DSA-SHA2-256s (small variant, security roughly equivalent to AES-256)
    SlhDsa256s,
}

impl fmt::Display for SlhDsaSecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SlhDsaSecurityLevel::SlhDsa128f => write!(f, "SLH-DSA-128f"),
            SlhDsaSecurityLevel::SlhDsa128s => write!(f, "SLH-DSA-128s"),
            SlhDsaSecurityLevel::SlhDsa192f => write!(f, "SLH-DSA-192f"),
            SlhDsaSecurityLevel::SlhDsa192s => write!(f, "SLH-DSA-192s"),
            SlhDsaSecurityLevel::SlhDsa256f => write!(f, "SLH-DSA-256f"),
            SlhDsaSecurityLevel::SlhDsa256s => write!(f, "SLH-DSA-256s"),
        }
    }
}
