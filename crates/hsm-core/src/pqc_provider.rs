use oqs::kem::{self as oqs_kem, Algorithm as KemAlgorithm};
use oqs::sig::{self as oqs_sig, Algorithm as SigAlgorithm};

use crate::{
    error::{HsmError, HsmResult},
    models::{KeyMaterial, KeyMaterialType},
    pqc::{CryptoProvider, MlDsaSecurityLevel, MlKemSecurityLevel, SlhDsaSecurityLevel},
};

/// OQS-based implementation of the CryptoProvider trait
pub struct OqsCryptoProvider;

impl OqsCryptoProvider {
    pub fn new() -> Self {
        Self
    }

    fn init() {
        oqs::init();
    }

    fn mlkem_algorithm(level: MlKemSecurityLevel) -> KemAlgorithm {
        match level {
            MlKemSecurityLevel::MlKem512 => KemAlgorithm::Kyber512,
            MlKemSecurityLevel::MlKem768 => KemAlgorithm::Kyber768,
            MlKemSecurityLevel::MlKem1024 => KemAlgorithm::Kyber1024,
        }
    }

    fn mlkem_name(level: MlKemSecurityLevel) -> &'static str {
        match level {
            MlKemSecurityLevel::MlKem512 => "ML-KEM-512",
            MlKemSecurityLevel::MlKem768 => "ML-KEM-768",
            MlKemSecurityLevel::MlKem1024 => "ML-KEM-1024",
        }
    }

    fn mldsa_algorithm(level: MlDsaSecurityLevel) -> SigAlgorithm {
        match level {
            MlDsaSecurityLevel::MlDsa44 => SigAlgorithm::Dilithium2,
            MlDsaSecurityLevel::MlDsa65 => SigAlgorithm::Dilithium3,
            MlDsaSecurityLevel::MlDsa87 => SigAlgorithm::Dilithium5,
        }
    }

    fn mldsa_name(level: MlDsaSecurityLevel) -> &'static str {
        match level {
            MlDsaSecurityLevel::MlDsa44 => "ML-DSA-44",
            MlDsaSecurityLevel::MlDsa65 => "ML-DSA-65",
            MlDsaSecurityLevel::MlDsa87 => "ML-DSA-87",
        }
    }

    fn slhdsa_algorithm(level: SlhDsaSecurityLevel) -> SigAlgorithm {
        match level {
            SlhDsaSecurityLevel::SlhDsaSha2128f => SigAlgorithm::SphincsSha2128fSimple,
            SlhDsaSecurityLevel::SlhDsaSha2128s => SigAlgorithm::SphincsSha2128sSimple,
            SlhDsaSecurityLevel::SlhDsaSha2192f => SigAlgorithm::SphincsSha2192fSimple,
            SlhDsaSecurityLevel::SlhDsaSha2192s => SigAlgorithm::SphincsSha2192sSimple,
            SlhDsaSecurityLevel::SlhDsaSha2256f => SigAlgorithm::SphincsSha2256fSimple,
            SlhDsaSecurityLevel::SlhDsaSha2256s => SigAlgorithm::SphincsSha2256sSimple,
        }
    }

    fn slhdsa_variant(level: SlhDsaSecurityLevel) -> &'static str {
        match level {
            SlhDsaSecurityLevel::SlhDsaSha2128f => "SHA2-128f",
            SlhDsaSecurityLevel::SlhDsaSha2128s => "SHA2-128s",
            SlhDsaSecurityLevel::SlhDsaSha2192f => "SHA2-192f",
            SlhDsaSecurityLevel::SlhDsaSha2192s => "SHA2-192s",
            SlhDsaSecurityLevel::SlhDsaSha2256f => "SHA2-256f",
            SlhDsaSecurityLevel::SlhDsaSha2256s => "SHA2-256s",
        }
    }

    fn invalid_length(label: &str, expected: usize, actual: usize) -> HsmError {
        HsmError::InvalidRequest(format!(
            "invalid {label} length: expected {expected} bytes, got {actual}"
        ))
    }

    fn kem_instance(level: MlKemSecurityLevel) -> HsmResult<oqs_kem::Kem> {
        Self::init();
        oqs_kem::Kem::new(Self::mlkem_algorithm(level))
            .map_err(|e| HsmError::crypto(format!("Failed to initialize ML-KEM: {e}")))
    }

    fn sig_instance(algorithm: SigAlgorithm, label: &str) -> HsmResult<oqs_sig::Sig> {
        Self::init();
        oqs_sig::Sig::new(algorithm)
            .map_err(|e| HsmError::crypto(format!("Failed to initialize {label}: {e}")))
    }
}

impl CryptoProvider for OqsCryptoProvider {
    fn generate_mlkem_keypair(&self, security_level: MlKemSecurityLevel) -> HsmResult<KeyMaterial> {
        let kem = Self::kem_instance(security_level)?;

        let (public_key, secret_key) = kem
            .keypair()
            .map_err(|e| HsmError::crypto(format!("Failed to generate ML-KEM keypair: {}", e)))?;

        Ok(KeyMaterial::PostQuantum {
            public_key: public_key.into_vec(),
            private_key: Some(secret_key.into_vec()),
            algorithm: Self::mlkem_name(security_level).to_string(),
        })
    }

    fn generate_mldsa_keypair(&self, security_level: MlDsaSecurityLevel) -> HsmResult<KeyMaterial> {
        let sig = Self::sig_instance(Self::mldsa_algorithm(security_level), "ML-DSA")?;

        let (public_key, secret_key) = sig
            .keypair()
            .map_err(|e| HsmError::crypto(format!("Failed to generate ML-DSA keypair: {}", e)))?;

        Ok(KeyMaterial::PostQuantum {
            public_key: public_key.into_vec(),
            private_key: Some(secret_key.into_vec()),
            algorithm: Self::mldsa_name(security_level).to_string(),
        })
    }

    fn generate_slhdsa_keypair(
        &self,
        security_level: SlhDsaSecurityLevel,
    ) -> HsmResult<KeyMaterial> {
        let sig = Self::sig_instance(Self::slhdsa_algorithm(security_level), "SLH-DSA")?;

        let (public_key, secret_key) = sig
            .keypair()
            .map_err(|e| HsmError::crypto(format!("Failed to generate SLH-DSA keypair: {}", e)))?;

        Ok(KeyMaterial::PostQuantum {
            public_key: public_key.into_vec(),
            private_key: Some(secret_key.into_vec()),
            algorithm: format!("SLH-DSA-{}", Self::slhdsa_variant(security_level)),
        })
    }

    fn mlkem_encapsulate(
        &self,
        public_key: &[u8],
        security_level: MlKemSecurityLevel,
    ) -> HsmResult<(Vec<u8>, Vec<u8>)> {
        let kem = Self::kem_instance(security_level)?;
        let pk_ref = kem.public_key_from_bytes(public_key).ok_or_else(|| {
            Self::invalid_length(
                "ML-KEM public key",
                kem.length_public_key(),
                public_key.len(),
            )
        })?;

        let (ciphertext, shared_secret) = kem
            .encapsulate(pk_ref)
            .map_err(|e| HsmError::crypto(format!("ML-KEM encapsulation failed: {}", e)))?;

        Ok((ciphertext.into_vec(), shared_secret.into_vec()))
    }

    fn mlkem_decapsulate(
        &self,
        ciphertext: &[u8],
        private_key: &[u8],
        security_level: MlKemSecurityLevel,
    ) -> HsmResult<Vec<u8>> {
        let kem = Self::kem_instance(security_level)?;
        let sk_ref = kem.secret_key_from_bytes(private_key).ok_or_else(|| {
            Self::invalid_length(
                "ML-KEM private key",
                kem.length_secret_key(),
                private_key.len(),
            )
        })?;
        let ct_ref = kem.ciphertext_from_bytes(ciphertext).ok_or_else(|| {
            Self::invalid_length(
                "ML-KEM ciphertext",
                kem.length_ciphertext(),
                ciphertext.len(),
            )
        })?;

        let shared_secret = kem
            .decapsulate(sk_ref, ct_ref)
            .map_err(|e| HsmError::crypto(format!("ML-KEM decapsulation failed: {}", e)))?;

        Ok(shared_secret.into_vec())
    }

    fn mldsa_sign(
        &self,
        message: &[u8],
        private_key: &[u8],
        security_level: MlDsaSecurityLevel,
    ) -> HsmResult<Vec<u8>> {
        let sig = Self::sig_instance(Self::mldsa_algorithm(security_level), "ML-DSA")?;
        let sk_ref = sig.secret_key_from_bytes(private_key).ok_or_else(|| {
            Self::invalid_length(
                "ML-DSA private key",
                sig.length_secret_key(),
                private_key.len(),
            )
        })?;

        let signature = sig
            .sign(message, sk_ref)
            .map_err(|e| HsmError::crypto(format!("ML-DSA signing failed: {}", e)))?;

        Ok(signature.into_vec())
    }

    fn mldsa_verify(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
        security_level: MlDsaSecurityLevel,
    ) -> HsmResult<bool> {
        let sig = Self::sig_instance(Self::mldsa_algorithm(security_level), "ML-DSA")?;
        let sig_ref = sig.signature_from_bytes(signature).ok_or_else(|| {
            Self::invalid_length("ML-DSA signature", sig.length_signature(), signature.len())
        })?;
        let pk_ref = sig.public_key_from_bytes(public_key).ok_or_else(|| {
            Self::invalid_length(
                "ML-DSA public key",
                sig.length_public_key(),
                public_key.len(),
            )
        })?;

        Ok(sig.verify(message, sig_ref, pk_ref).is_ok())
    }

    fn slhdsa_sign(
        &self,
        message: &[u8],
        private_key: &[u8],
        security_level: SlhDsaSecurityLevel,
    ) -> HsmResult<Vec<u8>> {
        let sig = Self::sig_instance(Self::slhdsa_algorithm(security_level), "SLH-DSA")?;
        let sk_ref = sig.secret_key_from_bytes(private_key).ok_or_else(|| {
            Self::invalid_length(
                "SLH-DSA private key",
                sig.length_secret_key(),
                private_key.len(),
            )
        })?;

        let signature = sig
            .sign(message, sk_ref)
            .map_err(|e| HsmError::crypto(format!("SLH-DSA signing failed: {}", e)))?;

        Ok(signature.into_vec())
    }

    fn slhdsa_verify(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
        security_level: SlhDsaSecurityLevel,
    ) -> HsmResult<bool> {
        let sig = Self::sig_instance(Self::slhdsa_algorithm(security_level), "SLH-DSA")?;
        let sig_ref = sig.signature_from_bytes(signature).ok_or_else(|| {
            Self::invalid_length("SLH-DSA signature", sig.length_signature(), signature.len())
        })?;
        let pk_ref = sig.public_key_from_bytes(public_key).ok_or_else(|| {
            Self::invalid_length(
                "SLH-DSA public key",
                sig.length_public_key(),
                public_key.len(),
            )
        })?;

        Ok(sig.verify(message, sig_ref, pk_ref).is_ok())
    }

    // Hybrid operations
    fn hybrid_ecdh_mlkem_encapsulate(
        &self,
        _ec_public_key: &[u8],
        pq_public_key: &[u8],
        _ec_type: KeyMaterialType,
        pq_level: MlKemSecurityLevel,
    ) -> HsmResult<(Vec<u8>, Vec<u8>)> {
        // First perform ML-KEM encapsulation
        let (mlkem_ciphertext, mlkem_shared) = self.mlkem_encapsulate(pq_public_key, pq_level)?;

        // For a real implementation, we would also perform ECDH here and combine the shared secrets
        // This is a simplified version that just returns the ML-KEM result
        // In a complete implementation, we would:
        // 1. Generate an ephemeral EC key pair
        // 2. Perform ECDH with the provided EC public key
        // 3. Combine the ECDH shared secret with the ML-KEM shared secret
        // 4. Return the combined ciphertext (EC public key + ML-KEM ciphertext)

        Ok((mlkem_ciphertext, mlkem_shared))
    }

    fn hybrid_ecdh_mlkem_decapsulate(
        &self,
        ciphertext: &[u8],
        _ec_private_key: &[u8],
        pq_private_key: &[u8],
        _ec_type: KeyMaterialType,
        pq_level: MlKemSecurityLevel,
    ) -> HsmResult<Vec<u8>> {
        // In a complete implementation, we would:
        // 1. Extract the EC public key and ML-KEM ciphertext from the combined ciphertext
        // 2. Perform ECDH with the EC private key and the ephemeral EC public key
        // 3. Perform ML-KEM decapsulation
        // 4. Combine the shared secrets

        // This is a simplified version that just performs ML-KEM decapsulation
        let shared_secret = self.mlkem_decapsulate(ciphertext, pq_private_key, pq_level)?;

        Ok(shared_secret)
    }

    fn hybrid_ecdsa_mldsa_sign(
        &self,
        message: &[u8],
        _ec_private_key: &[u8],
        pq_private_key: &[u8],
        _ec_type: KeyMaterialType,
        pq_level: MlDsaSecurityLevel,
    ) -> HsmResult<Vec<u8>> {
        // For a complete hybrid signature implementation, we would:
        // 1. Sign the message with ECDSA
        // 2. Sign the message with ML-DSA
        // 3. Combine the signatures

        // This is a simplified version that just performs ML-DSA signing
        let signature = self.mldsa_sign(message, pq_private_key, pq_level)?;

        Ok(signature)
    }

    fn hybrid_ecdsa_mldsa_verify(
        &self,
        message: &[u8],
        signature: &[u8],
        _ec_public_key: &[u8],
        pq_public_key: &[u8],
        _ec_type: KeyMaterialType,
        pq_level: MlDsaSecurityLevel,
    ) -> HsmResult<bool> {
        // For a complete hybrid verification implementation, we would:
        // 1. Extract the ECDSA and ML-DSA signatures
        // 2. Verify both signatures
        // 3. Return true only if both verifications succeed

        // This is a simplified version that just performs ML-DSA verification
        let valid = self.mldsa_verify(message, signature, pq_public_key, pq_level)?;

        Ok(valid)
    }
}
