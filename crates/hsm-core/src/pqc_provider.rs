use oqs::kem::{self as oqs_kem, Algorithm as KemAlgorithm};
use oqs::sig::{self as oqs_sig, Algorithm as SigAlgorithm};
use p256::{
    PublicKey as P256PublicKey, SecretKey as P256SecretKey,
    ecdh::diffie_hellman,
    ecdsa::signature::{Signer, Verifier},
    elliptic_curve::sec1::ToEncodedPoint,
};
use p384::{PublicKey as P384PublicKey, SecretKey as P384SecretKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::{
    error::{HsmError, HsmResult},
    models::{KeyMaterial, KeyMaterialType},
    pqc::{CryptoProvider, MlDsaSecurityLevel, MlKemSecurityLevel, SlhDsaSecurityLevel},
};

/// OQS-based implementation of the CryptoProvider trait
pub struct OqsCryptoProvider;

impl Default for OqsCryptoProvider {
    fn default() -> Self {
        Self::new()
    }
}

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
            SlhDsaSecurityLevel::SlhDsa128f => SigAlgorithm::SphincsSha2128fSimple,
            SlhDsaSecurityLevel::SlhDsa128s => SigAlgorithm::SphincsSha2128sSimple,
            SlhDsaSecurityLevel::SlhDsa192f => SigAlgorithm::SphincsSha2192fSimple,
            SlhDsaSecurityLevel::SlhDsa192s => SigAlgorithm::SphincsSha2192sSimple,
            SlhDsaSecurityLevel::SlhDsa256f => SigAlgorithm::SphincsSha2256fSimple,
            SlhDsaSecurityLevel::SlhDsa256s => SigAlgorithm::SphincsSha2256sSimple,
        }
    }

    fn slhdsa_variant(level: SlhDsaSecurityLevel) -> &'static str {
        match level {
            SlhDsaSecurityLevel::SlhDsa128f => "128f",
            SlhDsaSecurityLevel::SlhDsa128s => "128s",
            SlhDsaSecurityLevel::SlhDsa192f => "192f",
            SlhDsaSecurityLevel::SlhDsa192s => "192s",
            SlhDsaSecurityLevel::SlhDsa256f => "256f",
            SlhDsaSecurityLevel::SlhDsa256s => "256s",
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
        ec_public_key: &[u8],
        pq_public_key: &[u8],
        ec_type: KeyMaterialType,
        pq_level: MlKemSecurityLevel,
    ) -> HsmResult<(Vec<u8>, Vec<u8>)> {
        // 1. Generate an ephemeral EC key pair
        let (ephemeral_public_key, ec_shared) = match ec_type {
            KeyMaterialType::EcP256 => {
                let ephemeral_sk = P256SecretKey::random(&mut OsRng);
                let ephemeral_pk = ephemeral_sk.public_key();
                let peer_pk = P256PublicKey::from_sec1_bytes(ec_public_key)
                    .map_err(|e| HsmError::crypto(format!("invalid P256 public key: {e}")))?;
                let shared = diffie_hellman(ephemeral_sk.to_nonzero_scalar(), peer_pk.as_affine());
                (
                    ephemeral_pk.to_encoded_point(false).as_bytes().to_vec(),
                    shared.raw_secret_bytes().to_vec(),
                )
            }
            KeyMaterialType::EcP384 => {
                let ephemeral_sk = P384SecretKey::random(&mut OsRng);
                let ephemeral_pk = ephemeral_sk.public_key();
                let peer_pk = P384PublicKey::from_sec1_bytes(ec_public_key)
                    .map_err(|e| HsmError::crypto(format!("invalid P384 public key: {e}")))?;
                let shared = diffie_hellman(ephemeral_sk.to_nonzero_scalar(), peer_pk.as_affine());
                (
                    ephemeral_pk.to_encoded_point(false).as_bytes().to_vec(),
                    shared.raw_secret_bytes().to_vec(),
                )
            }
            _ => return Err(HsmError::unsupported_algorithm("EC type for hybrid KEM")),
        };

        // 2. Perform ML-KEM encapsulation
        let (mlkem_ciphertext, mlkem_shared) = self.mlkem_encapsulate(pq_public_key, pq_level)?;

        // 3. Combine the ECDH shared secret with the ML-KEM shared secret
        let mut combined_secret = Vec::new();
        combined_secret.extend_from_slice(&ec_shared);
        combined_secret.extend_from_slice(&mlkem_shared);
        let mut hasher = Sha256::new();
        hasher.update(&combined_secret);
        let final_shared_secret = hasher.finalize().to_vec();

        // 4. Return the combined ciphertext (EC public key + ML-KEM ciphertext)
        let mut combined_ciphertext = Vec::new();
        combined_ciphertext.extend_from_slice(&ephemeral_public_key);
        combined_ciphertext.extend_from_slice(&mlkem_ciphertext);

        Ok((combined_ciphertext, final_shared_secret))
    }

    fn hybrid_ecdh_mlkem_decapsulate(
        &self,
        ciphertext: &[u8],
        ec_private_key: &[u8],
        pq_private_key: &[u8],
        ec_type: KeyMaterialType,
        pq_level: MlKemSecurityLevel,
    ) -> HsmResult<Vec<u8>> {
        // 1. Extract the EC public key and ML-KEM ciphertext from the combined ciphertext
        let (ephemeral_pk_bytes, mlkem_ciphertext) = match ec_type {
            KeyMaterialType::EcP256 => ciphertext.split_at(65),
            KeyMaterialType::EcP384 => ciphertext.split_at(97),
            _ => return Err(HsmError::unsupported_algorithm("EC type for hybrid KEM")),
        };

        // 2. Perform ECDH with the EC private key and the ephemeral EC public key
        let ec_shared = match ec_type {
            KeyMaterialType::EcP256 => {
                let ephemeral_pk = P256PublicKey::from_sec1_bytes(ephemeral_pk_bytes)
                    .map_err(|e| HsmError::crypto(format!("invalid ephemeral P256 key: {e}")))?;
                let sk = P256SecretKey::from_slice(ec_private_key)
                    .map_err(|e| HsmError::crypto(format!("invalid P256 private key: {e}")))?;
                let shared = diffie_hellman(sk.to_nonzero_scalar(), ephemeral_pk.as_affine());
                shared.raw_secret_bytes().to_vec()
            }
            KeyMaterialType::EcP384 => {
                let ephemeral_pk = P384PublicKey::from_sec1_bytes(ephemeral_pk_bytes)
                    .map_err(|e| HsmError::crypto(format!("invalid ephemeral P384 key: {e}")))?;
                let sk = P384SecretKey::from_slice(ec_private_key)
                    .map_err(|e| HsmError::crypto(format!("invalid P384 private key: {e}")))?;
                let shared = diffie_hellman(sk.to_nonzero_scalar(), ephemeral_pk.as_affine());
                shared.raw_secret_bytes().to_vec()
            }
            _ => return Err(HsmError::unsupported_algorithm("EC type for hybrid KEM")),
        };

        // 3. Perform ML-KEM decapsulation
        let mlkem_shared = self.mlkem_decapsulate(mlkem_ciphertext, pq_private_key, pq_level)?;

        // 4. Combine the shared secrets
        let mut combined_secret = Vec::new();
        combined_secret.extend_from_slice(&ec_shared);
        combined_secret.extend_from_slice(&mlkem_shared);
        let mut hasher = Sha256::new();
        hasher.update(&combined_secret);
        let final_shared_secret = hasher.finalize().to_vec();

        Ok(final_shared_secret)
    }

    fn hybrid_ecdsa_mldsa_sign(
        &self,
        message: &[u8],
        ec_private_key: &[u8],
        pq_private_key: &[u8],
        ec_type: KeyMaterialType,
        pq_level: MlDsaSecurityLevel,
    ) -> HsmResult<Vec<u8>> {
        // 1. Sign the message with ECDSA
        let ec_signature = match ec_type {
            KeyMaterialType::EcP256 => {
                let sk = P256SecretKey::from_slice(ec_private_key)
                    .map_err(|e| HsmError::crypto(format!("invalid p256 private key: {e}")))?;
                let signing_key: p256::ecdsa::SigningKey = sk.into();
                let signature: p256::ecdsa::Signature = signing_key.sign(message);
                signature.to_vec()
            }
            KeyMaterialType::EcP384 => {
                let sk = P384SecretKey::from_slice(ec_private_key)
                    .map_err(|e| HsmError::crypto(format!("invalid p384 private key: {e}")))?;
                let signing_key: p384::ecdsa::SigningKey = sk.into();
                let signature: p384::ecdsa::Signature = signing_key.sign(message);
                signature.to_vec()
            }
            _ => {
                return Err(HsmError::unsupported_algorithm(
                    "EC type for hybrid signing",
                ));
            }
        };

        // 2. Sign the message with ML-DSA
        let pq_signature = self.mldsa_sign(message, pq_private_key, pq_level)?;

        // 3. Combine the signatures
        let mut combined_signature = Vec::new();
        combined_signature.extend_from_slice(&ec_signature);
        combined_signature.extend_from_slice(&pq_signature);

        Ok(combined_signature)
    }

    fn hybrid_ecdsa_mldsa_verify(
        &self,
        message: &[u8],
        signature: &[u8],
        ec_public_key: &[u8],
        pq_public_key: &[u8],
        ec_type: KeyMaterialType,
        pq_level: MlDsaSecurityLevel,
    ) -> HsmResult<bool> {
        // 1. Extract the ECDSA and ML-DSA signatures
        let (ec_sig, pq_sig) = match ec_type {
            KeyMaterialType::EcP256 => signature.split_at(64),
            KeyMaterialType::EcP384 => signature.split_at(96),
            _ => {
                return Err(HsmError::unsupported_algorithm(
                    "EC type for hybrid verification",
                ));
            }
        };

        // 2. Verify both signatures
        let ec_valid = match ec_type {
            KeyMaterialType::EcP256 => {
                let pk = P256PublicKey::from_sec1_bytes(ec_public_key)
                    .map_err(|e| HsmError::crypto(format!("invalid p256 public key: {e}")))?;
                let verifying_key: p256::ecdsa::VerifyingKey = pk.into();
                let signature = p256::ecdsa::Signature::from_slice(ec_sig)
                    .map_err(|e| HsmError::crypto(format!("invalid p256 signature: {e}")))?;
                verifying_key.verify(message, &signature).is_ok()
            }
            KeyMaterialType::EcP384 => {
                let pk = P384PublicKey::from_sec1_bytes(ec_public_key)
                    .map_err(|e| HsmError::crypto(format!("invalid p384 public key: {e}")))?;
                let verifying_key: p384::ecdsa::VerifyingKey = pk.into();
                let signature = p384::ecdsa::Signature::from_slice(ec_sig)
                    .map_err(|e| HsmError::crypto(format!("invalid p384 signature: {e}")))?;
                verifying_key.verify(message, &signature).is_ok()
            }
            _ => false,
        };

        let pq_valid = self.mldsa_verify(message, pq_sig, pq_public_key, pq_level)?;

        // 3. Return true only if both verifications succeed
        Ok(ec_valid && pq_valid)
    }
}
