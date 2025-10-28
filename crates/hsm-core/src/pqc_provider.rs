use oqs::kem::{self as oqs_kem};
use oqs::sig::{self as oqs_sig};
use rand::{rngs::OsRng, RngCore};

use crate::{
    error::{HsmError, HsmResult},
    models::{KeyMaterial, KeyMaterialType},
    pqc::{
        CryptoProvider, MlDsaSecurityLevel, MlKemSecurityLevel, SlhDsaSecurityLevel,
    },
};

/// OQS-based implementation of the CryptoProvider trait
pub struct OqsCryptoProvider;

impl OqsCryptoProvider {
    pub fn new() -> Self {
        Self
    }

    fn get_mlkem_algorithm(&self, level: MlKemSecurityLevel) -> &'static str {
        match level {
            MlKemSecurityLevel::MlKem512 => "ML-KEM-512",
            MlKemSecurityLevel::MlKem768 => "ML-KEM-768",
            MlKemSecurityLevel::MlKem1024 => "ML-KEM-1024",
        }
    }

    fn get_mldsa_algorithm(&self, level: MlDsaSecurityLevel) -> &'static str {
        match level {
            MlDsaSecurityLevel::MlDsa44 => "ML-DSA-44",
            MlDsaSecurityLevel::MlDsa65 => "ML-DSA-65",
            MlDsaSecurityLevel::MlDsa87 => "ML-DSA-87",
        }
    }

    fn get_slhdsa_algorithm(&self, level: SlhDsaSecurityLevel) -> &'static str {
        match level {
            SlhDsaSecurityLevel::SlhDsaSha2128f => "SLH-DSA-SHA2-128f",
            SlhDsaSecurityLevel::SlhDsaSha2128s => "SLH-DSA-SHA2-128s",
            SlhDsaSecurityLevel::SlhDsaSha2192f => "SLH-DSA-SHA2-192f",
            SlhDsaSecurityLevel::SlhDsaSha2192s => "SLH-DSA-SHA2-192s",
            SlhDsaSecurityLevel::SlhDsaSha2256f => "SLH-DSA-SHA2-256f",
            SlhDsaSecurityLevel::SlhDsaSha2256s => "SLH-DSA-SHA2-256s",
        }
    }
}

impl CryptoProvider for OqsCryptoProvider {
    fn generate_mlkem_keypair(&self, security_level: MlKemSecurityLevel) -> HsmResult<KeyMaterial> {
        let alg_name = self.get_mlkem_algorithm(security_level);
        let kem = oqs_kem::Kem::new(alg_name)
            .map_err(|e| HsmError::crypto(format!("Failed to initialize ML-KEM: {}", e)))?;
        
        let (public_key, secret_key) = kem.keypair()
            .map_err(|e| HsmError::crypto(format!("Failed to generate ML-KEM keypair: {}", e)))?;
        
        Ok(KeyMaterial::PostQuantum {
            public_key,
            private_key: Some(secret_key),
            algorithm: format!("ML-KEM-{}", match security_level {
                MlKemSecurityLevel::MlKem512 => "512",
                MlKemSecurityLevel::MlKem768 => "768",
                MlKemSecurityLevel::MlKem1024 => "1024",
            }),
        })
    }

    fn generate_mldsa_keypair(&self, security_level: MlDsaSecurityLevel) -> HsmResult<KeyMaterial> {
        let alg_name = self.get_mldsa_algorithm(security_level);
        let sig = oqs_sig::Sig::new(alg_name)
            .map_err(|e| HsmError::crypto(format!("Failed to initialize ML-DSA: {}", e)))?;
        
        let (public_key, secret_key) = sig.keypair()
            .map_err(|e| HsmError::crypto(format!("Failed to generate ML-DSA keypair: {}", e)))?;
        
        Ok(KeyMaterial::PostQuantum {
            public_key,
            private_key: Some(secret_key),
            algorithm: format!("ML-DSA-{}", match security_level {
                MlDsaSecurityLevel::MlDsa44 => "44",
                MlDsaSecurityLevel::MlDsa65 => "65",
                MlDsaSecurityLevel::MlDsa87 => "87",
            }),
        })
    }

    fn generate_slhdsa_keypair(&self, security_level: SlhDsaSecurityLevel) -> HsmResult<KeyMaterial> {
        let alg_name = self.get_slhdsa_algorithm(security_level);
        let sig = oqs_sig::Sig::new(alg_name)
            .map_err(|e| HsmError::crypto(format!("Failed to initialize SLH-DSA: {}", e)))?;
        
        let (public_key, secret_key) = sig.keypair()
            .map_err(|e| HsmError::crypto(format!("Failed to generate SLH-DSA keypair: {}", e)))?;
        
        let variant = match security_level {
            SlhDsaSecurityLevel::SlhDsaSha2128f => "SHA2-128f",
            SlhDsaSecurityLevel::SlhDsaSha2128s => "SHA2-128s",
            SlhDsaSecurityLevel::SlhDsaSha2192f => "SHA2-192f",
            SlhDsaSecurityLevel::SlhDsaSha2192s => "SHA2-192s",
            SlhDsaSecurityLevel::SlhDsaSha2256f => "SHA2-256f",
            SlhDsaSecurityLevel::SlhDsaSha2256s => "SHA2-256s",
        };
        
        Ok(KeyMaterial::PostQuantum {
            public_key,
            private_key: Some(secret_key),
            algorithm: format!("SLH-DSA-{}", variant),
        })
    }
    
    fn mlkem_encapsulate(&self, public_key: &[u8], security_level: MlKemSecurityLevel) -> HsmResult<(Vec<u8>, Vec<u8>)> {
        let alg_name = self.get_mlkem_algorithm(security_level);
        let kem = oqs_kem::Kem::new(alg_name)
            .map_err(|e| HsmError::crypto(format!("Failed to initialize ML-KEM: {}", e)))?;
        
        let (ciphertext, shared_secret) = kem.encapsulate(public_key)
            .map_err(|e| HsmError::crypto(format!("ML-KEM encapsulation failed: {}", e)))?;
        
        Ok((ciphertext, shared_secret))
    }
    
    fn mlkem_decapsulate(&self, ciphertext: &[u8], private_key: &[u8], security_level: MlKemSecurityLevel) -> HsmResult<Vec<u8>> {
        let alg_name = self.get_mlkem_algorithm(security_level);
        let kem = oqs_kem::Kem::new(alg_name)
            .map_err(|e| HsmError::crypto(format!("Failed to initialize ML-KEM: {}", e)))?;
        
        let shared_secret = kem.decapsulate(ciphertext, private_key)
            .map_err(|e| HsmError::crypto(format!("ML-KEM decapsulation failed: {}", e)))?;
        
        Ok(shared_secret)
    }
    
    fn mldsa_sign(&self, message: &[u8], private_key: &[u8], security_level: MlDsaSecurityLevel) -> HsmResult<Vec<u8>> {
        let alg_name = self.get_mldsa_algorithm(security_level);
        let sig = oqs_sig::Sig::new(alg_name)
            .map_err(|e| HsmError::crypto(format!("Failed to initialize ML-DSA: {}", e)))?;
        
        let signature = sig.sign(message, private_key)
            .map_err(|e| HsmError::crypto(format!("ML-DSA signing failed: {}", e)))?;
        
        Ok(signature)
    }
    
    fn mldsa_verify(&self, message: &[u8], signature: &[u8], public_key: &[u8], security_level: MlDsaSecurityLevel) -> HsmResult<bool> {
        let alg_name = self.get_mldsa_algorithm(security_level);
        let sig = oqs_sig::Sig::new(alg_name)
            .map_err(|e| HsmError::crypto(format!("Failed to initialize ML-DSA: {}", e)))?;
        
        let result = sig.verify(message, signature, public_key);
        
        // OQS returns Ok(()) for successful verification and Err for failed verification
        match result {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
    
    fn slhdsa_sign(&self, message: &[u8], private_key: &[u8], security_level: SlhDsaSecurityLevel) -> HsmResult<Vec<u8>> {
        let alg_name = self.get_slhdsa_algorithm(security_level);
        let sig = oqs_sig::Sig::new(alg_name)
            .map_err(|e| HsmError::crypto(format!("Failed to initialize SLH-DSA: {}", e)))?;
        
        let signature = sig.sign(message, private_key)
            .map_err(|e| HsmError::crypto(format!("SLH-DSA signing failed: {}", e)))?;
        
        Ok(signature)
    }
    
    fn slhdsa_verify(&self, message: &[u8], signature: &[u8], public_key: &[u8], security_level: SlhDsaSecurityLevel) -> HsmResult<bool> {
        let alg_name = self.get_slhdsa_algorithm(security_level);
        let sig = oqs_sig::Sig::new(alg_name)
            .map_err(|e| HsmError::crypto(format!("Failed to initialize SLH-DSA: {}", e)))?;
        
        let result = sig.verify(message, signature, public_key);
        
        // OQS returns Ok(()) for successful verification and Err for failed verification
        match result {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
    
    // Hybrid operations
    fn hybrid_ecdh_mlkem_encapsulate(
        &self, 
        ec_public_key: &[u8], 
        pq_public_key: &[u8], 
        ec_type: KeyMaterialType, 
        pq_level: MlKemSecurityLevel
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
        ec_private_key: &[u8], 
        pq_private_key: &[u8], 
        ec_type: KeyMaterialType, 
        pq_level: MlKemSecurityLevel
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
        ec_private_key: &[u8], 
        pq_private_key: &[u8], 
        ec_type: KeyMaterialType, 
        pq_level: MlDsaSecurityLevel
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
        ec_public_key: &[u8], 
        pq_public_key: &[u8], 
        ec_type: KeyMaterialType, 
        pq_level: MlDsaSecurityLevel
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