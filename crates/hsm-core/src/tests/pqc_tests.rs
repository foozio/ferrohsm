use crate::{
    crypto::{CryptoEngine, CryptoOperation, KeyOperationResult},
    models::{KeyAlgorithm, KeyGenerationRequest, KeyMaterial},
    pqc::{MlKemSecurityLevel, MlDsaSecurityLevel, SlhDsaSecurityLevel},
    pqc_provider::OqsCryptoProvider,
    tests::pqc_test_vectors::*,
};

#[test]
fn test_ml_kem_roundtrip() {
    // Test ML-KEM key generation, encapsulation, and decapsulation
    let provider = OqsCryptoProvider::new();
    
    // Test ML-KEM-512
    let (public_key, private_key) = provider
        .ml_kem_keygen(MlKemSecurityLevel::Level1)
        .expect("Failed to generate ML-KEM-512 keypair");
    
    let (ciphertext, shared_secret1) = provider
        .ml_kem_encapsulate(MlKemSecurityLevel::Level1, &public_key)
        .expect("Failed to encapsulate with ML-KEM-512");
    
    let shared_secret2 = provider
        .ml_kem_decapsulate(MlKemSecurityLevel::Level1, &private_key, &ciphertext)
        .expect("Failed to decapsulate with ML-KEM-512");
    
    assert_eq!(shared_secret1, shared_secret2, "ML-KEM-512 shared secrets don't match");
    
    // Test ML-KEM-768
    let (public_key, private_key) = provider
        .ml_kem_keygen(MlKemSecurityLevel::Level3)
        .expect("Failed to generate ML-KEM-768 keypair");
    
    let (ciphertext, shared_secret1) = provider
        .ml_kem_encapsulate(MlKemSecurityLevel::Level3, &public_key)
        .expect("Failed to encapsulate with ML-KEM-768");
    
    let shared_secret2 = provider
        .ml_kem_decapsulate(MlKemSecurityLevel::Level3, &private_key, &ciphertext)
        .expect("Failed to decapsulate with ML-KEM-768");
    
    assert_eq!(shared_secret1, shared_secret2, "ML-KEM-768 shared secrets don't match");
    
    // Test ML-KEM-1024
    let (public_key, private_key) = provider
        .ml_kem_keygen(MlKemSecurityLevel::Level5)
        .expect("Failed to generate ML-KEM-1024 keypair");
    
    let (ciphertext, shared_secret1) = provider
        .ml_kem_encapsulate(MlKemSecurityLevel::Level5, &public_key)
        .expect("Failed to encapsulate with ML-KEM-1024");
    
    let shared_secret2 = provider
        .ml_kem_decapsulate(MlKemSecurityLevel::Level5, &private_key, &ciphertext)
        .expect("Failed to decapsulate with ML-KEM-1024");
    
    assert_eq!(shared_secret1, shared_secret2, "ML-KEM-1024 shared secrets don't match");
}

#[test]
fn test_ml_dsa_sign_verify() {
    // Test ML-DSA signature generation and verification
    let provider = OqsCryptoProvider::new();
    let message = b"This is a test message for ML-DSA signature";
    
    // Test ML-DSA-65
    let (public_key, private_key) = provider
        .ml_dsa_keygen(MlDsaSecurityLevel::Level2)
        .expect("Failed to generate ML-DSA-65 keypair");
    
    let signature = provider
        .ml_dsa_sign(MlDsaSecurityLevel::Level2, &private_key, message)
        .expect("Failed to sign with ML-DSA-65");
    
    let valid = provider
        .ml_dsa_verify(MlDsaSecurityLevel::Level2, &public_key, message, &signature)
        .expect("Failed to verify ML-DSA-65 signature");
    
    assert!(valid, "ML-DSA-65 signature verification failed");
    
    // Test ML-DSA-87
    let (public_key, private_key) = provider
        .ml_dsa_keygen(MlDsaSecurityLevel::Level3)
        .expect("Failed to generate ML-DSA-87 keypair");
    
    let signature = provider
        .ml_dsa_sign(MlDsaSecurityLevel::Level3, &private_key, message)
        .expect("Failed to sign with ML-DSA-87");
    
    let valid = provider
        .ml_dsa_verify(MlDsaSecurityLevel::Level3, &public_key, message, &signature)
        .expect("Failed to verify ML-DSA-87 signature");
    
    assert!(valid, "ML-DSA-87 signature verification failed");
    
    // Test ML-DSA-135
    let (public_key, private_key) = provider
        .ml_dsa_keygen(MlDsaSecurityLevel::Level5)
        .expect("Failed to generate ML-DSA-135 keypair");
    
    let signature = provider
        .ml_dsa_sign(MlDsaSecurityLevel::Level5, &private_key, message)
        .expect("Failed to sign with ML-DSA-135");
    
    let valid = provider
        .ml_dsa_verify(MlDsaSecurityLevel::Level5, &public_key, message, &signature)
        .expect("Failed to verify ML-DSA-135 signature");
    
    assert!(valid, "ML-DSA-135 signature verification failed");
}

#[test]
fn test_slh_dsa_sign_verify() {
    // Test SLH-DSA signature generation and verification
    let provider = OqsCryptoProvider::new();
    let message = b"This is a test message for SLH-DSA signature";
    
    // Test SLH-DSA-SHA2-128f
    let (public_key, private_key) = provider
        .slh_dsa_keygen(SlhDsaSecurityLevel::Level1)
        .expect("Failed to generate SLH-DSA-SHA2-128f keypair");
    
    let signature = provider
        .slh_dsa_sign(SlhDsaSecurityLevel::Level1, &private_key, message)
        .expect("Failed to sign with SLH-DSA-SHA2-128f");
    
    let valid = provider
        .slh_dsa_verify(SlhDsaSecurityLevel::Level1, &public_key, message, &signature)
        .expect("Failed to verify SLH-DSA-SHA2-128f signature");
    
    assert!(valid, "SLH-DSA-SHA2-128f signature verification failed");
    
    // Test SLH-DSA-SHA2-256f
    let (public_key, private_key) = provider
        .slh_dsa_keygen(SlhDsaSecurityLevel::Level5)
        .expect("Failed to generate SLH-DSA-SHA2-256f keypair");
    
    let signature = provider
        .slh_dsa_sign(SlhDsaSecurityLevel::Level5, &private_key, message)
        .expect("Failed to sign with SLH-DSA-SHA2-256f");
    
    let valid = provider
        .slh_dsa_verify(SlhDsaSecurityLevel::Level5, &public_key, message, &signature)
        .expect("Failed to verify SLH-DSA-SHA2-256f signature");
    
    assert!(valid, "SLH-DSA-SHA2-256f signature verification failed");
}

#[test]
fn test_hybrid_key_operations() {
    // Test hybrid key operations (P256 + ML-KEM-768)
    let crypto_engine = CryptoEngine::new([0u8; 32], [0u8; 32]);
    
    // Generate a hybrid key
    let key_request = KeyGenerationRequest {
        algorithm: KeyAlgorithm::HybridP256MlKem768,
        name: "test-hybrid-key".to_string(),
        policy_tags: vec![],
    };
    
    let generated = crypto_engine.generate_key(&key_request).expect("Failed to generate hybrid key");
    
    // Extract the key material
    if let KeyMaterial::Hybrid { 
        ec_public_pem, 
        pq_public_key, 
        ec_private_pem: Some(ec_private), 
        pq_private_key: Some(pq_private), 
        .. 
    } = &generated.material {
        // Test that we can perform operations with the hybrid key
        let plaintext = b"Test hybrid encryption".to_vec();
        
        // Test hybrid encryption/decryption
        let encrypt_op = CryptoOperation::HybridEncrypt { 
            plaintext: plaintext.clone() 
        };
        
        let result = crypto_engine.perform(encrypt_op, &generated.material, &Default::default())
            .expect("Failed to perform hybrid encryption");
        
        if let KeyOperationResult::HybridEncrypted { ciphertext, ephemeral_key } = result {
            let decrypt_op = CryptoOperation::HybridDecrypt { 
                ciphertext, 
                ephemeral_key 
            };
            
            let result = crypto_engine.perform(decrypt_op, &generated.material, &Default::default())
                .expect("Failed to perform hybrid decryption");
            
            if let KeyOperationResult::HybridDecrypted { plaintext: decrypted } = result {
                assert_eq!(plaintext, decrypted, "Hybrid decryption failed to recover original plaintext");
            } else {
                panic!("Unexpected result from hybrid decryption");
            }
        } else {
            panic!("Unexpected result from hybrid encryption");
        }
    } else {
        panic!("Generated key is not a hybrid key");
    }
}