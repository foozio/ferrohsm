use crate::{
    crypto::CryptoEngine,
    models::{KeyAlgorithm, KeyGenerationRequest, KeyMaterial, KeyPurpose},
    pqc::{CryptoProvider, MlDsaSecurityLevel, MlKemSecurityLevel, SlhDsaSecurityLevel},
    pqc_provider::OqsCryptoProvider,
};

fn pq_keypair(material: KeyMaterial) -> (Vec<u8>, Vec<u8>) {
    match material {
        KeyMaterial::PostQuantum {
            public_key,
            private_key: Some(private_key),
            ..
        } => (public_key, private_key),
        KeyMaterial::PostQuantum {
            private_key: None, ..
        } => {
            panic!("provider returned post-quantum material without private key")
        }
        other => panic!("expected post-quantum material, got {other:?}"),
    }
}

#[test]
fn test_ml_kem_roundtrip() {
    let provider = OqsCryptoProvider::new();

    for level in [
        MlKemSecurityLevel::MlKem512,
        MlKemSecurityLevel::MlKem768,
        MlKemSecurityLevel::MlKem1024,
    ] {
        let (public_key, private_key) = pq_keypair(
            provider
                .generate_mlkem_keypair(level)
                .expect("generate ML-KEM keypair"),
        );

        let (ciphertext, shared_secret1) = provider
            .mlkem_encapsulate(&public_key, level)
            .expect("encapsulate with ML-KEM");

        let shared_secret2 = provider
            .mlkem_decapsulate(&ciphertext, &private_key, level)
            .expect("decapsulate with ML-KEM");

        assert_eq!(
            shared_secret1, shared_secret2,
            "ML-KEM shared secrets mismatch for {:?}",
            level
        );
    }
}

#[test]
fn test_ml_dsa_sign_verify() {
    let provider = OqsCryptoProvider::new();
    let message = b"This is a test message for ML-DSA signature";

    for level in [
        MlDsaSecurityLevel::MlDsa44,
        MlDsaSecurityLevel::MlDsa65,
        MlDsaSecurityLevel::MlDsa87,
    ] {
        let (public_key, private_key) = pq_keypair(
            provider
                .generate_mldsa_keypair(level)
                .expect("generate ML-DSA keypair"),
        );

        let signature = provider
            .mldsa_sign(message, &private_key, level)
            .expect("sign with ML-DSA");

        let valid = provider
            .mldsa_verify(message, &signature, &public_key, level)
            .expect("verify ML-DSA signature");

        assert!(
            valid,
            "ML-DSA signature verification failed for {:?}",
            level
        );
    }
}

#[test]
fn test_slh_dsa_sign_verify() {
    let provider = OqsCryptoProvider::new();
    let message = b"This is a test message for SLH-DSA signature";

    for level in [
        SlhDsaSecurityLevel::SlhDsaSha2128f,
        SlhDsaSecurityLevel::SlhDsaSha2256f,
    ] {
        let (public_key, private_key) = pq_keypair(
            provider
                .generate_slhdsa_keypair(level)
                .expect("generate SLH-DSA keypair"),
        );

        let signature = provider
            .slhdsa_sign(message, &private_key, level)
            .expect("sign with SLH-DSA");

        let valid = provider
            .slhdsa_verify(message, &signature, &public_key, level)
            .expect("verify SLH-DSA signature");

        assert!(
            valid,
            "SLH-DSA signature verification failed for {:?}",
            level
        );
    }
}

#[test]
fn test_hybrid_key_operations() {
    let crypto_engine = CryptoEngine::new([0u8; 32], [0u8; 32]);

    let key_request = KeyGenerationRequest {
        algorithm: KeyAlgorithm::HybridP256MlKem768,
        usage: vec![KeyPurpose::Encrypt, KeyPurpose::Decrypt],
        policy_tags: vec![],
        description: Some("test hybrid key".to_string()),
    };

    let generated = crypto_engine
        .generate_material(&key_request)
        .expect("generate hybrid key material");
    let key_material = generated.material;

    if let KeyMaterial::Hybrid {
        ec_private_pem,
        ec_public_pem,
        pq_public_key,
        pq_private_key,
        ..
    } = &key_material
    {
        assert!(
            ec_private_pem.as_ref().is_some(),
            "hybrid key missing EC private component"
        );
        assert!(
            !ec_public_pem.is_empty(),
            "hybrid key missing EC public component"
        );
        assert!(
            !pq_public_key.is_empty(),
            "hybrid key missing PQ public component"
        );
        assert!(
            pq_private_key.as_ref().is_some(),
            "hybrid key missing PQ private component"
        );
    } else {
        panic!("Generated key is not hybrid key material");
    }
}
