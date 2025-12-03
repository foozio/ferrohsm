use crate::{
    crypto::CryptoEngine,
    models::{KeyAlgorithm, KeyGenerationRequest, KeyMaterial, KeyMaterialType, KeyPurpose},
    pqc::{CryptoProvider, MlDsaSecurityLevel, MlKemSecurityLevel, SlhDsaSecurityLevel},
    pqc_provider::OqsCryptoProvider,
};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey as P256PublicKey, SecretKey as P256SecretKey};
use p384::{PublicKey as P384PublicKey, SecretKey as P384SecretKey};
use pkcs8::{DecodePrivateKey, DecodePublicKey};

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

fn ec_public_sec1_bytes(pem: &str, curve: KeyMaterialType) -> Vec<u8> {
    match curve {
        KeyMaterialType::EcP256 => P256PublicKey::from_public_key_pem(pem)
            .expect("valid p256 public key")
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
        KeyMaterialType::EcP384 => P384PublicKey::from_public_key_pem(pem)
            .expect("valid p384 public key")
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
        other => panic!("unsupported EC curve for hybrid conversion: {other:?}"),
    }
}

fn ec_private_scalar(pem: &str, curve: KeyMaterialType) -> Vec<u8> {
    match curve {
        KeyMaterialType::EcP256 => P256SecretKey::from_pkcs8_pem(pem)
            .expect("valid p256 private key")
            .to_bytes()
            .to_vec(),
        KeyMaterialType::EcP384 => P384SecretKey::from_pkcs8_pem(pem)
            .expect("valid p384 private key")
            .to_bytes()
            .to_vec(),
        other => panic!("unsupported EC curve for hybrid conversion: {other:?}"),
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
        SlhDsaSecurityLevel::SlhDsa128f,
        SlhDsaSecurityLevel::SlhDsa256f,
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
fn test_hybrid_kem_roundtrip() {
    let provider = OqsCryptoProvider::new();
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
        ec_curve,
        ec_private_pem,
        ec_public_pem,
        pq_public_key,
        pq_private_key,
        ..
    } = &key_material
    {
        let ec_public = ec_public_sec1_bytes(ec_public_pem, *ec_curve);
        let ec_private = ec_private_scalar(ec_private_pem.as_ref().unwrap(), *ec_curve);

        let (ciphertext, shared_secret1) = provider
            .hybrid_ecdh_mlkem_encapsulate(
                &ec_public,
                pq_public_key,
                *ec_curve,
                MlKemSecurityLevel::MlKem768,
            )
            .expect("hybrid encapsulate");

        let shared_secret2 = provider
            .hybrid_ecdh_mlkem_decapsulate(
                &ciphertext,
                &ec_private,
                pq_private_key.as_ref().unwrap(),
                *ec_curve,
                MlKemSecurityLevel::MlKem768,
            )
            .expect("hybrid decapsulate");

        assert_eq!(
            shared_secret1, shared_secret2,
            "Hybrid KEM shared secrets mismatch"
        );
    } else {
        panic!("Generated key is not hybrid key material");
    }
}

#[test]
fn test_hybrid_sig_roundtrip() {
    let provider = OqsCryptoProvider::new();
    let crypto_engine = CryptoEngine::new([0u8; 32], [0u8; 32]);
    let message = b"test message for hybrid signature";

    let key_request = KeyGenerationRequest {
        algorithm: KeyAlgorithm::HybridP256MlDsa44,
        usage: vec![KeyPurpose::Sign, KeyPurpose::Verify],
        policy_tags: vec![],
        description: Some("test hybrid sig key".to_string()),
    };

    let generated = crypto_engine
        .generate_material(&key_request)
        .expect("generate hybrid key material");
    let key_material = generated.material;

    if let KeyMaterial::Hybrid {
        ec_curve,
        ec_private_pem,
        ec_public_pem,
        pq_public_key,
        pq_private_key,
        ..
    } = &key_material
    {
        let ec_public = ec_public_sec1_bytes(ec_public_pem, *ec_curve);
        let ec_private = ec_private_scalar(ec_private_pem.as_ref().unwrap(), *ec_curve);

        let signature = provider
            .hybrid_ecdsa_mldsa_sign(
                message,
                &ec_private,
                pq_private_key.as_ref().unwrap(),
                *ec_curve,
                MlDsaSecurityLevel::MlDsa44,
            )
            .expect("hybrid sign");

        let valid = provider
            .hybrid_ecdsa_mldsa_verify(
                message,
                &signature,
                &ec_public,
                pq_public_key,
                *ec_curve,
                MlDsaSecurityLevel::MlDsa44,
            )
            .expect("hybrid verify");

        assert!(valid, "Hybrid signature verification failed");
    } else {
        panic!("Generated key is not hybrid key material");
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
