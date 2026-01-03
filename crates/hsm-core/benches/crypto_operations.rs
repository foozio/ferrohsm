use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hsm_core::{
    crypto::{CryptoEngine, CryptoOperation, KeyOperationResult},
    models::{KeyAlgorithm, KeyGenerationRequest, KeyMaterial, KeyUsage, OperationContext},
};

fn bench_aes_gcm_encrypt(c: &mut Criterion) {
    let engine = CryptoEngine::new([0u8; 32], [0u8; 32]);
    let req = KeyGenerationRequest {
        algorithm: KeyAlgorithm::Aes256Gcm,
        usage: KeyUsage::default(),
        policy_tags: vec![],
        description: None,
    };
    let key = engine.generate_material(&req).unwrap();
    let plaintext = b"Hello, World! This is a test message for benchmarking.";
    let operation = CryptoOperation::Encrypt {
        plaintext: plaintext.to_vec(),
    };
    let ctx = OperationContext::new();

    c.bench_function("aes_gcm_encrypt", |b| {
        b.iter(|| {
            let result = engine.perform(black_box(operation.clone()), black_box(&key.material), black_box(&ctx)).unwrap();
            match result {
                KeyOperationResult::Encrypted { .. } => {}
                _ => panic!("Unexpected result"),
            }
        })
    });
}

fn bench_rsa_sign(c: &mut Criterion) {
    let engine = CryptoEngine::new([0u8; 32], [0u8; 32]);
    let req = KeyGenerationRequest {
        algorithm: KeyAlgorithm::Rsa2048,
        usage: KeyUsage::default(),
        policy_tags: vec![],
        description: None,
    };
    let key = engine.generate_material(&req).unwrap();
    let payload = b"Hello, World! This is a test message for RSA signing.";
    let operation = CryptoOperation::Sign {
        payload: payload.to_vec(),
    };
    let ctx = OperationContext::new();

    c.bench_function("rsa_sign", |b| {
        b.iter(|| {
            let result = engine.perform(black_box(operation.clone()), black_box(&key.material), black_box(&ctx)).unwrap();
            match result {
                KeyOperationResult::Signature { .. } => {}
                _ => panic!("Unexpected result"),
            }
        })
    });
}

fn bench_ecdsa_sign(c: &mut Criterion) {
    let engine = CryptoEngine::new([0u8; 32], [0u8; 32]);
    let req = KeyGenerationRequest {
        algorithm: KeyAlgorithm::P256,
        usage: KeyUsage::default(),
        policy_tags: vec![],
        description: None,
    };
    let key = engine.generate_material(&req).unwrap();
    let payload = b"Hello, World! This is a test message for ECDSA signing.";
    let operation = CryptoOperation::Sign {
        payload: payload.to_vec(),
    };
    let ctx = OperationContext::new();

    c.bench_function("ecdsa_sign", |b| {
        b.iter(|| {
            let result = engine.perform(black_box(operation.clone()), black_box(&key.material), black_box(&ctx)).unwrap();
            match result {
                KeyOperationResult::Signature { .. } => {}
                _ => panic!("Unexpected result"),
            }
        })
    });
}

criterion_group!(benches, bench_aes_gcm_encrypt, bench_rsa_sign, bench_ecdsa_sign);
criterion_main!(benches);