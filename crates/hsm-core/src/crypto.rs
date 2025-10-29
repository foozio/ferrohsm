use std::convert::TryFrom;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::{Aead, Payload}};
use hmac::{Hmac, Mac};
use ::rand::rngs::OsRng;
use ::rand::RngCore;

use ml_dsa::{
    MlDsa44, MlDsa65, MlDsa87,
    signature::{Signer, Verifier, SignatureEncoding},
};
use pkcs8::{PrivateKeyInfo, der::{Decode, EncodePem}, EncodePrivateKey, EncodePublicKey, DecodePublicKey, LineEnding};
use pkcs8::spki::SubjectPublicKeyInfo;
use base64;
use sec1::DecodeEcPrivateKey;
use aws_lc_rs::{encoding::AsDer, rsa, signature::{self, KeyPair}};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use p256::ecdsa::{SigningKey as P256SigningKey};
use p384::ecdsa::{SigningKey as P384SigningKey};
use uuid::Uuid;

use crate::{
    error::{HsmError, HsmResult},
    models::{
        GeneratedKey, KeyAlgorithm, KeyGenerationRequest, KeyMaterial, KeyMaterialType, KeyMetadata,
    },
    rbac::Action,
    storage::{KeyRecord, SealedKeyMaterial},
};
#[cfg(feature = "pqc")]
use crate::{
    pqc::{CryptoProvider, MlDsaSecurityLevel, MlKemSecurityLevel},
    pqc_provider::OqsCryptoProvider,
};

type HmacSha256 = Hmac<Sha256>;

#[cfg(not(feature = "pqc"))]
fn pqc_disabled_error() -> HsmError {
    HsmError::Crypto("post-quantum support requires enabling the `pqc` feature".into())
}

#[cfg(feature = "pqc")]
fn unpack_post_quantum_material(material: KeyMaterial) -> HsmResult<(Vec<u8>, Vec<u8>, String)> {
    match material {
        KeyMaterial::PostQuantum {
            public_key,
            private_key: Some(private_key),
            algorithm,
        } => Ok((public_key, private_key, algorithm)),
        KeyMaterial::PostQuantum {
            private_key: None, ..
        } => Err(HsmError::MissingPrivateKey),
        other => Err(HsmError::Unexpected(format!(
            "expected post-quantum material, got {other:?}"
        ))),
    }
}

#[cfg(feature = "pqc")]
fn mlkem_level_from_label(label: &str) -> HsmResult<MlKemSecurityLevel> {
    match label {
        "ML-KEM-512" => Ok(MlKemSecurityLevel::MlKem512),
        "ML-KEM-768" => Ok(MlKemSecurityLevel::MlKem768),
        "ML-KEM-1024" => Ok(MlKemSecurityLevel::MlKem1024),
        other => Err(HsmError::UnsupportedAlgorithm(other.to_string())),
    }
}

pub struct CryptoEngine {
    master_key: [u8; 32],
    hmac_key: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CryptoOperation {
    Encrypt {
        plaintext: Vec<u8>,
    },
    Decrypt {
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        associated_data: Option<Vec<u8>>,
    },
    Sign {
        payload: Vec<u8>,
    },
    Verify {
        payload: Vec<u8>,
        signature: Vec<u8>,
    },
    WrapKey {
        key_material: Vec<u8>,
    },
    UnwrapKey {
        wrapped: Vec<u8>,
        nonce: Vec<u8>,
    },
    // Post-quantum operations
    KemEncapsulate {
        recipient_public_key: Option<Vec<u8>>,
    },
    KemDecapsulate {
        ciphertext: Vec<u8>,
    },
    HybridEncrypt {
        plaintext: Vec<u8>,
    },
    HybridDecrypt {
        ciphertext: Vec<u8>,
        ephemeral_key: Vec<u8>,
    },
}

impl CryptoOperation {
    pub fn as_action(&self) -> Action {
        match self {
            CryptoOperation::Encrypt { .. } => Action::Encrypt,
            CryptoOperation::Decrypt { .. } => Action::Decrypt,
            CryptoOperation::Sign { .. } => Action::Sign,
            CryptoOperation::Verify { .. } => Action::Verify,
            CryptoOperation::WrapKey { .. } => Action::WrapKey,
            CryptoOperation::UnwrapKey { .. } => Action::UnwrapKey,
            CryptoOperation::KemEncapsulate { .. } => Action::Encrypt,
            CryptoOperation::KemDecapsulate { .. } => Action::Decrypt,
            CryptoOperation::HybridEncrypt { .. } => Action::Encrypt,
            CryptoOperation::HybridDecrypt { .. } => Action::Decrypt,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyOperationResult {
    Encrypted {
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
    },
    Decrypted {
        plaintext: Vec<u8>,
    },
    Signature {
        signature: Vec<u8>,
    },
    Verified {
        valid: bool,
    },
    Wrapped {
        wrapped: Vec<u8>,
        nonce: Vec<u8>,
    },
    Unwrapped {
        key_material: Vec<u8>,
    },
    // Post-quantum operation results
    KemEncapsulated {
        ciphertext: Vec<u8>,
        shared_secret: Vec<u8>,
    },
    KemDecapsulated {
        shared_secret: Vec<u8>,
    },
    HybridEncrypted {
        ciphertext: Vec<u8>,
        ephemeral_key: Vec<u8>,
    },
    HybridDecrypted {
        plaintext: Vec<u8>,
    },
}

impl CryptoEngine {
    pub fn new(master_key: [u8; 32], hmac_key: [u8; 32]) -> Self {
        Self {
            master_key,
            hmac_key,
        }
    }

    pub fn generate_material(&self, req: &KeyGenerationRequest) -> HsmResult<GeneratedKey> {
        let id = Uuid::new_v4().to_string();
        let material = match req.algorithm {
            KeyAlgorithm::Aes256Gcm => {
                let mut key = vec![0u8; 32];
                OsRng.fill_bytes(&mut key);
                KeyMaterial::Symmetric { key }
            }
            KeyAlgorithm::Rsa2048 => {
                let key_pair = rsa::KeyPair::generate(rsa::KeySize::Rsa2048).map_err(HsmError::crypto)?;
                rsa_material_aws(key_pair)?
            }
            KeyAlgorithm::Rsa4096 => {
                let key_pair = rsa::KeyPair::generate(rsa::KeySize::Rsa4096).map_err(HsmError::crypto)?;
                rsa_material_aws(key_pair)?
            }
            KeyAlgorithm::P256 => {
                let signing = P256SigningKey::random(&mut OsRng);
                let private_pem = signing
                    .to_pkcs8_pem(LineEnding::LF)
                    .map_err(HsmError::crypto)?
                    .to_string();
                let public_pem = signing
                    .verifying_key()
                    .to_public_key_pem(LineEnding::LF)
                    .map_err(HsmError::crypto)?;
                ecc_material_pem(private_pem, public_pem, KeyMaterialType::EcP256)
            }
            KeyAlgorithm::P384 => {
                let signing = P384SigningKey::random(&mut OsRng);
                let private_pem = signing
                    .to_pkcs8_pem(LineEnding::LF)
                    .map_err(HsmError::crypto)?
                    .to_string();
                let public_pem = signing
                    .verifying_key()
                    .to_public_key_pem(LineEnding::LF)
                    .map_err(HsmError::crypto)?;
                ecc_material_pem(private_pem, public_pem, KeyMaterialType::EcP384)
            }
            KeyAlgorithm::MlKem512 => {
                #[cfg(feature = "pqc")]
                {
                    let provider = OqsCryptoProvider::new();
                    provider.generate_mlkem_keypair(MlKemSecurityLevel::MlKem512)?
                }
                #[cfg(not(feature = "pqc"))]
                {
                    return Err(HsmError::UnsupportedAlgorithm(
                        "PQC not enabled".to_string(),
                    ));
                }
            }
            KeyAlgorithm::MlKem768 => {
                #[cfg(feature = "pqc")]
                {
                    let provider = OqsCryptoProvider::new();
                    provider.generate_mlkem_keypair(MlKemSecurityLevel::MlKem768)?
                }
                #[cfg(not(feature = "pqc"))]
                {
                    return Err(HsmError::UnsupportedAlgorithm(
                        "PQC not enabled".to_string(),
                    ));
                }
            }
            KeyAlgorithm::MlKem1024 => {
                #[cfg(feature = "pqc")]
                {
                    let provider = OqsCryptoProvider::new();
                    provider.generate_mlkem_keypair(MlKemSecurityLevel::MlKem1024)?
                }
                #[cfg(not(feature = "pqc"))]
                {
                    return Err(HsmError::UnsupportedAlgorithm(
                        "PQC not enabled".to_string(),
                    ));
                }
            }
            KeyAlgorithm::MlDsa44 => {
                #[cfg(feature = "pqc")]
                {
                    let provider = OqsCryptoProvider::new();
                    provider.generate_mldsa_keypair(MlDsaSecurityLevel::MlDsa44)?
                }
                #[cfg(not(feature = "pqc"))]
                {
                    return Err(HsmError::UnsupportedAlgorithm(
                        "PQC not enabled".to_string(),
                    ));
                }
            }
            KeyAlgorithm::MlDsa65 => {
                #[cfg(feature = "pqc")]
                {
                    let provider = OqsCryptoProvider::new();
                    provider.generate_mldsa_keypair(MlDsaSecurityLevel::MlDsa65)?
                }
                #[cfg(not(feature = "pqc"))]
                {
                    return Err(HsmError::UnsupportedAlgorithm(
                        "PQC not enabled".to_string(),
                    ));
                }
            }
            KeyAlgorithm::MlDsa87 => {
                #[cfg(feature = "pqc")]
                {
                    let provider = OqsCryptoProvider::new();
                    provider.generate_mldsa_keypair(MlDsaSecurityLevel::MlDsa87)?
                }
                #[cfg(not(feature = "pqc"))]
                {
                    return Err(HsmError::UnsupportedAlgorithm(
                        "PQC not enabled".to_string(),
                    ));
                }
            }
            KeyAlgorithm::SlhDsa128f => {
                return Err(HsmError::UnsupportedAlgorithm(
                    "SLH-DSA not implemented".to_string(),
                ));
            }
            KeyAlgorithm::SlhDsa128s => {
                return Err(HsmError::UnsupportedAlgorithm(
                    "SLH-DSA not implemented".to_string(),
                ));
            }
            KeyAlgorithm::SlhDsa192f => {
                return Err(HsmError::UnsupportedAlgorithm(
                    "SLH-DSA not implemented".to_string(),
                ));
            }
            KeyAlgorithm::SlhDsa192s => {
                return Err(HsmError::UnsupportedAlgorithm(
                    "SLH-DSA not implemented".to_string(),
                ));
            }
            KeyAlgorithm::SlhDsa256f => {
                return Err(HsmError::UnsupportedAlgorithm(
                    "SLH-DSA not implemented".to_string(),
                ));
            }
            KeyAlgorithm::SlhDsa256s => {
                return Err(HsmError::UnsupportedAlgorithm(
                    "SLH-DSA not implemented".to_string(),
                ));
            }
            KeyAlgorithm::HybridP256MlKem512 => {
                #[cfg(feature = "pqc")]
                {
                    let ec_signing = P256SigningKey::random(&mut OsRng);
                    let ec_private_pem = ec_signing
                        .to_pkcs8_pem(LineEnding::LF)
                        .map_err(|e| HsmError::crypto(format!("P256 pem: {e}")))?
                        .to_string();
                    let ec_public_pem = ec_signing
                        .verifying_key()
                        .to_public_key_pem(LineEnding::LF)
                        .map_err(|e| HsmError::crypto(format!("P256 public pem: {e}")))?;
                    let provider = OqsCryptoProvider::new();
                    let (pq_public_key, pq_private_key, pq_algorithm) =
                        unpack_post_quantum_material(
                            provider.generate_mlkem_keypair(MlKemSecurityLevel::MlKem512)?,
                        )?;
                    KeyMaterial::Hybrid {
                        ec_curve: KeyMaterialType::EcP256,
                        ec_private_pem: Some(ec_private_pem),
                        ec_public_pem,
                        pq_algorithm,
                        pq_public_key,
                        pq_private_key: Some(pq_private_key),
                    }
                }
                #[cfg(not(feature = "pqc"))]
                {
                    return Err(HsmError::UnsupportedAlgorithm(
                        "PQC not enabled".to_string(),
                    ));
                }
            }
            KeyAlgorithm::HybridP256MlKem768 => {
                #[cfg(feature = "pqc")]
                {
                    let ec_signing = P256SigningKey::random(&mut OsRng);
                    let ec_private_pem = ec_signing
                        .to_pkcs8_pem(LineEnding::LF)
                        .map_err(|e| HsmError::crypto(format!("P256 pem: {e}")))?
                        .to_string();
                    let ec_public_pem = ec_signing
                        .verifying_key()
                        .to_public_key_pem(LineEnding::LF)
                        .map_err(|e| HsmError::crypto(format!("P256 public pem: {e}")))?;
                    let provider = OqsCryptoProvider::new();
                    let (pq_public_key, pq_private_key, pq_algorithm) =
                        unpack_post_quantum_material(
                            provider.generate_mlkem_keypair(MlKemSecurityLevel::MlKem768)?,
                        )?;
                    KeyMaterial::Hybrid {
                        ec_curve: KeyMaterialType::EcP256,
                        ec_private_pem: Some(ec_private_pem),
                        ec_public_pem,
                        pq_algorithm,
                        pq_public_key,
                        pq_private_key: Some(pq_private_key),
                    }
                }
                #[cfg(not(feature = "pqc"))]
                {
                    return Err(HsmError::UnsupportedAlgorithm(
                        "PQC not enabled".to_string(),
                    ));
                }
            }
            KeyAlgorithm::HybridP384MlKem1024 => {
                #[cfg(feature = "pqc")]
                {
                    let ec_signing = P384SigningKey::random(&mut OsRng);
                    let ec_private_pem = ec_signing
                        .to_pkcs8_pem(LineEnding::LF)
                        .map_err(|e| HsmError::crypto(format!("P384 pem: {e}")))?
                        .to_string();
                    let ec_public_pem = ec_signing
                        .verifying_key()
                        .to_public_key_pem(LineEnding::LF)
                        .map_err(|e| HsmError::crypto(format!("P384 public pem: {e}")))?;
                    let provider = OqsCryptoProvider::new();
                    let (pq_public_key, pq_private_key, pq_algorithm) =
                        unpack_post_quantum_material(
                            provider.generate_mlkem_keypair(MlKemSecurityLevel::MlKem1024)?,
                        )?;
                    KeyMaterial::Hybrid {
                        ec_curve: KeyMaterialType::EcP384,
                        ec_private_pem: Some(ec_private_pem),
                        ec_public_pem,
                        pq_algorithm,
                        pq_public_key,
                        pq_private_key: Some(pq_private_key),
                    }
                }
                #[cfg(not(feature = "pqc"))]
                {
                    return Err(HsmError::UnsupportedAlgorithm(
                        "PQC not enabled".to_string(),
                    ));
                }
            }
            KeyAlgorithm::HybridP256MlDsa44 => {
                #[cfg(feature = "pqc")]
                {
                    let ec_signing = P256SigningKey::random(&mut OsRng);
                    let ec_private_pem = ec_signing
                        .to_pkcs8_pem(LineEnding::LF)
                        .map_err(|e| HsmError::crypto(format!("P256 pem: {e}")))?
                        .to_string();
                    let ec_public_pem = ec_signing
                        .verifying_key()
                        .to_public_key_pem(LineEnding::LF)
                        .map_err(|e| HsmError::crypto(format!("P256 public pem: {e}")))?;
                    let provider = OqsCryptoProvider::new();
                    let (pq_public_key, pq_private_key, pq_algorithm) =
                        unpack_post_quantum_material(
                            provider.generate_mldsa_keypair(MlDsaSecurityLevel::MlDsa44)?,
                        )?;
                    KeyMaterial::Hybrid {
                        ec_curve: KeyMaterialType::EcP256,
                        ec_private_pem: Some(ec_private_pem),
                        ec_public_pem,
                        pq_algorithm,
                        pq_public_key,
                        pq_private_key: Some(pq_private_key),
                    }
                }
                #[cfg(not(feature = "pqc"))]
                {
                    return Err(HsmError::UnsupportedAlgorithm(
                        "PQC not enabled".to_string(),
                    ));
                }
            }
            KeyAlgorithm::HybridP256MlDsa65 => {
                #[cfg(feature = "pqc")]
                {
                    let ec_signing = P256SigningKey::random(&mut OsRng);
                    let ec_private_pem = ec_signing
                        .to_pkcs8_pem(LineEnding::LF)
                        .map_err(|e| HsmError::crypto(format!("P256 pem: {e}")))?
                        .to_string();
                    let ec_public_pem = ec_signing
                        .verifying_key()
                        .to_public_key_pem(LineEnding::LF)
                        .map_err(|e| HsmError::crypto(format!("P256 public pem: {e}")))?;
                    let provider = OqsCryptoProvider::new();
                    let (pq_public_key, pq_private_key, pq_algorithm) =
                        unpack_post_quantum_material(
                            provider.generate_mldsa_keypair(MlDsaSecurityLevel::MlDsa65)?,
                        )?;
                    KeyMaterial::Hybrid {
                        ec_curve: KeyMaterialType::EcP256,
                        ec_private_pem: Some(ec_private_pem),
                        ec_public_pem,
                        pq_algorithm,
                        pq_public_key,
                        pq_private_key: Some(pq_private_key),
                    }
                }
                #[cfg(not(feature = "pqc"))]
                {
                    return Err(HsmError::UnsupportedAlgorithm(
                        "PQC not enabled".to_string(),
                    ));
                }
            }
            KeyAlgorithm::HybridP384MlDsa87 => {
                #[cfg(feature = "pqc")]
                {
                    let ec_signing = P384SigningKey::random(&mut OsRng);
                    let ec_private_pem = ec_signing
                        .to_pkcs8_pem(LineEnding::LF)
                        .map_err(|e| HsmError::crypto(format!("P384 pem: {e}")))?
                        .to_string();
                    let ec_public_pem = ec_signing
                        .verifying_key()
                        .to_public_key_pem(LineEnding::LF)
                        .map_err(|e| HsmError::crypto(format!("P384 public pem: {e}")))?;
                    let provider = OqsCryptoProvider::new();
                    let (pq_public_key, pq_private_key, pq_algorithm) =
                        unpack_post_quantum_material(
                            provider.generate_mldsa_keypair(MlDsaSecurityLevel::MlDsa87)?,
                        )?;
                    KeyMaterial::Hybrid {
                        ec_curve: KeyMaterialType::EcP384,
                        ec_private_pem: Some(ec_private_pem),
                        ec_public_pem,
                        pq_algorithm,
                        pq_public_key,
                        pq_private_key: Some(pq_private_key),
                    }
                }
                #[cfg(not(feature = "pqc"))]
                {
                    return Err(HsmError::UnsupportedAlgorithm(
                        "PQC not enabled".to_string(),
                    ));
                }
            }
        };
        Ok(GeneratedKey { id, material })
    }

    pub fn seal_key(&self, metadata: &KeyMetadata, material: KeyMaterial) -> HsmResult<KeyRecord> {
        let (material_type, plaintext) = self.serialise_material(&material)?;
        let cipher = Aes256Gcm::new_from_slice(&self.master_key).map_err(HsmError::crypto)?;
        let nonce = self.random_nonce();
        let aad = metadata.id.as_bytes();
        #[allow(deprecated)]
        let ciphertext = cipher
            .encrypt(
                &Nonce::clone_from_slice(&nonce),
                Payload {
                    aad,
                    msg: &plaintext,
                },
            )
            .map_err(HsmError::crypto)?;
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&self.hmac_key).map_err(HsmError::crypto)?;
        mac.update(&nonce);
        mac.update(aad);
        mac.update(&ciphertext);
        let mac_bytes = mac.finalize().into_bytes().to_vec();
        Ok(KeyRecord {
            metadata: metadata.clone(),
            sealed: SealedKeyMaterial {
                nonce,
                ciphertext,
                hmac: mac_bytes,
                material_type,
            },
        })
    }

    pub fn open_key(&self, record: &KeyRecord) -> HsmResult<KeyMaterial> {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&self.hmac_key).map_err(HsmError::crypto)?;
        mac.update(&record.sealed.nonce);
        mac.update(record.metadata.id.as_bytes());
        mac.update(&record.sealed.ciphertext);
        mac.verify_slice(&record.sealed.hmac)
            .map_err(|_| HsmError::TamperDetected(record.metadata.id.clone()))?;

        let cipher = Aes256Gcm::new_from_slice(&self.master_key).map_err(HsmError::crypto)?;
        #[allow(deprecated)]
        let plaintext = cipher
            .decrypt(
                &Nonce::clone_from_slice(&record.sealed.nonce),
                Payload {
                    aad: record.metadata.id.as_bytes(),
                    msg: &record.sealed.ciphertext,
                },
            )
            .map_err(HsmError::crypto)?;
        self.deserialise_material(&record.sealed.material_type, &plaintext)
    }

    pub fn perform(
        &self,
        operation: CryptoOperation,
        material: &KeyMaterial,
        ctx: &crate::models::OperationContext,
    ) -> HsmResult<KeyOperationResult> {
        match operation {
            CryptoOperation::Encrypt { plaintext } => {
                let key = expect_symmetric(material)?;
                let cipher = Aes256Gcm::new_from_slice(key).map_err(HsmError::crypto)?;
                let nonce = self.random_nonce();
                let aad = ctx.associated_data.as_deref().unwrap_or_default();
                #[allow(deprecated)]
                let ciphertext = cipher
                    .encrypt(
                        &Nonce::clone_from_slice(&nonce),
                        Payload {
                            aad,
                            msg: &plaintext,
                        },
                    )
                    .map_err(HsmError::crypto)?;
                Ok(KeyOperationResult::Encrypted { ciphertext, nonce })
            }
            CryptoOperation::Decrypt {
                ciphertext,
                nonce,
                associated_data,
            } => {
                let key = expect_symmetric(material)?;
                let cipher = Aes256Gcm::new_from_slice(key).map_err(HsmError::crypto)?;
                let aad = associated_data
                    .as_deref()
                    .unwrap_or_else(|| ctx.associated_data.as_deref().unwrap_or_default());
                #[allow(deprecated)]
                let plaintext = cipher
                    .decrypt(
                        &Nonce::clone_from_slice(&nonce),
                        Payload {
                            aad,
                            msg: &ciphertext,
                        },
                    )
                    .map_err(HsmError::crypto)?;
                Ok(KeyOperationResult::Decrypted { plaintext })
            }
            CryptoOperation::Sign { payload } => match material {
                KeyMaterial::Rsa { private_pem, .. } => {
                    let key_pair = rsa::KeyPair::from_pkcs8(private_pem.as_bytes()).map_err(HsmError::crypto)?;
                    let mut signature = vec![0; key_pair.public_modulus_len()];
                    let rng = aws_lc_rs::rand::SystemRandom::new();
                    key_pair.sign(&signature::RSA_PKCS1_SHA256, &rng, &payload, &mut signature).map_err(HsmError::crypto)?;
                    Ok(KeyOperationResult::Signature { signature })
                }
                KeyMaterial::Ec { private_pem, .. } => {
                    let signing_key = p256::ecdsa::SigningKey::from_sec1_pem(private_pem)
                        .map_err(HsmError::crypto)?;
                    let signature: p256::ecdsa::Signature = signing_key.sign(&payload);
                    Ok(KeyOperationResult::Signature {
                        signature: signature.to_vec(),
                    })
                }
                KeyMaterial::PostQuantum {
                    private_key,
                    algorithm,
                    ..
                } => {
                    let Some(private_key) = private_key else {
                        return Err(HsmError::MissingPrivateKey);
                    };
                    let signature = match algorithm.as_str() {
                        "ML-DSA-44" => {
                            let pki = PrivateKeyInfo::from_der(private_key.as_ref())
                                .map_err(|e| HsmError::crypto(e.to_string()))?;
                            let signing_key = <ml_dsa::SigningKey<MlDsa44>>::try_from(pki)
                                .map_err(|e| HsmError::crypto(e.to_string()))?;
                            let signature: ml_dsa::Signature<MlDsa44> = signing_key.sign(&payload);
                            signature.to_vec()
                        }
                        "ML-DSA-65" => {
                            let pki = PrivateKeyInfo::from_der(private_key.as_ref())
                                .map_err(|e| HsmError::crypto(e.to_string()))?;
                            let signing_key = <ml_dsa::SigningKey<MlDsa65>>::try_from(pki)
                                .map_err(|e| HsmError::crypto(e.to_string()))?;
                            let signature: ml_dsa::Signature<MlDsa65> = signing_key.sign(&payload);
                            signature.to_vec()
                        }
                        "ML-DSA-87" => {
                            let pki = PrivateKeyInfo::from_der(private_key.as_ref())
                                .map_err(|e| HsmError::crypto(e.to_string()))?;
                            let signing_key = <ml_dsa::SigningKey<MlDsa87>>::try_from(pki)
                                .map_err(|e| HsmError::crypto(e.to_string()))?;
                            let signature: ml_dsa::Signature<MlDsa87> = signing_key.sign(&payload);
                            signature.to_vec()
                        }
                        _ => {
                            return Err(HsmError::UnsupportedAlgorithm(
                                "Only ML-DSA algorithms can be used for signing".to_string(),
                            ));
                        }
                    };
                    Ok(KeyOperationResult::Signature { signature })
                }

                KeyMaterial::Hybrid {
                    ec_private_pem,
                    pq_private_key,
                    ..
                } => match (ec_private_pem, pq_private_key) {
                    (Some(private_pem), _) => {
                        let signing_key = p256::ecdsa::SigningKey::from_sec1_pem(private_pem)
                            .map_err(HsmError::crypto)?;
                        let signature: p256::ecdsa::Signature = signing_key.sign(&payload);
                        Ok(KeyOperationResult::Signature {
                            signature: signature.to_vec(),
                        })
                    }
                    (_, Some(private_key)) => {
                        let signature = {
                            let pki = PrivateKeyInfo::from_der(private_key.as_ref())
                                .map_err(|e| HsmError::crypto(e.to_string()))?;
                            let signing_key = <ml_dsa::SigningKey<MlDsa44>>::try_from(pki)
                                .map_err(|e| HsmError::crypto(e.to_string()))?;
                            signing_key.sign(&payload).to_vec()
                        };
                        Ok(KeyOperationResult::Signature { signature })
                    }
                    _ => Err(HsmError::MissingPrivateKey),
                },
                _ => Err(HsmError::UnsupportedAlgorithm(
                    "Unsupported signing algorithm".to_string(),
                )),
            },
            CryptoOperation::Verify { payload, signature } => match material {
                KeyMaterial::Rsa { public_pem, .. } => {
                    let der = {
                        let lines: Vec<&str> = public_pem.lines().collect();
                        if lines.len() < 3 { return Err(HsmError::crypto("Invalid PEM")) }
                        let base64 = lines[1..lines.len()-1].join("");
                        base64::decode(base64).map_err(HsmError::crypto)?
                    };
                    let public_key = signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, &der);
                    let valid = public_key.verify(&payload, &signature).is_ok();
                    Ok(KeyOperationResult::Verified { valid })
                }
                KeyMaterial::Ec { public_pem, .. } => {
                    let verifying_key =
                        p256::ecdsa::VerifyingKey::from_public_key_der(public_pem.as_bytes())
                            .map_err(HsmError::crypto)?;
                    let signature = p256::ecdsa::Signature::from_slice(&signature)
                        .map_err(|e| HsmError::crypto(e.to_string()))?;
                    let valid = verifying_key.verify(&payload, &signature).is_ok();
                    Ok(KeyOperationResult::Verified { valid })
                }
                KeyMaterial::PostQuantum {
                    public_key,
                    algorithm,
                    ..
                } => {
                    let valid = match algorithm.as_str() {
                        "ML-DSA-44" => {
                            let spki = SubjectPublicKeyInfo::from_der(public_key.as_ref())
                                .map_err(|e| HsmError::crypto(e.to_string()))?;
                            let verifying_key = <ml_dsa::VerifyingKey<MlDsa44>>::try_from(spki)
                                .map_err(|e| HsmError::crypto(e.to_string()))?;
                            let signature = ml_dsa::Signature::try_from(signature.as_ref())
                                .map_err(|e| HsmError::crypto(e.to_string()))?;
                            verifying_key.verify(&payload, &signature).is_ok()
                        }
                        "ML-DSA-65" => {
                            let spki = SubjectPublicKeyInfo::from_der(public_key.as_ref())
                                .map_err(|e| HsmError::crypto(e.to_string()))?;
                            let verifying_key = <ml_dsa::VerifyingKey<MlDsa65>>::try_from(spki)
                                .map_err(|e| HsmError::crypto(e.to_string()))?;
                            let signature = ml_dsa::Signature::try_from(signature.as_ref())
                                .map_err(|e| HsmError::crypto(e.to_string()))?;
                            verifying_key.verify(&payload, &signature).is_ok()
                        }
                        "ML-DSA-87" => {
                            let spki = SubjectPublicKeyInfo::from_der(public_key.as_ref())
                                .map_err(|e| HsmError::crypto(e.to_string()))?;
                            let verifying_key = <ml_dsa::VerifyingKey<MlDsa87>>::try_from(spki)
                                .map_err(|e| HsmError::crypto(e.to_string()))?;
                            let signature = ml_dsa::Signature::try_from(signature.as_ref())
                                .map_err(|e| HsmError::crypto(e.to_string()))?;
                            verifying_key.verify(&payload, &signature).is_ok()
                        }
                        _ => {
                            return Err(HsmError::UnsupportedAlgorithm(
                                "Only ML-DSA algorithms can be used for verification".to_string(),
                            ));
                        }
                    };
                    Ok(KeyOperationResult::Verified { valid })
                }
                KeyMaterial::Hybrid {
                    ec_public_pem,
                    pq_public_key,
                    ..
                } => {
                    // Try ECDSA verification first
                    let ecdsa_result =
                        p256::ecdsa::VerifyingKey::from_public_key_der(ec_public_pem.as_bytes())
                            .map_err(|e| HsmError::crypto(e.to_string()))
                            .and_then(|verifying_key| {
                                p256::ecdsa::Signature::from_slice(&signature)
                                    .map_err(|e| HsmError::crypto(e.to_string()))
                                    .map(|sig| verifying_key.verify(&payload, &sig).is_ok())
                            })
                            .unwrap_or(false);

                    if ecdsa_result {
                        Ok(KeyOperationResult::Verified { valid: true })
                    } else {
                        // Try ML-DSA verification
                        let valid = {
                            let spki = SubjectPublicKeyInfo::from_der(pq_public_key.as_ref())
                                .map_err(|e| HsmError::crypto(e.to_string()))?;
                            let verifying_key = <ml_dsa::VerifyingKey<MlDsa44>>::try_from(spki)
                                .map_err(|e| HsmError::crypto(e.to_string()))?;
                            let signature = ml_dsa::Signature::try_from(signature.as_ref())
                                .map_err(|e| HsmError::crypto(e.to_string()))?;
                            verifying_key.verify(&payload, &signature).is_ok()
                        };
                        Ok(KeyOperationResult::Verified { valid })
                    }
                }
                _ => Err(HsmError::UnsupportedAlgorithm(
                    "Unsupported verification algorithm".to_string(),
                )),
            },
            CryptoOperation::WrapKey { key_material } => {
                let key = expect_symmetric(material)?;
                let cipher = Aes256Gcm::new_from_slice(key).map_err(HsmError::crypto)?;
                let nonce = self.random_nonce();
                #[allow(deprecated)]
                let wrapped = cipher
                    .encrypt(
                        &Nonce::clone_from_slice(&nonce),
                        Payload {
                            aad: &[],
                            msg: &key_material,
                        },
                    )
                    .map_err(HsmError::crypto)?;
                Ok(KeyOperationResult::Wrapped { wrapped, nonce })
            }
            CryptoOperation::UnwrapKey { wrapped, nonce } => {
                let key = expect_symmetric(material)?;
                let cipher = Aes256Gcm::new_from_slice(key).map_err(HsmError::crypto)?;
                #[allow(deprecated)]
                let key_material = cipher
                    .decrypt(
                        &Nonce::clone_from_slice(&nonce),
                        Payload {
                            aad: &[],
                            msg: &wrapped,
                        },
                    )
                    .map_err(HsmError::crypto)?;
                Ok(KeyOperationResult::Unwrapped { key_material })
            }
            CryptoOperation::KemEncapsulate {
                recipient_public_key,
            } => {
                #[cfg(feature = "pqc")]
                {
                    match material {
                        KeyMaterial::PostQuantum {
                            algorithm,
                            public_key,
                            ..
                        } => {
                            let target_public_key =
                                recipient_public_key.as_ref().unwrap_or(public_key);
                            let provider = OqsCryptoProvider::new();
                            if algorithm.starts_with("ML-KEM") {
                                let security_level = mlkem_level_from_label(algorithm.as_str())?;
                                let (ciphertext, shared_secret) = provider
                                    .mlkem_encapsulate(target_public_key, security_level)
                                    .map_err(|e| {
                                        HsmError::crypto(format!("ML-KEM encapsulate: {e}"))
                                    })?;
                                Ok(KeyOperationResult::KemEncapsulated {
                                    ciphertext,
                                    shared_secret,
                                })
                            } else {
                                Err(HsmError::Crypto(
                                    "KEM encapsulate operation not supported for this algorithm"
                                        .into(),
                                ))
                            }
                        }
                        KeyMaterial::Hybrid {
                            pq_algorithm,
                            pq_public_key,
                            ..
                        } => {
                            let target_public_key =
                                recipient_public_key.as_ref().unwrap_or(pq_public_key);
                            let provider = OqsCryptoProvider::new();
                            if pq_algorithm.starts_with("ML-KEM") {
                                let security_level = mlkem_level_from_label(pq_algorithm.as_str())?;
                                let (ciphertext, shared_secret) = provider
                                    .mlkem_encapsulate(target_public_key, security_level)
                                    .map_err(|e| {
                                        HsmError::crypto(format!("ML-KEM encapsulate: {e}"))
                                    })?;
                                Ok(KeyOperationResult::KemEncapsulated {
                                    ciphertext,
                                    shared_secret,
                                })
                            } else {
                                Err(HsmError::Crypto(
                                    "KEM encapsulate operation not supported for this algorithm"
                                        .into(),
                                ))
                            }
                        }
                        _ => Err(HsmError::Crypto(
                            "KEM encapsulate operation not supported for key type".into(),
                        )),
                    }
                }
                #[cfg(not(feature = "pqc"))]
                {
                    let _ = recipient_public_key;
                    Err(pqc_disabled_error())
                }
            }
            CryptoOperation::KemDecapsulate { ciphertext } => {
                #[cfg(feature = "pqc")]
                {
                    match material {
                        KeyMaterial::PostQuantum {
                            algorithm,
                            private_key: Some(private_key),
                            ..
                        } => {
                            let provider = OqsCryptoProvider::new();
                            if algorithm.starts_with("ML-KEM") {
                                let security_level = mlkem_level_from_label(algorithm.as_str())?;
                                let shared_secret = provider
                                    .mlkem_decapsulate(&ciphertext, private_key, security_level)
                                    .map_err(|e| {
                                        HsmError::crypto(format!("ML-KEM decapsulate: {e}"))
                                    })?;
                                Ok(KeyOperationResult::KemDecapsulated { shared_secret })
                            } else {
                                Err(HsmError::Crypto(
                                    "KEM decapsulate operation not supported for this algorithm"
                                        .into(),
                                ))
                            }
                        }
                        KeyMaterial::Hybrid {
                            pq_algorithm,
                            pq_private_key: Some(pq_private_key),
                            ..
                        } => {
                            let provider = OqsCryptoProvider::new();
                            if pq_algorithm.starts_with("ML-KEM") {
                                let security_level = mlkem_level_from_label(pq_algorithm.as_str())?;
                                let shared_secret = provider
                                    .mlkem_decapsulate(&ciphertext, pq_private_key, security_level)
                                    .map_err(|e| {
                                        HsmError::crypto(format!("ML-KEM decapsulate: {e}"))
                                    })?;
                                Ok(KeyOperationResult::KemDecapsulated { shared_secret })
                            } else {
                                Err(HsmError::Crypto(
                                    "KEM decapsulate operation not supported for this algorithm"
                                        .into(),
                                ))
                            }
                        }
                        _ => Err(HsmError::Crypto(
                            "KEM decapsulate operation not supported for key type".into(),
                        )),
                    }
                }
                #[cfg(not(feature = "pqc"))]
                {
                    let _ = ciphertext;
                    Err(pqc_disabled_error())
                }
            }
            CryptoOperation::HybridEncrypt { plaintext } => {
                #[cfg(feature = "pqc")]
                {
                    let _ = &plaintext;
                    match material {
                        KeyMaterial::Hybrid {
                            ec_curve,
                            ec_public_pem,
                            pq_algorithm,
                            pq_public_key,
                            ..
                        } => {
                            let provider = OqsCryptoProvider::new();
                            if pq_algorithm.starts_with("ML-KEM") {
                                let security_level = mlkem_level_from_label(pq_algorithm.as_str())?;
                                let (kem_ciphertext, shared_secret) = provider
                                    .mlkem_encapsulate(pq_public_key, security_level)
                                    .map_err(|e| {
                                        HsmError::crypto(format!("ML-KEM encapsulate: {e}"))
                                    })?;

                                let ec_cipher = match ec_curve {
                                    KeyMaterialType::EcP256 => {
                                        let verifying =
                                            P256VerifyingKey::from_public_key_pem(ec_public_pem)
                                                .map_err(HsmError::crypto)?;
                                        verifying.to_encoded_point(false).as_bytes().to_vec()
                                    }
                                    KeyMaterialType::EcP384 => {
                                        let verifying =
                                            P384VerifyingKey::from_public_key_pem(ec_public_pem)
                                                .map_err(HsmError::crypto)?;
                                        verifying.to_encoded_point(false).as_bytes().to_vec()
                                    }
                                    _ => {
                                        return Err(HsmError::Crypto(
                                            "Unsupported EC curve for hybrid encryption".into(),
                                        ));
                                    }
                                };

                                let mut hybrid_ciphertext = Vec::new();
                                hybrid_ciphertext.extend_from_slice(&kem_ciphertext);
                                hybrid_ciphertext.extend_from_slice(&ec_cipher);
                                hybrid_ciphertext.extend_from_slice(&shared_secret);

                                Ok(KeyOperationResult::HybridEncrypted {
                                    ciphertext: hybrid_ciphertext,
                                    ephemeral_key: shared_secret,
                                })
                            } else {
                                Err(HsmError::Crypto(
                                    "Hybrid encryption not supported for this PQ algorithm".into(),
                                ))
                            }
                        }
                        _ => Err(HsmError::Crypto(
                            "Hybrid encryption requires hybrid key material".into(),
                        )),
                    }
                }
                #[cfg(not(feature = "pqc"))]
                {
                    let _ = plaintext;
                    Err(pqc_disabled_error())
                }
            }
            CryptoOperation::HybridDecrypt {
                ciphertext,
                ephemeral_key,
            } => {
                #[cfg(feature = "pqc")]
                {
                    match material {
                        KeyMaterial::Hybrid {
                            pq_algorithm,
                            pq_private_key: Some(pq_private_key),
                            ..
                        } => {
                            let provider = OqsCryptoProvider::new();
                            if pq_algorithm.starts_with("ML-KEM") {
                                let security_level = mlkem_level_from_label(pq_algorithm.as_str())?;
                                let shared_secret = provider
                                    .mlkem_decapsulate(&ciphertext, pq_private_key, security_level)
                                    .map_err(|e| {
                                        HsmError::crypto(format!("ML-KEM decapsulate: {e}"))
                                    })?;
                                if shared_secret == ephemeral_key {
                                    Ok(KeyOperationResult::HybridDecrypted {
                                        plaintext: shared_secret,
                                    })
                                } else {
                                    Err(HsmError::Crypto(
                                        "Hybrid decryption failed: shared secret mismatch".into(),
                                    ))
                                }
                            } else {
                                Err(HsmError::Crypto(
                                    "Hybrid decryption not supported for this PQ algorithm".into(),
                                ))
                            }
                        }
                        _ => Err(HsmError::Crypto(
                            "Hybrid decryption requires hybrid key material".into(),
                        )),
                    }
                }
                #[cfg(not(feature = "pqc"))]
                {
                    let _ = ciphertext;
                    let _ = ephemeral_key;
                    Err(pqc_disabled_error())
                }
            }
        }
    }

    fn serialise_material(&self, material: &KeyMaterial) -> HsmResult<(KeyMaterialType, Vec<u8>)> {
        match material {
            KeyMaterial::Symmetric { key } => Ok((KeyMaterialType::Symmetric, key.clone())),
            KeyMaterial::Rsa {
                private_pem,
                public_pem,
            } => {
                let combined =
                    serde_json::to_vec(&(private_pem, public_pem)).map_err(HsmError::crypto)?;
                Ok((KeyMaterialType::Rsa, combined))
            }
            KeyMaterial::Ec {
                curve,
                private_pem,
                public_pem,
            } => {
                let combined =
                    serde_json::to_vec(&(private_pem, public_pem)).map_err(HsmError::crypto)?;
                Ok((curve.clone(), combined))
            }
            KeyMaterial::PostQuantum {
                algorithm,
                private_key,
                public_key: _,
            } => Ok((
                KeyMaterialType::from_algorithm(algorithm)?,
                private_key.clone().unwrap_or_default(),
            )),
            KeyMaterial::Hybrid {
                ec_curve,
                ec_private_pem,
                ec_public_pem,
                pq_algorithm,
                pq_public_key,
                pq_private_key,
            } => {
                let combined = serde_json::to_vec(&(
                    ec_private_pem.clone().unwrap_or_default(),
                    ec_public_pem.clone(),
                    pq_private_key.clone().unwrap_or_default(),
                    pq_public_key.clone(),
                ))
                .map_err(HsmError::crypto)?;
                Ok((
                    KeyMaterialType::from_hybrid_algorithm(ec_curve, pq_algorithm)?,
                    combined,
                ))
            }
        }
    }

    fn deserialise_material(
        &self,
        material_type: &KeyMaterialType,
        bytes: &[u8],
    ) -> HsmResult<KeyMaterial> {
        match material_type {
            KeyMaterialType::Symmetric => Ok(KeyMaterial::Symmetric {
                key: bytes.to_vec(),
            }),
            KeyMaterialType::Rsa => {
                let (private_pem, public_pem): (String, String) =
                    serde_json::from_slice(bytes).map_err(HsmError::crypto)?;
                Ok(KeyMaterial::Rsa {
                    private_pem,
                    public_pem,
                })
            }
            KeyMaterialType::EcP256 | KeyMaterialType::EcP384 => {
                let (private_pem, public_pem): (String, String) =
                    serde_json::from_slice(bytes).map_err(HsmError::crypto)?;
                Ok(KeyMaterial::Ec {
                    curve: material_type.clone(),
                    private_pem,
                    public_pem,
                })
            }
            KeyMaterialType::MlKem512
            | KeyMaterialType::MlKem768
            | KeyMaterialType::MlKem1024
            | KeyMaterialType::MlDsa44
            | KeyMaterialType::MlDsa65
            | KeyMaterialType::MlDsa87
            | KeyMaterialType::SlhDsa128f
            | KeyMaterialType::SlhDsa128s
            | KeyMaterialType::SlhDsa192f
            | KeyMaterialType::SlhDsa192s
            | KeyMaterialType::SlhDsa256f
            | KeyMaterialType::SlhDsa256s => Ok(KeyMaterial::PostQuantum {
                algorithm: material_type.to_string(),
                private_key: Some(bytes.to_vec()),
                public_key: vec![], // Public key is derived from private key
            }),
            KeyMaterialType::HybridP256MlKem512
            | KeyMaterialType::HybridP256MlKem768
            | KeyMaterialType::HybridP384MlKem1024
            | KeyMaterialType::HybridP256MlDsa44
            | KeyMaterialType::HybridP256MlDsa65
            | KeyMaterialType::HybridP384MlDsa87 => {
                let (ec_private_pem, ec_public_pem, pqc_private_key, pqc_public_key) =
                    serde_json::from_slice(bytes).map_err(HsmError::crypto)?;
                Ok(KeyMaterial::Hybrid {
                    ec_curve: KeyMaterialType::EcP256,
                    ec_private_pem: Some(ec_private_pem),
                    ec_public_pem,
                    pq_algorithm: material_type.to_string(), // This needs to be derived from the material_type
                    pq_public_key: pqc_public_key,
                    pq_private_key: Some(pqc_private_key),
                })
            }
        }
    }

    fn random_nonce(&self) -> Vec<u8> {
        let mut nonce = vec![0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }
}

fn rsa_material_aws(key_pair: rsa::KeyPair) -> HsmResult<KeyMaterial> {
    let private_der = key_pair.as_der().map_err(HsmError::crypto)?;
    let pki = PrivateKeyInfo::from_der(private_der.as_ref()).map_err(HsmError::crypto)?;
    let private_pem = pki.to_pem(LineEnding::LF).map_err(HsmError::crypto)?;
    let public_key = key_pair.public_key();
    let public_der = public_key.as_der().map_err(HsmError::crypto)?;
    let public_pem = {
        let base64 = base64::encode(public_der.as_ref());
        format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", base64)
    };
    Ok(KeyMaterial::Rsa {
        private_pem,
        public_pem,
    })
}

fn ecc_material_pem(
    private_pem: String,
    public_pem: String,
    curve: KeyMaterialType,
) -> KeyMaterial {
    KeyMaterial::Ec {
        curve,
        private_pem,
        public_pem,
    }
}

fn expect_symmetric(material: &KeyMaterial) -> HsmResult<&[u8]> {
    if let KeyMaterial::Symmetric { key } = material {
        Ok(key)
    } else {
        Err(HsmError::Crypto(
            "operation requires symmetric key material".into(),
        ))
    }
}

pub fn sign_audit_record(key: &[u8], record: &crate::audit::AuditRecord) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(record.id.as_bytes());
    let ts = record.timestamp.unix_timestamp().to_be_bytes();
    mac.update(&ts);
    mac.update(record.action.as_str().as_bytes());
    if let Some(key_id) = &record.key_id {
        mac.update(key_id.as_bytes());
    }
    let tag = mac.finalize().into_bytes();
    hex::encode(tag)
}
