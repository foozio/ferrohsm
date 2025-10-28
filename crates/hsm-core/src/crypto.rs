use std::convert::TryFrom;

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hmac::{Hmac, Mac};
use p256::ecdsa::{
    signature::{Signer as _, Verifier as _},
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use p384::ecdsa::{
    signature::{Signer as _, Verifier as _},
    Signature as P384Signature, SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey,
};
use rand::{rngs::OsRng, RngCore};
use rsa::{
    pkcs1v15::{self, Signature as RsaSignature},
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    signature::SignatureEncoding,
    RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use crate::{
    error::{HsmError, HsmResult},
    models::{
        GeneratedKey, KeyAlgorithm, KeyGenerationRequest, KeyMaterial, KeyMaterialType, KeyMetadata,
    },
    pqc::{CryptoProvider, MlDsaSecurityLevel, MlKemSecurityLevel, SlhDsaSecurityLevel},
    pqc_provider::OqsCryptoProvider,
    rbac::Action,
    storage::{KeyRecord, SealedKeyMaterial},
};
};

type HmacSha256 = Hmac<Sha256>;

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
    Encrypted { ciphertext: Vec<u8>, nonce: Vec<u8> },
    Decrypted { plaintext: Vec<u8> },
    Signature { signature: Vec<u8> },
    Verified { valid: bool },
    Wrapped { wrapped: Vec<u8>, nonce: Vec<u8> },
    Unwrapped { key_material: Vec<u8> },
    // Post-quantum operation results
    KemEncapsulated { ciphertext: Vec<u8>, shared_secret: Vec<u8> },
    KemDecapsulated { shared_secret: Vec<u8> },
    HybridEncrypted { ciphertext: Vec<u8>, ephemeral_key: Vec<u8> },
    HybridDecrypted { plaintext: Vec<u8> },
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
                let private = RsaPrivateKey::new(&mut OsRng, 2048)
                    .map_err(|e| HsmError::crypto(format!("rsa generate: {e}")))?;
                rsa_material(private)?
            }
            KeyAlgorithm::Rsa4096 => {
                let private = RsaPrivateKey::new(&mut OsRng, 4096)
                    .map_err(|e| HsmError::crypto(format!("rsa generate: {e}")))?;
                rsa_material(private)?
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
                let provider = OqsCryptoProvider::new();
                let (public_key, private_key) = provider
                    .ml_kem_keygen(MlKemSecurityLevel::Level1)
                    .map_err(|e| HsmError::crypto(format!("ML-KEM-512 generate: {e}")))?;
                KeyMaterial::PostQuantum {
                    public_key,
                    private_key: Some(private_key),
                    algorithm: "ML-KEM-512".to_string(),
                }
            }
            KeyAlgorithm::MlKem768 => {
                let provider = OqsCryptoProvider::new();
                let (public_key, private_key) = provider
                    .ml_kem_keygen(MlKemSecurityLevel::Level3)
                    .map_err(|e| HsmError::crypto(format!("ML-KEM-768 generate: {e}")))?;
                KeyMaterial::PostQuantum {
                    public_key,
                    private_key: Some(private_key),
                    algorithm: "ML-KEM-768".to_string(),
                }
            }
            KeyAlgorithm::MlKem1024 => {
                let provider = OqsCryptoProvider::new();
                let (public_key, private_key) = provider
                    .ml_kem_keygen(MlKemSecurityLevel::Level5)
                    .map_err(|e| HsmError::crypto(format!("ML-KEM-1024 generate: {e}")))?;
                KeyMaterial::PostQuantum {
                    public_key,
                    private_key: Some(private_key),
                    algorithm: "ML-KEM-1024".to_string(),
                }
            }
            KeyAlgorithm::MlDsa65 => {
                let provider = OqsCryptoProvider::new();
                let (public_key, private_key) = provider
                    .ml_dsa_keygen(MlDsaSecurityLevel::Level2)
                    .map_err(|e| HsmError::crypto(format!("ML-DSA-65 generate: {e}")))?;
                KeyMaterial::PostQuantum {
                    public_key,
                    private_key: Some(private_key),
                    algorithm: "ML-DSA-65".to_string(),
                }
            }
            KeyAlgorithm::MlDsa87 => {
                let provider = OqsCryptoProvider::new();
                let (public_key, private_key) = provider
                    .ml_dsa_keygen(MlDsaSecurityLevel::Level3)
                    .map_err(|e| HsmError::crypto(format!("ML-DSA-87 generate: {e}")))?;
                KeyMaterial::PostQuantum {
                    public_key,
                    private_key: Some(private_key),
                    algorithm: "ML-DSA-87".to_string(),
                }
            }
            KeyAlgorithm::MlDsa135 => {
                let provider = OqsCryptoProvider::new();
                let (public_key, private_key) = provider
                    .ml_dsa_keygen(MlDsaSecurityLevel::Level5)
                    .map_err(|e| HsmError::crypto(format!("ML-DSA-135 generate: {e}")))?;
                KeyMaterial::PostQuantum {
                    public_key,
                    private_key: Some(private_key),
                    algorithm: "ML-DSA-135".to_string(),
                }
            }
            KeyAlgorithm::SlhDsaSha2128f => {
                let provider = OqsCryptoProvider::new();
                let (public_key, private_key) = provider
                    .slh_dsa_keygen(SlhDsaSecurityLevel::Level1)
                    .map_err(|e| HsmError::crypto(format!("SLH-DSA-SHA2-128f generate: {e}")))?;
                KeyMaterial::PostQuantum {
                    public_key,
                    private_key: Some(private_key),
                    algorithm: "SLH-DSA-SHA2-128f".to_string(),
                }
            }
            KeyAlgorithm::SlhDsaSha2128s => {
                let provider = OqsCryptoProvider::new();
                let (public_key, private_key) = provider
                    .slh_dsa_keygen(SlhDsaSecurityLevel::Level2)
                    .map_err(|e| HsmError::crypto(format!("SLH-DSA-SHA2-128s generate: {e}")))?;
                KeyMaterial::PostQuantum {
                    public_key,
                    private_key: Some(private_key),
                    algorithm: "SLH-DSA-SHA2-128s".to_string(),
                }
            }
            KeyAlgorithm::SlhDsaSha2192f => {
                let provider = OqsCryptoProvider::new();
                let (public_key, private_key) = provider
                    .slh_dsa_keygen(SlhDsaSecurityLevel::Level3)
                    .map_err(|e| HsmError::crypto(format!("SLH-DSA-SHA2-192f generate: {e}")))?;
                KeyMaterial::PostQuantum {
                    public_key,
                    private_key: Some(private_key),
                    algorithm: "SLH-DSA-SHA2-192f".to_string(),
                }
            }
            KeyAlgorithm::SlhDsaSha2192s => {
                let provider = OqsCryptoProvider::new();
                let (public_key, private_key) = provider
                    .slh_dsa_keygen(SlhDsaSecurityLevel::Level4)
                    .map_err(|e| HsmError::crypto(format!("SLH-DSA-SHA2-192s generate: {e}")))?;
                KeyMaterial::PostQuantum {
                    public_key,
                    private_key: Some(private_key),
                    algorithm: "SLH-DSA-SHA2-192s".to_string(),
                }
            }
            KeyAlgorithm::SlhDsaSha2256f => {
                let provider = OqsCryptoProvider::new();
                let (public_key, private_key) = provider
                    .slh_dsa_keygen(SlhDsaSecurityLevel::Level5)
                    .map_err(|e| HsmError::crypto(format!("SLH-DSA-SHA2-256f generate: {e}")))?;
                KeyMaterial::PostQuantum {
                    public_key,
                    private_key: Some(private_key),
                    algorithm: "SLH-DSA-SHA2-256f".to_string(),
                }
            }
            KeyAlgorithm::SlhDsaSha2256s => {
                let provider = OqsCryptoProvider::new();
                let (public_key, private_key) = provider
                    .slh_dsa_keygen(SlhDsaSecurityLevel::Level6)
                    .map_err(|e| HsmError::crypto(format!("SLH-DSA-SHA2-256s generate: {e}")))?;
                KeyMaterial::PostQuantum {
                    public_key,
                    private_key: Some(private_key),
                    algorithm: "SLH-DSA-SHA2-256s".to_string(),
                }
            }
            KeyAlgorithm::HybridP256MlKem768 => {
                // Generate EC key
                let signing = P256SigningKey::random(&mut OsRng);
                let ec_private_pem = signing
                    .to_pkcs8_pem(LineEnding::LF)
                    .map_err(HsmError::crypto)?
                    .to_string();
                let ec_public_pem = signing
                    .verifying_key()
                    .to_public_key_pem(LineEnding::LF)
                    .map_err(HsmError::crypto)?;
                
                // Generate PQ key
                let provider = OqsCryptoProvider::new();
                let (pq_public_key, pq_private_key) = provider
                    .ml_kem_keygen(MlKemSecurityLevel::Level3)
                    .map_err(|e| HsmError::crypto(format!("ML-KEM-768 generate: {e}")))?;
                
                KeyMaterial::Hybrid {
                    ec_curve: KeyMaterialType::EcP256,
                    ec_private_pem: Some(ec_private_pem),
                    ec_public_pem,
                    pq_algorithm: "ML-KEM-768".to_string(),
                    pq_public_key,
                    pq_private_key: Some(pq_private_key),
                }
            }
            KeyAlgorithm::HybridP384MlKem1024 => {
                // Generate EC key
                let signing = P384SigningKey::random(&mut OsRng);
                let ec_private_pem = signing
                    .to_pkcs8_pem(LineEnding::LF)
                    .map_err(HsmError::crypto)?
                    .to_string();
                let ec_public_pem = signing
                    .verifying_key()
                    .to_public_key_pem(LineEnding::LF)
                    .map_err(HsmError::crypto)?;
                
                // Generate PQ key
                let provider = OqsCryptoProvider::new();
                let (pq_public_key, pq_private_key) = provider
                    .ml_kem_keygen(MlKemSecurityLevel::Level5)
                    .map_err(|e| HsmError::crypto(format!("ML-KEM-1024 generate: {e}")))?;
                
                KeyMaterial::Hybrid {
                    ec_curve: KeyMaterialType::EcP384,
                    ec_private_pem: Some(ec_private_pem),
                    ec_public_pem,
                    pq_algorithm: "ML-KEM-1024".to_string(),
                    pq_public_key,
                    pq_private_key: Some(pq_private_key),
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
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    aad,
                    msg: &plaintext,
                CryptoOperation::KemEncapsulate { recipient_public_key } => match material {
                KeyMaterial::PostQuantum {
                    algorithm,
                    public_key,
                    ..
                } => {
                    // Use the provided recipient public key if available, otherwise use our own public key
                    let target_public_key = recipient_public_key.as_ref().unwrap_or(public_key);
                    
                    let provider = OqsCryptoProvider::new();
                    if algorithm.starts_with("ML-KEM") {
                        let security_level = match algorithm.as_str() {
                            "ML-KEM-512" => MlKemSecurityLevel::Level1,
                            "ML-KEM-768" => MlKemSecurityLevel::Level3,
                            "ML-KEM-1024" => MlKemSecurityLevel::Level5,
                            _ => return Err(HsmError::Crypto("Unsupported ML-KEM algorithm".into())),
                        };
                        let (ciphertext, shared_secret) = provider
                            .ml_kem_encapsulate(security_level, target_public_key)
                            .map_err(|e| HsmError::crypto(format!("ML-KEM encapsulate: {e}")))?;
                        Ok(KeyOperationResult::KemEncapsulated { ciphertext, shared_secret })
                    } else {
                        Err(HsmError::Crypto(
                            "KEM encapsulate operation not supported for this algorithm".into(),
                        ))
                    }
                }
                KeyMaterial::Hybrid {
                    pq_algorithm,
                    pq_public_key,
                    ..
                } => {
                    // Use the provided recipient public key if available, otherwise use our own public key
                    let target_public_key = recipient_public_key.as_ref().unwrap_or(pq_public_key);
                    
                    let provider = OqsCryptoProvider::new();
                    if pq_algorithm.starts_with("ML-KEM") {
                        let security_level = match pq_algorithm.as_str() {
                            "ML-KEM-512" => MlKemSecurityLevel::Level1,
                            "ML-KEM-768" => MlKemSecurityLevel::Level3,
                            "ML-KEM-1024" => MlKemSecurityLevel::Level5,
                            _ => return Err(HsmError::Crypto("Unsupported ML-KEM algorithm".into())),
                        };
                        let (ciphertext, shared_secret) = provider
                            .ml_kem_encapsulate(security_level, target_public_key)
                            .map_err(|e| HsmError::crypto(format!("ML-KEM encapsulate: {e}")))?;
                        Ok(KeyOperationResult::KemEncapsulated { ciphertext, shared_secret })
                    } else {
                        Err(HsmError::Crypto(
                            "KEM encapsulate operation not supported for this algorithm".into(),
                        ))
                    }
                }
                _ => Err(HsmError::Crypto(
                    "KEM encapsulate operation not supported for key type".into(),
                )),
            },
            CryptoOperation::HybridEncrypt { plaintext } => match material {
                KeyMaterial::Hybrid {
                    ec_curve,
                    ec_public_pem,
                    pq_algorithm,
                    pq_public_key,
                    ..
                } => {
                    // First perform KEM encapsulation to get a shared secret
                    let provider = OqsCryptoProvider::new();
                    
                    // Handle ML-KEM encapsulation
                    if pq_algorithm.starts_with("ML-KEM") {
                        let security_level = match pq_algorithm.as_str() {
                            "ML-KEM-512" => MlKemSecurityLevel::Level1,
                            "ML-KEM-768" => MlKemSecurityLevel::Level3,
                            "ML-KEM-1024" => MlKemSecurityLevel::Level5,
                            _ => return Err(HsmError::Crypto("Unsupported ML-KEM algorithm".into())),
                        };
                        
                        // Perform KEM encapsulation
                        let (kem_ciphertext, shared_secret) = provider
                            .ml_kem_encapsulate(security_level, pq_public_key)
                            .map_err(|e| HsmError::crypto(format!("ML-KEM encapsulate: {e}")))?;
                        
                        // Use the shared secret to encrypt the plaintext with AES-GCM
                        let cipher = Aes256Gcm::new_from_slice(&shared_secret[0..32])
                            .map_err(|_| HsmError::crypto("Failed to create AES cipher"))?;
                        
                        // Create a random nonce
                        let nonce = self.random_nonce();
                        let nonce_ref = Nonce::from_slice(&nonce);
                        
                        // Encrypt the plaintext
                        let ciphertext = cipher.encrypt(nonce_ref, plaintext.as_ref())
                            .map_err(|_| HsmError::crypto("AES-GCM encryption failed"))?;
                        
                        // Return the KEM ciphertext and encrypted data
                        Ok(KeyOperationResult::HybridEncrypted { ciphertext, ephemeral_key: kem_ciphertext })
                    } else {
                        Err(HsmError::Crypto(
                            "Hybrid encrypt operation not supported for this algorithm".into(),
                        ))
                    }
                }
                _ => Err(HsmError::Crypto(
                    "Hybrid encrypt operation not supported for key type".into(),
                )),
            },
            CryptoOperation::HybridDecrypt { ciphertext, ephemeral_key } => match material {
                KeyMaterial::Hybrid {
                    ec_curve,
                    pq_algorithm,
                    pq_private_key: Some(pq_private_key),
                    ..
                } => {
                    // Perform KEM decapsulation to recover the shared secret
                    let provider = OqsCryptoProvider::new();
                    
                    // Handle ML-KEM decapsulation
                    if pq_algorithm.starts_with("ML-KEM") {
                        let security_level = match pq_algorithm.as_str() {
                            "ML-KEM-512" => MlKemSecurityLevel::Level1,
                            "ML-KEM-768" => MlKemSecurityLevel::Level3,
                            "ML-KEM-1024" => MlKemSecurityLevel::Level5,
                            _ => return Err(HsmError::Crypto("Unsupported ML-KEM algorithm".into())),
                        };
                        
                        // Perform KEM decapsulation
                        let shared_secret = provider
                            .ml_kem_decapsulate(security_level, pq_private_key, &ephemeral_key)
                            .map_err(|e| HsmError::crypto(format!("ML-KEM decapsulate: {e}")))?;
                        
                        // Use the shared secret to decrypt with AES-GCM
                        let cipher = Aes256Gcm::new_from_slice(&shared_secret[0..32])
                            .map_err(|_| HsmError::crypto("Failed to create AES cipher"))?;
                        
                        // Extract nonce from the beginning of the ciphertext
                        if ciphertext.len() < 12 {
                            return Err(HsmError::Crypto("Invalid ciphertext format".into()));
                        }
                        let (nonce_bytes, actual_ciphertext) = ciphertext.split_at(12);
                        let nonce = Nonce::from_slice(nonce_bytes);
                        
                        // Decrypt the ciphertext
                        let plaintext = cipher.decrypt(nonce, actual_ciphertext)
                            .map_err(|_| HsmError::crypto("AES-GCM decryption failed"))?;
                        
                        Ok(KeyOperationResult::HybridDecrypted { plaintext })
                    } else {
                        Err(HsmError::Crypto(
                            "Hybrid decrypt operation not supported for this algorithm".into(),
                        ))
                    }
                }
                _ => Err(HsmError::Crypto(
                    "Hybrid decrypt operation not supported for key type".into(),
                )),
            },
            CryptoOperation::KemDecapsulate { ciphertext } => match material {
                KeyMaterial::PostQuantum {
                    algorithm,
                    private_key: Some(private_key),
                    ..
                } => {
                    let provider = OqsCryptoProvider::new();
                    if algorithm.starts_with("ML-KEM") {
                        let security_level = match algorithm.as_str() {
                            "ML-KEM-512" => MlKemSecurityLevel::Level1,
                            "ML-KEM-768" => MlKemSecurityLevel::Level3,
                            "ML-KEM-1024" => MlKemSecurityLevel::Level5,
                            _ => return Err(HsmError::Crypto("Unsupported ML-KEM algorithm".into())),
                        };
                        let shared_secret = provider
                            .ml_kem_decapsulate(security_level, private_key, &ciphertext)
                            .map_err(|e| HsmError::crypto(format!("ML-KEM decapsulate: {e}")))?;
                        Ok(KeyOperationResult::KemDecapsulated { shared_secret })
                    } else {
                        Err(HsmError::Crypto(
                            "KEM decapsulate operation not supported for this algorithm".into(),
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
                        let security_level = match pq_algorithm.as_str() {
                            "ML-KEM-512" => MlKemSecurityLevel::Level1,
                            "ML-KEM-768" => MlKemSecurityLevel::Level3,
                            "ML-KEM-1024" => MlKemSecurityLevel::Level5,
                            _ => return Err(HsmError::Crypto("Unsupported ML-KEM algorithm".into())),
                        };
                        let shared_secret = provider
                            .ml_kem_decapsulate(security_level, pq_private_key, &ciphertext)
                            .map_err(|e| HsmError::crypto(format!("ML-KEM decapsulate: {e}")))?;
                        Ok(KeyOperationResult::KemDecapsulated { shared_secret })
                    } else {
                        Err(HsmError::Crypto(
                            "KEM decapsulate operation not supported for this algorithm".into(),
                        ))
                    }
                }
                _ => Err(HsmError::Crypto(
                    "KEM decapsulate operation not supported for key type".into(),
                )),
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
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&record.sealed.nonce),
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
                let ciphertext = cipher
                    .encrypt(
                        Nonce::from_slice(&nonce),
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
                let plaintext = cipher
                    .decrypt(
                        Nonce::from_slice(&nonce),
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
                    let private =
                        RsaPrivateKey::from_pkcs8_pem(private_pem).map_err(HsmError::crypto)?;
                    let signing_key = pkcs1v15::SigningKey::<Sha256>::new(private);
                    let signature = signing_key.sign(&payload).to_vec();
                    Ok(KeyOperationResult::Signature { signature })
                }
                KeyMaterial::Ec {
                    curve: KeyMaterialType::EcP256,
                    private_pem,
                    ..
                } => {
                    let signing =
                        P256SigningKey::from_pkcs8_pem(private_pem).map_err(HsmError::crypto)?;
                    let signature: P256Signature = signing.sign(&payload);
                    Ok(KeyOperationResult::Signature {
                        signature: signature.to_der().as_bytes().to_vec(),
                    })
                }
                KeyMaterial::Ec {
                    curve: KeyMaterialType::EcP384,
                    private_pem,
                    ..
                } => {
                    let signing =
                        P384SigningKey::from_pkcs8_pem(private_pem).map_err(HsmError::crypto)?;
                    let signature: P384Signature = signing.sign(&payload);
                    Ok(KeyOperationResult::Signature {
                        signature: signature.to_der().as_bytes().to_vec(),
                    })
                }
                KeyMaterial::PostQuantum {
                    algorithm,
                    private_key: Some(private_key),
                    ..
                } => {
                    let provider = OqsCryptoProvider::new();
                    if algorithm.starts_with("ML-DSA") {
                        let security_level = match algorithm.as_str() {
                            "ML-DSA-65" => MlDsaSecurityLevel::Level2,
                            "ML-DSA-87" => MlDsaSecurityLevel::Level3,
                            "ML-DSA-135" => MlDsaSecurityLevel::Level5,
                            _ => return Err(HsmError::Crypto("Unsupported ML-DSA algorithm".into())),
                        };
                        let signature = provider
                            .ml_dsa_sign(security_level, private_key, &payload)
                            .map_err(|e| HsmError::crypto(format!("ML-DSA sign: {e}")))?;
                        Ok(KeyOperationResult::Signature { signature })
                    } else if algorithm.starts_with("SLH-DSA") {
                        let security_level = match algorithm.as_str() {
                            "SLH-DSA-SHA2-128f" => SlhDsaSecurityLevel::Level1,
                            "SLH-DSA-SHA2-128s" => SlhDsaSecurityLevel::Level2,
                            "SLH-DSA-SHA2-192f" => SlhDsaSecurityLevel::Level3,
                            "SLH-DSA-SHA2-192s" => SlhDsaSecurityLevel::Level4,
                            "SLH-DSA-SHA2-256f" => SlhDsaSecurityLevel::Level5,
                            "SLH-DSA-SHA2-256s" => SlhDsaSecurityLevel::Level6,
                            _ => return Err(HsmError::Crypto("Unsupported SLH-DSA algorithm".into())),
                        };
                        let signature = provider
                            .slh_dsa_sign(security_level, private_key, &payload)
                            .map_err(|e| HsmError::crypto(format!("SLH-DSA sign: {e}")))?;
                        Ok(KeyOperationResult::Signature { signature })
                    } else {
                        Err(HsmError::Crypto(
                            "sign operation not supported for this PQ algorithm".into(),
                        ))
                    }
                }
                KeyMaterial::Hybrid {
                    ec_curve,
                    ec_private_pem: Some(ec_private_pem),
                    pq_algorithm,
                    pq_private_key: Some(pq_private_key),
                    ..
                } => {
                    // For hybrid signatures, we sign with both algorithms and concatenate
                    let ec_signature = match ec_curve {
                        KeyMaterialType::EcP256 => {
                            let signing = P256SigningKey::from_pkcs8_pem(ec_private_pem)
                                .map_err(HsmError::crypto)?;
                            let signature: P256Signature = signing.sign(&payload);
                            signature.to_der().as_bytes().to_vec()
                        }
                        KeyMaterialType::EcP384 => {
                            let signing = P384SigningKey::from_pkcs8_pem(ec_private_pem)
                                .map_err(HsmError::crypto)?;
                            let signature: P384Signature = signing.sign(&payload);
                            signature.to_der().as_bytes().to_vec()
                        }
                        _ => return Err(HsmError::Crypto("Unsupported EC curve".into())),
                    };

                    let provider = OqsCryptoProvider::new();
                    let pq_signature = if pq_algorithm.starts_with("ML-DSA") {
                        let security_level = match pq_algorithm.as_str() {
                            "ML-DSA-65" => MlDsaSecurityLevel::Level2,
                            "ML-DSA-87" => MlDsaSecurityLevel::Level3,
                            "ML-DSA-135" => MlDsaSecurityLevel::Level5,
                            _ => return Err(HsmError::Crypto("Unsupported ML-DSA algorithm".into())),
                        };
                        provider
                            .ml_dsa_sign(security_level, pq_private_key, &payload)
                            .map_err(|e| HsmError::crypto(format!("ML-DSA sign: {e}")))?                        
                    } else if pq_algorithm.starts_with("SLH-DSA") {
                        let security_level = match pq_algorithm.as_str() {
                            "SLH-DSA-SHA2-128f" => SlhDsaSecurityLevel::Level1,
                            "SLH-DSA-SHA2-128s" => SlhDsaSecurityLevel::Level2,
                            "SLH-DSA-SHA2-192f" => SlhDsaSecurityLevel::Level3,
                            "SLH-DSA-SHA2-192s" => SlhDsaSecurityLevel::Level4,
                            "SLH-DSA-SHA2-256f" => SlhDsaSecurityLevel::Level5,
                            "SLH-DSA-SHA2-256s" => SlhDsaSecurityLevel::Level6,
                            _ => return Err(HsmError::Crypto("Unsupported SLH-DSA algorithm".into())),
                        };
                        provider
                            .slh_dsa_sign(security_level, pq_private_key, &payload)
                            .map_err(|e| HsmError::crypto(format!("SLH-DSA sign: {e}")))?                        
                    } else {
                        return Err(HsmError::Crypto(
                            "sign operation not supported for this PQ algorithm".into(),
                        ));
                    };

                    // Combine signatures: [ec_sig_len(4 bytes)][ec_sig][pq_sig]
                    let mut combined = Vec::new();
                    let ec_sig_len = ec_signature.len() as u32;
                    combined.extend_from_slice(&ec_sig_len.to_be_bytes());
                    combined.extend_from_slice(&ec_signature);
                    combined.extend_from_slice(&pq_signature);

                    Ok(KeyOperationResult::Signature { signature: combined })
                }
                _ => Err(HsmError::Crypto(
                    "sign operation not supported for key type".into(),
                )),
            },
            CryptoOperation::Verify { payload, signature } => match material {
                KeyMaterial::Rsa { public_pem, .. } => {
                    let public =
                        RsaPublicKey::from_public_key_pem(public_pem).map_err(HsmError::crypto)?;
                    let verifying = pkcs1v15::VerifyingKey::<Sha256>::new(public);
                    let signature =
                        RsaSignature::try_from(signature.as_slice()).map_err(HsmError::crypto)?;
                    let valid = verifying.verify(&payload, &signature).is_ok();
                    Ok(KeyOperationResult::Verified { valid })
                }
                KeyMaterial::Ec {
                    curve: KeyMaterialType::EcP256,
                    public_pem,
                    ..
                } => {
                    let verifying = P256VerifyingKey::from_public_key_pem(public_pem)
                        .map_err(HsmError::crypto)?;
                    let valid = verifying
                        .verify(
                            &payload,
                            &P256Signature::from_der(&signature).map_err(HsmError::crypto)?,
                        )
                        .is_ok();
                    Ok(KeyOperationResult::Verified { valid })
                }
                KeyMaterial::Ec {
                    curve: KeyMaterialType::EcP384,
                    public_pem,
                    ..
                } => {
                    let verifying = P384VerifyingKey::from_public_key_pem(public_pem)
                        .map_err(HsmError::crypto)?;
                    let valid = verifying
                        .verify(
                            &payload,
                            &P384Signature::from_der(&signature).map_err(HsmError::crypto)?,
                        )
                        .is_ok();
                    Ok(KeyOperationResult::Verified { valid })
                }
                KeyMaterial::PostQuantum {
                    algorithm,
                    public_key,
                    ..
                } => {
                    let provider = OqsCryptoProvider::new();
                    if algorithm.starts_with("ML-DSA") {
                        let security_level = match algorithm.as_str() {
                            "ML-DSA-65" => MlDsaSecurityLevel::Level2,
                            "ML-DSA-87" => MlDsaSecurityLevel::Level3,
                            "ML-DSA-135" => MlDsaSecurityLevel::Level5,
                            _ => return Err(HsmError::Crypto("Unsupported ML-DSA algorithm".into())),
                        };
                        let valid = provider
                            .ml_dsa_verify(security_level, public_key, &payload, &signature)
                            .map_err(|e| HsmError::crypto(format!("ML-DSA verify: {e}")))?;
                        Ok(KeyOperationResult::Verified { valid })
                    } else if algorithm.starts_with("SLH-DSA") {
                        let security_level = match algorithm.as_str() {
                            "SLH-DSA-SHA2-128f" => SlhDsaSecurityLevel::Level1,
                            "SLH-DSA-SHA2-128s" => SlhDsaSecurityLevel::Level2,
                            "SLH-DSA-SHA2-192f" => SlhDsaSecurityLevel::Level3,
                            "SLH-DSA-SHA2-192s" => SlhDsaSecurityLevel::Level4,
                            "SLH-DSA-SHA2-256f" => SlhDsaSecurityLevel::Level5,
                            "SLH-DSA-SHA2-256s" => SlhDsaSecurityLevel::Level6,
                            _ => return Err(HsmError::Crypto("Unsupported SLH-DSA algorithm".into())),
                        };
                        let valid = provider
                            .slh_dsa_verify(security_level, public_key, &payload, &signature)
                            .map_err(|e| HsmError::crypto(format!("SLH-DSA verify: {e}")))?;
                        Ok(KeyOperationResult::Verified { valid })
                    } else {
                        Err(HsmError::Crypto(
                            "verify operation not supported for this PQ algorithm".into(),
                        ))
                    }
                }
                KeyMaterial::Hybrid {
                    ec_curve,
                    ec_public_pem,
                    pq_algorithm,
                    pq_public_key,
                    ..
                } => {
                    // Extract EC signature and PQ signature from combined signature
                    if signature.len() < 4 {
                        return Err(HsmError::Crypto("Invalid hybrid signature format".into()));
                    }
                    
                    let mut ec_sig_len_bytes = [0u8; 4];
                    ec_sig_len_bytes.copy_from_slice(&signature[0..4]);
                    let ec_sig_len = u32::from_be_bytes(ec_sig_len_bytes) as usize;
                    
                    if signature.len() < 4 + ec_sig_len {
                        return Err(HsmError::Crypto("Invalid hybrid signature format".into()));
                    }
                    
                    let ec_signature = &signature[4..(4 + ec_sig_len)];
                    let pq_signature = &signature[(4 + ec_sig_len)..];
                    
                    // Verify EC signature
                    let ec_valid = match ec_curve {
                        KeyMaterialType::EcP256 => {
                            let verifying = P256VerifyingKey::from_public_key_pem(&ec_public_pem)
                                .map_err(HsmError::crypto)?;
                            verifying
                                .verify(
                                    &payload,
                                    &P256Signature::from_der(ec_signature).map_err(HsmError::crypto)?,
                                )
                                .is_ok()
                        }
                        KeyMaterialType::EcP384 => {
                            let verifying = P384VerifyingKey::from_public_key_pem(&ec_public_pem)
                                .map_err(HsmError::crypto)?;
                            verifying
                                .verify(
                                    &payload,
                                    &P384Signature::from_der(ec_signature).map_err(HsmError::crypto)?,
                                )
                                .is_ok()
                        }
                        _ => return Err(HsmError::Crypto("Unsupported EC curve".into())),
                    };
                    
                    if !ec_valid {
                        return Ok(KeyOperationResult::Verified { valid: false });
                    }
                    
                    // Verify PQ signature
                    let provider = OqsCryptoProvider::new();
                    let pq_valid = if pq_algorithm.starts_with("ML-DSA") {
                        let security_level = match pq_algorithm.as_str() {
                            "ML-DSA-65" => MlDsaSecurityLevel::Level2,
                            "ML-DSA-87" => MlDsaSecurityLevel::Level3,
                            "ML-DSA-135" => MlDsaSecurityLevel::Level5,
                            _ => return Err(HsmError::Crypto("Unsupported ML-DSA algorithm".into())),
                        };
                        provider
                            .ml_dsa_verify(security_level, pq_public_key, &payload, pq_signature)
                            .map_err(|e| HsmError::crypto(format!("ML-DSA verify: {e}")))?
                    } else if pq_algorithm.starts_with("SLH-DSA") {
                        let security_level = match pq_algorithm.as_str() {
                            "SLH-DSA-SHA2-128f" => SlhDsaSecurityLevel::Level1,
                            "SLH-DSA-SHA2-128s" => SlhDsaSecurityLevel::Level2,
                            "SLH-DSA-SHA2-192f" => SlhDsaSecurityLevel::Level3,
                            "SLH-DSA-SHA2-192s" => SlhDsaSecurityLevel::Level4,
                            "SLH-DSA-SHA2-256f" => SlhDsaSecurityLevel::Level5,
                            "SLH-DSA-SHA2-256s" => SlhDsaSecurityLevel::Level6,
                            _ => return Err(HsmError::Crypto("Unsupported SLH-DSA algorithm".into())),
                        };
                        provider
                            .slh_dsa_verify(security_level, pq_public_key, &payload, pq_signature)
                            .map_err(|e| HsmError::crypto(format!("SLH-DSA verify: {e}")))?
                    } else {
                        return Err(HsmError::Crypto(
                            "verify operation not supported for this PQ algorithm".into(),
                        ));
                    };
                    
                    // Both signatures must be valid
                    Ok(KeyOperationResult::Verified { valid: ec_valid && pq_valid })
                }
                _ => Err(HsmError::Crypto(
                    "verify operation not supported for key type".into(),
                )),
            },
            CryptoOperation::WrapKey { key_material } => {
                let key = expect_symmetric(material)?;
                let cipher = Aes256Gcm::new_from_slice(key).map_err(HsmError::crypto)?;
                let nonce = self.random_nonce();
                let wrapped = cipher
                    .encrypt(
                        Nonce::from_slice(&nonce),
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
                let key_material = cipher
                    .decrypt(
                        Nonce::from_slice(&nonce),
                        Payload {
                            aad: &[],
                            msg: &wrapped,
                        },
                    )
                    .map_err(HsmError::crypto)?;
                Ok(KeyOperationResult::Unwrapped { key_material })
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
        }
    }

    fn random_nonce(&self) -> Vec<u8> {
        let mut nonce = vec![0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }
}

fn rsa_material(private: RsaPrivateKey) -> HsmResult<KeyMaterial> {
    let public = RsaPublicKey::from(&private);
    let private_pem = private
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(HsmError::crypto)?
        .to_string();
    let public_pem = public
        .to_public_key_pem(LineEnding::LF)
        .map_err(HsmError::crypto)?
        .to_string();
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
