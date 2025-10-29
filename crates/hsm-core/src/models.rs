use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{attributes::AttributeSet, rbac::Role, HsmError, HsmResult};

pub type KeyId = String;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum KeyAlgorithm {
    Aes256Gcm,
    Rsa2048,
    Rsa4096,
    P256,
    P384,
    // Post-quantum algorithms
    MlKem512,   // ML-KEM-512 (Kyber)
    MlKem768,   // ML-KEM-768 (Kyber)
    MlKem1024,  // ML-KEM-1024 (Kyber)
    MlDsa44,    // ML-DSA-44 (Dilithium)
    MlDsa65,    // ML-DSA-65 (Dilithium)
    MlDsa87,    // ML-DSA-87 (Dilithium)
    SlhDsa128f, // SLH-DSA-SHA2-128f (SPHINCS+)
    SlhDsa128s, // SLH-DSA-SHA2-128s (SPHINCS+)
    SlhDsa192f, // SLH-DSA-SHA2-192f (SPHINCS+)
    SlhDsa192s, // SLH-DSA-SHA2-192s (SPHINCS+)
    SlhDsa256f, // SLH-DSA-SHA2-256f (SPHINCS+)
    SlhDsa256s, // SLH-DSA-SHA2-256s (SPHINCS+)
    // Hybrid algorithms
    HybridP256MlKem512,  // P-256 + ML-KEM-512
    HybridP256MlKem768,  // P-256 + ML-KEM-768
    HybridP384MlKem1024, // P-384 + ML-KEM-1024
    HybridP256MlDsa44,   // P-256 + ML-DSA-44
    HybridP256MlDsa65,   // P-256 + ML-DSA-65
    HybridP384MlDsa87,   // P-384 + ML-DSA-87
}

impl KeyAlgorithm {
    /// Check if the algorithm is a post-quantum algorithm
    pub fn is_post_quantum(&self) -> bool {
        matches!(
            self,
            KeyAlgorithm::MlKem512
                | KeyAlgorithm::MlKem768
                | KeyAlgorithm::MlKem1024
                | KeyAlgorithm::MlDsa44
                | KeyAlgorithm::MlDsa65
                | KeyAlgorithm::MlDsa87
                | KeyAlgorithm::SlhDsa128f
                | KeyAlgorithm::SlhDsa128s
                | KeyAlgorithm::SlhDsa192f
                | KeyAlgorithm::SlhDsa192s
                | KeyAlgorithm::SlhDsa256f
                | KeyAlgorithm::SlhDsa256s
        )
    }

    /// Check if the algorithm is a hybrid algorithm
    pub fn is_hybrid(&self) -> bool {
        matches!(
            self,
            KeyAlgorithm::HybridP256MlKem512
                | KeyAlgorithm::HybridP256MlKem768
                | KeyAlgorithm::HybridP384MlKem1024
                | KeyAlgorithm::HybridP256MlDsa44
                | KeyAlgorithm::HybridP256MlDsa65
                | KeyAlgorithm::HybridP384MlDsa87
        )
    }

    /// Check if the algorithm is a KEM (Key Encapsulation Mechanism)
    pub fn is_kem(&self) -> bool {
        matches!(
            self,
            KeyAlgorithm::MlKem512
                | KeyAlgorithm::MlKem768
                | KeyAlgorithm::MlKem1024
                | KeyAlgorithm::HybridP256MlKem512
                | KeyAlgorithm::HybridP256MlKem768
                | KeyAlgorithm::HybridP384MlKem1024
        )
    }

    /// Check if the algorithm is a signature algorithm
    pub fn is_signature(&self) -> bool {
        matches!(
            self,
            KeyAlgorithm::MlDsa44
                | KeyAlgorithm::MlDsa65
                | KeyAlgorithm::MlDsa87
                | KeyAlgorithm::SlhDsa128f
                | KeyAlgorithm::SlhDsa128s
                | KeyAlgorithm::SlhDsa192f
                | KeyAlgorithm::SlhDsa192s
                | KeyAlgorithm::SlhDsa256f
                | KeyAlgorithm::SlhDsa256s
                | KeyAlgorithm::HybridP256MlDsa44
                | KeyAlgorithm::HybridP256MlDsa65
                | KeyAlgorithm::HybridP384MlDsa87
        )
    }

    /// Get the security level of the algorithm
    pub fn security_level(&self) -> u32 {
        match self {
            KeyAlgorithm::MlKem512
            | KeyAlgorithm::MlDsa44
            | KeyAlgorithm::SlhDsa128f
            | KeyAlgorithm::SlhDsa128s => 1,
            KeyAlgorithm::MlKem768
            | KeyAlgorithm::MlDsa65
            | KeyAlgorithm::SlhDsa192f
            | KeyAlgorithm::SlhDsa192s => 3,
            KeyAlgorithm::MlKem1024
            | KeyAlgorithm::MlDsa87
            | KeyAlgorithm::SlhDsa256f
            | KeyAlgorithm::SlhDsa256s => 5,
            KeyAlgorithm::HybridP256MlKem512 | KeyAlgorithm::HybridP256MlDsa44 => 1,
            KeyAlgorithm::HybridP256MlKem768 | KeyAlgorithm::HybridP256MlDsa65 => 3,
            KeyAlgorithm::HybridP384MlKem1024 | KeyAlgorithm::HybridP384MlDsa87 => 5,
            _ => 0, // Non-PQC algorithms
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum KeyPurpose {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    Wrap,
    Unwrap,
}

pub type KeyUsage = Vec<KeyPurpose>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum KeyState {
    Staged,
    Active,
    Revoked,
    PurgeScheduled,
    Destroyed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TamperStatus {
    Clean,
    Suspect(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyMetadata {
    pub id: KeyId,
    pub version: u32,
    pub algorithm: KeyAlgorithm,
    pub usage: KeyUsage,
    pub description: Option<String>,
    pub created_at: OffsetDateTime,
    pub state: KeyState,
    pub policy_tags: Vec<String>,
    pub tamper_status: TamperStatus,
    #[serde(default)]
    pub attributes: AttributeSet,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyListQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<KeyAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<KeyState>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_tags: Vec<String>,
    pub page: u32,
    pub per_page: u32,
}

impl Default for KeyListQuery {
    fn default() -> Self {
        Self {
            algorithm: None,
            state: None,
            policy_tags: Vec::new(),
            page: 1,
            per_page: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyListPage {
    pub items: Vec<KeyMetadata>,
    pub total: usize,
    pub page: u32,
    pub per_page: u32,
    pub has_more: bool,
}

impl KeyMetadata {
    pub fn from_request(req: &KeyGenerationRequest, id: KeyId) -> Self {
        Self {
            id,
            version: 1,
            algorithm: req.algorithm,
            usage: req.usage.clone(),
            description: req.description.clone(),
            created_at: OffsetDateTime::now_utc(),
            state: KeyState::Active,
            policy_tags: req.policy_tags.clone(),
            tamper_status: TamperStatus::Clean,
            attributes: AttributeSet::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyGenerationRequest {
    pub algorithm: KeyAlgorithm,
    pub usage: KeyUsage,
    pub policy_tags: Vec<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyMaterialType {
    Symmetric,
    Rsa,
    EcP256,
    EcP384,
    // Post-quantum material types
    MlKem512,
    MlKem768,
    MlKem1024,
    MlDsa44,
    MlDsa65,
    MlDsa87,
    SlhDsa128f,
    SlhDsa128s,
    SlhDsa192f,
    SlhDsa192s,
    SlhDsa256f,
    SlhDsa256s,
    // Hybrid material types
    HybridP256MlKem512,
    HybridP256MlKem768,
    HybridP384MlKem1024,
    HybridP256MlDsa44,
    HybridP256MlDsa65,
    HybridP384MlDsa87,
}

impl std::fmt::Display for KeyMaterialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl KeyMaterialType {
    pub fn from_algorithm(algorithm: &str) -> HsmResult<Self> {
        match algorithm {
            "MlKem512" => Ok(KeyMaterialType::MlKem512),
            "MlKem768" => Ok(KeyMaterialType::MlKem768),
            "MlKem1024" => Ok(KeyMaterialType::MlKem1024),
            "MlDsa44" => Ok(KeyMaterialType::MlDsa44),
            "MlDsa65" => Ok(KeyMaterialType::MlDsa65),
            "MlDsa87" => Ok(KeyMaterialType::MlDsa87),
            "SlhDsaShake256f" => Ok(KeyMaterialType::SlhDsa256f),
            _ => Err(HsmError::UnsupportedAlgorithm(algorithm.to_string())),
        }
    }

    pub fn from_hybrid_algorithm(
        ec_curve: &KeyMaterialType,
        pq_algorithm: &str,
    ) -> HsmResult<Self> {
        match (ec_curve, pq_algorithm) {
            (KeyMaterialType::EcP256, "MlKem768") => Ok(KeyMaterialType::HybridP256MlKem768),
            _ => Err(HsmError::UnsupportedAlgorithm(format!(
                "Hybrid: {:?}+{}",
                ec_curve, pq_algorithm
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub enum KeyMaterial {
    Symmetric {
        key: Vec<u8>,
    },
    Rsa {
        private_pem: String,
        public_pem: String,
    },
    Ec {
        curve: KeyMaterialType,
        private_pem: String,
        public_pem: String,
    },
    PostQuantum {
        public_key: Vec<u8>,
        private_key: Option<Vec<u8>>,
        algorithm: String,
    },
    Hybrid {
        ec_curve: KeyMaterialType,
        ec_private_pem: Option<String>,
        ec_public_pem: String,
        pq_algorithm: String,
        pq_public_key: Vec<u8>,
        pq_private_key: Option<Vec<u8>>,
    },
}

#[derive(Debug, Clone)]
pub struct GeneratedKey {
    pub id: KeyId,
    pub material: KeyMaterial,
}

#[derive(Debug, Clone)]
pub struct KeyHandle {
    pub id: KeyId,
    pub version: u32,
}

#[derive(Debug, Clone)]
pub struct OperationContext {
    pub correlation_id: Uuid,
    pub associated_data: Option<Vec<u8>>,
    pub expires_after: Option<Duration>,
}

impl OperationContext {
    pub fn new() -> Self {
        Self {
            correlation_id: Uuid::new_v4(),
            associated_data: None,
            expires_after: Some(Duration::seconds(30)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    pub actor_id: String,
    pub session_id: Uuid,
    pub roles: Vec<Role>,
    pub client_fingerprint: Option<String>,
    pub source_ip: Option<String>,
}

impl AuthContext {
    pub fn has_role(&self, role: &Role) -> bool {
        self.roles.contains(role)
    }
}
