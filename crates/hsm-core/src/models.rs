use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{HsmError, HsmResult, attributes::AttributeSet, rbac::Role};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
        let label = match self {
            KeyMaterialType::Symmetric => "Symmetric",
            KeyMaterialType::Rsa => "Rsa",
            KeyMaterialType::EcP256 => "EcP256",
            KeyMaterialType::EcP384 => "EcP384",
            KeyMaterialType::MlKem512 => "ML-KEM-512",
            KeyMaterialType::MlKem768 => "ML-KEM-768",
            KeyMaterialType::MlKem1024 => "ML-KEM-1024",
            KeyMaterialType::MlDsa44 => "ML-DSA-44",
            KeyMaterialType::MlDsa65 => "ML-DSA-65",
            KeyMaterialType::MlDsa87 => "ML-DSA-87",
            KeyMaterialType::SlhDsa128f => "SLH-DSA-128f",
            KeyMaterialType::SlhDsa128s => "SLH-DSA-128s",
            KeyMaterialType::SlhDsa192f => "SLH-DSA-192f",
            KeyMaterialType::SlhDsa192s => "SLH-DSA-192s",
            KeyMaterialType::SlhDsa256f => "SLH-DSA-256f",
            KeyMaterialType::SlhDsa256s => "SLH-DSA-256s",
            KeyMaterialType::HybridP256MlKem512 => "HybridP256MlKem512",
            KeyMaterialType::HybridP256MlKem768 => "HybridP256MlKem768",
            KeyMaterialType::HybridP384MlKem1024 => "HybridP384MlKem1024",
            KeyMaterialType::HybridP256MlDsa44 => "HybridP256MlDsa44",
            KeyMaterialType::HybridP256MlDsa65 => "HybridP256MlDsa65",
            KeyMaterialType::HybridP384MlDsa87 => "HybridP384MlDsa87",
        };
        write!(f, "{label}")
    }
}

impl KeyMaterialType {
    pub fn from_algorithm(algorithm: &str) -> HsmResult<Self> {
        match algorithm {
            "ML-KEM-512" | "MlKem512" => Ok(KeyMaterialType::MlKem512),
            "ML-KEM-768" | "MlKem768" => Ok(KeyMaterialType::MlKem768),
            "ML-KEM-1024" | "MlKem1024" => Ok(KeyMaterialType::MlKem1024),
            "ML-DSA-44" | "MlDsa44" => Ok(KeyMaterialType::MlDsa44),
            "ML-DSA-65" | "MlDsa65" => Ok(KeyMaterialType::MlDsa65),
            "ML-DSA-87" | "MlDsa87" => Ok(KeyMaterialType::MlDsa87),
            "SLH-DSA-128f" | "SlhDsa128f" => Ok(KeyMaterialType::SlhDsa128f),
            "SLH-DSA-128s" | "SlhDsa128s" => Ok(KeyMaterialType::SlhDsa128s),
            "SLH-DSA-192f" | "SlhDsa192f" => Ok(KeyMaterialType::SlhDsa192f),
            "SLH-DSA-192s" | "SlhDsa192s" => Ok(KeyMaterialType::SlhDsa192s),
            "SLH-DSA-256f" | "SlhDsa256f" => Ok(KeyMaterialType::SlhDsa256f),
            "SLH-DSA-256s" | "SlhDsa256s" => Ok(KeyMaterialType::SlhDsa256s),
            _ => Err(HsmError::UnsupportedAlgorithm(algorithm.to_string())),
        }
    }

    pub fn from_hybrid_algorithm(
        ec_curve: &KeyMaterialType,
        pq_algorithm: &str,
    ) -> HsmResult<Self> {
        match (ec_curve, pq_algorithm) {
            (KeyMaterialType::EcP256, "ML-KEM-512") | (KeyMaterialType::EcP256, "MlKem512") => {
                Ok(KeyMaterialType::HybridP256MlKem512)
            }
            (KeyMaterialType::EcP256, "ML-KEM-768") | (KeyMaterialType::EcP256, "MlKem768") => {
                Ok(KeyMaterialType::HybridP256MlKem768)
            }
            (KeyMaterialType::EcP384, "ML-KEM-1024") | (KeyMaterialType::EcP384, "MlKem1024") => {
                Ok(KeyMaterialType::HybridP384MlKem1024)
            }
            (KeyMaterialType::EcP256, "ML-DSA-44") | (KeyMaterialType::EcP256, "MlDsa44") => {
                Ok(KeyMaterialType::HybridP256MlDsa44)
            }
            (KeyMaterialType::EcP256, "ML-DSA-65") | (KeyMaterialType::EcP256, "MlDsa65") => {
                Ok(KeyMaterialType::HybridP256MlDsa65)
            }
            (KeyMaterialType::EcP384, "ML-DSA-87") | (KeyMaterialType::EcP384, "MlDsa87") => {
                Ok(KeyMaterialType::HybridP384MlDsa87)
            }
            _ => Err(HsmError::UnsupportedAlgorithm(format!(
                "Hybrid: {:?}+{}",
                ec_curve, pq_algorithm
            ))),
        }
    }

    pub fn hybrid_components(&self) -> Option<(KeyMaterialType, &'static str)> {
        match self {
            KeyMaterialType::HybridP256MlKem512 => Some((KeyMaterialType::EcP256, "ML-KEM-512")),
            KeyMaterialType::HybridP256MlKem768 => Some((KeyMaterialType::EcP256, "ML-KEM-768")),
            KeyMaterialType::HybridP384MlKem1024 => Some((KeyMaterialType::EcP384, "ML-KEM-1024")),
            KeyMaterialType::HybridP256MlDsa44 => Some((KeyMaterialType::EcP256, "ML-DSA-44")),
            KeyMaterialType::HybridP256MlDsa65 => Some((KeyMaterialType::EcP256, "ML-DSA-65")),
            KeyMaterialType::HybridP384MlDsa87 => Some((KeyMaterialType::EcP384, "ML-DSA-87")),
            _ => None,
        }
    }

    pub fn algorithm_label(&self) -> Option<&'static str> {
        match self {
            KeyMaterialType::MlKem512 => Some("ML-KEM-512"),
            KeyMaterialType::MlKem768 => Some("ML-KEM-768"),
            KeyMaterialType::MlKem1024 => Some("ML-KEM-1024"),
            KeyMaterialType::MlDsa44 => Some("ML-DSA-44"),
            KeyMaterialType::MlDsa65 => Some("ML-DSA-65"),
            KeyMaterialType::MlDsa87 => Some("ML-DSA-87"),
            KeyMaterialType::SlhDsa128f => Some("SLH-DSA-128f"),
            KeyMaterialType::SlhDsa128s => Some("SLH-DSA-128s"),
            KeyMaterialType::SlhDsa192f => Some("SLH-DSA-192f"),
            KeyMaterialType::SlhDsa192s => Some("SLH-DSA-192s"),
            KeyMaterialType::SlhDsa256f => Some("SLH-DSA-256f"),
            KeyMaterialType::SlhDsa256s => Some("SLH-DSA-256s"),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyMaterial {
    #[serde(rename = "symmetric")]
    Symmetric { key: Vec<u8> },
    #[serde(rename = "rsa")]
    Rsa {
        private_pem: String,
        public_pem: String,
    },
    #[serde(rename = "ec")]
    Ec {
        curve: KeyMaterialType,
        private_pem: String,
        public_pem: String,
    },
    #[serde(rename = "post_quantum")]
    PostQuantum {
        public_key: Vec<u8>,
        private_key: Option<Vec<u8>>,
        algorithm: String,
    },
    #[serde(rename = "hybrid")]
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
        Self::default()
    }
}

impl Default for OperationContext {
    fn default() -> Self {
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListApprovalsQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_tags: Vec<String>,
    pub page: u32,
    pub per_page: u32,
    pub include_resolved: bool,
}

impl Default for ListApprovalsQuery {
    fn default() -> Self {
        Self {
            action: None,
            subject: None,
            policy_tags: Vec::new(),
            page: 1,
            per_page: 50,
            include_resolved: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalListPage {
    pub items: Vec<crate::approvals::PendingApprovalInfo>,
    pub total: usize,
    pub page: u32,
    pub per_page: u32,
    pub has_more: bool,
}
