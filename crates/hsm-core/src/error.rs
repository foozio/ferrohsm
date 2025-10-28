use thiserror::Error;
use uuid::Uuid;

use crate::models::KeyState;

pub type HsmResult<T> = Result<T, HsmError>;

#[derive(Debug, Error)]
pub enum HsmError {
    #[error("storage error: {0}")]
    Storage(String),
    #[error("policy denied action")]
    PolicyDenied,
    #[error("cryptography error: {0}")]
    Crypto(String),
    #[error("key not found: {0}")]
    KeyNotFound(String),
    #[error("key inactive: {0:?}")]
    KeyInactive(KeyState),
    #[error("tamper detected for key {0}")]
    TamperDetected(String),
    #[error("audit failure: {0}")]
    Audit(String),
    #[error("authorization error: {0}")]
    Authorization(String),
    #[error("dual-control approval required: {approval_id}")]
    ApprovalRequired { approval_id: Uuid },
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("unexpected error: {0}")]
    Unexpected(String),
}

impl HsmError {
    pub fn storage<E: std::fmt::Display>(err: E) -> Self {
        Self::Storage(err.to_string())
    }
    pub fn crypto<E: std::fmt::Display>(err: E) -> Self {
        Self::Crypto(err.to_string())
    }
    pub fn audit<E: std::fmt::Display>(err: E) -> Self {
        Self::Audit(err.to_string())
    }
    pub fn invalid<E: std::fmt::Display>(err: E) -> Self {
        Self::InvalidRequest(err.to_string())
    }
}
