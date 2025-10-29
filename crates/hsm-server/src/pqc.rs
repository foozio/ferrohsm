// Post-Quantum Cryptography API extensions for FerroHSM.
// Provides REST API endpoints for PQC operations.

#[cfg(feature = "pqc")]
use axum::{
    Router,
    extract::{Path as AxumPath, State, connect_info::ConnectInfo},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
};
#[cfg(feature = "pqc")]
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
#[cfg(feature = "pqc")]
use hsm_core::pqc::{MlDsaSecurityLevel, MlKemSecurityLevel, PqKeyAlgorithm, SlhDsaSecurityLevel};

#[cfg(feature = "pqc")]
use hsm_core::{KeyAlgorithm, KeyGenerationRequest, KeyUsage, OperationContext};
#[cfg(feature = "pqc")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "pqc")]
use std::net::SocketAddr;

use crate::AppState;
#[cfg(feature = "pqc")]
use crate::{AppError, KeySummary, authenticate_request};

// Request and response types for PQC operations

#[cfg(feature = "pqc")]
#[derive(Debug, Deserialize)]
pub struct CreatePqKeyRequest {
    pub algorithm: PqKeyAlgorithm,
    pub security_level: Option<MlKemSecurityLevel>, // Default to MlKemSecurityLevel for now
    pub usage: KeyUsage,
    pub policy_tags: Option<Vec<String>>,
    pub description: Option<String>,
}

#[cfg(feature = "pqc")]
#[derive(Debug, Deserialize)]
pub struct CreateHybridKeyRequest {
    pub pq_algorithm: PqKeyAlgorithm,
    pub security_level: Option<MlKemSecurityLevel>, // Default to MlKemSecurityLevel for now
    pub classic_algorithm: KeyAlgorithm,
    pub usage: KeyUsage,
    pub policy_tags: Option<Vec<String>>,
    pub description: Option<String>,
}

#[cfg(feature = "pqc")]
#[derive(Debug, Serialize)]
pub struct PqEncapsulateResponse {
    pub ciphertext_b64: String,
    pub shared_secret_b64: String,
}

#[cfg(feature = "pqc")]
#[derive(Debug, Deserialize)]
pub struct PqDecapsulateRequest {
    pub ciphertext_b64: String,
}

#[cfg(feature = "pqc")]
#[derive(Debug, Serialize)]
pub struct PqDecapsulateResponse {
    pub shared_secret_b64: String,
}

// Register PQC routes with the main application router
#[cfg(feature = "pqc")]
pub fn register_routes<P: hsm_core::PolicyEngine + 'static>(
    router: Router<AppState<P>>,
) -> Router<AppState<P>> {
    router
        // PQC key management
        .route("/api/v1/keys/pqc", post(create_pq_key::<P>))
        .route("/api/v1/keys/hybrid", post(create_hybrid_key::<P>))
        // KEM operations
        .route("/api/v1/keys/:id/encapsulate", post(encapsulate::<P>))
        .route("/api/v1/keys/:id/decapsulate", post(decapsulate::<P>))
}

#[cfg(not(feature = "pqc"))]
pub fn register_routes<P: hsm_core::PolicyEngine + 'static>(
    router: axum::Router<AppState<P>>,
) -> axum::Router<AppState<P>> {
    router
}

// Handler implementations

#[cfg(feature = "pqc")]
async fn create_pq_key<P: hsm_core::PolicyEngine>(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    Json(payload): Json<CreatePqKeyRequest>,
) -> Result<Json<KeySummary>, AppError> {
    let ctx = authenticate_request(&state, &headers, addr.ip())?;

    // Map PqKeyAlgorithm to KeyAlgorithm
    let algorithm = match payload.algorithm {
        PqKeyAlgorithm::MlKem(security_level) => match security_level {
            MlKemSecurityLevel::MlKem512 => KeyAlgorithm::MlKem512,
            MlKemSecurityLevel::MlKem768 => KeyAlgorithm::MlKem768,
            MlKemSecurityLevel::MlKem1024 => KeyAlgorithm::MlKem1024,
        },
        PqKeyAlgorithm::MlDsa(security_level) => match security_level {
            MlDsaSecurityLevel::MlDsa44 => KeyAlgorithm::MlDsa44,
            MlDsaSecurityLevel::MlDsa65 => KeyAlgorithm::MlDsa65,
            MlDsaSecurityLevel::MlDsa87 => KeyAlgorithm::MlDsa87,
        },
        PqKeyAlgorithm::SlhDsa(security_level) => match security_level {
            SlhDsaSecurityLevel::SlhDsaSha2128f => KeyAlgorithm::SlhDsa128f,
            SlhDsaSecurityLevel::SlhDsaSha2128s => KeyAlgorithm::SlhDsa128s,
            SlhDsaSecurityLevel::SlhDsaSha2192f => KeyAlgorithm::SlhDsa192f,
            SlhDsaSecurityLevel::SlhDsaSha2192s => KeyAlgorithm::SlhDsa192s,
            SlhDsaSecurityLevel::SlhDsaSha2256f => KeyAlgorithm::SlhDsa256f,
            SlhDsaSecurityLevel::SlhDsaSha2256s => KeyAlgorithm::SlhDsa256s,
        },
        _ => {
            return Err(AppError::bad_request(
                "Hybrid algorithms require using the hybrid endpoint",
            ));
        }
    };

    let req = KeyGenerationRequest {
        algorithm,
        usage: payload.usage,
        policy_tags: payload.policy_tags.unwrap_or_default(),
        description: payload.description,
    };

    let meta = state.manager.generate_key(req, &ctx)?;
    Ok(Json(KeySummary::from(meta)))
}

#[cfg(feature = "pqc")]
async fn create_hybrid_key<P: hsm_core::PolicyEngine>(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    Json(payload): Json<CreateHybridKeyRequest>,
) -> Result<Json<KeySummary>, AppError> {
    let ctx = authenticate_request(&state, &headers, addr.ip())?;

    // Create the appropriate hybrid algorithm
    let algorithm = match payload.pq_algorithm {
        PqKeyAlgorithm::HybridEcdhMlKem(KeyAlgorithm::P256, security_level) => match security_level
        {
            MlKemSecurityLevel::MlKem512 => KeyAlgorithm::HybridP256MlKem512,
            MlKemSecurityLevel::MlKem768 => KeyAlgorithm::HybridP256MlKem768,
            MlKemSecurityLevel::MlKem1024 => KeyAlgorithm::HybridP384MlKem1024,
        },
        PqKeyAlgorithm::HybridEcdhMlKem(KeyAlgorithm::P384, security_level) => match security_level
        {
            MlKemSecurityLevel::MlKem512 => KeyAlgorithm::HybridP256MlKem512,
            MlKemSecurityLevel::MlKem768 => KeyAlgorithm::HybridP256MlKem768,
            MlKemSecurityLevel::MlKem1024 => KeyAlgorithm::HybridP384MlKem1024,
        },
        PqKeyAlgorithm::HybridEcdsaMlDsa(KeyAlgorithm::P256, security_level) => {
            match security_level {
                MlDsaSecurityLevel::MlDsa44 => KeyAlgorithm::HybridP256MlDsa44,
                MlDsaSecurityLevel::MlDsa65 => KeyAlgorithm::HybridP256MlDsa65,
                MlDsaSecurityLevel::MlDsa87 => KeyAlgorithm::HybridP384MlDsa87,
            }
        }
        PqKeyAlgorithm::HybridEcdsaMlDsa(KeyAlgorithm::P384, security_level) => {
            match security_level {
                MlDsaSecurityLevel::MlDsa44 => KeyAlgorithm::HybridP256MlDsa44,
                MlDsaSecurityLevel::MlDsa65 => KeyAlgorithm::HybridP256MlDsa65,
                MlDsaSecurityLevel::MlDsa87 => KeyAlgorithm::HybridP384MlDsa87,
            }
        }
        _ => return Err(AppError::bad_request("Not a supported hybrid algorithm")),
    };

    let req = KeyGenerationRequest {
        algorithm,
        usage: payload.usage,
        policy_tags: payload.policy_tags.unwrap_or_default(),
        description: payload.description,
    };

    let meta = state.manager.generate_key(req, &ctx)?;
    Ok(Json(KeySummary::from(meta)))
}

#[cfg(feature = "pqc")]
async fn encapsulate<P: hsm_core::PolicyEngine>(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<PqEncapsulateResponse>, AppError> {
    let ctx = authenticate_request(&state, &headers, addr.ip())?;

    let operation = hsm_core::CryptoOperation::KemEncapsulate {
        recipient_public_key: None,
    };
    let result = state
        .manager
        .perform_operation(&id, operation, &ctx, &OperationContext::new())?;

    if let hsm_core::KeyOperationResult::KemEncapsulated {
        ciphertext,
        shared_secret,
    } = result
    {
        Ok(Json(PqEncapsulateResponse {
            ciphertext_b64: B64.encode(ciphertext),
            shared_secret_b64: B64.encode(shared_secret),
        }))
    } else {
        Err(AppError::internal("unexpected operation result"))
    }
}

#[cfg(feature = "pqc")]
async fn decapsulate<P: hsm_core::PolicyEngine>(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(payload): Json<PqDecapsulateRequest>,
) -> Result<Json<PqDecapsulateResponse>, AppError> {
    let ctx = authenticate_request(&state, &headers, addr.ip())?;

    // Validate payload size before decoding
    if payload.ciphertext_b64.len() > 10_000_000 {
        return Err(AppError::bad_request("ciphertext too large"));
    }

    let ciphertext = B64
        .decode(&payload.ciphertext_b64)
        .map_err(|_| AppError::bad_request("invalid base64 ciphertext"))?;

    let operation = hsm_core::CryptoOperation::KemDecapsulate { ciphertext };
    let result = state
        .manager
        .perform_operation(&id, operation, &ctx, &OperationContext::new())?;

    if let hsm_core::KeyOperationResult::KemDecapsulated { shared_secret } = result {
        Ok(Json(PqDecapsulateResponse {
            shared_secret_b64: B64.encode(shared_secret),
        }))
    } else {
        Err(AppError::internal("unexpected operation result"))
    }
}
