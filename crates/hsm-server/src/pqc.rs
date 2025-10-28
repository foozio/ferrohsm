// Post-Quantum Cryptography API extensions for FerroHSM
// Provides REST API endpoints for PQC operations

use axum::{
    extract::{connect_info::ConnectInfo, Path as AxumPath, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use hsm_core::{
    crypto::pqc::{PqKeyAlgorithm, PqSecurityLevel},
    KeyAlgorithm, KeyGenerationRequest, KeyUsage, OperationContext,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::{authenticate_request, AppError, AppState, KeySummary};

// Request and response types for PQC operations

#[derive(Debug, Deserialize)]
pub struct CreatePqKeyRequest {
    pub algorithm: PqKeyAlgorithm,
    pub security_level: Option<PqSecurityLevel>,
    pub usage: KeyUsage,
    pub policy_tags: Option<Vec<String>>,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateHybridKeyRequest {
    pub pq_algorithm: PqKeyAlgorithm,
    pub security_level: Option<PqSecurityLevel>,
    pub classic_algorithm: KeyAlgorithm,
    pub usage: KeyUsage,
    pub policy_tags: Option<Vec<String>>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PqEncapsulateResponse {
    pub ciphertext_b64: String,
    pub shared_secret_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct PqDecapsulateRequest {
    pub ciphertext_b64: String,
}

#[derive(Debug, Serialize)]
pub struct PqDecapsulateResponse {
    pub shared_secret_b64: String,
}

// Register PQC routes with the main application router
pub fn register_routes<P: hsm_core::PolicyEngine + 'static>(router: Router<AppState<P>>) -> Router<AppState<P>> {
    router
        // PQC key management
        .route("/api/v1/keys/pqc", post(create_pq_key::<P>))
        .route("/api/v1/keys/hybrid", post(create_hybrid_key::<P>))
        // KEM operations
        .route("/api/v1/keys/:id/encapsulate", post(encapsulate::<P>))
        .route("/api/v1/keys/:id/decapsulate", post(decapsulate::<P>))
}

// Handler implementations

async fn create_pq_key<P: hsm_core::PolicyEngine>(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    Json(payload): Json<CreatePqKeyRequest>,
) -> Result<Json<KeySummary>, AppError> {
    let ctx = authenticate_request(&state, &headers, addr.ip())?;
    
    // Map PqKeyAlgorithm to KeyAlgorithm
    let algorithm = match payload.algorithm {
        PqKeyAlgorithm::MlKem => KeyAlgorithm::MlKem(payload.security_level.unwrap_or_default()),
        PqKeyAlgorithm::MlDsa => KeyAlgorithm::MlDsa(payload.security_level.unwrap_or_default()),
        PqKeyAlgorithm::SlhDsa => KeyAlgorithm::SlhDsa(payload.security_level.unwrap_or_default()),
        _ => return Err(AppError::bad_request("Hybrid algorithms require using the hybrid endpoint")),
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

async fn create_hybrid_key<P: hsm_core::PolicyEngine>(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    Json(payload): Json<CreateHybridKeyRequest>,
) -> Result<Json<KeySummary>, AppError> {
    let ctx = authenticate_request(&state, &headers, addr.ip())?;
    
    // Create the appropriate hybrid algorithm
    let algorithm = match payload.pq_algorithm {
        PqKeyAlgorithm::MlKemWithP256 => {
            if payload.classic_algorithm != KeyAlgorithm::EcP256 {
                return Err(AppError::bad_request("MlKemWithP256 requires EcP256 as classic algorithm"));
            }
            KeyAlgorithm::MlKemWithP256(payload.security_level.unwrap_or_default())
        },
        PqKeyAlgorithm::MlKemWithP384 => {
            if payload.classic_algorithm != KeyAlgorithm::EcP384 {
                return Err(AppError::bad_request("MlKemWithP384 requires EcP384 as classic algorithm"));
            }
            KeyAlgorithm::MlKemWithP384(payload.security_level.unwrap_or_default())
        },
        PqKeyAlgorithm::MlDsaWithP256 => {
            if payload.classic_algorithm != KeyAlgorithm::EcP256 {
                return Err(AppError::bad_request("MlDsaWithP256 requires EcP256 as classic algorithm"));
            }
            KeyAlgorithm::MlDsaWithP256(payload.security_level.unwrap_or_default())
        },
        PqKeyAlgorithm::MlDsaWithP384 => {
            if payload.classic_algorithm != KeyAlgorithm::EcP384 {
                return Err(AppError::bad_request("MlDsaWithP384 requires EcP384 as classic algorithm"));
            }
            KeyAlgorithm::MlDsaWithP384(payload.security_level.unwrap_or_default())
        },
        _ => return Err(AppError::bad_request("Not a hybrid algorithm")),
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

async fn encapsulate<P: hsm_core::PolicyEngine>(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState<P>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<PqEncapsulateResponse>, AppError> {
    let ctx = authenticate_request(&state, &headers, addr.ip())?;
    
    let operation = hsm_core::CryptoOperation::Encapsulate {};
    let result = state.manager.perform_operation(&id, operation, &ctx, &OperationContext::new())?;
    
    if let hsm_core::KeyOperationResult::Encapsulated { ciphertext, shared_secret } = result {
        Ok(Json(PqEncapsulateResponse {
            ciphertext_b64: B64.encode(ciphertext),
            shared_secret_b64: B64.encode(shared_secret),
        }))
    } else {
        Err(AppError::internal("unexpected operation result"))
    }
}

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
    
    let operation = hsm_core::CryptoOperation::Decapsulate { ciphertext };
    let result = state.manager.perform_operation(&id, operation, &ctx, &OperationContext::new())?;
    
    if let hsm_core::KeyOperationResult::Decapsulated { shared_secret } = result {
        Ok(Json(PqDecapsulateResponse {
            shared_secret_b64: B64.encode(shared_secret),
        }))
    } else {
        Err(AppError::internal("unexpected operation result"))
    }
}