//! PKCS#11 compatibility layer for FerroHSM.
//!
//! This crate exposes C ABI entrypoints that bridge the PKCS#11
//! specification onto existing FerroHSM primitives. The implementation
//! is staged; initial scaffolding wires basic initialization flows and
//! shared state management while the full function surface is added
//! incrementally during Phase 1.
//!
//! This implementation includes support for post-quantum cryptography
//! algorithms including ML-KEM, ML-DSA, SLH-DSA, and hybrid combinations
//! with classical algorithms.

use cryptoki_sys::{
    CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED, CKR_OK,
    CK_RV, CK_VOID_PTR,
};
use hsm_core::{
    models::{KeyAlgorithm, KeyMaterial, KeyMaterialType, KeyMetadata},
    pqc::{CryptoProvider, MlDsaSecurityLevel, MlKemSecurityLevel, SlhDsaSecurityLevel},
};
use parking_lot::RwLock;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error, info, warn};

// Module declarations
pub mod mechanism;
pub mod attribute;

#[derive(Debug)]
struct InstanceContext {
    created_at: std::time::Instant,
}

#[derive(Debug, Default)]
struct GlobalState {
    context: Option<Arc<InstanceContext>>,
}

static STATE: once_cell::sync::Lazy<RwLock<GlobalState>> =
    once_cell::sync::Lazy::new(|| RwLock::new(GlobalState::default()));

/// Errors raised by the PKCS#11 front-end prior to translation into
/// CKR_* return codes.
#[derive(Debug, Error)]
pub enum FrontendError {
    #[error("cryptoki already initialized")]
    AlreadyInitialized,
    #[error("cryptoki not initialized")]
    NotInitialized,
    #[error("internal error: {0}")]
    Internal(String),
}

/// Initialize the PKCS#11 front-end.
pub fn initialize(_args: CK_VOID_PTR) -> Result<(), FrontendError> {
    let mut guard = STATE.write();
    if guard.context.is_some() {
        return Err(FrontendError::AlreadyInitialized);
    }
    guard.context = Some(Arc::new(InstanceContext {
        created_at: std::time::Instant::now(),
    }));
    info!("PKCS#11 instance initialized");
    Ok(())
}

/// Finalize the PKCS#11 front-end, releasing resources.
pub fn finalize() -> Result<(), FrontendError> {
    let mut guard = STATE.write();
    if guard.context.take().is_none() {
        return Err(FrontendError::NotInitialized);
    }
    info!("PKCS#11 instance finalized");
    Ok(())
}

fn translate_error(err: FrontendError) -> CK_RV {
    match err {
        FrontendError::AlreadyInitialized => CKR_CRYPTOKI_ALREADY_INITIALIZED,
        FrontendError::NotInitialized => CKR_CRYPTOKI_NOT_INITIALIZED,
        FrontendError::Internal(_) => CKR_FUNCTION_FAILED,
    }
}

#[no_mangle]
pub extern "C" fn C_Initialize(p_init_args: CK_VOID_PTR) -> CK_RV {
    match initialize(p_init_args) {
        Ok(()) => CKR_OK,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 initialize internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

#[no_mangle]
pub extern "C" fn C_Finalize(_reserved: CK_VOID_PTR) -> CK_RV {
    match finalize() {
        Ok(()) => CKR_OK,
        Err(err) => {
            if let FrontendError::Internal(ref msg) = err {
                error!("pkcs11 finalize internal error: {msg}");
            }
            translate_error(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_and_finalize_roundtrip() {
        initialize(std::ptr::null_mut()).expect("init");
        finalize().expect("finalize");
        assert_eq!(
            translate_error(finalize().unwrap_err()),
            CKR_CRYPTOKI_NOT_INITIALIZED
        );
    }

    #[test]
    fn double_initialize_is_rejected() {
        initialize(std::ptr::null_mut()).expect("init");
        let rv = translate_error(initialize(std::ptr::null_mut()).unwrap_err());
        assert_eq!(rv, CKR_CRYPTOKI_ALREADY_INITIALIZED);
        finalize().expect("finalize");
    }
}
