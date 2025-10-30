//! PKCS#11 type definitions and conversions

use cryptoki::types::*;
use hsm_core::error::HsmError;

/// Convert HsmError to PKCS#11 CK_RV
pub fn hsm_error_to_ckr(error: HsmError) -> CK_RV {
    match error {
        HsmError::InvalidArgument => CK_RV::CKR_ARGUMENTS_BAD,
        HsmError::NotFound => CK_RV::CKR_OBJECT_HANDLE_INVALID,
        HsmError::PermissionDenied => CK_RV::CKR_USER_NOT_LOGGED_IN,
        HsmError::AlreadyExists => CK_RV::CKR_OBJECT_HANDLE_INVALID,
        HsmError::CryptoError(_) => CK_RV::CKR_DEVICE_ERROR,
        HsmError::StorageError(_) => CK_RV::CKR_DEVICE_MEMORY,
        HsmError::IoError(_) => CK_RV::CKR_DEVICE_ERROR,
        HsmError::SerializationError(_) => CK_RV::CKR_DEVICE_ERROR,
        HsmError::InvalidState => CK_RV::CKR_OPERATION_NOT_INITIALIZED,
        HsmError::Timeout => CK_RV::CKR_DEVICE_ERROR,
        HsmError::NotSupported => CK_RV::CKR_MECHANISM_INVALID,
        HsmError::RateLimited => CK_RV::CKR_DEVICE_ERROR,
        HsmError::InternalError(_) => CK_RV::CKR_GENERAL_ERROR,
    }
}