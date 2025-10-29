//! FerroHSM core library encapsulating key lifecycle management, policy enforcement,
//! tamper-evident storage, and audit logging. Higher level components (REST service,
//! CLI, SDKs) interact exclusively with this crate.

pub mod approvals;
pub mod attributes;
pub mod audit;
pub mod crypto;
pub mod error;
pub mod fs_utils;
pub mod models;
pub mod policy;
#[cfg(feature = "pqc")]
pub mod pqc;
#[cfg(feature = "pqc")]
pub mod pqc_policy;
#[cfg(feature = "pqc")]
pub mod pqc_provider;
pub mod rbac;
pub mod retention;
pub mod session;
pub mod storage;

#[cfg(test)]
pub mod tests;

pub use approvals::{
    ApprovalRecord, ApprovalStore, FileApprovalStore, PendingApprovalInfo, SqliteApprovalStore,
};
pub use attributes::{AttributeId, AttributeSet, AttributeTemplate, AttributeValue};
pub use audit::{
    AuditEvent, AuditLog, AuditRecord, AuditSink, FileAuditLog, SqliteAuditLog, compute_event_hash,
};
pub use crypto::{CryptoEngine, CryptoOperation, KeyOperationResult};
pub use error::{HsmError, HsmResult};
pub use models::{
    AuthContext, KeyAlgorithm, KeyGenerationRequest, KeyHandle, KeyId, KeyListPage, KeyListQuery,
    KeyMaterialType, KeyMetadata, KeyPurpose, KeyState, KeyUsage, OperationContext, TamperStatus,
};
pub use policy::{DefaultPolicyEngine, PolicyDecision, PolicyEngine};
#[cfg(not(feature = "pqc"))]
pub struct PqcPolicyController;
#[cfg(not(feature = "pqc"))]
impl PqcPolicyController {
    pub fn is_authorized(&self, _ctx: &AuthContext, _algorithm: &KeyAlgorithm) -> bool {
        true
    }

    pub fn get_policy_tags(&self, _algorithm: &KeyAlgorithm) -> Vec<String> {
        Vec::new()
    }
}
#[cfg(not(feature = "pqc"))]
impl Default for PqcPolicyController {
    fn default() -> Self {
        PqcPolicyController
    }
}
#[cfg(feature = "pqc")]
pub use pqc_policy::PqcPolicyController;
pub use rbac::{Action, RbacAuthorizer, Role};
pub use retention::{RetentionLedger, RetentionLedgerEntry, RetentionPolicy};
pub use session::{
    HardwareAdapter, ObjectDescriptor, ObjectHandle, SessionHandle, SessionInfo, SessionManager,
    SessionState, SlotDescriptor, SlotId,
};
pub use storage::{
    FileKeyStore, KeyRecord, KeyStore, MemoryKeyStore, PurgeReport, RemoteKeyStore, RemoteKeyVault,
    SqliteKeyStore,
};

use std::sync::Arc;
use time::OffsetDateTime;

/// Primary façade for key lifecycle management and controlled cryptographic access.
pub struct KeyManager<S: KeyStore + ?Sized, A: AuditLog + ?Sized, P: PolicyEngine> {
    storage: Arc<S>,
    audit: Arc<A>,
    policy: P,
    crypto: CryptoEngine,
}

impl<S, A, P> KeyManager<S, A, P>
where
    S: KeyStore + ?Sized,
    A: AuditLog + ?Sized,
    P: PolicyEngine,
{
    /// Instantiate the key manager with a storage backend, audit sink, policy engine, and
    /// master secrets required to seal key material.
    pub fn new(
        storage: Arc<S>,
        audit: Arc<A>,
        policy: P,
        master_key: [u8; 32],
        hmac_key: [u8; 32],
    ) -> Self {
        Self {
            storage,
            audit,
            policy,
            crypto: CryptoEngine::new(master_key, hmac_key),
        }
    }

    /// Generate a new key according to the provided request and store a sealed record.
    pub fn generate_key(
        &self,
        request: KeyGenerationRequest,
        ctx: &AuthContext,
    ) -> HsmResult<KeyMetadata> {
        self.authorize(ctx, &Action::CreateKey, &request.policy_tags, None)?;
        let generated = self.crypto.generate_material(&request)?;
        let metadata = KeyMetadata::from_request(&request, generated.id.clone());
        let record = self
            .crypto
            .seal_key(&metadata, generated.material.clone())?;
        self.storage.store(record)?;
        self.audit.record(AuditRecord::new(
            ctx.clone(),
            metadata.id.clone(),
            Action::CreateKey,
            "Key generated",
        ))?;
        Ok(metadata)
    }

    /// Retrieve public details about a key. Fails if key is not active or access denied.
    pub fn describe_key(&self, id: &KeyId, ctx: &AuthContext) -> HsmResult<KeyMetadata> {
        let record = self.storage.fetch(id)?;
        self.authorize(
            ctx,
            &Action::DescribeKey,
            &record.metadata.policy_tags,
            Some(id),
        )?;
        Ok(record.metadata.clone())
    }

    /// Retrieve the metadata for a specific key version.
    pub fn describe_key_version(
        &self,
        id: &KeyId,
        version: u32,
        ctx: &AuthContext,
    ) -> HsmResult<KeyMetadata> {
        let record = self.storage.fetch_version(id, version)?;
        self.authorize(
            ctx,
            &Action::DescribeKey,
            &record.metadata.policy_tags,
            Some(id),
        )?;
        Ok(record.metadata.clone())
    }

    /// List metadata for all keys subject to policy constraints.
    pub fn list_keys(&self, ctx: &AuthContext) -> HsmResult<Vec<KeyMetadata>> {
        let query = KeyListQuery {
            per_page: u32::MAX,
            ..Default::default()
        };
        let page = self.list_keys_with_query(ctx, &query)?;
        Ok(page.items)
    }

    /// List metadata for all keys subject to policy constraints with pagination and filtering.
    pub fn list_keys_with_query(
        &self,
        ctx: &AuthContext,
        query: &KeyListQuery,
    ) -> HsmResult<KeyListPage> {
        let mut filtered = Vec::new();
        let records = self.storage.list()?;
        let tags = {
            let mut t = query.policy_tags.clone();
            t.sort();
            t
        };

        for record in records {
            if self
                .authorize(
                    ctx,
                    &Action::DescribeKey,
                    &record.metadata.policy_tags,
                    Some(&record.metadata.id),
                )
                .is_err()
            {
                continue;
            }

            let metadata = record.metadata.clone();
            if let Some(algorithm) = query.algorithm
                && metadata.algorithm != algorithm
            {
                continue;
            }

            if let Some(ref state) = query.state
                && &metadata.state != state
            {
                continue;
            }

            if !tags.is_empty() {
                let mut policy_tags = metadata.policy_tags.clone();
                policy_tags.sort();
                let matches = tags
                    .iter()
                    .all(|tag| policy_tags.binary_search(tag).is_ok());
                if !matches {
                    continue;
                }
            }

            filtered.push(metadata);
        }

        filtered.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        let per_page = if query.per_page == u32::MAX {
            filtered.len().max(1)
        } else {
            query.per_page.clamp(1, 1000) as usize
        };
        let page_index = if query.page == 0 { 0 } else { query.page - 1 } as usize;
        let total = filtered.len();
        let start = page_index.saturating_mul(per_page);
        let end = (start + per_page).min(total);
        let items = if start >= total {
            Vec::new()
        } else {
            filtered[start..end].to_vec()
        };
        let has_more = end < total;

        Ok(KeyListPage {
            items,
            total,
            page: if query.page == 0 { 1 } else { query.page },
            per_page: per_page as u32,
            has_more,
        })
    }

    /// Perform a cryptographic operation (encrypt, decrypt, sign, verify) with policy checks.
    pub fn perform_operation(
        &self,
        key_id: &KeyId,
        operation: CryptoOperation,
        ctx: &AuthContext,
        op_ctx: &OperationContext,
    ) -> HsmResult<KeyOperationResult> {
        let record = self.storage.fetch(key_id)?;
        if record.metadata.state != KeyState::Active {
            return Err(HsmError::KeyInactive(record.metadata.state));
        }
        let action = operation.as_action();

        // Apply PQC-specific policy controls if applicable
        if record.metadata.algorithm.is_post_quantum() || record.metadata.algorithm.is_hybrid() {
            let pqc_controller = PqcPolicyController;

            // Check if the user is authorized to use this PQC algorithm
            if !pqc_controller.is_authorized(ctx, &record.metadata.algorithm) {
                return Err(HsmError::Authorization(format!(
                    "User is not authorized to use PQC algorithm {:?}",
                    record.metadata.algorithm
                )));
            }

            // Add PQC-specific policy tags for authorization
            let mut policy_tags = record.metadata.policy_tags.clone();
            policy_tags.extend(pqc_controller.get_policy_tags(&record.metadata.algorithm));

            self.authorize(ctx, &action, &policy_tags, Some(key_id))?;
        } else {
            // Standard authorization for non-PQC algorithms
            self.authorize(ctx, &action, &record.metadata.policy_tags, Some(key_id))?;
        }

        let material = self.crypto.open_key(&record)?;
        let result = self.crypto.perform(operation.clone(), &material, op_ctx)?;
        self.audit.record(AuditRecord::new(
            ctx.clone(),
            record.metadata.id.clone(),
            action,
            "Operation performed",
        ))?;
        Ok(result)
    }

    /// Rotate a key by generating new material with the same metadata settings.
    pub fn rotate_key(&self, key_id: &KeyId, ctx: &AuthContext) -> HsmResult<KeyMetadata> {
        let mut current_record = self.storage.fetch(key_id)?;
        self.authorize(
            ctx,
            &Action::RotateKey,
            &current_record.metadata.policy_tags,
            Some(key_id),
        )?;
        let request = KeyGenerationRequest {
            algorithm: current_record.metadata.algorithm,
            usage: current_record.metadata.usage.clone(),
            policy_tags: current_record.metadata.policy_tags.clone(),
            description: current_record.metadata.description.clone(),
        };
        let new_key = self.crypto.generate_material(&request)?;
        let mut new_metadata = current_record.metadata.clone();
        let previous_version = new_metadata.version;
        new_metadata.version += 1;
        new_metadata.state = KeyState::Active;
        new_metadata.created_at = OffsetDateTime::now_utc();
        let new_record = self.crypto.seal_key(&new_metadata, new_key.material)?;
        current_record.metadata.state = KeyState::Revoked;
        self.storage.store(current_record.clone())?;
        self.storage.store(new_record.clone())?;
        self.audit.record(AuditRecord::new(
            ctx.clone(),
            new_metadata.id.clone(),
            Action::RotateKey,
            format!(
                "Key rotated from version {previous_version} to {}",
                new_metadata.version
            ),
        ))?;
        Ok(new_metadata)
    }

    /// List metadata for each stored version of a key.
    pub fn list_key_versions(
        &self,
        key_id: &KeyId,
        ctx: &AuthContext,
    ) -> HsmResult<Vec<KeyMetadata>> {
        let current = self.storage.fetch(key_id)?;
        self.authorize(
            ctx,
            &Action::DescribeKey,
            &current.metadata.policy_tags,
            Some(key_id),
        )?;
        let records = self.storage.list_versions(key_id)?;
        Ok(records.into_iter().map(|r| r.metadata).collect())
    }

    /// Restore an earlier key version by promoting it as the latest generation.
    pub fn rollback_key(
        &self,
        key_id: &KeyId,
        target_version: u32,
        ctx: &AuthContext,
    ) -> HsmResult<KeyMetadata> {
        let mut current = self.storage.fetch(key_id)?;
        self.authorize(
            ctx,
            &Action::RollbackKey,
            &current.metadata.policy_tags,
            Some(key_id),
        )?;

        if target_version == current.metadata.version {
            return Err(HsmError::invalid("requested version already active"));
        }

        if target_version == 0 {
            return Err(HsmError::invalid("version numbers start at 1"));
        }

        let source = self.storage.fetch_version(key_id, target_version)?;

        let mut restored = source.metadata.clone();
        let previous_version = current.metadata.version;
        restored.version = previous_version + 1;
        restored.state = KeyState::Active;
        restored.created_at = OffsetDateTime::now_utc();

        let restored_record = KeyRecord {
            metadata: restored.clone(),
            sealed: source.sealed.clone(),
        };

        current.metadata.state = KeyState::Revoked;
        self.storage.store(current.clone())?;
        self.storage.store(restored_record.clone())?;

        self.audit.record(AuditRecord::new(
            ctx.clone(),
            restored.id.clone(),
            Action::RollbackKey,
            format!(
                "Key rolled back from version {previous_version} to historical version {target_version}, new active version {}",
                restored.version
            ),
        ))?;

        Ok(restored)
    }

    /// Mark a key as revoked and persist metadata change.
    pub fn revoke_key(&self, key_id: &KeyId, ctx: &AuthContext) -> HsmResult<()> {
        let mut record = self.storage.fetch(key_id)?;
        self.authorize(
            ctx,
            &Action::RevokeKey,
            &record.metadata.policy_tags,
            Some(key_id),
        )?;
        record.metadata.state = KeyState::Revoked;
        self.storage.store(record)?;
        self.audit.record(AuditRecord::new(
            ctx.clone(),
            key_id.clone(),
            Action::RevokeKey,
            "Key revoked",
        ))?;
        Ok(())
    }

    /// Securely delete the key material and metadata.
    pub fn destroy_key(&self, key_id: &KeyId, ctx: &AuthContext) -> HsmResult<()> {
        let record = self.storage.fetch(key_id)?;
        self.authorize(
            ctx,
            &Action::DestroyKey,
            &record.metadata.policy_tags,
            Some(key_id),
        )?;
        self.storage.delete(key_id)?;
        self.audit.record(AuditRecord::new(
            ctx.clone(),
            record.metadata.id,
            Action::DestroyKey,
            "Key destroyed",
        ))?;
        Ok(())
    }

    /// Internal utility to list every stored key version for retention workflows.
    pub fn list_all_version_records(&self) -> HsmResult<Vec<KeyRecord>> {
        self.storage.list_all_versions()
    }

    /// System-only helper to mutate the state of a specific key version and emit an audit record.
    pub fn mark_version_state_system(
        &self,
        key_id: &KeyId,
        version: u32,
        new_state: KeyState,
        ctx: &AuthContext,
        message: impl Into<String>,
    ) -> HsmResult<KeyMetadata> {
        let mut record = self.storage.fetch_version(key_id, version)?;
        record.metadata.state = new_state;
        self.storage.update_version(record.clone())?;
        let message = message.into();
        self.audit.record(AuditRecord::new(
            ctx.clone(),
            key_id.clone(),
            Action::PurgeKeyVersion,
            message,
        ))?;
        Ok(record.metadata)
    }

    /// System-only helper to purge a key version from storage with audit coverage.
    pub fn purge_version_system(
        &self,
        key_id: &KeyId,
        version: u32,
        ctx: &AuthContext,
        message: impl Into<String>,
    ) -> HsmResult<PurgeReport> {
        let report = self.storage.purge_version(key_id, version)?;
        let message = message.into();
        self.audit.record(AuditRecord::new(
            ctx.clone(),
            key_id.clone(),
            Action::PurgeKeyVersion,
            message,
        ))?;
        Ok(report)
    }

    fn authorize(
        &self,
        ctx: &AuthContext,
        action: &Action,
        policy_tags: &[String],
        subject: Option<&str>,
    ) -> HsmResult<()> {
        let decision = self.policy.evaluate(ctx, action, policy_tags, subject)?;
        if decision.allowed {
            return Ok(());
        }

        if decision.quorum_required
            && let Some(approval_id) = decision.approval_id
        {
            return Err(HsmError::ApprovalRequired { approval_id });
        }

        Err(HsmError::PolicyDenied)
    }

    pub fn list_pending_approvals(&self, ctx: &AuthContext) -> HsmResult<Vec<PendingApprovalInfo>> {
        self.policy.list_pending(ctx)
    }

    pub fn approve_pending(&self, approval_id: uuid::Uuid, ctx: &AuthContext) -> HsmResult<()> {
        self.policy.approve(ctx, approval_id)
    }

    pub fn deny_pending(&self, approval_id: uuid::Uuid, ctx: &AuthContext) -> HsmResult<()> {
        self.policy.deny(ctx, approval_id)
    }
}
