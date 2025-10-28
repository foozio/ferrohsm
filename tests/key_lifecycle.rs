use std::{collections::HashSet, sync::Arc};

use hsm_core::{
    audit::FileAuditLog,
    ApprovalStore,
    storage::FileKeyStore,
    AuthContext,
    CryptoOperation,
    DefaultPolicyEngine,
    FileApprovalStore,
    HsmError,
    KeyAlgorithm,
    KeyGenerationRequest,
    KeyManager,
    KeyOperationResult,
    KeyState,
    KeyPurpose,
    MemoryKeyStore,
    OperationContext,
    RbacAuthorizer,
    Role,
    SqliteKeyStore,
};
use rand::{rngs::OsRng, RngCore};
use tempfile::TempDir;
use uuid::Uuid;

fn master_secrets() -> ([u8; 32], [u8; 32]) {
    let mut master = [0u8; 32];
    let mut hmac = [0u8; 32];
    OsRng.fill_bytes(&mut master);
    OsRng.fill_bytes(&mut hmac);
    (master, hmac)
}

fn auth_context() -> AuthContext {
    AuthContext {
        actor_id: "test-admin".into(),
        session_id: Uuid::new_v4(),
        roles: vec![Role::Administrator],
        client_fingerprint: None,
        source_ip: None,
    }
}

fn context_with_roles(roles: Vec<Role>) -> AuthContext {
    AuthContext {
        actor_id: Uuid::new_v4().to_string(),
        session_id: Uuid::new_v4(),
        roles,
        client_fingerprint: None,
        source_ip: None,
    }
}

fn setup_manager() -> (
    TempDir,
    KeyManager<FileKeyStore, FileAuditLog, DefaultPolicyEngine>,
) {
    let dir = TempDir::new().expect("tempdir");
    let audit_path = dir.path().join("audit.log");
    let storage = Arc::new(FileKeyStore::new(dir.path()).expect("storage"));
    let audit = Arc::new(FileAuditLog::new(&audit_path).expect("audit"));
    let approvals_dir = dir.path().join("approvals");
    let approval_store: Arc<dyn ApprovalStore> =
        Arc::new(FileApprovalStore::new(&approvals_dir).expect("approvals"));
    let policy = DefaultPolicyEngine::new(RbacAuthorizer::default(), HashSet::new(), approval_store);
    let (master, hmac) = master_secrets();
    let manager = KeyManager::new(storage, audit, policy, master, hmac);
    (dir, manager)
}

#[test]
fn symmetric_key_lifecycle() {
    let dir = TempDir::new().expect("tempdir");
    let audit_path = dir.path().join("audit.log");
    let storage = Arc::new(FileKeyStore::new(dir.path()).expect("storage"));
    let audit = Arc::new(FileAuditLog::new(&audit_path).expect("audit"));
    let approvals_dir = dir.path().join("approvals");
    let approval_store: Arc<dyn ApprovalStore> =
        Arc::new(FileApprovalStore::new(&approvals_dir).expect("approvals"));
    let policy = DefaultPolicyEngine::new(RbacAuthorizer::default(), HashSet::new(), approval_store);
    let (master, hmac) = master_secrets();
    let manager = KeyManager::new(storage, audit, policy, master, hmac);

    let ctx = auth_context();
    let request = KeyGenerationRequest {
        algorithm: KeyAlgorithm::Aes256Gcm,
        usage: vec![KeyPurpose::Encrypt, KeyPurpose::Decrypt],
        policy_tags: vec!["test".into()],
        description: Some("integration test key".into()),
    };
    let metadata = manager
        .generate_key(request, &ctx)
        .expect("key generation");

    assert_eq!(metadata.version, 1);
    assert_eq!(metadata.algorithm, KeyAlgorithm::Aes256Gcm);

    let op_ctx = OperationContext::new();
    let payload = b"confidential".to_vec();
    let enc_result = manager
        .perform_operation(
            &metadata.id,
            CryptoOperation::Encrypt {
                plaintext: payload.clone(),
            },
            &ctx,
            &op_ctx,
        )
        .expect("encrypt");

    let (ciphertext, nonce) = match enc_result {
        hsm_core::KeyOperationResult::Encrypted { ciphertext, nonce } => (ciphertext, nonce),
        _ => panic!("unexpected encrypt result"),
    };

    let dec_result = manager
        .perform_operation(
            &metadata.id,
            CryptoOperation::Decrypt {
                ciphertext,
                nonce,
                associated_data: None,
            },
            &ctx,
            &OperationContext::new(),
        )
        .expect("decrypt");

    let decrypted = match dec_result {
        hsm_core::KeyOperationResult::Decrypted { plaintext } => plaintext,
        _ => panic!("unexpected decrypt result"),
    };

    assert_eq!(decrypted, payload);

    let rotated = manager.rotate_key(&metadata.id, &ctx).expect("rotate");
    assert_eq!(rotated.version, 2);

    let history = manager
        .list_key_versions(&metadata.id, &ctx)
        .expect("history");
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].version, 1);
    assert_eq!(history[0].state, hsm_core::KeyState::Revoked);
    assert_eq!(history[1].version, 2);
    assert_eq!(history[1].state, hsm_core::KeyState::Active);

    let rollbacked = manager
        .rollback_key(&metadata.id, 1, &ctx)
        .expect("rollback");
    assert_eq!(rollbacked.version, 3);

    let history = manager
        .list_key_versions(&metadata.id, &ctx)
        .expect("history after rollback");
    assert_eq!(history.len(), 3);
    assert_eq!(history[2].version, 3);
    assert_eq!(history[2].state, hsm_core::KeyState::Active);

    manager
        .revoke_key(&metadata.id, &ctx)
        .expect("revoke");
    manager
        .destroy_key(&metadata.id, &ctx)
        .expect("destroy");
    assert!(manager.list_keys(&ctx).expect("Failed to list keys").is_empty());
}

#[test]
fn rsa_key_sign_verify_rotation_flow() {
    let (_dir, manager) = setup_manager();
    let ctx = auth_context();

    let request = KeyGenerationRequest {
        algorithm: KeyAlgorithm::Rsa2048,
        usage: vec![KeyPurpose::Sign, KeyPurpose::Verify],
        policy_tags: vec!["signing.rsa".into()],
        description: Some("rsa lifecycle".into()),
    };
    let metadata = manager
        .generate_key(request, &ctx)
        .expect("rsa key generation");
    assert_eq!(metadata.version, 1);
    assert_eq!(metadata.algorithm, KeyAlgorithm::Rsa2048);

    let payload = b"document-hash".to_vec();
    let op_ctx = OperationContext::new();

    let signature = match manager
        .perform_operation(
            &metadata.id,
            CryptoOperation::Sign {
                payload: payload.clone(),
            },
            &ctx,
            &op_ctx,
        )
        .expect("rsa sign")
    {
        KeyOperationResult::Signature { signature } => signature,
        other => panic!("unexpected sign result: {other:?}"),
    };

    let verify = manager
        .perform_operation(
            &metadata.id,
            CryptoOperation::Verify {
                payload: payload.clone(),
                signature: signature.clone(),
            },
            &ctx,
            &op_ctx,
        )
        .expect("rsa verify");
    match verify {
        KeyOperationResult::Verified { valid } => assert!(valid),
        other => panic!("unexpected verify result: {other:?}"),
    }

    let rotated = manager
        .rotate_key(&metadata.id, &ctx)
        .expect("rsa rotate");
    assert_eq!(rotated.version, 2);

    let new_signature = match manager
        .perform_operation(
            &metadata.id,
            CryptoOperation::Sign {
                payload: payload.clone(),
            },
            &ctx,
            &op_ctx,
        )
        .expect("rsa sign after rotate")
    {
        KeyOperationResult::Signature { signature } => signature,
        other => panic!("unexpected sign result: {other:?}"),
    };
    let verify_after_rotate = manager
        .perform_operation(
            &metadata.id,
            CryptoOperation::Verify {
                payload: payload.clone(),
                signature: new_signature,
            },
            &ctx,
            &op_ctx,
        )
        .expect("rsa verify after rotate");
    match verify_after_rotate {
        KeyOperationResult::Verified { valid } => assert!(valid),
        other => panic!("unexpected verify result: {other:?}"),
    }

    let history = manager
        .list_key_versions(&metadata.id, &ctx)
        .expect("rsa history");
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].state, KeyState::Revoked);
    assert_eq!(history[1].version, 2);

    let rollbacked = manager
        .rollback_key(&metadata.id, 1, &ctx)
        .expect("rsa rollback");
    assert_eq!(rollbacked.version, 3);

    let rollback_payload = b"rollback".to_vec();
    let rollback_signature = match manager
        .perform_operation(
            &metadata.id,
            CryptoOperation::Sign {
                payload: rollback_payload.clone(),
            },
            &ctx,
            &op_ctx,
        )
        .expect("rsa sign after rollback")
    {
        KeyOperationResult::Signature { signature } => signature,
        other => panic!("unexpected sign result: {other:?}"),
    };
    let verify_after_rollback = manager
        .perform_operation(
            &metadata.id,
            CryptoOperation::Verify {
                payload: rollback_payload,
                signature: rollback_signature,
            },
            &ctx,
            &op_ctx,
        )
        .expect("rsa verify after rollback");
    match verify_after_rollback {
        KeyOperationResult::Verified { valid } => assert!(valid),
        other => panic!("unexpected verify result: {other:?}"),
    }

    manager.revoke_key(&metadata.id, &ctx).expect("rsa revoke");
    manager
        .destroy_key(&metadata.id, &ctx)
        .expect("rsa destroy");
}

#[test]
fn p256_key_sign_verify_flow() {
    let (_dir, manager) = setup_manager();
    let ctx = auth_context();

    let request = KeyGenerationRequest {
        algorithm: KeyAlgorithm::P256,
        usage: vec![KeyPurpose::Sign, KeyPurpose::Verify],
        policy_tags: vec!["signing.ec".into()],
        description: Some("p256 lifecycle".into()),
    };
    let metadata = manager
        .generate_key(request, &ctx)
        .expect("p256 key generation");
    assert_eq!(metadata.version, 1);
    assert_eq!(metadata.algorithm, KeyAlgorithm::P256);

    let message = b"firmware-digest".to_vec();
    let op_ctx = OperationContext::new();

    let signature = match manager
        .perform_operation(
            &metadata.id,
            CryptoOperation::Sign {
                payload: message.clone(),
            },
            &ctx,
            &op_ctx,
        )
        .expect("p256 sign")
    {
        KeyOperationResult::Signature { signature } => signature,
        other => panic!("unexpected sign result: {other:?}"),
    };

    let verify = manager
        .perform_operation(
            &metadata.id,
            CryptoOperation::Verify {
                payload: message.clone(),
                signature: signature.clone(),
            },
            &ctx,
            &op_ctx,
        )
        .expect("p256 verify");
    match verify {
        KeyOperationResult::Verified { valid } => assert!(valid),
        other => panic!("unexpected verify result: {other:?}"),
    }

    let rotated = manager
        .rotate_key(&metadata.id, &ctx)
        .expect("p256 rotate");
    assert_eq!(rotated.version, 2);

    let rotated_sig = match manager
        .perform_operation(
            &metadata.id,
            CryptoOperation::Sign {
                payload: message.clone(),
            },
            &ctx,
            &op_ctx,
        )
        .expect("p256 sign after rotate")
    {
        KeyOperationResult::Signature { signature } => signature,
        other => panic!("unexpected sign result: {other:?}"),
    };
    let verify_rotated = manager
        .perform_operation(
            &metadata.id,
            CryptoOperation::Verify {
                payload: message.clone(),
                signature: rotated_sig,
            },
            &ctx,
            &op_ctx,
        )
        .expect("p256 verify after rotate");
    match verify_rotated {
        KeyOperationResult::Verified { valid } => assert!(valid),
        other => panic!("unexpected verify result: {other:?}"),
    }

    let rollbacked = manager
        .rollback_key(&metadata.id, 1, &ctx)
        .expect("p256 rollback");
    assert_eq!(rollbacked.version, 3);

    let rollback_message = b"post-rollback".to_vec();
    let rollback_sig = match manager
        .perform_operation(
            &metadata.id,
            CryptoOperation::Sign {
                payload: rollback_message.clone(),
            },
            &ctx,
            &op_ctx,
        )
        .expect("p256 sign after rollback")
    {
        KeyOperationResult::Signature { signature } => signature,
        other => panic!("unexpected sign result: {other:?}"),
    };
    let verify_rollback = manager
        .perform_operation(
            &metadata.id,
            CryptoOperation::Verify {
                payload: rollback_message,
                signature: rollback_sig,
            },
            &ctx,
            &op_ctx,
        )
        .expect("p256 verify after rollback");
    match verify_rollback {
        KeyOperationResult::Verified { valid } => assert!(valid),
        other => panic!("unexpected verify result: {other:?}"),
    }
}

#[test]
fn policy_enforces_role_permissions() {
    let (_dir, manager) = setup_manager();
    let admin_ctx = auth_context();

    let create_request = KeyGenerationRequest {
        algorithm: KeyAlgorithm::Aes256Gcm,
        usage: vec![KeyPurpose::Encrypt, KeyPurpose::Decrypt],
        policy_tags: vec!["confidential".into()],
        description: Some("policy test key".into()),
    };
    let key = manager
        .generate_key(create_request, &admin_ctx)
        .expect("admin can create key");

    let service_ctx = context_with_roles(vec![Role::Service]);
    let rotate_err = manager
        .rotate_key(&key.id, &service_ctx)
        .expect_err("service role should be blocked from rotation");
    assert!(matches!(rotate_err, HsmError::PolicyDenied));

    let destroy_err = manager
        .destroy_key(&key.id, &service_ctx)
        .expect_err("service role should be blocked from destroy");
    assert!(matches!(destroy_err, HsmError::PolicyDenied));

    let auditor_ctx = context_with_roles(vec![Role::Auditor]);
    let auditor_request = KeyGenerationRequest {
        algorithm: KeyAlgorithm::Aes256Gcm,
        usage: vec![KeyPurpose::Encrypt],
        policy_tags: vec![],
        description: Some("auditor create attempt".into()),
    };
    let create_err = manager
        .generate_key(auditor_request, &auditor_ctx)
        .expect_err("auditor should not be able to create keys");
    assert!(matches!(create_err, HsmError::PolicyDenied));
}

#[test]
fn purge_version_removes_revoked_material() {
    let (_dir, manager) = setup_manager();
    let admin_ctx = auth_context();

    let request = KeyGenerationRequest {
        algorithm: KeyAlgorithm::Aes256Gcm,
        usage: vec![KeyPurpose::Encrypt],
        policy_tags: vec!["operational.default".into()],
        description: Some("purge test".into()),
    };

    let metadata = manager
        .generate_key(request, &admin_ctx)
        .expect("generate");
    manager
        .rotate_key(&metadata.id, &admin_ctx)
        .expect("rotate to create revoked version");

    let system_ctx = context_with_roles(vec![Role::Administrator, Role::Auditor]);
    let version_one = manager
        .describe_key_version(&metadata.id, 1, &admin_ctx)
        .expect("describe v1");
    assert_eq!(version_one.state, KeyState::Revoked);

    manager
        .mark_version_state_system(
            &metadata.id,
            1,
            KeyState::PurgeScheduled,
            &system_ctx,
            "test scheduling", 
        )
        .expect("mark purge scheduled");

    let report = manager
        .purge_version_system(&metadata.id, 1, &system_ctx, "test purge")
        .expect("purge version");
    assert!(report.bytes_overwritten > 0);

    let fetch_err = manager.describe_key_version(&metadata.id, 1, &admin_ctx);
    assert!(matches!(fetch_err, Err(HsmError::KeyNotFound(_))));
}

#[test]
fn key_listing_pagination_and_filters() {
    let dir = TempDir::new().expect("tempdir");
    let audit_path = dir.path().join("audit.log");
    let storage = Arc::new(FileKeyStore::new(dir.path()).expect("storage"));
    let audit = Arc::new(FileAuditLog::new(&audit_path).expect("audit"));
    let approvals_dir = dir.path().join("approvals");
    let approval_store: Arc<dyn ApprovalStore> =
        Arc::new(FileApprovalStore::new(&approvals_dir).expect("approvals"));
    let policy =
        DefaultPolicyEngine::new(RbacAuthorizer::default(), HashSet::new(), approval_store);
    let (master, hmac) = master_secrets();
    let manager = KeyManager::new(storage, audit, policy, master, hmac);

    let ctx = auth_context();

    let request_a = KeyGenerationRequest {
        algorithm: KeyAlgorithm::Aes256Gcm,
        usage: vec![KeyPurpose::Encrypt],
        policy_tags: vec!["operational.default".into()],
        description: Some("alpha".into()),
    };
    let key_a = manager
        .generate_key(request_a, &ctx)
        .expect("key a generation");

    let request_b = KeyGenerationRequest {
        algorithm: KeyAlgorithm::Rsa2048,
        usage: vec![KeyPurpose::Sign],
        policy_tags: vec!["operational.critical".into(), "beta".into()],
        description: Some("beta".into()),
    };
    let key_b = manager
        .generate_key(request_b, &ctx)
        .expect("key b generation");

    let mut query = hsm_core::KeyListQuery::default();
    query.per_page = 1;
    query.page = 1;
    let page_one = manager
        .list_keys_with_query(&ctx, &query)
        .expect("page one");
    assert_eq!(page_one.total, 2);
    assert_eq!(page_one.items.len(), 1);
    assert!(page_one.has_more);

    query.page = 2;
    let page_two = manager
        .list_keys_with_query(&ctx, &query)
        .expect("page two");
    assert_eq!(page_two.items.len(), 1);
    assert!(!page_two.has_more);

    let mut filter = hsm_core::KeyListQuery::default();
    filter.algorithm = Some(KeyAlgorithm::Rsa2048);
    let filtered = manager
        .list_keys_with_query(&ctx, &filter)
        .expect("filter algorithm");
    assert_eq!(filtered.total, 1);
    assert_eq!(filtered.items[0].id, key_b.id);

    let mut tag_filter = hsm_core::KeyListQuery::default();
    tag_filter.policy_tags = vec!["beta".into()];
    let tag_page = manager
        .list_keys_with_query(&ctx, &tag_filter)
        .expect("filter tags");
    assert_eq!(tag_page.total, 1);
    assert_eq!(tag_page.items[0].id, key_b.id);

    let mut state_filter = hsm_core::KeyListQuery::default();
    state_filter.state = Some(KeyState::Revoked);
    let state_page = manager
        .list_keys_with_query(&ctx, &state_filter)
        .expect("filter state");
    assert_eq!(state_page.total, 0);

    // rotate to introduce revoked version and test state filter again
    manager
        .rotate_key(&key_a.id, &ctx)
        .expect("rotate for state filter");
    let state_page = manager
        .list_keys_with_query(&ctx, &state_filter)
        .expect("filter state after rotate");
    assert!(state_page.total >= 1);
}

#[test]
fn sqlite_key_store_roundtrip() {
    let dir = TempDir::new().expect("tempdir");
    let audit_path = dir.path().join("audit.log");
    let approvals_dir = dir.path().join("approvals");
    let db_path = dir.path().join("keys.sqlite");
    let storage = Arc::new(SqliteKeyStore::new(&db_path).expect("sqlite store"));
    let audit = Arc::new(FileAuditLog::new(&audit_path).expect("audit log"));
    let approval_store: Arc<dyn ApprovalStore> =
        Arc::new(FileApprovalStore::new(&approvals_dir).expect("approvals"));
    let policy = DefaultPolicyEngine::new(RbacAuthorizer::default(), HashSet::new(), approval_store);
    let (master, hmac) = master_secrets();
    let manager = KeyManager::new(storage, audit, policy, master, hmac);

    let ctx = auth_context();
    let key = manager
        .generate_key(
            KeyGenerationRequest {
                algorithm: KeyAlgorithm::P256,
                usage: vec![KeyPurpose::Sign, KeyPurpose::Verify],
                policy_tags: vec!["operational.default".into()],
                description: Some("sqlite".into()),
            },
            &ctx,
        )
        .expect("generate");

    let rotated = manager
        .rotate_key(&key.id, &ctx)
        .expect("rotate sqlite");
    assert_eq!(rotated.version, 2);

    let versions = manager
        .list_key_versions(&key.id, &ctx)
        .expect("versions sqlite");
    assert_eq!(versions.len(), 2);
}

#[test]
fn memory_key_store_supports_basic_flows() {
    let dir = TempDir::new().expect("tempdir");
    let audit_path = dir.path().join("audit.log");
    let approvals_dir = dir.path().join("approvals");
    let storage = Arc::new(MemoryKeyStore::new());
    let audit = Arc::new(FileAuditLog::new(&audit_path).expect("audit log"));
    let approval_store: Arc<dyn ApprovalStore> =
        Arc::new(FileApprovalStore::new(&approvals_dir).expect("approvals"));
    let policy = DefaultPolicyEngine::new(RbacAuthorizer::default(), HashSet::new(), approval_store);
    let (master, hmac) = master_secrets();
    let manager = KeyManager::new(storage, audit, policy, master, hmac);

    let ctx = auth_context();
    let key = manager
        .generate_key(
            KeyGenerationRequest {
                algorithm: KeyAlgorithm::Aes256Gcm,
                usage: vec![KeyPurpose::Encrypt, KeyPurpose::Decrypt],
                policy_tags: vec!["ephemeral".into()],
                description: Some("memory".into()),
            },
            &ctx,
        )
        .expect("generate memory");

    manager
        .revoke_key(&key.id, &ctx)
        .expect("revoke memory");
    let versions = manager
        .list_key_versions(&key.id, &ctx)
        .expect("versions memory");
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].state, KeyState::Revoked);
}
