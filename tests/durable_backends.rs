use hsm_core::{
    rbac::Action, ApprovalRecord, SqliteApprovalStore, SqliteAuditLog,
    audit::AuditRecord,
};
use tempfile::TempDir;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[test]
fn sqlite_audit_log_retention_purges_old_events() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("audit.sqlite");
    let log = SqliteAuditLog::new(&path).expect("create audit store");

    let old_record = AuditRecord {
        id: Uuid::new_v4(),
        timestamp: OffsetDateTime::now_utc() - Duration::days(400),
        actor_id: "tester".into(),
        session_id: Uuid::new_v4(),
        action: Action::CreateKey,
        key_id: Some("audit-key".into()),
        message: "old event".into(),
    };
    log.record(old_record).expect("record old event");

    let recent_record = AuditRecord {
        id: Uuid::new_v4(),
        timestamp: OffsetDateTime::now_utc(),
        actor_id: "tester".into(),
        session_id: Uuid::new_v4(),
        action: Action::RotateKey,
        key_id: Some("audit-key".into()),
        message: "recent event".into(),
    };
    log.record(recent_record).expect("record new event");

    let cutoff = OffsetDateTime::now_utc() - Duration::days(365);
    let pruned = log
        .purge_older_than(cutoff)
        .expect("purge audit events");
    assert_eq!(pruned, 1);

    // second pass should find nothing additional to prune
    let pruned_again = log
        .purge_older_than(cutoff)
        .expect("second purge noop");
    assert_eq!(pruned_again, 0);
}

#[test]
fn sqlite_approval_store_purges_approved_records_after_retention() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("approvals.sqlite");
    let store = SqliteApprovalStore::new(&path).expect("create approvals store");

    let mut record = ApprovalRecord::new(
        Action::PurgeKeyVersion,
        "key@v1".into(),
        "requester".into(),
        vec!["policy.default".into()],
    );
    store.insert(&record).expect("insert record");

    record.approved_by = Some("approver".into());
    record.approved_at = Some(OffsetDateTime::now_utc() - Duration::days(120));
    store.save(&record).expect("update approval");

    let cutoff = OffsetDateTime::now_utc() - Duration::days(90);
    let pruned = store
        .purge_older_than(cutoff)
        .expect("purge approvals");
    assert_eq!(pruned, 1);

    let remaining = store.list().expect("list approvals");
    assert!(remaining.is_empty());
}
