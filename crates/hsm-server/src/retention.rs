use std::{path::PathBuf, sync::Arc, time::Duration as StdDuration};

use ::time::{Duration, OffsetDateTime};
use anyhow::Context;
use hsm_core::{
    Action, ApprovalRecord, ApprovalStore, AuditLog, AuthContext, KeyManager, KeyRecord, KeyState,
    KeyStore, PolicyEngine, PurgeReport, RetentionLedger, RetentionLedgerEntry, RetentionPolicy,
    Role,
};
use tokio::time::{self, MissedTickBehavior};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

const SCHEDULER_ACTOR: &str = "retention-scheduler";

pub struct RetentionScheduler<P: PolicyEngine + 'static> {
    manager: Arc<KeyManager<dyn KeyStore, dyn AuditLog, P>>,
    approvals: Arc<dyn ApprovalStore>,
    ledger: Arc<RetentionLedger>,
    config_path: PathBuf,
    interval: StdDuration,
    grace_period: Duration,
}

impl<P: PolicyEngine + 'static> Clone for RetentionScheduler<P> {
    fn clone(&self) -> Self {
        Self {
            manager: Arc::clone(&self.manager),
            approvals: Arc::clone(&self.approvals),
            ledger: Arc::clone(&self.ledger),
            config_path: self.config_path.clone(),
            interval: self.interval,
            grace_period: self.grace_period,
        }
    }
}

impl<P: PolicyEngine + 'static> RetentionScheduler<P> {
    pub fn new(
        manager: Arc<KeyManager<dyn KeyStore, dyn AuditLog, P>>,
        approvals: Arc<dyn ApprovalStore>,
        ledger: Arc<RetentionLedger>,
        config_path: PathBuf,
        interval: StdDuration,
        grace_period: Duration,
    ) -> Self {
        Self {
            manager,
            approvals,
            ledger,
            config_path,
            interval,
            grace_period,
        }
    }

    pub async fn run(self) {
        let mut ticker = time::interval(self.interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let scheduler = self.clone();
            if let Err(err) = tokio::task::spawn_blocking(move || scheduler.run_once())
                .await
                .context("retention scheduler task join")
                .and_then(|res| res)
            {
                error!("retention scheduler failed: {err:#}");
            }
        }
    }

    fn run_once(&self) -> anyhow::Result<()> {
        if !self.config_path.exists() {
            debug!(
                "retention config {:?} not found; skipping sweep",
                self.config_path
            );
            metrics::gauge!("ferrohsm_retention_queue_length").set(0.0);
            return Ok(());
        }

        let policy = RetentionPolicy::from_path(&self.config_path)
            .with_context(|| "failed to parse retention policy")?;
        let now = OffsetDateTime::now_utc();

        let records = self
            .manager
            .list_all_version_records()
            .with_context(|| "failed to enumerate key versions")?;

        let mut queue = 0usize;

        for record in records {
            if !policy.should_purge(&record.metadata, now) {
                continue;
            }
            queue += 1;
            self.process_record(&record, &policy, now)?;
        }

        metrics::gauge!("ferrohsm_retention_queue_length").set(queue as f64);
        Ok(())
    }

    fn process_record(
        &self,
        record: &KeyRecord,
        policy: &RetentionPolicy,
        now: OffsetDateTime,
    ) -> anyhow::Result<()> {
        let metadata = &record.metadata;
        let subject = format!("{}@v{}", metadata.id, metadata.version);
        let deadline = policy.retention_deadline(metadata);

        match metadata.state {
            KeyState::Revoked => {
                if self
                    .approvals
                    .fetch_by_action_subject(&Action::PurgeKeyVersion, &subject)?
                    .is_none()
                {
                    let approval = ApprovalRecord::new(
                        Action::PurgeKeyVersion,
                        subject.clone(),
                        SCHEDULER_ACTOR.to_string(),
                        metadata.policy_tags.clone(),
                    );
                    self.approvals.insert(&approval)?;
                    let ctx = self.system_context();
                    self.manager
                        .mark_version_state_system(
                            &metadata.id,
                            metadata.version,
                            KeyState::PurgeScheduled,
                            &ctx,
                            format!(
                                "Retention purge scheduled; approval {} pending (deadline {})",
                                approval.id, deadline
                            ),
                        )?
                        .state;
                    metrics::counter!("ferrohsm_retention_purge_scheduled_total").increment(1);
                    info!(
                        key_id = metadata.id.as_str(),
                        version = metadata.version,
                        approval = %approval.id,
                        "retention purge scheduled"
                    );
                }
            }
            KeyState::PurgeScheduled => {
                match self
                    .approvals
                    .fetch_by_action_subject(&Action::PurgeKeyVersion, &subject)?
                {
                    Some(approval) => {
                        if let Some(approved_at) = approval.approved_at {
                            let elapsed = now - approved_at;
                            if elapsed >= self.grace_period {
                                self.execute_purge(metadata, &approval, now, deadline)?;
                            } else {
                                debug!(
                                    key_id = metadata.id.as_str(),
                                    version = metadata.version,
                                    approval = %approval.id,
                                    "retention purge awaiting grace period"
                                );
                            }
                        } else {
                            debug!(
                                key_id = metadata.id.as_str(),
                                version = metadata.version,
                                approval = %approval.id,
                                "retention purge awaiting approval"
                            );
                        }
                    }
                    None => {
                        warn!(
                            key_id = metadata.id.as_str(),
                            version = metadata.version,
                            "purge scheduled without approval record; reissuing approval"
                        );
                        let reissue = ApprovalRecord::new(
                            Action::PurgeKeyVersion,
                            subject,
                            SCHEDULER_ACTOR.to_string(),
                            metadata.policy_tags.clone(),
                        );
                        self.approvals.insert(&reissue)?;
                    }
                }
            }
            KeyState::Destroyed => {
                // Already purged; nothing to do.
            }
            _ => {}
        }

        Ok(())
    }

    fn execute_purge(
        &self,
        metadata: &hsm_core::KeyMetadata,
        approval: &ApprovalRecord,
        now: OffsetDateTime,
        deadline: OffsetDateTime,
    ) -> anyhow::Result<()> {
        let ctx = self.system_context();
        let report: PurgeReport = self
            .manager
            .purge_version_system(
                &metadata.id,
                metadata.version,
                &ctx,
                format!(
                    "Retention purge executed after approval {}; deadline {}",
                    approval.id, deadline
                ),
            )
            .with_context(|| "failed to purge key version")?;

        let entry = RetentionLedgerEntry {
            id: Uuid::new_v4(),
            timestamp: now,
            key_id: metadata.id.clone(),
            version: metadata.version,
            approval_id: Some(approval.id),
            requester: Some(approval.requester.clone()),
            approved_by: approval.approved_by.clone(),
            approved_at: approval.approved_at,
            purged_at: now,
            bytes_overwritten: report.bytes_overwritten,
            data_hash: report.data_hash,
            method: "secure_random_overwrite".into(),
            notes: Some(format!("retention deadline {}", deadline)),
        };
        self.ledger.append(&entry)?;
        self.approvals.delete(&approval.id)?;
        metrics::counter!("ferrohsm_retention_purge_completed_total").increment(1);
        info!(
            key_id = metadata.id.as_str(),
            version = metadata.version,
            approval = %approval.id,
            "retention purge completed"
        );
        Ok(())
    }

    fn system_context(&self) -> AuthContext {
        AuthContext {
            actor_id: SCHEDULER_ACTOR.to_string(),
            session_id: Uuid::new_v4(),
            roles: vec![Role::Administrator, Role::Auditor],
            client_fingerprint: None,
            source_ip: None,
        }
    }
}
