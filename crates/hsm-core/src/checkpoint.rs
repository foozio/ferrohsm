//! Periodic audit log checkpoint verification

use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

use crate::audit::FileAuditLog;

pub struct CheckpointScheduler {
    audit_log: Arc<FileAuditLog>,
    interval: Duration,
}

impl CheckpointScheduler {
    pub fn new(audit_log: Arc<FileAuditLog>, interval: Duration) -> Self {
        Self {
            audit_log,
            interval,
        }
    }

    pub fn run(self) {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(self.interval);
            loop {
                ticker.tick().await;
                info!("Performing periodic audit log checkpoint verification");
                if let Err(e) = self.audit_log.checkpoint_verification() {
                    error!("Audit log checkpoint verification failed: {}", e);
                }
            }
        });
    }
}
