//! Periodic audit log signing key rotation

use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

use crate::audit::FileAuditLog;

pub struct KeyRotationScheduler {
    audit_log: Arc<FileAuditLog>,
    interval: Duration,
}

impl KeyRotationScheduler {
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
                info!("Performing periodic audit log signing key rotation check");
                if let Err(e) = self
                    .audit_log
                    .rotate_signing_key(FileAuditLog::generate_new_key())
                {
                    error!("Audit log signing key rotation failed: {}", e);
                }
            }
        });
    }
}
