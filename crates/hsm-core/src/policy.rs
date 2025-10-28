use std::{collections::HashSet, sync::Arc};

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    approvals::{ApprovalRecord, ApprovalStore, PendingApprovalInfo},
    error::{HsmError, HsmResult},
    models::AuthContext,
    rbac::{Action, RbacAuthorizer, Role},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub message: Option<String>,
    pub quorum_required: bool,
    pub approval_id: Option<Uuid>,
}

pub trait PolicyEngine: Send + Sync {
    fn evaluate(
        &self,
        ctx: &AuthContext,
        action: &Action,
        policy_tags: &[String],
        subject: Option<&str>,
    ) -> HsmResult<PolicyDecision>;

    fn approve(&self, ctx: &AuthContext, approval_id: Uuid) -> HsmResult<()>;

    fn list_pending(&self, ctx: &AuthContext) -> HsmResult<Vec<PendingApprovalInfo>>;

    fn deny(&self, ctx: &AuthContext, approval_id: Uuid) -> HsmResult<()>;
}

/// Minimal policy engine that layers RBAC with optional tag constraints and dual-control
/// enforcement per tag backed by a persistent approval store.
pub struct DefaultPolicyEngine {
    rbac: RbacAuthorizer,
    dual_control_tags: HashSet<String>,
    approvals: Arc<dyn ApprovalStore>,
    ttl: Duration,
}

impl DefaultPolicyEngine {
    pub fn new(
        rbac: RbacAuthorizer,
        dual_control_tags: HashSet<String>,
        approvals: Arc<dyn ApprovalStore>,
    ) -> Self {
        Self {
            rbac,
            dual_control_tags,
            approvals,
            ttl: Duration::hours(1),
        }
    }

    fn requires_quorum(&self, ctx: &AuthContext, policy_tags: &[String]) -> bool {
        policy_tags
            .iter()
            .any(|tag| self.dual_control_tags.contains(tag) && !ctx.has_role(&Role::Administrator))
    }

    fn approval_subject(action: &Action, subject: Option<&str>, policy_tags: &[String]) -> String {
        if let Some(s) = subject {
            format!("{}::{s}", action.as_str())
        } else if policy_tags.is_empty() {
            action.as_str().to_string()
        } else {
            format!("{}::tags:{}", action.as_str(), policy_tags.join(","))
        }
    }

    fn purge_expired(&self) -> HsmResult<()> {
        let cutoff = OffsetDateTime::now_utc() - self.ttl;
        for record in self.approvals.list()? {
            if record.created_at < cutoff {
                self.approvals.delete(&record.id)?;
            }
        }
        Ok(())
    }
}

impl PolicyEngine for DefaultPolicyEngine {
    fn evaluate(
        &self,
        ctx: &AuthContext,
        action: &Action,
        policy_tags: &[String],
        subject: Option<&str>,
    ) -> HsmResult<PolicyDecision> {
        if !self.rbac.is_allowed(ctx, action) {
            return Err(HsmError::PolicyDenied);
        }

        self.purge_expired().ok();

        let quorum_required = self.requires_quorum(ctx, policy_tags);
        if !quorum_required {
            return Ok(PolicyDecision {
                allowed: true,
                message: None,
                quorum_required: false,
                approval_id: None,
            });
        }

        let subject_key = Self::approval_subject(action, subject, policy_tags);
        if let Some(mut record) = self
            .approvals
            .fetch_by_action_subject(action, &subject_key)?
        {
            if let Some(approved_by) = &record.approved_by {
                if record.requester == ctx.actor_id || approved_by == &ctx.actor_id {
                    self.approvals.delete(&record.id)?;
                    return Ok(PolicyDecision {
                        allowed: true,
                        message: Some("dual-control quorum satisfied".into()),
                        quorum_required: true,
                        approval_id: Some(record.id),
                    });
                }
                // already approved by someone else; allow and clean up
                self.approvals.delete(&record.id)?;
                return Ok(PolicyDecision {
                    allowed: true,
                    message: Some("dual-control approval completed".into()),
                    quorum_required: true,
                    approval_id: Some(record.id),
                });
            }

            if record.requester == ctx.actor_id {
                return Ok(PolicyDecision {
                    allowed: false,
                    message: Some("awaiting secondary approval".into()),
                    quorum_required: true,
                    approval_id: Some(record.id),
                });
            }

            // Implicit approval by executing actor.
            record.approved_by = Some(ctx.actor_id.clone());
            record.approved_at = Some(OffsetDateTime::now_utc());
            self.approvals.save(&record)?;
            self.approvals.delete(&record.id)?;
            return Ok(PolicyDecision {
                allowed: true,
                message: Some("peer approval granted".into()),
                quorum_required: true,
                approval_id: Some(record.id),
            });
        }

        let record = ApprovalRecord::new(
            action.clone(),
            subject_key,
            ctx.actor_id.clone(),
            policy_tags.to_vec(),
        );
        self.approvals.insert(&record)?;
        Ok(PolicyDecision {
            allowed: false,
            message: Some("dual-control approval recorded".into()),
            quorum_required: true,
            approval_id: Some(record.id),
        })
    }

    fn approve(&self, ctx: &AuthContext, approval_id: Uuid) -> HsmResult<()> {
        if !ctx.has_role(&Role::Administrator)
            && !ctx.has_role(&Role::Operator)
            && !ctx.has_role(&Role::Auditor)
        {
            return Err(HsmError::Authorization(
                "insufficient privileges to approve".into(),
            ));
        }

        let mut record = self
            .approvals
            .fetch(&approval_id)?
            .ok_or_else(|| HsmError::Authorization("approval not found".into()))?;

        if record.requester == ctx.actor_id {
            return Err(HsmError::Authorization(
                "requester cannot self-approve".into(),
            ));
        }

        if record.approved_by.is_some() {
            return Err(HsmError::Authorization("approval already granted".into()));
        }

        record.approved_by = Some(ctx.actor_id.clone());
        record.approved_at = Some(OffsetDateTime::now_utc());
        self.approvals.save(&record)?;
        Ok(())
    }

    fn list_pending(&self, ctx: &AuthContext) -> HsmResult<Vec<PendingApprovalInfo>> {
        if !ctx.has_role(&Role::Administrator)
            && !ctx.has_role(&Role::Operator)
            && !ctx.has_role(&Role::Auditor)
        {
            return Err(HsmError::Authorization(
                "insufficient privileges to view approvals".into(),
            ));
        }

        self.purge_expired().ok();

        let now = OffsetDateTime::now_utc();
        let cutoff = now - self.ttl;

        let approvals = self
            .approvals
            .list()?
            .into_iter()
            .filter(|record| record.created_at >= cutoff)
            .map(|record| PendingApprovalInfo {
                id: record.id,
                action: record.action,
                subject: record.subject,
                requester: record.requester,
                created_at: record.created_at,
                approved_by: record.approved_by,
                approved_at: record.approved_at,
            })
            .collect();

        Ok(approvals)
    }

    fn deny(&self, ctx: &AuthContext, approval_id: Uuid) -> HsmResult<()> {
        if !ctx.has_role(&Role::Administrator)
            && !ctx.has_role(&Role::Operator)
            && !ctx.has_role(&Role::Auditor)
        {
            return Err(HsmError::Authorization(
                "insufficient privileges to deny".into(),
            ));
        }

        let record = self
            .approvals
            .fetch(&approval_id)?
            .ok_or_else(|| HsmError::Authorization("approval not found".into()))?;

        if record.approved_by.is_some() {
            return Err(HsmError::Authorization("approval already resolved".into()));
        }

        self.approvals.delete(&approval_id)?;
        Ok(())
    }
}
