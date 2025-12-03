use std::{collections::HashSet, sync::Arc};

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    approvals::{ApprovalRecord, ApprovalStore, PendingApprovalInfo},
    error::{HsmError, HsmResult},
    models::{ApprovalListPage, AuthContext, ListApprovalsQuery},
    rbac::{Action, RbacAuthorizer, Role},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub message: Option<String>,
    pub quorum_required: bool,
    pub approval_id: Option<Uuid>,
    pub current_approvals: u8,
    pub required_approvals: u8,
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

    fn list_pending(&self, ctx: &AuthContext) -> HsmResult<Vec<PendingApprovalInfo>> {
        let query = ListApprovalsQuery {
            per_page: u32::MAX,
            include_resolved: false,
            ..Default::default()
        };
        let page = self.list_pending_with_query(ctx, &query)?;
        Ok(page.items)
    }

    fn list_pending_with_query(
        &self,
        ctx: &AuthContext,
        query: &ListApprovalsQuery,
    ) -> HsmResult<ApprovalListPage>;

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
                current_approvals: 0,
                required_approvals: 0,
            });
        }

        let subject_key = Self::approval_subject(action, subject, policy_tags);
        if let Some(mut record) = self
            .approvals
            .fetch_by_action_subject(action, &subject_key)?
        {
            // Update the record with the current actor's approval
            if !record.approvers.contains(&ctx.actor_id) {
                record.approvers.push(ctx.actor_id.clone());
            }

            // Check if quorum is satisfied
            if record.approvers.len() >= record.quorum_size as usize {
                self.approvals.delete(&record.id)?;
                return Ok(PolicyDecision {
                    allowed: true,
                    message: Some("dual-control quorum satisfied".into()),
                    quorum_required: true,
                    approval_id: Some(record.id),
                    current_approvals: record.approvers.len() as u8,
                    required_approvals: record.quorum_size,
                });
            }

            // Still awaiting more approvals
            self.approvals.save(&record)?;
            return Ok(PolicyDecision {
                allowed: false,
                message: Some("awaiting more approvals".into()),
                quorum_required: true,
                approval_id: Some(record.id),
                current_approvals: record.approvers.len() as u8,
                required_approvals: record.quorum_size,
            });
        }

        // No existing approval record, create a new one
        let new_record = ApprovalRecord::new(
            action.clone(),
            subject_key,
            ctx.actor_id.clone(),
            policy_tags.to_vec(),
        );
        self.approvals.insert(&new_record)?;
        Ok(PolicyDecision {
            allowed: false,
            message: Some("dual-control approval initiated".into()),
            quorum_required: true,
            approval_id: Some(new_record.id),
            current_approvals: 0, // Requester does not count as approver
            required_approvals: new_record.quorum_size,
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

        if record.approvers.contains(&ctx.actor_id) {
            return Err(HsmError::Authorization(
                "already approved by this actor".into(),
            ));
        }

        record.approvers.push(ctx.actor_id.clone());
        self.approvals.save(&record)?;
        Ok(())
    }

    fn list_pending_with_query(
        &self,
        ctx: &AuthContext,
        query: &ListApprovalsQuery,
    ) -> HsmResult<ApprovalListPage> {
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

        let mut filtered: Vec<PendingApprovalInfo> = self
            .approvals
            .list()?
            .into_iter()
            .filter(|record| {
                // Filter by creation time
                record.created_at >= cutoff
                    // Filter by action
                    && (query.action.is_none() || query.action.as_ref().map(|s| s == &record.action.to_string()).unwrap_or(false))
                    // Filter by subject
                    && (query.subject.is_none() || query.subject.as_ref().map(|s| s == &record.subject).unwrap_or(false))
                    // Filter by policy tags
                    && (query.policy_tags.is_empty() || query.policy_tags.iter().all(|tag| record.policy_tags.contains(tag)))
                    // Filter resolved if not requested
                    && (query.include_resolved || record.approvers.len() < record.quorum_size as usize)
            })
            .map(|record| PendingApprovalInfo {
                id: record.id,
                action: record.action,
                subject: record.subject,
                requester: record.requester,
                created_at: record.created_at,
                approved_by: record.approved_by, // Note: This field will be deprecated/removed in favor of `approvers`
                approved_at: record.approved_at, // Note: This field will be deprecated/removed in favor of `approvers`
                quorum_size: record.quorum_size,
                approvers: record.approvers,
            })
            .collect();

        // Sort by creation date descending
        filtered.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        let per_page = query.per_page.clamp(1, 1000) as usize;
        let page_index = (query.page.max(1) - 1) as usize;
        let total = filtered.len();
        let start = page_index.saturating_mul(per_page);
        let end = (start + per_page).min(total);
        let items = if start >= total {
            Vec::new()
        } else {
            filtered[start..end].to_vec()
        };
        let has_more = end < total;

        Ok(ApprovalListPage {
            items,
            total,
            page: query.page,
            per_page: query.per_page,
            has_more,
        })
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

        let _record = self
            .approvals
            .fetch(&approval_id)?
            .ok_or_else(|| HsmError::Authorization("approval not found".into()))?;

        // Allow any authorized user to deny an approval
        self.approvals.delete(&approval_id)?;
        Ok(())
    }
}
