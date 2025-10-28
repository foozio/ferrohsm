use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::models::AuthContext;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Role {
    Administrator,
    Operator,
    Auditor,
    Service,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Action {
    CreateKey,
    DescribeKey,
    RotateKey,
    RollbackKey,
    RevokeKey,
    DestroyKey,
    PurgeKeyVersion,
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    WrapKey,
    UnwrapKey,
    ConfigurePolicy,
    ViewAudit,
}

impl Action {
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::CreateKey => "key:create",
            Action::DescribeKey => "key:describe",
            Action::RotateKey => "key:rotate",
            Action::RollbackKey => "key:rollback",
            Action::RevokeKey => "key:revoke",
            Action::DestroyKey => "key:destroy",
            Action::PurgeKeyVersion => "key:purge_version",
            Action::Encrypt => "crypto:encrypt",
            Action::Decrypt => "crypto:decrypt",
            Action::Sign => "crypto:sign",
            Action::Verify => "crypto:verify",
            Action::WrapKey => "crypto:wrap",
            Action::UnwrapKey => "crypto:unwrap",
            Action::ConfigurePolicy => "policy:configure",
            Action::ViewAudit => "audit:view",
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for Role {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "administrator" | "admin" => Ok(Role::Administrator),
            "operator" => Ok(Role::Operator),
            "auditor" => Ok(Role::Auditor),
            "service" => Ok(Role::Service),
            other => Err(format!("unknown role '{other}'")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RbacAuthorizer {
    grants: HashMap<Role, HashSet<Action>>,
}

impl Default for RbacAuthorizer {
    fn default() -> Self {
        let mut grants = HashMap::new();
        grants.insert(
            Role::Administrator,
            HashSet::from([
                Action::CreateKey,
                Action::DescribeKey,
                Action::RotateKey,
                Action::RollbackKey,
                Action::RevokeKey,
                Action::DestroyKey,
                Action::PurgeKeyVersion,
                Action::Encrypt,
                Action::Decrypt,
                Action::Sign,
                Action::Verify,
                Action::WrapKey,
                Action::UnwrapKey,
                Action::ConfigurePolicy,
                Action::ViewAudit,
            ]),
        );
        grants.insert(
            Role::Operator,
            HashSet::from([
                Action::CreateKey,
                Action::DescribeKey,
                Action::RotateKey,
                Action::RollbackKey,
                Action::PurgeKeyVersion,
                Action::Encrypt,
                Action::Decrypt,
                Action::Sign,
                Action::Verify,
                Action::WrapKey,
                Action::UnwrapKey,
            ]),
        );
        grants.insert(
            Role::Auditor,
            HashSet::from([
                Action::DescribeKey,
                Action::ViewAudit,
                Action::PurgeKeyVersion,
            ]),
        );
        grants.insert(
            Role::Service,
            HashSet::from([
                Action::DescribeKey,
                Action::Encrypt,
                Action::Decrypt,
                Action::Sign,
                Action::Verify,
            ]),
        );
        Self { grants }
    }
}

impl RbacAuthorizer {
    pub fn new(grants: HashMap<Role, HashSet<Action>>) -> Self {
        Self { grants }
    }

    pub fn is_allowed(&self, ctx: &AuthContext, action: &Action) -> bool {
        ctx.roles
            .iter()
            .flat_map(|role| self.grants.get(role))
            .any(|allowed| allowed.contains(action))
    }
}
