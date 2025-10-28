use std::collections::HashSet;

use crate::{
    models::{AuthContext, KeyAlgorithm},
    rbac::Role,
};

/// PQC policy controller that enforces additional constraints for post-quantum algorithms
pub struct PqcPolicyController {
    // Algorithms that require administrative approval
    admin_approval_algorithms: HashSet<KeyAlgorithm>,
    // Algorithms that require dual control (two-person rule)
    dual_control_algorithms: HashSet<KeyAlgorithm>,
    // Algorithms that are restricted to specific roles
    restricted_algorithms: HashSet<KeyAlgorithm>,
}

impl Default for PqcPolicyController {
    fn default() -> Self {
        let mut admin_approval_algorithms = HashSet::new();
        admin_approval_algorithms.insert(KeyAlgorithm::MlKem1024);
        admin_approval_algorithms.insert(KeyAlgorithm::MlDsa135);
        admin_approval_algorithms.insert(KeyAlgorithm::SlhDsaSha2256f);
        admin_approval_algorithms.insert(KeyAlgorithm::SlhDsaSha2256s);
        admin_approval_algorithms.insert(KeyAlgorithm::HybridP384MlKem1024);

        let mut dual_control_algorithms = HashSet::new();
        dual_control_algorithms.insert(KeyAlgorithm::MlKem768);
        dual_control_algorithms.insert(KeyAlgorithm::MlKem1024);
        dual_control_algorithms.insert(KeyAlgorithm::MlDsa87);
        dual_control_algorithms.insert(KeyAlgorithm::MlDsa135);
        dual_control_algorithms.insert(KeyAlgorithm::SlhDsaSha2192f);
        dual_control_algorithms.insert(KeyAlgorithm::SlhDsaSha2192s);
        dual_control_algorithms.insert(KeyAlgorithm::SlhDsaSha2256f);
        dual_control_algorithms.insert(KeyAlgorithm::SlhDsaSha2256s);
        dual_control_algorithms.insert(KeyAlgorithm::HybridP256MlKem768);
        dual_control_algorithms.insert(KeyAlgorithm::HybridP384MlKem1024);

        let mut restricted_algorithms = HashSet::new();
        restricted_algorithms.insert(KeyAlgorithm::MlKem1024);
        restricted_algorithms.insert(KeyAlgorithm::MlDsa135);
        restricted_algorithms.insert(KeyAlgorithm::SlhDsaSha2256f);
        restricted_algorithms.insert(KeyAlgorithm::SlhDsaSha2256s);
        restricted_algorithms.insert(KeyAlgorithm::HybridP384MlKem1024);

        Self {
            admin_approval_algorithms,
            dual_control_algorithms,
            restricted_algorithms,
        }
    }
}

impl PqcPolicyController {
    /// Create a new PQC policy controller with custom algorithm restrictions
    pub fn new(
        admin_approval_algorithms: HashSet<KeyAlgorithm>,
        dual_control_algorithms: HashSet<KeyAlgorithm>,
        restricted_algorithms: HashSet<KeyAlgorithm>,
    ) -> Self {
        Self {
            admin_approval_algorithms,
            dual_control_algorithms,
            restricted_algorithms,
        }
    }

    /// Check if the algorithm requires administrative approval
    pub fn requires_admin_approval(&self, algorithm: &KeyAlgorithm) -> bool {
        self.admin_approval_algorithms.contains(algorithm)
    }

    /// Check if the algorithm requires dual control (two-person rule)
    pub fn requires_dual_control(&self, algorithm: &KeyAlgorithm) -> bool {
        self.dual_control_algorithms.contains(algorithm)
    }

    /// Check if the algorithm is restricted to specific roles
    pub fn is_restricted(&self, algorithm: &KeyAlgorithm) -> bool {
        self.restricted_algorithms.contains(algorithm)
    }

    /// Check if the user is authorized to use the specified PQC algorithm
    pub fn is_authorized(&self, ctx: &AuthContext, algorithm: &KeyAlgorithm) -> bool {
        // If the algorithm is not PQC, allow it
        if !algorithm.is_post_quantum() && !algorithm.is_hybrid() {
            return true;
        }

        // If the algorithm is restricted, only administrators can use it
        if self.is_restricted(algorithm) && !ctx.has_role(&Role::Administrator) {
            return false;
        }

        // If the algorithm requires admin approval, check if the user is an administrator
        if self.requires_admin_approval(algorithm) && !ctx.has_role(&Role::Administrator) {
            return false;
        }

        true
    }

    /// Get policy tags for a PQC algorithm
    pub fn get_policy_tags(&self, algorithm: &KeyAlgorithm) -> Vec<String> {
        let mut tags = Vec::new();

        if algorithm.is_post_quantum() {
            tags.push("pqc".to_string());
        }

        if algorithm.is_hybrid() {
            tags.push("hybrid".to_string());
        }

        if self.requires_admin_approval(algorithm) {
            tags.push("pqc.admin_approval".to_string());
        }

        if self.requires_dual_control(algorithm) {
            tags.push("pqc.dual_control".to_string());
        }

        if self.is_restricted(algorithm) {
            tags.push("pqc.restricted".to_string());
        }

        match algorithm {
            KeyAlgorithm::MlKem512 | KeyAlgorithm::MlKem768 | KeyAlgorithm::MlKem1024 => {
                tags.push("pqc.kem".to_string());
            }
            KeyAlgorithm::MlDsa65 | KeyAlgorithm::MlDsa87 | KeyAlgorithm::MlDsa135 => {
                tags.push("pqc.signature".to_string());
                tags.push("pqc.ml_dsa".to_string());
            }
            KeyAlgorithm::SlhDsaSha2128f
            | KeyAlgorithm::SlhDsaSha2128s
            | KeyAlgorithm::SlhDsaSha2192f
            | KeyAlgorithm::SlhDsaSha2192s
            | KeyAlgorithm::SlhDsaSha2256f
            | KeyAlgorithm::SlhDsaSha2256s => {
                tags.push("pqc.signature".to_string());
                tags.push("pqc.slh_dsa".to_string());
            }
            KeyAlgorithm::HybridP256MlKem768 | KeyAlgorithm::HybridP384MlKem1024 => {
                tags.push("pqc.hybrid".to_string());
                tags.push("pqc.kem".to_string());
            }
            _ => {}
        }

        tags
    }
}