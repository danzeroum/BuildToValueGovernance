//! Policy Engine Module
//! Implementação de Policy-as-Code.
//! Policy Engine Module v1.6.0
//! Policy-as-Code: YAML → Runtime with hard blocks.
#[allow(clippy::module_inception)]
pub mod policy;
pub mod budget_enforcer; // Cenário 30: hierarquia de contas no hot path
pub mod loader;

pub use policy::{
    PolicyEngine, PolicySet, Policy, PolicyAction,
    PolicyConditions, PolicyMetadata, PolicyEvaluation,
    PolicyMetrics,
};
pub use budget_enforcer::{enforce as enforce_budget, AccountTier, PolicyDecision};
pub use loader::{PolicyWatcher, PolicyLoadError};