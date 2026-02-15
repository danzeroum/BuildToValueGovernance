//! Policy Engine Module
//! Implementação de Policy-as-Code.
//! Policy Engine Module v1.6.0
//! Policy-as-Code: YAML → Runtime with hard blocks.
pub mod policy;
pub use policy::{
    PolicyEngine, PolicySet, Policy, PolicyAction,
    PolicyConditions, PolicyMetadata, PolicyEvaluation,
    PolicyMetrics,
};