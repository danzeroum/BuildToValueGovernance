//! BTV Gateway library — exposes router for testing.

pub mod routes;
pub mod middleware;
pub mod state;
pub mod fairness_mode;  // ADR-0088 §D3
pub mod tenant_status;  // ADR-0089 §D1
pub mod policy_loader;  // ADR-0089 §D1 — boot step
pub mod audit;          // audit-sink-local sprint