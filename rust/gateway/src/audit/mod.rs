//! Audit subsystem (`audit-sink-local` sprint).
//!
//! Ver `docs/audit-sink-local-design.md` para contrato e operação.

pub mod event;
pub mod sink;
pub mod drainer;
pub mod grpc_exposer; // ADR-0091 — gRPC streaming exposer
