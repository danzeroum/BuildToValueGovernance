//! Observability Module v2.3.2
//!
//! **CHANGELOG v2.3.2**:
//! - ✅ Correção de conflito de namespace (crate `tracing` vs module `tracing`)
//! - ✅ Stubbing automático de `init_tracer` quando feature está off
//! - ✅ threat_ingestor_v2 (WAL) integrado

pub mod metrics;
pub mod threat_ingestor;

// ✅ CORREÇÃO 1: Módulo 'tracing' só existe se a feature estiver ativa.
// Usamos 'self::tracing' no use abaixo para desambiguar da crate externa.
#[cfg(feature = "observability")]
pub mod tracing;

pub use threat_ingestor::ThreatIngestor;
pub use metrics::Metrics;

// ✅ CORREÇÃO 2: Re-export condicional usando self::tracing
#[cfg(feature = "observability")]
pub use self::tracing::{init_tracer, shutdown_tracer};

// ✅ CORREÇÃO 3: Fallback (Stub) para quando a feature estiver desligada.
// Mantém a assinatura compatível (Result<(), ...>) para não quebrar o main.rs/lib.rs.
#[cfg(not(feature = "observability"))]
pub fn init_tracer() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // No-op: Observabilidade desativada
    Ok(())
}

#[cfg(not(feature = "observability"))]
pub fn shutdown_tracer() {
    // No-op
}