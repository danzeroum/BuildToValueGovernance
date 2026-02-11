//! Observability Module v2.3.1
//!
//! **CHANGELOG v2.3.1**:
//! - ✅ threat_ingestor_v2 promovido para versão oficial
//! - ✅ Remoção de threat_ingestor (v1)
//! - ✅ Correção de conflito de nomes no módulo tracing [E0432]

pub mod metrics;
pub mod threat_ingestor;

pub use threat_ingestor::ThreatIngestor;
pub use metrics::Metrics;

// ═══════════════════════════════════════════════════════════════════════════
// TRACING CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

// ✅ CORREÇÃO 1 & 2: O módulo 'tracing' só é declarado se a feature estiver ativa.
// Usamos 'self::tracing' para evitar conflito com a crate 'tracing'.
#[cfg(feature = "observability")]
pub mod tracing;

#[cfg(feature = "observability")]
pub use self::tracing::init_tracer;

// ✅ CORREÇÃO 3: Fallback (Stub)
// Se a observabilidade estiver desligada, fornecemos uma função dummy
// para que o código que chama init_tracer() não quebre.
#[cfg(not(feature = "observability"))]
pub fn init_tracer() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // No-op: Observabilidade desativada, nada a fazer.
    Ok(())
}