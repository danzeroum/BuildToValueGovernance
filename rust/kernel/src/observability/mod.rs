//! Observability Module v2.3.1
//!
//! **CHANGELOG v2.3.1**:
//! - ✅ threat_ingestor_v2 promovido para versão oficial
//! - ✅ Remoção de threat_ingestor (v1)

pub mod metrics;
pub mod tracing;
pub mod threat_ingestor;  // Agora é a v2 (com WAL)

pub use threat_ingestor::ThreatIngestor;
pub use metrics::Metrics;
pub use tracing::init_tracer;