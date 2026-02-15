//! Observability Module v2.3.1
//!
//! **CHANGELOG v2.3.1**:
//! - ✅ threat_ingestor_v2 promovido para versão oficial
//! - ✅ Remoção de threat_ingestor (v1)
//! - ✅ Correção de conflito de nomes no módulo tracing [E0432]

pub use threat_ingestor::ThreatIngestor;
pub use metrics::Metrics;
pub use tracing::init_tracer;

// ═══════════════════════════════════════════════════════════════════════════
// METRICS STUB
// ═══════════════════════════════════════════════════════════════════════════
pub mod metrics {
    pub struct Metrics;

    pub struct MetricsGuard;

    pub struct GatekeeperMetrics;

    impl Metrics {
        #[inline]
        pub fn record_validation(_profile: &str) {}

        #[inline]
        pub fn record_finding(_finding_type: &str, _severity: &str) {}

        #[inline]
        pub fn start_validation_timer(_profile: &str) -> MetricsGuard {
            MetricsGuard
        }
    }

    impl Drop for MetricsGuard {
        fn drop(&mut self) {}
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// THREAT INGESTOR STUB
// ═══════════════════════════════════════════════════════════════════════════
pub mod threat_ingestor {
    pub struct ThreatIngestor;

    #[derive(Debug, Clone)]
    pub struct ThreatEvent;

    impl ThreatIngestor {
        pub fn new(_path: impl AsRef<std::path::Path>) -> Result<Self, String> {
            Ok(ThreatIngestor)
        }

        pub fn ingest(&mut self, _event: ThreatEvent) -> Result<(), String> {
            Ok(())
        }

        pub fn query_by_type(&self, _threat_type: &str) -> Vec<&ThreatEvent> {
            vec![]
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TRACING STUB
// ═══════════════════════════════════════════════════════════════════════════
pub mod tracing {
    pub fn init_tracer() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    pub fn shutdown_tracer() {}

    pub struct SpanGuard {
        _private: (),
    }

    impl SpanGuard {
        pub fn new(_name: &'static str) -> Self {
            SpanGuard { _private: () }
        }

        pub fn record_error(&self, _error: &str) {}
        pub fn record_success(&self) {}
    }
}


