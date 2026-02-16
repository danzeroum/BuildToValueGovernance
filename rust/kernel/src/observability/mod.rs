//! Observability Module v1.9.0 (ADR-019)
//!
//! - Feature-gated: `observability` enables real Prometheus metrics
//! - Without feature: no-op stubs (zero overhead)
//! - Tracing and ThreatIngestor always available as stubs

// ═══════════════════════════════════════════════════════════════════════════
// METRICS (feature-gated)
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "observability")]
#[path = "metrics.rs"]
pub mod metrics;

#[cfg(not(feature = "observability"))]
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
        pub fn start_validation_timer(_profile: &str) -> MetricsGuard { MetricsGuard }
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

// ═══════════════════════════════════════════════════════════════════════════
// RE-EXPORTS
// ═══════════════════════════════════════════════════════════════════════════
pub use metrics::Metrics;
pub use tracing::init_tracer;
pub use threat_ingestor::ThreatIngestor;