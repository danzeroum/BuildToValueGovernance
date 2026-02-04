
use prometheus::{
    Counter, CounterVec, Histogram, HistogramVec, Gauge, GaugeVec,
    Registry, Opts, HistogramOpts,
};
use lazy_static::lazy_static;

lazy_static! {
    /// Global metrics registry
    pub static ref REGISTRY: Registry = Registry::new();
    
    // ═══════════════════════════════════════════════════════════════
    // Request Metrics
    // ═══════════════════════════════════════════════════════════════
    
    /// Total HTTP requests
    pub static ref HTTP_REQUESTS_TOTAL: CounterVec = {
        let opts = Opts::new(
            "http_requests_total",
            "Total number of HTTP requests"
        );
        let counter = CounterVec::new(opts, &["method", "status"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };
    
    /// HTTP request duration (histogram)
    pub static ref HTTP_REQUEST_DURATION: HistogramVec = {
        let opts = HistogramOpts::new(
            "http_request_duration_seconds",
            "HTTP request latencies in seconds"
        )
        .buckets(vec![
            0.001,  // 1ms
            0.005,  // 5ms
            0.010,  // 10ms
            0.025,  // 25ms
            0.050,  // 50ms
            0.075,  // 75ms
            0.100,  // 100ms
            0.250,  // 250ms
            0.500,  // 500ms
            1.000,  // 1s
        ]);
        
        let histogram = HistogramVec::new(opts, &["method", "endpoint"]).unwrap();
        REGISTRY.register(Box::new(histogram.clone())).unwrap();
        histogram
    };
    
    // ═══════════════════════════════════════════════════════════════
    // Evidence Protocol Metrics
    // ═══════════════════════════════════════════════════════════════
    
    /// Findings detected (by module and severity)
    pub static ref FINDINGS_TOTAL: CounterVec = {
        let opts = Opts::new(
            "buildtovalue_findings_total",
            "Total findings detected by validators"
        );
        let counter = CounterVec::new(opts, &["module", "severity"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };
    
    /// Evidence finalization duration
    pub static ref EVIDENCE_FINALIZATION_DURATION: Histogram = {
        let opts = HistogramOpts::new(
            "buildtovalue_evidence_finalization_duration_seconds",
            "Time to finalize evidence"
        )
        .buckets(vec![0.001, 0.002, 0.005, 0.010, 0.020, 0.050]);
        
        let histogram = Histogram::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(histogram.clone())).unwrap();
        histogram
    };
    
    /// Composite risk distribution
    pub static ref COMPOSITE_RISK: Histogram = {
        let opts = HistogramOpts::new(
            "buildtovalue_composite_risk",
            "Distribution of composite risk scores"
        )
        .buckets(vec![0.0, 50.0, 100.0, 150.0, 192.0, 224.0, 255.0]);
        
        let histogram = Histogram::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(histogram.clone())).unwrap();
        histogram
    };
    
    // ═══════════════════════════════════════════════════════════════
    // Ledger Metrics
    // ═══════════════════════════════════════════════════════════════
    
    /// Ledger appends
    pub static ref LEDGER_APPENDS_TOTAL: Counter = {
        let opts = Opts::new(
            "buildtovalue_ledger_appends_total",
            "Total entries appended to ledger"
        );
        let counter = Counter::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };
    
    /// WAL utilization (0.0 to 1.0)
    pub static ref LEDGER_WAL_UTILIZATION: Gauge = {
        let opts = Opts::new(
            "buildtovalue_ledger_wal_utilization",
            "Write-Ahead Log utilization ratio"
        );
        let gauge = Gauge::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(gauge.clone())).unwrap();
        gauge
    };
    
    /// Ledger validation failures
    pub static ref LEDGER_VALIDATION_FAILURES: Counter = {
        let opts = Opts::new(
            "buildtovalue_ledger_validation_failures_total",
            "Ledger integrity validation failures (CRITICAL)"
        );
        let counter = Counter::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };
    
    // ═══════════════════════════════════════════════════════════════
    // Ethical Governance Metrics
    // ═══════════════════════════════════════════════════════════════
    
    /// Decisions by action type
    pub static ref DECISIONS_TOTAL: CounterVec = {
        let opts = Opts::new(
            "buildtovalue_decisions_total",
            "Total decisions by action type"
        );
        let counter = CounterVec::new(opts, &["action", "domain", "role"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };
    
    /// Mercy score distribution
    pub static ref MERCY_SCORE: Histogram = {
        let opts = HistogramOpts::new(
            "buildtovalue_mercy_score",
            "Distribution of mercy scores (Gilligan)"
        )
        .buckets(vec![0.0, 0.2, 0.4, 0.5, 0.6, 0.8, 1.0]);
        
        let histogram = Histogram::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(histogram.clone())).unwrap();
        histogram
    };
    
    /// Trust score distribution
    pub static ref TRUST_SCORE: HistogramVec = {
        let opts = HistogramOpts::new(
            "buildtovalue_trust_score",
            "Distribution of trust scores"
        )
        .buckets(vec![0.0, 0.2, 0.4, 0.6, 0.8, 1.0]);
        
        let histogram = HistogramVec::new(opts, &["role", "domain"]).unwrap();
        REGISTRY.register(Box::new(histogram.clone())).unwrap();
        histogram
    };
    
    /// Appeals (contestability)
    pub static ref APPEALS_TOTAL: CounterVec = {
        let opts = Opts::new(
            "buildtovalue_appeals_total",
            "Total appeals by result"
        );
        let counter = CounterVec::new(opts, &["result"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };
    
    // ═══════════════════════════════════════════════════════════════
    // BiasDeclaration Metrics
    // ═══════════════════════════════════════════════════════════════
    
    /// False positive rate (by module)
    pub static ref BIAS_FALSE_POSITIVE_RATE: GaugeVec = {
        let opts = Opts::new(
            "buildtovalue_bias_false_positive_rate",
            "False positive rate by module"
        );
        let gauge = GaugeVec::new(opts, &["module"]).unwrap();
        REGISTRY.register(Box::new(gauge.clone())).unwrap();
        gauge
    };
    
    /// Last calibration timestamp
    pub static ref BIAS_CALIBRATION_TIMESTAMP: GaugeVec = {
        let opts = Opts::new(
            "buildtovalue_bias_calibration_timestamp",
            "Unix timestamp of last calibration"
        );
        let gauge = GaugeVec::new(opts, &["module"]).unwrap();
        REGISTRY.register(Box::new(gauge.clone())).unwrap();
        gauge
    };
    
    // ═══════════════════════════════════════════════════════════════
    // Security Metrics
    // ═══════════════════════════════════════════════════════════════
    
    /// Rate limit violations
    pub static ref RATE_LIMIT_EXCEEDED: CounterVec = {
        let opts = Opts::new(
            "buildtovalue_rate_limit_exceeded_total",
            "Rate limit violations by source"
        );
        let counter = CounterVec::new(opts, &["source_ip"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };
}

/// Expose metrics for Prometheus scraping
pub fn metrics_handler() -> String {
    use prometheus::Encoder;
    
    let encoder = prometheus::TextEncoder::new();
    let metric_families = REGISTRY.gather();
    
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    
    String::from_utf8(buffer).unwrap()
}