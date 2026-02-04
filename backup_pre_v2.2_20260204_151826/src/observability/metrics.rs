
//! Prometheus metrics for BuildToValue Rust kernel

use lazy_static::lazy_static;
use prometheus::{
    register_counter_vec, register_histogram_vec, register_gauge, register_int_counter_vec,
    CounterVec, HistogramVec, Gauge, IntCounterVec,
};

lazy_static! {
    // ═══════════════════════════════════════════════════════════════
    // Request Counters
    // ═══════════════════════════════════════════════════════════════
    
    /// Total validation requests
    pub static ref VALIDATION_REQUESTS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "buildtovalue_validation_requests_total",
        "Total number of validation requests",
        &["profile"]
    ).unwrap();
    
    /// Findings detected by type
    pub static ref FINDINGS_DETECTED_TOTAL: IntCounterVec = register_int_counter_vec!(
        "buildtovalue_findings_detected_total",
        "Total number of findings detected",
        &["finding_type", "severity"]
    ).unwrap();
    
    // ═══════════════════════════════════════════════════════════════
    // Latency Histograms
    // ═══════════════════════════════════════════════════════════════
    
    /// Validation latency (end-to-end)
    pub static ref VALIDATION_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "buildtovalue_validation_duration_seconds",
        "Validation request duration in seconds",
        &["profile"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0] // 1ms to 1s
    ).unwrap();
    
    /// Validator-specific latency
    pub static ref VALIDATOR_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "buildtovalue_validator_duration_seconds",
        "Individual validator duration in seconds",
        &["validator"],
        vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05] // 0.1ms to 50ms
    ).unwrap();
    
    // ═══════════════════════════════════════════════════════════════
    // Evidence Protocol Metrics
    // ═══════════════════════════════════════════════════════════════
    
    /// Evidence serialization time
    pub static ref EVIDENCE_SERIALIZATION_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "buildtovalue_evidence_serialization_duration_seconds",
        "Evidence serialization duration",
        &["operation"], // "serialize" or "deserialize"
        vec![0.00001, 0.00005, 0.0001, 0.0005, 0.001] // 10μs to 1ms
    ).unwrap();
    
    /// Evidence hash collisions (should be zero)
    pub static ref EVIDENCE_HASH_COLLISIONS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "buildtovalue_evidence_hash_collisions_total",
        "Evidence hash collisions detected",
        &[]
    ).unwrap();
    
    // ═══════════════════════════════════════════════════════════════
    // Resource Usage
    // ═══════════════════════════════════════════════════════════════
    
    /// Current memory usage (bytes)
    pub static ref MEMORY_USAGE_BYTES: Gauge = register_gauge!(
        "buildtovalue_memory_usage_bytes",
        "Current memory usage in bytes"
    ).unwrap();
    
    /// Bloom filter size (bytes)
    pub static ref BLOOM_FILTER_SIZE_BYTES: Gauge = register_gauge!(
        "buildtovalue_bloom_filter_size_bytes",
        "Bloom filter memory size in bytes"
    ).unwrap();
}

// ═══════════════════════════════════════════════════════════════
// Instrumentation Helpers
// ═══════════════════════════════════════════════════════════════

pub struct MetricsGuard {
    start: std::time::Instant,
    histogram: HistogramVec,
    labels: Vec<String>,
}

impl MetricsGuard {
    pub fn new(histogram: &HistogramVec, labels: &[&str]) -> Self {
        Self {
            start: std::time::Instant::now(),
            histogram: histogram.clone(),
            labels: labels.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl Drop for MetricsGuard {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed().as_secs_f64();
        let label_refs: Vec<&str> = self.labels.iter().map(|s| s.as_str()).collect();
        self.histogram
            .with_label_values(&label_refs)
            .observe(elapsed);
    }
}

// ═══════════════════════════════════════════════════════════════
// Example Usage
// ═══════════════════════════════════════════════════════════════

pub fn record_validation(profile: &str) {
    let _timer = MetricsGuard::new(&VALIDATION_DURATION_SECONDS, &[profile]);
    
    VALIDATION_REQUESTS_TOTAL
        .with_label_values(&[profile])
        .inc();
    
    // ... do validation work ...
}

pub fn record_finding(finding_type: &str, severity: &str) {
    FINDINGS_DETECTED_TOTAL
        .with_label_values(&[finding_type, severity])
        .inc();
}