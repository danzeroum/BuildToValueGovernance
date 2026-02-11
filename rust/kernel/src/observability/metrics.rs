//! Prometheus metrics for BuildToValue Rust kernel
//!
//! Fornece instrumentação para monitoramento de performance e segurança.
//! Controlado pela feature "observability".

// Desativa avisos se a feature estiver desligada
#![cfg_attr(not(feature = "observability"), allow(dead_code, unused_imports, unused_variables))]

#[cfg(feature = "observability")]
use lazy_static::lazy_static;
#[cfg(feature = "observability")]
use prometheus::{
    register_counter_vec, register_histogram_vec, register_gauge, register_int_counter_vec,
    CounterVec, HistogramVec, Gauge, IntCounterVec,
};

// ═══════════════════════════════════════════════════════════════════════════
// METRICS DEFINITIONS (Feature-Gated)
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "observability")]
lazy_static! {
    // --- Request Counters ---

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

    // --- Latency Histograms ---

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

    // --- Protocol Metrics ---

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

    // --- Resource Usage ---

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

// ═══════════════════════════════════════════════════════════════════════════
// METRICS GUARD (RAII Timer)
// ═══════════════════════════════════════════════════════════════════════════

/// Guard que registra a duração ao ser dropado.
#[cfg(feature = "observability")]
pub struct MetricsGuard {
    start: std::time::Instant,
    histogram: HistogramVec,
    labels: Vec<String>,
}

#[cfg(feature = "observability")]
impl MetricsGuard {
    pub fn new(histogram: &HistogramVec, labels: &[&str]) -> Self {
        Self {
            start: std::time::Instant::now(),
            histogram: histogram.clone(),
            labels: labels.iter().map(|s| s.to_string()).collect(),
        }
    }
}

#[cfg(feature = "observability")]
impl Drop for MetricsGuard {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed().as_secs_f64();
        let label_refs: Vec<&str> = self.labels.iter().map(|s| s.as_str()).collect();
        self.histogram
            .with_label_values(&label_refs)
            .observe(elapsed);
    }
}

// Implementação Stub (No-Op) quando observability está off
#[cfg(not(feature = "observability"))]
pub struct MetricsGuard;

// ═══════════════════════════════════════════════════════════════════════════
// PUBLIC FACADE (API)
// ═══════════════════════════════════════════════════════════════════════════

// ✅ CORREÇÃO: Adicionada a struct Metrics para agrupar as funções (exigido pelo mod.rs)
pub struct Metrics;

impl Metrics {
    /// Registra uma requisição de validação.
    pub fn record_validation(profile: &str) {
        #[cfg(feature = "observability")]
        {
            VALIDATION_REQUESTS_TOTAL
                .with_label_values(&[profile])
                .inc();
        }
    }

    /// Registra um finding detectado.
    pub fn record_finding(finding_type: &str, severity: &str) {
        #[cfg(feature = "observability")]
        {
            FINDINGS_DETECTED_TOTAL
                .with_label_values(&[finding_type, severity])
                .inc();
        }
    }

    /// Inicia um timer para medir latência de validação.
    /// Retorna um Guard que deve ser mantido até o fim da operação.
    #[cfg(feature = "observability")]
    pub fn start_validation_timer(profile: &str) -> MetricsGuard {
        MetricsGuard::new(&VALIDATION_DURATION_SECONDS, &[profile])
    }

    /// Stub para timer (retorna struct vazia que não faz nada no drop).
    #[cfg(not(feature = "observability"))]
    pub fn start_validation_timer(_profile: &str) -> MetricsGuard {
        MetricsGuard
    }
}