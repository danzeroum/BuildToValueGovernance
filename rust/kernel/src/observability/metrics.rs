//! Prometheus metrics v1.9.0 (ADR-019)
//! Feature-gated: only compiled with `observability` feature.

use lazy_static::lazy_static;
use prometheus::{
    IntCounterVec, HistogramVec, Gauge,
    register_int_counter_vec, register_histogram_vec, register_gauge,
};

lazy_static! {
    pub static ref VALIDATION_REQUESTS: IntCounterVec = register_int_counter_vec!(
        "btv_validation_requests_total",
        "Total validation requests",
        &["profile"]
    ).expect("metric: validation_requests");

    pub static ref FINDINGS_DETECTED: IntCounterVec = register_int_counter_vec!(
        "btv_findings_detected_total",
        "Findings detected by type and severity",
        &["finding_type", "severity"]
    ).expect("metric: findings_detected");

    pub static ref VALIDATION_LATENCY: HistogramVec = register_histogram_vec!(
        "btv_validation_duration_seconds",
        "Validation latency in seconds",
        &["profile"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1]
    ).expect("metric: validation_latency");

    pub static ref VALIDATOR_LATENCY: HistogramVec = register_histogram_vec!(
        "btv_validator_duration_seconds",
        "Per-validator latency",
        &["validator"],
        vec![0.0001, 0.0005, 0.001, 0.005, 0.01]
    ).expect("metric: validator_latency");

    pub static ref KERNEL_UPTIME: Gauge = register_gauge!(
        "btv_kernel_uptime_seconds",
        "Kernel uptime in seconds"
    ).expect("metric: kernel_uptime");

    pub static ref MERCY_APPLIED: IntCounterVec = register_int_counter_vec!(
        "btv_mercy_applied_total",
        "Mercy decisions applied",
        &["reason"]
    ).expect("metric: mercy_applied");

    pub static ref APPEALS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "btv_appeals_total",
        "Appeals by result",
        &["result"]
    ).expect("metric: appeals_total");

    pub static ref BIAS_FP_RATE: prometheus::GaugeVec = prometheus::register_gauge_vec!(
        "btv_bias_false_positive_rate",
        "False positive rate by module",
        &["module"]
    ).expect("metric: bias_fp_rate");
}

pub struct Metrics;
pub struct MetricsGuard {
    timer: Option<prometheus::HistogramTimer>,
}

impl Metrics {
    #[inline]
    pub fn start_validation_timer(profile: &str) -> MetricsGuard {
        MetricsGuard {
            timer: Some(VALIDATION_LATENCY.with_label_values(&[profile]).start_timer()),
        }
    }
}

impl Drop for MetricsGuard {
    fn drop(&mut self) {
        if let Some(timer) = self.timer.take() {
            timer.observe_duration();
        }
    }
}