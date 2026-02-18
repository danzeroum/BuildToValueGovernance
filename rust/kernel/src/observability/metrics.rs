//! Observability Metrics v1.9.0 — Kernel-level Prometheus metrics.
//! Per-module latency, finding counts, and error tracking.
//!
//! Filosofia (Jonas): Monitorar é responsabilidade proporcional ao poder.

use prometheus::{
    register_histogram_vec, register_counter_vec, register_gauge,
    HistogramVec, CounterVec, Gauge,
};
use lazy_static::lazy_static;

lazy_static! {
    // ── Scan metrics ──────────────────────────────────────────
    pub static ref SCAN_DURATION: HistogramVec = register_histogram_vec!(
        "btv_kernel_scan_duration_seconds",
        "Gatekeeper scan_for_evidence latency",
        &["module"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1]
    ).unwrap();

    pub static ref FINDINGS_TOTAL: CounterVec = register_counter_vec!(
        "btv_kernel_findings_total",
        "Total findings by module and severity",
        &["module", "severity"]
    ).unwrap();

    pub static ref CRITICAL_FINDINGS: CounterVec = register_counter_vec!(
        "btv_kernel_critical_findings_total",
        "Critical findings by module",
        &["module"]
    ).unwrap();

    // ── Policy metrics ────────────────────────────────────────
    pub static ref POLICY_DECISIONS: CounterVec = register_counter_vec!(
        "btv_kernel_policy_decisions_total",
        "Policy decisions by action",
        &["action"]
    ).unwrap();

    pub static ref HARD_BLOCKS: CounterVec = register_counter_vec!(
        "btv_kernel_hard_blocks_total",
        "Hard block triggers by term",
        &["term"]
    ).unwrap();

    // ── Deobfuscation metrics ─────────────────────────────────
    pub static ref DEOBFUSCATION_LAYERS: CounterVec = register_counter_vec!(
        "btv_kernel_deobfuscation_layers_total",
        "Deobfuscation layers applied",
        &["layer_type"]
    ).unwrap();

    // ── Session metrics ───────────────────────────────────────
    pub static ref ACTIVE_SESSIONS: Gauge = register_gauge!(
        "btv_kernel_active_sessions",
        "Current tracked sessions"
    ).unwrap();

    pub static ref DRIFT_EVENTS: CounterVec = register_counter_vec!(
        "btv_kernel_drift_events_total",
        "Session drift events by level",
        &["level"]
    ).unwrap();

    // ── Network metrics ───────────────────────────────────────
    pub static ref IP_CLASSIFICATIONS: CounterVec = register_counter_vec!(
        "btv_kernel_ip_classifications_total",
        "IP classifications by category",
        &["category"]
    ).unwrap();

    // ── Error metrics ─────────────────────────────────────────
    pub static ref ERRORS_TOTAL: CounterVec = register_counter_vec!(
        "btv_kernel_errors_total",
        "Errors by module",
        &["module"]
    ).unwrap();
}

/// Record a scan duration for a specific module.
pub fn record_scan(module: &str, duration_secs: f64) {
    SCAN_DURATION.with_label_values(&[module]).observe(duration_secs);
}

/// Record a finding.
pub fn record_finding(module: &str, severity: &str) {
    FINDINGS_TOTAL.with_label_values(&[module, severity]).inc();
}

/// Record a policy decision.
pub fn record_policy_decision(action: &str) {
    POLICY_DECISIONS.with_label_values(&[action]).inc();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_scan_no_panic() {
        record_scan("gatekeeper", 0.015);
        record_scan("validators", 0.003);
    }

    #[test]
    fn test_record_finding_no_panic() {
        record_finding("cpf", "critical");
        record_finding("email", "medium");
    }

    #[test]
    fn test_record_policy_decision_no_panic() {
        record_policy_decision("BLOCK");
        record_policy_decision("ALLOW");
    }
}