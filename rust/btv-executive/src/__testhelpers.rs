//! Test helpers for integration tests — only compiled in `#[cfg(test)]`.
//!
//! Exposes internal bridge types so integration tests in `tests/` can
//! construct `ScanResult` and `FindingRecord` values without duplicating
//! scan logic.

pub use crate::gatekeeper_bridge::{GatekeeperBridge, ScanResult, FindingRecord, InputStatistics};
use btv_types::RiskLevel;

/// Construct a minimal `ScanResult` with the given findings and composite risk.
pub fn make_scan_result(findings: Vec<FindingRecord>, composite_risk: f32) -> ScanResult {
    ScanResult {
        findings,
        composite_risk,
        risk_level: RiskLevel::from_score(composite_risk),
        statistics: InputStatistics {
            entropy:      0.0,
            z_score:      0.0,
            input_size:   10,
            digit_ratio:  0.0,
            letter_ratio: 1.0,
            symbol_ratio: 0.0,
            unique_chars: 5,
            total_chars:  10,
        },
        evidence_bytes:    vec![0u8; 8],
        executed_stages:   0,
        detected_language: String::new(),
        scan_duration_us:  0,
        bias:              btv_types::BiasDeclaration::bootstrap_unvalidated(),
    }
}

/// Construct a `FindingRecord` with the specified metadata.
pub fn make_finding(rule_id: &str, category: &str, severity: u8, confidence: u8) -> FindingRecord {
    FindingRecord {
        rule_id:          rule_id.to_string(),
        title:            rule_id.to_string(),
        severity,
        confidence,
        validator_module: "test".to_string(),
        category:         category.to_string(),
    }
}

/// Thin handle that exposes `GatekeeperBridge::scan` for integration tests.
pub struct GatekeeperBridgeHandle(GatekeeperBridge);

impl Default for GatekeeperBridgeHandle {
    fn default() -> Self { Self::new() }
}

impl GatekeeperBridgeHandle {
    pub fn new() -> Self { Self(GatekeeperBridge::new()) }

    pub fn scan(&self, input: &[u8]) -> Result<ScanResult, crate::gatekeeper_bridge::ScanError> {
        self.0.scan(input)
    }
}
