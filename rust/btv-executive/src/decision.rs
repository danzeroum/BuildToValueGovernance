//! `DecisionMaker` — converts scan findings into a `Decision`.
//!
//! NOT policy evaluation (Legislative prerogative).
//! This is the Executive's application of Legislative rules to concrete evidence.
use crate::gatekeeper_bridge::ScanResult;
use btv_types::Decision;

/// Deterministic decision logic: findings → Allow / Deny / Block.
///
/// Threshold hierarchy (checked in order):
/// 1. `composite_risk >= threat_threshold` → Block (active threat)
/// 2. critical finding (severity ≥ 200) OR `composite_risk >= deny_threshold` → Deny (policy)
/// 3. otherwise → Allow
pub struct DecisionMaker {
    /// Threshold for Decision::Block (active threat). Default 0.95. Must be > deny_threshold.
    threat_threshold: f32,
    /// Threshold for Decision::Deny (policy). Default 0.80.
    deny_threshold: f32,
    // escalate_threshold reserved for EscalatedVerdict (Phase 6, Corollary 4.8)
    _escalate_threshold: f32,
}

impl DecisionMaker {
    pub fn new(threat_threshold: f32, deny_threshold: f32, escalate_threshold: f32) -> Self {
        assert!(
            threat_threshold > deny_threshold,
            "threat_threshold ({}) must be greater than deny_threshold ({})",
            threat_threshold, deny_threshold
        );
        Self { threat_threshold, deny_threshold, _escalate_threshold: escalate_threshold }
    }

    /// Default thresholds: Block ≥ 0.95, Deny ≥ 0.80, escalate ≥ 0.60.
    pub fn default_thresholds() -> Self {
        Self::new(0.95, 0.80, 0.60)
    }

    /// Deterministic: active-threat check first, then policy Deny, then Allow.
    pub fn decide(&self, scan: &ScanResult) -> Decision {
        if scan.composite_risk >= self.threat_threshold {
            return Decision::Block;
        }
        let has_critical = scan.findings.iter().any(|f| f.severity >= 200);
        if has_critical || scan.composite_risk >= self.deny_threshold {
            Decision::Deny
        } else {
            Decision::Allow
        }
    }

    /// Deterministic explanation string (hashed into VerdictRecord).
    pub fn explain(&self, scan: &ScanResult, decision: &Decision) -> String {
        match decision {
            Decision::Allow => format!(
                "ALLOW: composite_risk={:.3}, findings={}, lang={}, stages={:#b}",
                scan.composite_risk,
                scan.findings.len(),
                scan.detected_language,
                scan.executed_stages,
            ),
            Decision::Deny => {
                let criticals: Vec<_> = scan.findings.iter()
                    .filter(|f| f.severity >= 200)
                    .collect();
                if criticals.is_empty() {
                    format!(
                        "DENY: composite_risk={:.3} \u{2265} threshold={:.3}. Fail-secure.",
                        scan.composite_risk, self.deny_threshold,
                    )
                } else {
                    format!(
                        "DENY: {} critical finding(s). Lead: {} (sev={},conf={}). Fail-secure.",
                        criticals.len(),
                        criticals[0].title,
                        criticals[0].severity,
                        criticals[0].confidence,
                    )
                }
            }
            Decision::Block => format!(
                "BLOCK: composite_risk={:.3} \u{2265} threat_threshold={:.3}. \
                 Active threat detected. Security alert generated. Fail-secure.",
                scan.composite_risk, self.threat_threshold,
            ),
        }
    }
}
