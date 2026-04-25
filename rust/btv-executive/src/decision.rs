//! `DecisionMaker` — converts scan findings into a `Decision`.
//!
//! NOT policy evaluation (Legislative prerogative).
//! This is the Executive's application of Legislative rules to concrete evidence.
use crate::gatekeeper_bridge::ScanResult;
use btv_types::Decision;

/// Deterministic decision logic: findings → Allow/Deny.
pub struct DecisionMaker {
    block_threshold:    f32,
    // escalate_threshold reserved for EscalatedVerdict (Fase 6, Corollary 4.8)
    _escalate_threshold: f32,
}

impl DecisionMaker {
    pub fn new(block_threshold: f32, escalate_threshold: f32) -> Self {
        Self { block_threshold, _escalate_threshold: escalate_threshold }
    }

    /// Default thresholds: block ≥ 0.8 composite risk, escalate ≥ 0.6
    pub fn default_thresholds() -> Self {
        Self::new(0.8, 0.6)
    }

    /// Deterministic: any critical finding → Deny; composite ≥ threshold → Deny; else → Allow.
    pub fn decide(&self, scan: &ScanResult) -> Decision {
        let has_critical = scan.findings.iter().any(|f| f.severity >= 200);
        if has_critical || scan.composite_risk >= self.block_threshold {
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
                        scan.composite_risk, self.block_threshold,
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
        }
    }
}
