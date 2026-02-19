
use serde::{Deserialize, Serialize};

/// Demographic groups for AJL compliance
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DemographicGroup {
    Gender(String),
    Age(String),
    Race(String),
    Language(String),
}

impl Default for AJLMetricsEngine {
    fn default() -> Self { Self::new() }
}
/// Bias metric result (EU AI Act Art. 10)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiasMetric {
    pub group_a: DemographicGroup,
    pub group_b: DemographicGroup,
    pub dir: f64, // Disparate Impact Ratio
    pub pass_threshold: f64, // 0.8 (80% rule)
    pub compliant: bool,
    pub sample_size: usize,
    pub timestamp: i64,
}

/// AJL Certification Engine (deterministic calculations)
pub struct AJLMetricsEngine {
    threshold: f64, // Default: 0.8 (AJL standard)
}

impl AJLMetricsEngine {
    pub fn new() -> Self {
        Self { threshold: 0.8 }
    }

    /// Calculate Disparate Impact Ratio (DIR)
    /// DIR = (favorable_rate_group_a) / (favorable_rate_group_b)
    /// Compliant if DIR >= 0.8 (80% rule)
    pub fn calculate_dir(
        &self,
        favorable_a: usize,
        total_a: usize,
        favorable_b: usize,
        total_b: usize,
    ) -> f64 {
        if total_a == 0 || total_b == 0 {
            return 0.0; // Invalid sample
        }

        let rate_a = favorable_a as f64 / total_a as f64;
        let rate_b = favorable_b as f64 / total_b as f64;

        if rate_b == 0.0 {
            return 0.0; // Avoid division by zero
        }

        rate_a / rate_b
    }

    /// Check if DIR is compliant (>= threshold)
    pub fn is_compliant(&self, dir: f64) -> bool {
        dir >= self.threshold
    }

    /// Generate AJL audit report (Protobuf-ready)
    pub fn generate_report(
        &self,
        metrics: Vec<BiasMetric>,
    ) -> AJLReport {
        let total = metrics.len();
        let compliant = metrics.iter().filter(|m| m.compliant).count();
        let compliance_rate = if total > 0 {
            compliant as f64 / total as f64
        } else {
            0.0
        };

        AJLReport {
            timestamp: chrono::Utc::now().timestamp(),
            total_metrics: total,
            compliant_metrics: compliant,
            compliance_rate,
            metrics,
            certification_eligible: compliance_rate >= 0.95, // 95% pass rate
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AJLReport {
    pub timestamp: i64,
    pub total_metrics: usize,
    pub compliant_metrics: usize,
    pub compliance_rate: f64,
    pub metrics: Vec<BiasMetric>,
    pub certification_eligible: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dir_calculation() {
        let engine = AJLMetricsEngine::new();
        
        // Example: Gender bias in hiring
        // Male: 80/100 hired, Female: 60/100 hired
        // DIR = 0.60 / 0.80 = 0.75 (FAIL)
        let dir = engine.calculate_dir(60, 100, 80, 100);
        assert!((dir - 0.75).abs() < 1e-10, "dir = {}", dir);
        assert!(!engine.is_compliant(dir));
    }

    #[test]
    fn test_ajl_report_generation() {
        let engine = AJLMetricsEngine::new();
        let metrics = vec![
            BiasMetric {
                group_a: DemographicGroup::Gender("Female".to_string()),
                group_b: DemographicGroup::Gender("Male".to_string()),
                dir: 0.94,
                pass_threshold: 0.8,
                compliant: true,
                sample_size: 200,
                timestamp: 0,
            },
        ];

        let report = engine.generate_report(metrics);
        assert!(report.certification_eligible);
    }
}