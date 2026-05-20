//! Session Drift v1.7.0 — Cosine similarity behavioral drift (ADR-014)

use crate::core::types::BiasDeclaration;

// ---------------------------------------------------------------------
// SESSION VECTOR (behavioral fingerprint)
// ---------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct SessionVector {
    pub avg_input_len: f32,
    pub avg_entropy: f32,
    pub finding_rate: f32,
    pub critical_rate: f32,
    pub pii_rate: f32,
    pub request_frequency: f32, // requests per minute
}

impl SessionVector {
    pub fn zero() -> Self {
        Self {
            avg_input_len: 0.0,
            avg_entropy: 0.0,
            finding_rate: 0.0,
            critical_rate: 0.0,
            pii_rate: 0.0,
            request_frequency: 0.0,
        }
    }

    fn as_slice(&self) -> [f32; 6] {
        [
            self.avg_input_len,
            self.avg_entropy,
            self.finding_rate,
            self.critical_rate,
            self.pii_rate,
            self.request_frequency,
        ]
    }
}

// ---------------------------------------------------------------------
// DRIFT LEVEL
// ---------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

// ---------------------------------------------------------------------
// DRIFT RESULT
// ---------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct DriftResult {
    pub similarity: f32,
    pub drift: f32,
    pub level: DriftLevel,
    pub identity_challenge: bool,
}

// ---------------------------------------------------------------------
// SESSION DRIFT
// ---------------------------------------------------------------------
pub struct SessionDrift {
    low_threshold: f32,
    medium_threshold: f32,
    high_threshold: f32,
    critical_threshold: f32,
}

impl SessionDrift {
    pub fn new() -> Self {
        Self {
            low_threshold: 0.85,
            medium_threshold: 0.70,
            high_threshold: 0.50,
            critical_threshold: 0.30,
        }
    }

    pub fn with_thresholds(low: f32, medium: f32, high: f32, critical: f32) -> Self {
        Self {
            low_threshold: low,
            medium_threshold: medium,
            high_threshold: high,
            critical_threshold: critical,
        }
    }

    /// Compare current session vector against historical baseline.
    pub fn compare(&self, baseline: &SessionVector, current: &SessionVector) -> DriftResult {
        let similarity = Self::cosine_similarity(
            &baseline.as_slice(),
            &current.as_slice(),
        );

        let drift = 1.0 - similarity;

        let level = if similarity >= self.low_threshold {
            DriftLevel::None
        } else if similarity >= self.medium_threshold {
            DriftLevel::Low
        } else if similarity >= self.high_threshold {
            DriftLevel::Medium
        } else if similarity >= self.critical_threshold {
            DriftLevel::High
        } else {
            DriftLevel::Critical
        };

        let identity_challenge = matches!(level, DriftLevel::High | DriftLevel::Critical);

        DriftResult { similarity, drift, level, identity_challenge }
    }

    fn cosine_similarity(a: &[f32; 6], b: &[f32; 6]) -> f32 {
        let mut dot = 0.0f32;
        let mut mag_a = 0.0f32;
        let mut mag_b = 0.0f32;

        for i in 0..6 {
            dot += a[i] * b[i];
            mag_a += a[i] * a[i];
            mag_b += b[i] * b[i];
        }

        let denom = mag_a.sqrt() * mag_b.sqrt();
        if denom < f32::EPSILON {
            return 0.0; // fail-secure: zero vectors = no similarity
        }

        (dot / denom).clamp(0.0, 1.0)
    }

    pub fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.08, 0.12, 20260517, 200)
            .with_limitations(
                "6-dimensional vector. Cold-start problem: first requests have no baseline."
            )
            .with_affected_groups(
                "Users with variable usage patterns may trigger false drift."
            )
    }
}

impl Default for SessionDrift {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identical_vectors_no_drift() {
        let sd = SessionDrift::new();
        let v = SessionVector {
            avg_input_len: 50.0, avg_entropy: 3.5, finding_rate: 0.1,
            critical_rate: 0.01, pii_rate: 0.05, request_frequency: 2.0,
        };
        let r = sd.compare(&v, &v);
        assert!(r.similarity > 0.99);
        assert_eq!(r.level, DriftLevel::None);
        assert!(!r.identity_challenge);
    }

    #[test]
    fn test_completely_different_vectors() {
        let sd = SessionDrift::new();
        let baseline = SessionVector {
            avg_input_len: 50.0, avg_entropy: 3.5, finding_rate: 0.1,
            critical_rate: 0.0, pii_rate: 0.0, request_frequency: 1.0,
        };
        let current = SessionVector {
            avg_input_len: 0.0, avg_entropy: 0.0, finding_rate: 0.9,
            critical_rate: 0.8, pii_rate: 0.9, request_frequency: 0.0,
        };
        let r = sd.compare(&baseline, &current);
        assert!(r.similarity < 0.85, "Similarity was {}", r.similarity);
    }

    #[test]
    fn test_high_drift_triggers_challenge() {
        let sd = SessionDrift::new();
        let baseline = SessionVector {
            avg_input_len: 30.0, avg_entropy: 2.0, finding_rate: 0.0,
            critical_rate: 0.0, pii_rate: 0.0, request_frequency: 0.5,
        };
        let current = SessionVector {
            avg_input_len: 0.0, avg_entropy: 0.0, finding_rate: 1.0,
            critical_rate: 1.0, pii_rate: 1.0, request_frequency: 0.0,
        };
        let r = sd.compare(&baseline, &current);
        assert!(r.identity_challenge, "Sim={}, should trigger challenge", r.similarity);
    }
    #[test]
    fn test_zero_baseline_failsecure() {
        let sd = SessionDrift::new();
        let r = sd.compare(&SessionVector::zero(), &SessionVector::zero());
        assert_eq!(r.similarity, 0.0);
        // Zero vectors → no similarity → fail-secure
    }

    #[test]
    fn test_slight_drift_is_low() {
        let sd = SessionDrift::new();
        let baseline = SessionVector {
            avg_input_len: 50.0, avg_entropy: 3.5, finding_rate: 0.1,
            critical_rate: 0.01, pii_rate: 0.05, request_frequency: 2.0,
        };
        let current = SessionVector {
            avg_input_len: 55.0, avg_entropy: 3.7, finding_rate: 0.12,
            critical_rate: 0.01, pii_rate: 0.06, request_frequency: 2.5,
        };
        let r = sd.compare(&baseline, &current);
        assert!(r.similarity > 0.95);
        assert_eq!(r.level, DriftLevel::None);
    }

    #[test]
    fn test_custom_thresholds() {
        let sd = SessionDrift::with_thresholds(0.95, 0.90, 0.80, 0.60);
        let baseline = SessionVector {
            avg_input_len: 50.0, avg_entropy: 3.5, finding_rate: 0.1,
            critical_rate: 0.01, pii_rate: 0.05, request_frequency: 2.0,
        };
        let current = SessionVector {
            avg_input_len: 60.0, avg_entropy: 4.0, finding_rate: 0.15,
            critical_rate: 0.02, pii_rate: 0.08, request_frequency: 3.0,
        };
        let r = sd.compare(&baseline, &current);
        // With stricter thresholds, same drift may be classified higher
        assert!(r.similarity < 1.0);
    }
}