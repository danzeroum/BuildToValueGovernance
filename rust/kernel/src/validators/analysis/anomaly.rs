//! Anomaly Detector (StatisticalValidator)
//! Utiliza Entropy e Z-Score para detectar padrões anômalos.

use crate::evidence::finding::Finding;
use crate::core::types::{ValidatorModule, TechnicalSeverity};
use crate::validators::Validator;
use crate::statistics::{EntropyCalculator, ZScoreCalculator};

pub struct StatisticalValidator {
    entropy_calc: EntropyCalculator,
    zscore_calc: ZScoreCalculator,
}

impl StatisticalValidator {
    pub fn new() -> Self {
        Self {
            entropy_calc: EntropyCalculator::new(),
            zscore_calc: ZScoreCalculator::new(),
        }
    }

    pub fn name(&self) -> &'static str { "StatisticalValidator" }
    pub fn module(&self) -> ValidatorModule { ValidatorModule::Statistics }
}

impl Validator for StatisticalValidator {
    fn validate(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let entropy = self.entropy_calc.calculate(input);
        if entropy > 7.0 {
            findings.push(
                Finding::new(
                    ValidatorModule::Statistics,
                    TechnicalSeverity::Medium,
                    "STATISTICS_HIGH_ENTROPY",
                    "HIGH_ENTROPY_DETECTED",
                    &format!("Entropy: {:.2} bits/char", entropy),
                )
                    .with_confidence(200)
            );
        }

        let zscore = self.zscore_calc.calculate(input);
        if zscore > 3.0 {
            findings.push(
                Finding::new(
                    ValidatorModule::Statistics,
                    TechnicalSeverity::Low,
                    "STATISTICS_ABNORMAL_DIST",
                    "ABNORMAL_CHAR_DISTRIBUTION",
                    &format!("Z-Score: {:.2}", zscore),
                )
                    .with_confidence(180)
            );
        }

        findings
    }

    // bias_declaration herdado (default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_high_entropy() {
        let v = StatisticalValidator::new();
        let findings = v.validate("U2FsdGVkX1+Qx9JYzKqJ6w8vZ3nR4mL==");
        assert!(!findings.is_empty());
    }
}