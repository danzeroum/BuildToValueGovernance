//! Entropy Calculator

use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, ValidatorModule, TechnicalSeverity, InputStatistics};
use crate::evidence::Finding;
use std::collections::HashMap;
impl Default for EntropyCalculator {
    fn default() -> Self { Self::new() }
}
pub struct EntropyCalculator {
    rule_id_high: String,
    rule_id_low: String,
}

impl EntropyCalculator {
    pub fn new() -> Self {
        Self {
            rule_id_high: "STATISTICS_ENTROPY_HIGH".to_string(),
            rule_id_low: "STATISTICS_ENTROPY_LOW".to_string(),
        }
    }

    pub fn calculate(&self, input: &str) -> f32 {
        if input.is_empty() {
            return 0.0;
        }

        let mut freq_map: HashMap<char, usize> = HashMap::new();
        for ch in input.chars() {
            *freq_map.entry(ch).or_insert(0) += 1;
        }

        let total = input.chars().count() as f32;
        let mut entropy = 0.0;

        for &count in freq_map.values() {
            let probability = count as f32 / total;
            entropy -= probability * probability.log2();
        }

        entropy
    }

    pub fn validate(&self, input: &str, stats: &mut InputStatistics) -> Vec<Finding> {
        let entropy = self.calculate(input);
        stats.entropy = entropy;
        let mut findings = Vec::new();

        if entropy >= 6.0 {
            findings.push(
                Finding::new(
                    ValidatorModule::Entropy,
                    TechnicalSeverity::Medium,
                    &self.rule_id_high,
                    "HIGH_ENTROPY_DETECTED",
                    &format!("Abnormally high entropy: {:.2} bits/char", entropy),
                )
                    .with_confidence(200)
            );
        } else if entropy < 2.0 && input.len() > 50 {
            findings.push(
                Finding::new(
                    ValidatorModule::Entropy,
                    TechnicalSeverity::Low,
                    &self.rule_id_low,
                    "LOW_ENTROPY_DETECTED",
                    &format!("Abnormally low entropy: {:.2} bits/char", entropy),
                )
                    .with_confidence(180)
            );
        }

        findings
    }
}

impl Module for EntropyCalculator {
    fn scan(&self, input: &str, ctx: &mut ScanContext) -> Vec<Finding> {
        self.validate(input, &mut ctx.stats)
    }

    fn name(&self) -> &'static str { "entropy" }

    fn module_id(&self) -> ValidatorModule { ValidatorModule::Entropy }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.13, 0.20, 20260209, 500)
            .with_limitations("Textos curtos (<50 chars) podem ter alta entropia.")
            .with_affected_groups("N/A")
    }
}