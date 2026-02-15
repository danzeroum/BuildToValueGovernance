//! Z‑Score Calculator

use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, ValidatorModule, TechnicalSeverity, InputStatistics};
use crate::evidence::Finding;
use std::collections::HashMap;

pub struct ZScoreCalculator {
    rule_id: String,
}

impl ZScoreCalculator {
    pub fn new() -> Self {
        Self {
            rule_id: "STATISTICS_ZSCORE_001".to_string(),
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
        let frequencies: Vec<f32> = freq_map.values()
            .map(|&count| count as f32 / total)
            .collect();

        let mean = frequencies.iter().sum::<f32>() / frequencies.len() as f32;

        let variance = frequencies.iter()
            .map(|&f| (f - mean).powi(2))
            .sum::<f32>() / frequencies.len() as f32;
        let std_dev = variance.sqrt();

        let max_freq = frequencies.iter()
            .copied()
            .max_by(|a, b| a.partial_cmp(b).unwrap())
            .unwrap_or(0.0);

        if std_dev == 0.0 {
            return 10.0;
        }

        (max_freq - mean) / std_dev
    }

    pub fn validate(&self, input: &str, stats: &mut InputStatistics) -> Vec<Finding> {
        let zscore = self.calculate(input);
        stats.z_score = zscore;
        let mut findings = Vec::new();

        if zscore > 3.0 {
            findings.push(
                Finding::new(
                    ValidatorModule::ZScore,
                    TechnicalSeverity::Low,
                    &self.rule_id,
                    "ABNORMAL_CHAR_DISTRIBUTION",
                    &format!("Z-Score: {:.2} (expected: -2.0 to +2.0)", zscore),
                )
                    .with_confidence(180)
            );
        }

        findings
    }
}

impl Module for ZScoreCalculator {
    fn scan(&self, input: &str, ctx: &mut ScanContext) -> Vec<Finding> {
        self.validate(input, &mut ctx.stats)
    }

    fn name(&self) -> &'static str { "zscore" }

    fn module_id(&self) -> ValidatorModule { ValidatorModule::ZScore }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.10, 0.18, 20260209, 400)
            .with_limitations("Assume distribuição normal; textos com repetições geram Z‑score alto.")
            .with_affected_groups("N/A")
    }
}