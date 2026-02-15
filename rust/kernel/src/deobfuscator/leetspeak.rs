//! Leetspeak Detector

use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, ValidatorModule, TechnicalSeverity};
use crate::evidence::Finding;
use std::collections::HashMap;
use lazy_static::lazy_static;

lazy_static! {
    static ref LEET_MAP: HashMap<char, char> = {
        let mut m = HashMap::new();
        m.insert('0', 'o');
        m.insert('1', 'i');
        m.insert('3', 'e');
        m.insert('4', 'a');
        m.insert('5', 's');
        m.insert('7', 't');
        m.insert('8', 'b');
        m.insert('9', 'g');
        m.insert('@', 'a');
        m.insert('$', 's');
        m
    };
}

pub struct LeetspeakDetector {
    rule_id: String,
}

impl LeetspeakDetector {
    pub fn new() -> Self {
        Self {
            rule_id: "DEOBFUSCATOR_LEET_001".to_string(),
        }
    }

    pub fn decode(&self, input: &str) -> String {
        input.chars()
            .map(|c| LEET_MAP.get(&c).copied().unwrap_or(c))
            .collect()
    }

    pub fn detect(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let leet_count = input.chars()
            .filter(|c| LEET_MAP.contains_key(c))
            .count();

        let total_chars = input.chars().count();

        if total_chars == 0 {
            return findings;
        }

        let leet_ratio = leet_count as f32 / total_chars as f32;

        if leet_ratio > 0.3 && leet_count > 5 {
            let finding = Finding::new(
                ValidatorModule::Deobfuscator,
                TechnicalSeverity::Medium,
                &self.rule_id,
                "LEETSPEAK_DETECTED",
                input,
            )
                .with_confidence((leet_ratio * 255.0) as u8);

            findings.push(finding);
        }

        findings
    }
}

impl Module for LeetspeakDetector {
    fn scan(&self, input: &str, _ctx: &mut ScanContext) -> Vec<Finding> {
        self.detect(input)
    }

    fn name(&self) -> &'static str { "leetspeak" }

    fn module_id(&self) -> ValidatorModule { ValidatorModule::Deobfuscator }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.15, 0.30, 20260209, 250)
            .with_limitations("Variantes regionais de leetspeak não cobertas.")
            .with_affected_groups("N/A")
    }
}