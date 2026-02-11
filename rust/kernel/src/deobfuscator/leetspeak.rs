//! Leetspeak Detector v2.3.2
//!
//! Detecta substituições comuns de caracteres (1337) usadas para evasão.

use std::collections::HashMap;
use lazy_static::lazy_static;
use crate::evidence::Finding;
use crate::core::types::{TechnicalSeverity, ValidatorModule, BiasDeclaration};

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

    /// Converte leetspeak para texto normal
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

        // Se > 30% dos caracteres são leetspeak e há volume suficiente
        if leet_ratio > 0.3 && leet_count > 5 {
            let _decoded = self.decode(input);

            // ✅ CORREÇÃO: Finding::new atualizado
            let finding = Finding::new(
                ValidatorModule::Deobfuscator,
                TechnicalSeverity::Medium,
                &self.rule_id,
                "LEETSPEAK_DETECTED",
                input, // matched_text (input original)
            )
                .with_confidence((leet_ratio * 255.0) as u8);

            findings.push(finding);
        }

        findings
    }

    /// ✅ IMPLEMENTAÇÃO ADR-010: Bias Declaration
    pub fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(
            0.250, // FPR: Gírias, números em contexto normal
            0.150, // FNR: Substituições complexas não mapeadas
            20260209,
            1000
        )
            .with_limitations("Substituicoes comuns vs girias legitimas")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leetspeak_detect() {
        let detector = LeetspeakDetector::new();
        let findings = detector.detect("H3ll0 W0rld 1337");
        assert_eq!(findings.len(), 1);
    }
}