//! Hex Decoder v2.3.2
//!
//! Detecta strings hexadecimais que podem esconder payloads.

use regex::Regex;
use lazy_static::lazy_static;
use crate::evidence::Finding;
use crate::core::types::{TechnicalSeverity, ValidatorModule, BiasDeclaration};

lazy_static! {
    // Detecta strings hexadecimais longas (0x... ou apenas hex)
    static ref HEX_REGEX: Regex = Regex::new(
        r"(?:0x)?[0-9a-fA-F]{16,}"
    ).unwrap();
}

pub struct HexDecoder {
    rule_id: String,
}

impl HexDecoder {
    pub fn new() -> Self {
        Self {
            rule_id: "DEOBFUSCATOR_HEX_001".to_string(),
        }
    }

    pub fn detect(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for mat in HEX_REGEX.find_iter(input) {
            let matched = mat.as_str();
            let cleaned = matched.trim_start_matches("0x");

            // Tenta decodificar hex para bytes
            if let Ok(_decoded) = hex::decode(cleaned) {
                // ✅ CORREÇÃO: Finding::new atualizado
                let finding = Finding::new(
                    ValidatorModule::Deobfuscator,
                    TechnicalSeverity::Medium,
                    &self.rule_id,
                    "HEX_ENCODING_DETECTED",
                    matched,
                )
                    .with_position(mat.start() as u16, mat.end() as u16)
                    .with_confidence(180);

                findings.push(finding);
            }
        }

        findings
    }

    /// ✅ IMPLEMENTAÇÃO ADR-010: Bias Declaration
    pub fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(
            0.200, // FPR: Hashes, chaves, UUIDs legítimos
            0.050, // FNR: Hex com formatação não padrão
            20260209,
            1000
        )
            .with_limitations("Ambiguidade com hashes e chaves de API")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_detection() {
        let decoder = HexDecoder::new();
        let findings = decoder.detect("48656c6c6f576f726c64"); // "HelloWorld"
        assert_eq!(findings.len(), 1);
    }
}