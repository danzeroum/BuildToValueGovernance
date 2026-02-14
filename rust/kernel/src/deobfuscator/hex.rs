//! Hex Decoder v2.3.2
//! Detecta strings hexadecimais.

use regex::Regex;
use lazy_static::lazy_static;
use crate::evidence::Finding;
use crate::core::types::{TechnicalSeverity, ValidatorModule, BiasDeclaration};

lazy_static! {
    static ref HEX_REGEX: Regex = Regex::new(r"(?:0x)?[0-9a-fA-F]{16,}").unwrap();
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
            if hex::decode(cleaned).is_ok() {
                findings.push(
                    Finding::new(
                        ValidatorModule::Deobfuscator,
                        TechnicalSeverity::Medium,
                        &self.rule_id,
                        "HEX_ENCODING_DETECTED",
                        matched,
                    )
                        .with_position(mat.start() as u16, mat.end() as u16)
                        .with_confidence(180)
                );
            }
        }
        findings
    }

    pub fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.200, 0.050, 20260209, 1000)
            .with_limitations("Ambiguity with hashes and API keys")
    }
}