//! Hex Decoder

use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, ValidatorModule, TechnicalSeverity};
use crate::evidence::Finding;
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    static ref HEX_REGEX: Regex = Regex::new(r"(?:0x)?[0-9a-fA-F]{16,}").unwrap();
}

impl Default for HexDecoder {
    fn default() -> Self { Self::new() }
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
}

impl Module for HexDecoder {
    fn scan(&self, input: &str, _ctx: &mut ScanContext) -> Vec<Finding> {
        self.detect(input)
    }

    fn name(&self) -> &'static str { "hex" }

    fn module_id(&self) -> ValidatorModule { ValidatorModule::Deobfuscator }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.02, 0.20, 20260209, 200)
            .with_limitations("UUIDs sem prefixo 0x podem não ser detectados.")
            .with_affected_groups("N/A")
    }
}