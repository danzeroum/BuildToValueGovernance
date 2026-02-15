//! Base64 Detector

use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, ValidatorModule, TechnicalSeverity};
use crate::evidence::Finding;
use base64::{Engine as _, engine::general_purpose};
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    static ref BASE64_REGEX: Regex = Regex::new(
        r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
    ).unwrap();
}

pub struct Base64Detector {
    rule_id: String,
}

impl Base64Detector {
    pub fn new() -> Self {
        Self {
            rule_id: "DEOBFUSCATOR_BASE64_001".to_string(),
        }
    }

    pub fn detect(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for mat in BASE64_REGEX.find_iter(input) {
            let matched = mat.as_str();
            if matched.len() < 16 {
                continue;
            }

            if let Ok(decoded) = general_purpose::STANDARD.decode(matched) {
                let is_text = std::str::from_utf8(&decoded).is_ok();
                let has_suspicious = if is_text {
                    // heurística simples
                    let text = String::from_utf8_lossy(&decoded);
                    text.chars().filter(|c| c.is_numeric()).count() >= 11
                        && (text.contains('.') || text.contains('-'))
                } else {
                    false
                };

                let severity = if has_suspicious {
                    TechnicalSeverity::High
                } else {
                    TechnicalSeverity::Medium
                };

                let finding = Finding::new(
                    ValidatorModule::Deobfuscator,
                    severity,
                    &self.rule_id,
                    "BASE64_ENCODING_DETECTED",
                    &format!("Base64 content ({})", if is_text { "text" } else { "binary" }),
                )
                    .with_matched_text(matched)
                    .with_position(mat.start() as u16, mat.end() as u16)
                    .with_confidence(200);

                findings.push(finding);
            }
        }

        findings
    }
}

impl Module for Base64Detector {
    fn scan(&self, input: &str, _ctx: &mut ScanContext) -> Vec<Finding> {
        self.detect(input)
    }

    fn name(&self) -> &'static str { "base64" }

    fn module_id(&self) -> ValidatorModule { ValidatorModule::Deobfuscator }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.03, 0.25, 20260209, 300)
            .with_limitations("Strings curtas (<16 chars) podem ser falsos positivos.")
            .with_affected_groups("N/A")
    }
}