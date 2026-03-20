//! NHS Number Validator v1.0.0 (ADR-035)
//! Módulo 11 checksum. Ex: "943 476 5919".
//! Filosofia (Levinas): dados de saúde → BLOCK por padrão.

use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, TechnicalSeverity, ValidatorModule};
use crate::evidence::Finding;
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref NHS_PATTERN: Regex =
        Regex::new(r"\b(\d{3})[\s\-]*(\d{3})[\s\-]*(\d{4})\b").unwrap();
}

pub struct NhsValidator;

impl NhsValidator {
    pub fn new() -> Self { Self }

    /// Módulo 11: soma ponderada 10..2, resto == 0.
    pub fn is_valid_nhs(digits: &str) -> bool {
        let d: Vec<u32> = digits
            .chars()
            .filter(|c| c.is_ascii_digit())
            .filter_map(|c| c.to_digit(10))
            .collect();
        if d.len() != 10 { return false; }
        if d.iter().all(|&v| v == 0) { return false; }
        let sum: u32 = d.iter().enumerate()
            .map(|(i, &v)| v * (10 - i as u32))
            .sum();
        sum.is_multiple_of(11)
    }
}

impl Default for NhsValidator {
    fn default() -> Self { Self::new() }
}

impl Module for NhsValidator {
    fn scan(&self, input: &str, _ctx: &mut ScanContext) -> Vec<Finding> {
        NHS_PATTERN
            .find_iter(input)
            .filter(|m| Self::is_valid_nhs(m.as_str()))
            .map(|m| {
                Finding::new(
                    ValidatorModule::NhsNumber,
                    TechnicalSeverity::Critical(255),
                    "NHS_NUMBER_DETECTED",
                    "UK_HEALTH_IDENTIFIER",
                    &format!("NHS:{}...", &m.as_str()[..3]),
                )
                .with_confidence(90)
            })
            .collect()
    }

    fn name(&self) -> &'static str { "nhs_validator" }
    fn module_id(&self) -> ValidatorModule { ValidatorModule::NhsNumber }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.12, 0.05, 20260224, 200)
            .with_limitations("Sequências de 10 dígitos sem contexto podem FP (~12%).")
            .with_affected_groups("Textos técnicos com números de 10 dígitos.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_nhs() {
        assert!(NhsValidator::is_valid_nhs("9434765919"));
        assert!(NhsValidator::is_valid_nhs("4010232137"));
    }

    #[test]
    fn test_invalid_nhs() {
        assert!(!NhsValidator::is_valid_nhs("1234567890"));
        assert!(!NhsValidator::is_valid_nhs("0000000000"));
    }

    #[test]
    fn test_scan_detects_nhs() {
        let v = NhsValidator::new();
        let mut ctx = ScanContext::default();
        let findings = v.scan("Patient NHS: 943 476 5919 admitted", &mut ctx);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_scan_clean() {
        let v = NhsValidator::new();
        let mut ctx = ScanContext::default();
        let findings = v.scan("No NHS number here at all", &mut ctx);
        assert!(findings.is_empty());
    }
}
