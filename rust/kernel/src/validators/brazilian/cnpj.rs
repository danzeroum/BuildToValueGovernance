//! CNPJ Validator v2.4.0
//! Valida CNPJ brasileiro.

use crate::validators::Validator;
use crate::{Finding, ValidatorModule, TechnicalSeverity};
use crate::core::types::BiasDeclaration;

pub struct CnpjValidator;

impl CnpjValidator {
    pub fn new() -> Self {
        Self
    }

    fn validate_cnpj(&self, cnpj: &str) -> bool {
        let digits: String = cnpj.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() != 14 { return false; }
        if digits.chars().all(|c| c == digits.chars().next().unwrap()) { return false; }

        let nums: Vec<u32> = digits.chars().map(|c| c.to_digit(10).unwrap()).collect();

        // Primeiro dígito
        let w1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
        let sum1: u32 = w1.iter().enumerate().map(|(i, &w)| nums[i] * w).sum();
        let rem1 = sum1 % 11;
        let dv1 = if rem1 < 2 { 0 } else { 11 - rem1 };
        if dv1 != nums[12] { return false; }

        // Segundo dígito
        let w2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
        let sum2: u32 = w2.iter().enumerate().map(|(i, &w)| nums[i] * w).sum();
        let rem2 = sum2 % 11;
        let dv2 = if rem2 < 2 { 0 } else { 11 - rem2 };
        dv2 == nums[13]
    }

    fn mask_cnpj(cnpj: &str) -> String {
        let digits: String = cnpj.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() == 14 {
            format!("{}.***.***/****-{}", &digits[0..2], &digits[12..14])
        } else {
            "***".to_string()
        }
    }

    pub fn name(&self) -> &'static str { "CNPJ" }
    pub fn module(&self) -> ValidatorModule { ValidatorModule::CNPJ }
}

impl Default for CnpjValidator {
    fn default() -> Self {
        Self::new()
    }
}


impl Validator for CnpjValidator {
    fn validate(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let pattern = regex::Regex::new(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b").unwrap();

        for mat in pattern.find_iter(input) {
            let candidate = mat.as_str();
            if !self.validate_cnpj(candidate) {
                findings.push(
                    Finding::new(
                        ValidatorModule::CNPJ,
                        TechnicalSeverity::High,
                        "CNPJ_INVALID",
                        "INVALID_CNPJ",
                        candidate,
                    )
                        .with_confidence(93)
                );
            } else {
                findings.push(
                    Finding::new(
                        ValidatorModule::CNPJ,
                        TechnicalSeverity::Critical(255),
                        "CNPJ_DETECTED",
                        "PII_LEAKAGE",
                        &Self::mask_cnpj(candidate),
                    )
                        .with_position(mat.start() as u16, mat.end() as u16)
                        .with_confidence(97)
                );
            }
        }
        findings
    }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.06, 0.03, 20260209, 400)
            .with_limitations(
                "Algorithm validation only; does not check Receita Federal. Cannot detect formatting variations."
            )
            .with_affected_groups(
                "Non-standard formatting; OCR errors; missing branch code."
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_cnpj() {
        let v = CnpjValidator::new();
        assert!(v.validate_cnpj("11.222.333/0001-81"));
    }

    #[test]
    fn test_invalid_cnpj() {
        let v = CnpjValidator::new();
        assert!(!v.validate_cnpj("11.222.333/0001-00"));
    }

    #[test]
    fn test_bias_declaration() {
        let v = CnpjValidator::new();
        let bias = v.bias_declaration();
        assert_eq!(bias.false_positive_rate, 0.06);
    }

    #[test]
    fn test_cnpj_masking() {
        assert_eq!(CnpjValidator::mask_cnpj("11.222.333/0001-81"), "11.***.***/****-81");
    }
}