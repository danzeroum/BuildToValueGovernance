//! CPF Validator v2.4.0
//! Valida CPF brasileiro.

use crate::validators::Validator;
use crate::{Finding, ValidatorModule, TechnicalSeverity};
use crate::core::types::BiasDeclaration;

pub struct CpfValidator;

impl CpfValidator {
    pub fn new() -> Self {
        Self
    }

    fn validate_cpf(&self, cpf: &str) -> bool {
        let digits: String = cpf.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() != 11 { return false; }
        if digits.chars().all(|c| c == digits.chars().next().unwrap()) { return false; }

        let nums: Vec<u32> = digits.chars().map(|c| c.to_digit(10).unwrap()).collect();

        // Primeiro dígito verificador
        let mut sum = 0;
        for i in 0..9 {
            sum += nums[i] * (10 - i as u32);
        }
        let rem = sum % 11;
        let dv1 = if rem < 2 { 0 } else { 11 - rem };
        if dv1 != nums[9] { return false; }

        // Segundo dígito verificador
        sum = 0;
        for i in 0..10 {
            sum += nums[i] * (11 - i as u32);
        }
        let rem = sum % 11;
        let dv2 = if rem < 2 { 0 } else { 11 - rem };
        dv2 == nums[10]
    }

    fn mask_cpf(cpf: &str) -> String {
        let digits: String = cpf.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() == 11 {
            format!("{}.***.***-{}", &digits[0..3], &digits[9..11])
        } else {
            "***".to_string()
        }
    }

    // Métodos inerentes (não fazem parte do trait)
    pub fn name(&self) -> &'static str { "CPF" }
    pub fn module(&self) -> ValidatorModule { ValidatorModule::CPF }
}

impl Default for CpfValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl Validator for CpfValidator {
    fn validate(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let pattern = regex::Regex::new(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b").unwrap();

        for mat in pattern.find_iter(input) {
            let candidate = mat.as_str();
            if !self.validate_cpf(candidate) {
                findings.push(
                    Finding::new(
                        ValidatorModule::CPF,
                        TechnicalSeverity::High,
                        "CPF_INVALID",
                        "INVALID_CPF",
                        candidate,
                    )
                        .with_confidence(95)
                );
            } else {
                findings.push(
                    Finding::new(
                        ValidatorModule::CPF,
                        TechnicalSeverity::Critical(255),
                        "CPF_DETECTED",
                        "PII_LEAKAGE",
                        &Self::mask_cpf(candidate),
                    )
                        .with_position(mat.start() as u16, mat.end() as u16)
                        .with_confidence(98)
                );
            }
        }
        findings
    }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.08, 0.02, 20260209, 500)
            .with_limitations(
                "Algorithm validation only; does not check Receita Federal. Cannot detect obfuscated CPFs."
            )
            .with_affected_groups(
                "Non-standard formatting; OCR errors; international formats."
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_cpf() {
        let v = CpfValidator::new();
        assert!(v.validate_cpf("123.456.789-09"));
        assert!(v.validate_cpf("12345678909"));
    }

    #[test]
    fn test_invalid_cpf() {
        let v = CpfValidator::new();
        assert!(!v.validate_cpf("123.456.789-00"));
        assert!(!v.validate_cpf("111.111.111-11"));
    }

    #[test]
    fn test_bias_declaration() {
        let v = CpfValidator::new();
        let bias = v.bias_declaration();
        assert_eq!(bias.false_positive_rate, 0.08);
        assert_eq!(bias.calibration_date, 20260209);
    }

    #[test]
    fn test_cpf_masking() {
        assert_eq!(CpfValidator::mask_cpf("123.456.789-09"), "123.***.***-09");
    }
}