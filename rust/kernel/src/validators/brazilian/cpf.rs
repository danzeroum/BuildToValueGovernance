//! CPF Validator v2.4.0

use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, ValidatorModule, TechnicalSeverity};
use crate::evidence::Finding;
use crate::validators::Validator;
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref CPF_PATTERN: Regex = Regex::new(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")
        .unwrap_or_else(|e| panic!("BTV initialization failed: Invalid regex in CPF_PATTERN: {e}"));
}

pub struct CpfValidator;

impl CpfValidator {
    pub fn new() -> Self {
        Self
    }

    fn validate_cpf(&self, cpf: &str) -> bool {
        let digits: String = cpf.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() != 11 { return false; }
        let first = match digits.chars().next() {
            Some(c) => c,
            None => return false,
        };
        if digits.chars().all(|c| c == first) { return false; }

        let nums: Vec<u32> = digits
            .chars()
            .filter_map(|c| c.to_digit(10))
            .collect();
        if nums.len() != 11 { return false; }

        // Primeiro dígito verificador
        let mut sum = 0;
        #[allow(clippy::needless_range_loop)]
        for i in 0..9 {
            sum += nums[i] * (10 - i as u32);
        }
        let rem = sum % 11;
        let dv1 = if rem < 2 { 0 } else { 11 - rem };
        if dv1 != nums[9] { return false; }

        // Segundo dígito verificador
        sum = 0;
        #[allow(clippy::needless_range_loop)]
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

    fn validate_impl(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for mat in CPF_PATTERN.find_iter(input) {
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
}

impl Default for CpfValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl Validator for CpfValidator {
    fn validate(&self, input: &str) -> Vec<Finding> {
        self.validate_impl(input)
    }
}

impl Module for CpfValidator {
    fn scan(&self, input: &str, _ctx: &mut ScanContext) -> Vec<Finding> {
        self.validate_impl(input)
    }

    fn name(&self) -> &'static str { "cpf" }

    fn module_id(&self) -> ValidatorModule { ValidatorModule::CPF }

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
