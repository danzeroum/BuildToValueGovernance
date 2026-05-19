//! Phone Validator v2.4.0

use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, ValidatorModule, TechnicalSeverity};
use crate::evidence::Finding;
use crate::validators::Validator;
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref PHONE_PATTERN: Regex = Regex::new(
        r"\b(?:\+?55\s?)?(?:\(?\d{2}\)?\s?)?\d{4,5}-?\d{4}\b"
    ).unwrap_or_else(|e| panic!("BTV initialization failed: Invalid regex in PHONE_PATTERN: {e}"));
}

pub struct PhoneValidator;

impl PhoneValidator {
    pub fn new() -> Self {
        Self
    }

    fn mask_phone(phone: &str) -> String {
        let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() >= 8 {
            format!("(##) ****-{}", &digits[digits.len()-4..])
        } else {
            "****".to_string()
        }
    }

    fn validate_impl(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for mat in PHONE_PATTERN.find_iter(input) {
            let phone = mat.as_str();
            findings.push(
                Finding::new(
                    ValidatorModule::Phone,
                    TechnicalSeverity::Medium,
                    "PHONE_DETECTED",
                    "PII_LEAKAGE",
                    &Self::mask_phone(phone),
                )
                    .with_confidence(85)
            );
        }
        findings
    }
}

impl Default for PhoneValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl Validator for PhoneValidator {
    fn validate(&self, input: &str) -> Vec<Finding> {
        self.validate_impl(input)
    }
}

impl Module for PhoneValidator {
    fn scan(&self, input: &str, _ctx: &mut ScanContext) -> Vec<Finding> {
        self.validate_impl(input)
    }

    fn name(&self) -> &'static str { "phone" }

    fn module_id(&self) -> ValidatorModule { ValidatorModule::Phone }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.10, 0.05, 20260517, 600)
                .expect("static bias values are valid")
            .with_limitations(
                "Brazilian format only; does not validate carrier."
            )
            .with_affected_groups(
                "International numbers; non-standard separators; extensions."
            )
    }
}
