//! Phone Validator v2.4.0
//! Detecta números de telefone brasileiros.

use crate::validators::Validator;
use crate::{Finding, ValidatorModule, TechnicalSeverity};
use crate::core::types::BiasDeclaration;

pub struct PhoneValidator {
    pattern: regex::Regex,
}

impl PhoneValidator {
    pub fn new() -> Self {
        Self {
            pattern: regex::Regex::new(
                r"\b(?:\+?55\s?)?(?:\(?\d{2}\)?\s?)?\d{4,5}-?\d{4}\b"
            ).unwrap(),
        }
    }

    fn mask_phone(phone: &str) -> String {
        let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() >= 8 {
            format!("(##) ****-{}", &digits[digits.len()-4..])
        } else {
            "****".to_string()
        }
    }

    pub fn name(&self) -> &'static str { "Phone" }
    pub fn module(&self) -> ValidatorModule { ValidatorModule::Phone }
}

impl Default for PhoneValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl Validator for PhoneValidator {
    fn validate(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for mat in self.pattern.find_iter(input) {
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

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.10, 0.05, 20260209, 600)
            .with_limitations(
                "Brazilian format only; does not validate carrier."
            )
            .with_affected_groups(
                "International numbers; non-standard separators; extensions."
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phone_detection() {
        let v = PhoneValidator::new();
        let findings = v.validate("Call: (11) 98765-4321");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_bias_declaration() {
        let v = PhoneValidator::new();
        let bias = v.bias_declaration();
        assert_eq!(bias.false_positive_rate, 0.10);
    }
}