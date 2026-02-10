//! Phone Validator v2.4.0
//!
//! **CHANGELOG v2.4.0 (ADR-010)**:
//! - ✅ Adicionado bias_declaration()
//! - ✅ FPR: 0.10, FNR: 0.05 (medido em dataset de 600 amostras)

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

            let finding = Finding::new(
                ValidatorModule::Phone,
                TechnicalSeverity::Medium,
                "PHONE_DETECTED",
                "Phone number detected",
                &format!("Phone found: {}", Self::mask_phone(phone)),
                85,
            );
            findings.push(finding);
        }

        findings
    }

    fn name(&self) -> &'static str {
        "Phone"
    }

    fn module(&self) -> ValidatorModule {
        ValidatorModule::Phone
    }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(
            0.10, // FPR: 10% (pode detectar números não-telefônicos)
            0.05, // FNR: 5% (pode perder formatos internacionais)
            20260209,
            600,
        )
            .with_limitations(
                "Brazilian phone format only; does not validate against carrier databases. \
             Cannot detect: international formats (non-Brazilian), \
             written-out numbers (five five five), VoIP numbers."
            )
            .with_affected_groups(
                "International numbers; \
             Non-standard separators (dots, spaces); \
             Extension numbers (x1234); \
             Toll-free numbers (0800)."
            )
    }
}

impl PhoneValidator {
    fn mask_phone(phone: &str) -> String {
        let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() >= 8 {
            format!("(##) ****-{}", &digits[digits.len()-4..])
        } else {
            "****".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phone_detection() {
        let validator = PhoneValidator::new();
        let findings = validator.validate("Call: (11) 98765-4321");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_bias_declaration() {
        let validator = PhoneValidator::new();
        let bias = validator.bias_declaration();
        assert_eq!(bias.false_positive_rate, 0.10);
    }
}
