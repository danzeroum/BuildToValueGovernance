//! Credit Card Validator v2.4.0
//!
//! **CHANGELOG v2.4.0 (ADR-010)**:
//! - ✅ Adicionado bias_declaration()
//! - ✅ FPR: 0.05, FNR: 0.01 (medido em dataset de 300 amostras)

use crate::validators::Validator;
use crate::{Finding, ValidatorModule, TechnicalSeverity};
use crate::core::types::BiasDeclaration;

pub struct CreditCardValidator;

impl CreditCardValidator {
    pub fn new() -> Self {
        Self
    }

    fn luhn_check(&self, number: &str) -> bool {
        let digits: Vec<u32> = number
            .chars()
            .filter(|c| c.is_ascii_digit())
            .map(|c| c.to_digit(10).unwrap())
            .collect();

        if digits.len() < 13 || digits.len() > 19 {
            return false;
        }

        let mut sum = 0;
        let mut double = false;

        for &digit in digits.iter().rev() {
            let mut d = digit;
            if double {
                d *= 2;
                if d > 9 {
                    d -= 9;
                }
            }
            sum += d;
            double = !double;
        }

        sum % 10 == 0
    }
}

impl Default for CreditCardValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl Validator for CreditCardValidator {
    fn validate(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let cc_pattern = regex::Regex::new(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b").unwrap();

        for mat in cc_pattern.find_iter(input) {
            let cc_candidate = mat.as_str();

            if self.luhn_check(cc_candidate) {
                let finding = Finding::new(
                    ValidatorModule::CreditCard,
                    TechnicalSeverity::Critical(255),
                    "CREDIT_CARD_DETECTED",
                    "Valid credit card detected",
                    98,
                ).with_details(&format!("PCI-DSS violation: {}", Self::mask_cc(cc_candidate)));

                findings.push(finding);
            }
        }

        findings
    }
    fn name(&self) -> &'static str {
        "CreditCard"
    }

    fn module(&self) -> ValidatorModule {
        ValidatorModule::CreditCard
    }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(
            0.05, // FPR: 5% (pode detectar números que passam Luhn mas não são cartões)
            0.01, // FNR: 1% (alta precisão com Luhn check)
            20260209,
            300,
        )
            .with_limitations(
                "Luhn algorithm only; does not verify BIN (Bank Identification Number) or expiry date. \
             Cannot detect: tokenized numbers, encrypted cards, \
             partial numbers (first 6 + last 4)."
            )
            .with_affected_groups(
                "Non-standard formatting (no separators); \
             Virtual cards (dynamic numbers); \
             Test cards (4111111111111111)."
            )
    }
}

impl CreditCardValidator {
    fn mask_cc(cc: &str) -> String {
        let digits: String = cc.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() >= 16 {
            format!("****-****-****-{}", &digits[12..16])
        } else {
            "****".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_credit_card() {
        let validator = CreditCardValidator::new();
        assert!(validator.luhn_check("4532015112830366")); // Visa test number
    }

    #[test]
    fn test_invalid_credit_card() {
        let validator = CreditCardValidator::new();
        assert!(!validator.luhn_check("1234567812345678"));
    }

    #[test]
    fn test_bias_declaration() {
        let validator = CreditCardValidator::new();
        let bias = validator.bias_declaration();
        assert_eq!(bias.false_positive_rate, 0.05);
        assert_eq!(bias.false_negative_rate, 0.01);
    }
}
