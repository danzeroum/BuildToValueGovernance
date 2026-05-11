//! Credit Card Validator v2.4.0
//! Detecta números de cartão de crédito com algoritmo de Luhn.

use crate::validators::Validator;
use crate::{Finding, ValidatorModule, TechnicalSeverity};
use crate::core::types::BiasDeclaration;
use lazy_static::lazy_static;

lazy_static! {
    static ref CC_PATTERN: regex::Regex =
        regex::Regex::new(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b")
            .unwrap_or_else(|e| panic!("BTV initialization failed: Invalid regex in CC_PATTERN: {e}"));
}

pub struct CreditCardValidator;

impl CreditCardValidator {
    pub fn new() -> Self {
        Self
    }

    fn luhn_check(&self, number: &str) -> bool {
        let digits: Vec<u32> = number
            .chars()
            .filter(|c| c.is_ascii_digit())
            .filter_map(|c| c.to_digit(10))
            .collect();

        if digits.len() < 13 || digits.len() > 19 {
            return false;
        }

        let mut sum = 0;
        let mut double = false;
        for &d in digits.iter().rev() {
            let mut n = d;
            if double {
                n *= 2;
                if n > 9 {
                    n -= 9;
                }
            }
            sum += n;
            double = !double;
        }
        sum % 10 == 0
    }

    fn mask_cc(cc: &str) -> String {
        let digits: String = cc.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() >= 16 {
            format!("****-****-****-{}", &digits[12..16])
        } else {
            "****".to_string()
        }
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
        for mat in CC_PATTERN.find_iter(input) {
            let candidate = mat.as_str();
            if self.luhn_check(candidate) {
                findings.push(
                    Finding::new(
                        ValidatorModule::CreditCard,
                        TechnicalSeverity::Critical(255),
                        "CREDIT_CARD_DETECTED",
                        "PCI_VIOLATION",
                        &Self::mask_cc(candidate),
                    )
                        .with_confidence(98)
                );
            }
        }
        findings
    }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.05, 0.01, 20260209, 300)
            .with_limitations(
                "Luhn algorithm only; does not verify BIN or expiry date."
            )
            .with_affected_groups(
                "Non-standard formatting; virtual cards; test cards."
            )
    }
}

use crate::core::module::{Module, ScanContext};

impl Module for CreditCardValidator {
    fn scan(&self, input: &str, _ctx: &mut ScanContext) -> Vec<Finding> {
        self.validate(input)
    }

    fn name(&self) -> &'static str {
        "CreditCard"
    }

    fn module_id(&self) -> ValidatorModule {
        ValidatorModule::CreditCard
    }

    fn bias_declaration(&self) -> BiasDeclaration {
        <Self as Validator>::bias_declaration(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_credit_card() {
        let v = CreditCardValidator::new();
        assert!(v.luhn_check("4532015112830366"));
    }

    #[test]
    fn test_invalid_credit_card() {
        let v = CreditCardValidator::new();
        assert!(!v.luhn_check("1234567812345678"));
    }

    #[test]
    fn test_bias_declaration() {
        let v = CreditCardValidator::new();
        let bias = Module::bias_declaration(&v);
        assert_eq!(bias.false_positive_rate, 0.05);
    }
}
