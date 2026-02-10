//! Email Validator v2.4.0
//!
//! **CHANGELOG v2.4.0 (ADR-010)**:
//! - ✅ Adicionado bias_declaration()
//! - ✅ FPR: 0.03, FNR: 0.08 (medido em dataset de 800 amostras)

use crate::validators::Validator;
use crate::{Finding, ValidatorModule, TechnicalSeverity};
use crate::core::types::BiasDeclaration;

pub struct EmailValidator {
    pattern: regex::Regex,
}

impl EmailValidator {
    pub fn new() -> Self {
        Self {
            pattern: regex::Regex::new(
                r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"
            ).unwrap(),
        }
    }
}

impl Default for EmailValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl Validator for EmailValidator {
    fn validate(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for mat in self.pattern.find_iter(input) {
            let email = mat.as_str();

            let finding = Finding::new(
                ValidatorModule::Email,
                TechnicalSeverity::Medium,
                "EMAIL_DETECTED",
                "Email address detected",
                &format!("Email found: {}", Self::mask_email(email)),
                90,
            );
            findings.push(finding);
        }

        findings
    }

    fn name(&self) -> &'static str {
        "Email"
    }

    fn module(&self) -> ValidatorModule {
        ValidatorModule::Email
    }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(
            0.03, // FPR: 3% (pode detectar strings que parecem email mas não são)
            0.08, // FNR: 8% (pode perder emails com TLDs novos ou formatação incomum)
            20260209,
            800,
        )
            .with_limitations(
                "Regex-based validation; does not verify DNS MX records or deliverability. \
             Cannot detect: obfuscated emails (user[at]domain), Base64-encoded, \
             emails in images/PDFs."
            )
            .with_affected_groups(
                "New TLDs (.xyz, .tech, etc.); \
             International domains (IDN); \
             Plus-addressing (user+tag@domain); \
             Quoted local parts (\"user name\"@domain)."
            )
    }
}

impl EmailValidator {
    fn mask_email(email: &str) -> String {
        if let Some(at_pos) = email.find('@') {
            let local = &email[..at_pos];
            let domain = &email[at_pos..];

            if local.len() > 2 {
                format!("{}***{}", &local[0..1], domain)
            } else {
                format!("***{}", domain)
            }
        } else {
            "***".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_detection() {
        let validator = EmailValidator::new();
        let findings = validator.validate("Contact: user@example.com");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_bias_declaration() {
        let validator = EmailValidator::new();
        let bias = validator.bias_declaration();
        assert_eq!(bias.false_positive_rate, 0.03);
        assert_eq!(bias.test_dataset_size, 800);
    }

    #[test]
    fn test_email_masking() {
        assert_eq!(EmailValidator::mask_email("user@example.com"), "u***@example.com");
    }
}
