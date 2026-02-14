//! Email Validator v2.4.0
//! Detecta endereços de e-mail.

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

    fn mask_email(email: &str) -> String {
        if let Some(at) = email.find('@') {
            let local = &email[..at];
            let domain = &email[at..];
            if local.len() > 2 {
                format!("{}***{}", &local[0..1], domain)
            } else {
                format!("***{}", domain)
            }
        } else {
            "***".to_string()
        }
    }

    pub fn name(&self) -> &'static str { "Email" }
    pub fn module(&self) -> ValidatorModule { ValidatorModule::Email }
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
            findings.push(
                Finding::new(
                    ValidatorModule::Email,
                    TechnicalSeverity::Medium,
                    "EMAIL_DETECTED",
                    "PII_LEAKAGE",
                    &Self::mask_email(email),
                )
                    .with_confidence(90)
            );
        }
        findings
    }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.03, 0.08, 20260209, 800)
            .with_limitations(
                "Regex-based; does not verify DNS. May miss obfuscated emails."
            )
            .with_affected_groups(
                "New TLDs; international domains; plus-addressing."
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_detection() {
        let v = EmailValidator::new();
        let findings = v.validate("Contact: user@example.com");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_bias_declaration() {
        let v = EmailValidator::new();
        let bias = v.bias_declaration();
        assert_eq!(bias.false_positive_rate, 0.03);
    }

    #[test]
    fn test_email_masking() {
        assert_eq!(EmailValidator::mask_email("user@example.com"), "u***@example.com");
    }
}