//! Email Validator v2.4.0

use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, ValidatorModule, TechnicalSeverity};
use crate::evidence::Finding;
use crate::validators::Validator;
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref EMAIL_PATTERN: Regex = Regex::new(
        r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"
    ).unwrap_or_else(|e| panic!("BTV initialization failed: Invalid regex in EMAIL_PATTERN: {e}"));
}

pub struct EmailValidator;

impl EmailValidator {
    pub fn new() -> Self {
        Self
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

    fn validate_impl(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for mat in EMAIL_PATTERN.find_iter(input) {
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
}

impl Default for EmailValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl Validator for EmailValidator {
    fn validate(&self, input: &str) -> Vec<Finding> {
        self.validate_impl(input)
    }
}

impl Module for EmailValidator {
    fn scan(&self, input: &str, _ctx: &mut ScanContext) -> Vec<Finding> {
        self.validate_impl(input)
    }

    fn name(&self) -> &'static str { "email" }

    fn module_id(&self) -> ValidatorModule { ValidatorModule::Email }

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
