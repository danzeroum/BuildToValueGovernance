//! Pattern Validators (Email, URL, IP)

use super::{Validator, ValidationResult};

pub struct EmailValidator;

impl Validator for EmailValidator {
    fn validate(&self, input: &str, name: &str) -> Option<ValidationResult> {
        if input.contains('@') && input.contains('.') {
            return Some(ValidationResult {
                validator_name: name.to_string(),
                is_violation: true,
                message: "Email pattern detected".to_string(),
                category: "pii".to_string(),
                location: "input".to_string(),
                evidence: "contains @ and .".to_string(),
                severity: 0.5,
                confidence: 0.7,
            });
        }
        None
    }
}

pub struct UrlValidator;

impl Validator for UrlValidator {
    fn validate(&self, input: &str, name: &str) -> Option<ValidationResult> {
        if input.contains("http://") || input.contains("https://") {
            return Some(ValidationResult {
                validator_name: name.to_string(),
                is_violation: true,
                message: "URL detected".to_string(),
                category: "network".to_string(),
                location: "input".to_string(),
                evidence: "contains http(s)://".to_string(),
                severity: 0.3,
                confidence: 0.9,
            });
        }
        None
    }
}
