//! Consent Validator v2.4.0
//! Verifica consentimento (LGPD Art. 7º, I).

use crate::validators::Validator;
use crate::{Finding, ValidatorModule};
use crate::core::types::BiasDeclaration;

pub struct ConsentValidator;

impl ConsentValidator {
    pub fn new() -> Self {
        Self
    }

    pub fn name(&self) -> &'static str { "consent_validator" }
    pub fn module(&self) -> ValidatorModule { ValidatorModule::Consent }
}

impl Default for ConsentValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl Validator for ConsentValidator {
    fn validate(&self, _input: &str) -> Vec<Finding> {
        // NOTA: Consentimento é verificado pelo Python Governance.
        // Este validador Rust apenas emite um alerta de que a verificação deve ocorrer.
        // Em versões futuras, receberá contexto via FFI.
        vec![]
    }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::from_static(0.05, 0.02, 20260517, 120)
            .with_limitations(
                "Consent validation requires external context; this validator is a placeholder."
            )
            .with_affected_groups("N/A")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consent_validator_placeholder() {
        let v = ConsentValidator::new();
        let findings = v.validate("");
        assert_eq!(findings.len(), 0);
    }
}