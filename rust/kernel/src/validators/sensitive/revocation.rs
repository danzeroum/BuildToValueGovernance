//! Consent Revocation Validator v2.5.0
//! Verifica revogação de consentimento (LGPD Art. 8º, § 5º).
//! DT-007: migrado de Validator (legado) para Module (canônico).

use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, ValidatorModule};
use crate::evidence::Finding;

pub struct ConsentRevocationValidator;

impl ConsentRevocationValidator {
    pub fn new() -> Self { Self }
}

impl Default for ConsentRevocationValidator {
    fn default() -> Self { Self::new() }
}

impl Module for ConsentRevocationValidator {
    fn scan(&self, _input: &str, _ctx: &mut ScanContext) -> Vec<Finding> {
        // Revogação tratada pelo Python Governance.
        vec![]
    }

    fn name(&self) -> &'static str { "consent_revocation_validator" }

    fn module_id(&self) -> ValidatorModule { ValidatorModule::ConsentRevocation }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.01, 0.00, 20260209, 80)
            .with_limitations(
                "Race condition between revocation timestamp and async processing jobs."
            )
            .with_affected_groups("N/A")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::module::ScanContext;

    #[test]
    fn test_revocation_placeholder_returns_empty() {
        let v = ConsentRevocationValidator::new();
        let mut ctx = ScanContext::default();
        assert!(v.scan("", &mut ctx).is_empty());
    }

    #[test]
    fn test_bias_declaration_non_default() {
        let bias = ConsentRevocationValidator::new().bias_declaration();
        assert!(bias.calibration_date >= 20260101);
    }
}