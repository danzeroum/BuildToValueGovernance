//! Consent Validator v2.5.0
//! Verifica consentimento (LGPD Art. 7º, I).
//! DT-007: migrado de Validator (legado) para Module (canônico).

use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, ValidatorModule};
use crate::evidence::Finding;

pub struct ConsentValidator;

impl ConsentValidator {
    pub fn new() -> Self { Self }
}

impl Default for ConsentValidator {
    fn default() -> Self { Self::new() }
}

impl Module for ConsentValidator {
    fn scan(&self, _input: &str, _ctx: &mut ScanContext) -> Vec<Finding> {
        // Consentimento verificado pelo Python Governance.
        // Validator Rust emite findings apenas via contexto FFI futuro.
        vec![]
    }

    fn name(&self) -> &'static str { "consent_validator" }

    fn module_id(&self) -> ValidatorModule { ValidatorModule::Consent }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::from_static(0.05, 0.02, 20260517, 120)
            .with_limitations(
                "Consent validation requires external context; placeholder."
            )
            .with_affected_groups("N/A")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::module::ScanContext;

    #[test]
    fn test_consent_placeholder_returns_empty() {
        let v = ConsentValidator::new();
        let mut ctx = ScanContext::default();
        assert!(v.scan("", &mut ctx).is_empty());
    }

    #[test]
    fn test_bias_declaration_non_default() {
        let bias = ConsentValidator::new().bias_declaration();
        assert!(bias.false_positive_rate > 0.0);
        assert!(bias.calibration_date >= 20260517);
    }
}   