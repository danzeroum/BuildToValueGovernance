//! EU VAT Validator v1.0.0 (ADR-035)
//! Formato: CC + alfanumérico. Ex: "DE123456789".
//! Checksum por país em v1.8+ (fora de escopo agora).

use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, TechnicalSeverity, ValidatorModule};
use crate::evidence::Finding;
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    // Cobre DE, FR, IT, ES, PT, NL, BE, PL, SE, AT
    static ref VAT_PATTERN: Regex = Regex::new(
        r"\b(DE\d{9}|FR\s?[0-9A-Z]{2}\s?\d{9}|IT\d{11}|ES[0-9A-Z]\d{7}[0-9A-Z]|PT\d{9}|NL\d{9}B\d{2}|BE0\d{9}|PL\d{10}|SE\d{12}|AT U\d{8})\b"
    ).unwrap();
}

pub struct VatValidator;

impl VatValidator {
    pub fn new() -> Self { Self }
}

impl Default for VatValidator {
    fn default() -> Self { Self::new() }
}

impl Module for VatValidator {
    fn scan(&self, input: &str, _ctx: &mut ScanContext) -> Vec<Finding> {
        VAT_PATTERN
            .find_iter(input)
            .map(|m| {
                let raw = m.as_str();
                let masked = format!("{}***", &raw[..2]);
                Finding::new(
                    ValidatorModule::EuVat,
                    TechnicalSeverity::High,
                    "EU_VAT_DETECTED",
                    "EU_TAX_IDENTIFIER",
                    &masked,
                )
                .with_confidence(80)
            })
            .collect()
    }

    fn name(&self) -> &'static str { "eu_vat_validator" }
    fn module_id(&self) -> ValidatorModule { ValidatorModule::EuVat }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.08, 0.10, 20260224, 150)
            .with_limitations("Sem checksum por país (v1.7). Apenas formato.")
            .with_affected_groups("Documentos fiscais EU.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_de_vat() {
        let v = VatValidator::new();
        let mut ctx = ScanContext::default();
        let f = v.scan("Company VAT: DE123456789 registered", &mut ctx);
        assert!(!f.is_empty());
    }

    #[test]
    fn test_clean() {
        let v = VatValidator::new();
        let mut ctx = ScanContext::default();
        let f = v.scan("No VAT number here", &mut ctx);
        assert!(f.is_empty());
    }
}
