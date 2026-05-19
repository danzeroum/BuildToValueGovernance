//! IBAN Validator v1.0.0 (ADR-035)
//! Módulo 97 checksum (ISO 13616).

use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, TechnicalSeverity, ValidatorModule};
use crate::evidence::Finding;
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref IBAN_PATTERN: Regex =
        Regex::new(r"\b([A-Z]{2}\d{2}[A-Z0-9]{4,30})\b")
            .unwrap_or_else(|e| panic!("BTV initialization failed: Invalid regex in IBAN_PATTERN: {e}"));
}

pub struct IbanValidator;

impl IbanValidator {
    pub fn new() -> Self { Self }

    /// Módulo 97: move os 4 primeiros chars para o fim, converte A=10..Z=35, mod 97 == 1.
    pub fn is_valid_iban(iban: &str) -> bool {
        let clean: String = iban.chars().filter(|c| !c.is_whitespace()).collect();
        if clean.len() < 15 || clean.len() > 34 { return false; }

        let rearranged = format!("{}{}", &clean[4..], &clean[..4]);
        let numeric: String = rearranged.chars().map(|c| {
            if c.is_ascii_uppercase() {
                format!("{}", c as u32 - 'A' as u32 + 10)
            } else {
                c.to_string()
            }
        }).collect();

        // Big integer mod 97 via chunked processing
        let mut remainder = 0u64;
        for ch in numeric.chars() {
            remainder = remainder * 10 + ch.to_digit(10).unwrap_or(0) as u64;
            remainder %= 97;
        }
        remainder == 1
    }
}

impl Default for IbanValidator {
    fn default() -> Self { Self::new() }
}

impl Module for IbanValidator {
    fn scan(&self, input: &str, _ctx: &mut ScanContext) -> Vec<Finding> {
        IBAN_PATTERN
            .find_iter(input)
            .filter(|m| Self::is_valid_iban(m.as_str()))
            .map(|m| {
                let raw = m.as_str();
                let masked = format!("{}****{}", &raw[..4], &raw[raw.len()-4..]);
                Finding::new(
                    ValidatorModule::Iban,
                    TechnicalSeverity::Critical(255),
                    "IBAN_DETECTED",
                    "BANK_ACCOUNT_IDENTIFIER",
                    &masked,
                )
                .with_confidence(95)
            })
            .collect()
    }

    fn name(&self) -> &'static str { "iban_validator" }
    fn module_id(&self) -> ValidatorModule { ValidatorModule::Iban }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.02, 0.05, 20260224, 300)
                .expect("static bias values are valid")
            .with_limitations("Mod 97 elimina quase todos os FP. FNR em IBANs com espaços.")
            .with_affected_groups("Documentos bancários EU.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_iban() {
        assert!(IbanValidator::is_valid_iban("DE89370400440532013000"));
        assert!(IbanValidator::is_valid_iban("GB29NWBK60161331926819"));
    }

    #[test]
    fn test_invalid_iban() {
        assert!(!IbanValidator::is_valid_iban("DE00370400440532013000"));
        assert!(!IbanValidator::is_valid_iban("XX00000000000000"));
    }

    #[test]
    fn test_scan_detects_iban() {
        let v = IbanValidator::new();
        let mut ctx = ScanContext::default();
        let f = v.scan("Transfer to DE89370400440532013000 please", &mut ctx);
        assert!(!f.is_empty());
    }
}
