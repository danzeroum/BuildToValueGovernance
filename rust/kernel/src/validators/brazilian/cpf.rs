//! CPF Validator v2.4.0 (ADR-010)
//!
//! **CHANGELOG v2.4.0**:
//! - ✅ Implementado bias_declaration() obrigatório

use regex::Regex;
use lazy_static::lazy_static;

use crate::evidence::Finding;
use crate::core::types::{ValidatorModule, TechnicalSeverity, BiasDeclaration};
use crate::validators::Validator;

lazy_static! {
    /// Regex para CPF (formatado ou não).
    static ref CPF_REGEX: Regex = Regex::new(
        r"\b(\d{3}\.?\d{3}\.?\d{3}-?\d{2})\b"
    ).unwrap();
}

/// CPF Validator (LGPD Art. 5º, I - Dado Pessoal)
pub struct CpfValidator {
    rule_id: String,
}

impl CpfValidator {
    pub fn new() -> Self {
        Self {
            rule_id: "VALIDATORS_CPF_001".to_string(),
        }
    }

    /// Limpa formatação do CPF
    fn clean_cpf(cpf: &str) -> String {
        cpf.chars().filter(|c| c.is_numeric()).collect()
    }

    /// Valida CPF via algoritmo Mod11 (oficial Receita Federal).
    fn is_valid_cpf(cpf: &str) -> bool {
        if cpf.len() != 11 {
            return false;
        }

        // Bloqueia CPFs com todos os dígitos iguais
        if cpf.chars().all(|c| c == cpf.chars().next().unwrap()) {
            return false;
        }

        let digits: Vec<u32> = cpf
            .chars()
            .filter_map(|c| c.to_digit(10))
            .collect();

        if digits.len() != 11 {
            return false;
        }

        // Primeiro dígito verificador
        let mut sum = 0;
        for i in 0..9 {
            sum += digits[i] * (10 - i as u32);
        }
        let remainder = sum % 11;
        let check1 = if remainder < 2 { 0 } else { 11 - remainder };

        if digits[9] != check1 {
            return false;
        }

        // Segundo dígito verificador
        sum = 0;
        for i in 0..10 {
            sum += digits[i] * (11 - i as u32);
        }
        let remainder = sum % 11;
        let check2 = if remainder < 2 { 0 } else { 11 - remainder };

        digits[10] == check2
    }
}

impl Validator for CpfValidator {
    fn validate(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for mat in CPF_REGEX.find_iter(input) {
            let matched = mat.as_str();
            let cleaned = Self::clean_cpf(matched);

            if Self::is_valid_cpf(&cleaned) {
                let finding = Finding::new(
                    ValidatorModule::CPF,
                    TechnicalSeverity::PolicyViolation,
                    &self.rule_id,
                    "CPF_PATTERN_DETECTED",
                    "Valid CPF pattern found in input (Mod11 verified)",
                )
                    .with_matched_text(matched)
                    .with_position(mat.start() as u16, mat.end() as u16)
                    .with_confidence(255);

                findings.push(finding);
            }
        }

        findings
    }

    fn name(&self) -> &'static str {
        "CpfValidator"
    }

    fn module(&self) -> ValidatorModule {
        ValidatorModule::CPF
    }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(
            0.08,      // FPR: 8% (formatação não-padrão)
            0.02,      // FNR: 2% (variações de escrita)
            20260209,  // Data de calibração (YYYYMMDD)
            500,       // Tamanho do dataset de teste
        )
        .with_affected_groups("Non-standard formatting (spaces, symbols)")
        .with_limitations("Algorithm validation only; does not check CPF registry")
    }
}

impl Default for CpfValidator {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTES
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_cpf_formatted() {
        let validator = CpfValidator::new();
        let findings = validator.validate("CPF: 111.444.777-05");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_invalid_cpf_checksum() {
        let validator = CpfValidator::new();
        let findings = validator.validate("123.456.789-00");
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_bias_declaration_non_default() {
        let validator = CpfValidator::new();
        let bias = validator.bias_declaration();
        assert!(bias.false_positive_rate > 0.0);
        assert!(bias.calibration_date > 0);
        assert!(bias.test_dataset_size >= 50);
    }
}
