//! API Response Types v2.3.2
//!
//! Estruturas de resposta padronizadas para comunicação com o mundo externo (CLI/Python).

use serde::{Deserialize, Serialize};
use crate::evidence::Finding;

/// Resultado da validação (Enum principal)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationResult {
    /// Nenhuma violação encontrada (Safe)
    Clean,

    /// Violação detectada (Block/Redact/Log)
    Violation(Finding),
}

/// Tipo de resposta (Nível de detalhe)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ResponseType {
    /// Genérico: Não revela o que foi detectado (Security by Obscurity / Safe Defaults)
    Generic,

    /// Específico: Apenas para logs internos (nunca exposto ao usuário final inseguro)
    Specific,
}

impl ValidationResult {
    /// Converte resultado em mensagem para usuário (uniforme e segura)
    pub fn to_user_message(&self) -> String {
        match self {
            ValidationResult::Clean => {
                "Request processed successfully.".to_string()
            }
            ValidationResult::Violation(_) => {
                // SEMPRE a mesma mensagem genérica para o usuário final
                // para evitar enumeração de regras (Blind Policy).
                "Request blocked by security policy. Reference ID provided in headers.".to_string()
            }
        }
    }

    /// Mensagem detalhada (apenas para logs/auditoria/admin)
    pub fn to_audit_message(&self) -> String {
        match self {
            ValidationResult::Clean => "No violations detected.".to_string(),
            ValidationResult::Violation(finding) => {
                // Recupera string do ID da regra (tratando bytes fixos)
                let rule_id = String::from_utf8_lossy(&finding.rule_id).trim_matches('\0').to_string();

                format!(
                    "Violation detected: [{}] confidence={} severity={:?}",
                    rule_id,
                    finding.confidence,
                    finding.severity
                )
            }
        }
    }

    /// Retorna se é limpo
    pub fn is_clean(&self) -> bool {
        matches!(self, ValidationResult::Clean)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{ValidatorModule, TechnicalSeverity};

    #[test]
    fn test_user_message_security() {
        // Garante que a mensagem de erro não vaza detalhes
        let finding = Finding::new(
            ValidatorModule::CPF,
            TechnicalSeverity::High,
            "CPF_LEAK",
            "PII",
            "123.456.789-00"
        );
        let result = ValidationResult::Violation(finding);

        assert_eq!(
            result.to_user_message(),
            "Request blocked by security policy. Reference ID provided in headers."
        );
        assert!(!result.to_user_message().contains("CPF"));
    }
}