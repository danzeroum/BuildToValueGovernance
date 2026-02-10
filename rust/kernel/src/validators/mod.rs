//! Validators Module v2.4.0
//!
//! **CHANGELOG v2.4.0 (ADR-010)**:
//! - ✅ BREAKING: bias_declaration() adicionado ao trait Validator
//! - ✅ Todos validators DEVEM declarar viés empiricamente calibrado
//!
//! **CHANGELOG v2.3.1**:
//! - ✅ Consolidação de validators (brazilian/)
//! - ✅ Remoção de duplicações (CPF, penalty_calculator)
//! - ✅ Estrutura modular por domínio

// ═══════════════════════════════════════════════════════════════════════════
// SUBMÓDULOS POR DOMÍNIO
// ═══════════════════════════════════════════════════════════════════════════
pub mod brazilian;        // CPF, CNPJ (LGPD)
pub mod financial;        // Credit Card (PCI-DSS)
pub mod communication;    // Email, Phone
pub mod network;          // IP, Domain
pub mod sensitive;        // LGPD Sensitive Data Pattern Detection
pub mod privacy;          // Consent & Rights Governance
pub mod analysis;         // Statistical Anomaly Detection

// ═══════════════════════════════════════════════════════════════════════════
// RE-EXPORTS (Convenience)
// ═══════════════════════════════════════════════════════════════════════════
pub use brazilian::{CpfValidator, CnpjValidator};
pub use financial::CreditCardValidator;
pub use communication::{EmailValidator, PhoneValidator};
pub use network::{Ipv4Validator, UrlValidator};
pub use sensitive::SensitiveDataValidator;
pub use privacy::{ConsentValidator, ConsentRevocationValidator};
pub use analysis::StatisticalValidator;

// ═══════════════════════════════════════════════════════════════════════════
// TRAIT UNIFICADO
// ═══════════════════════════════════════════════════════════════════════════

use crate::Finding;
use crate::ValidatorModule;
use crate::core::types::BiasDeclaration;

/// Trait comum para todos os validators.
///
/// **BREAKING CHANGE v2.4.0 (ADR-010)**: Adicionado `bias_declaration()` obrigatório.
///
/// Garante interface uniforme para Gatekeeper e documenta limitações técnicas.
///
/// # Philosophy (Jonas, 1984)
///
/// > "Responsabilidade sobre consequências imprevisíveis exige documentação
/// > honesta de limitações."
///
/// Cada validator DEVE declarar empiricamente suas taxas de erro (FPR/FNR),
/// data de calibração e grupos afetados desproporcionalmente.
///
/// # Example Implementation
///
/// ```rust
/// use buildtovalue_kernel::validators::Validator;
/// use buildtovalue_kernel::{Finding, ValidatorModule};
/// use buildtovalue_kernel::core::types::BiasDeclaration;
///
/// struct MyValidator;
///
/// impl Validator for MyValidator {
///     fn validate(&self, input: &str) -> Vec<Finding> {
///         // Validation logic
///         vec![]
///     }
///
///     fn name(&self) -> &'static str {
///         "MyValidator"
///     }
///
///     fn module(&self) -> ValidatorModule {
///         ValidatorModule::Unknown
///     }
///
///     fn bias_declaration(&self) -> BiasDeclaration {
///         BiasDeclaration::new(
///             0.08,      // FPR: 8% false positives (measured on test dataset)
///             0.02,      // FNR: 2% false negatives
///             20260209,  // Calibration date: Feb 9, 2026
///             500,       // Test dataset size: 500 samples
///         )
///         .with_limitations("Algorithm validation only; does not check external registry")
///         .with_affected_groups("Non-standard formatting (spaces, special chars)")
///     }
/// }
/// ```
///
/// # Contract
///
/// - `validate()`: MUST be deterministic for same input
/// - `name()`: MUST be unique across validators
/// - `module()`: MUST match validator's domain
/// - `bias_declaration()`: MUST return calibrated values (not Default::default())
///
/// # Thread Safety
///
/// All validators MUST be `Send + Sync` for parallel execution in Gatekeeper.
pub trait Validator: Send + Sync {
    /// Valida input e retorna findings.
    ///
    /// # Arguments
    /// * `input` - String a ser validada (normalizada pelo Gatekeeper)
    ///
    /// # Returns
    /// Vec de findings detectados (vazio se input válido)
    ///
    /// # Performance
    /// - Target: < 5ms p95 para inputs < 1KB
    /// - DEVE evitar heap allocations no hot path
    /// - DEVE usar iteradores lazy quando possível
    fn validate(&self, input: &str) -> Vec<Finding>;

    /// Nome do validator (para logging/metrics).
    ///
    /// DEVE ser único e descritivo (ex: "CPF", "Email", "CreditCard").
    fn name(&self) -> &'static str;

    /// Módulo ao qual pertence (para evidence).
    ///
    /// Usado para bitmap `executed_modules` em TechnicalEvidence.
    fn module(&self) -> ValidatorModule;

    /// **NOVO v2.4.0**: Declaração obrigatória de viés.
    ///
    /// DEVE retornar valores reais calibrados empiricamente.
    /// PROIBIDO retornar `Default::default()` em produção.
    ///
    /// # Calibration Guidelines (ADR-010)
    ///
    /// 1. **FPR/FNR**: Medir em dataset representativo (≥ 50 samples)
    /// 2. **Calibration Date**: YYYYMMDD format, max 90 dias de validade
    /// 3. **Test Dataset Size**: Documentar tamanho real usado
    /// 4. **Affected Groups**: Listar grupos com erro desproporcional
    /// 5. **Limitations**: Documentar edge cases conhecidos
    ///
    /// # Failure Modes
    ///
    /// - Se calibração expirada (> 90 dias), Gatekeeper DEVE logar warning
    /// - Se FPR/FNR = 0.0, assumir "não calibrado" (worst-case = 1.0)
    ///
    /// # Example Values (ADR-010 Table)
    ///
    /// | Validator    | FPR  | FNR  | Dataset | Calibration Date |
    /// |--------------|------|------|---------|------------------|
    /// | CPF          | 0.08 | 0.02 | 500     | 2026-02-09       |
    /// | Email        | 0.03 | 0.08 | 800     | 2026-02-09       |
    /// | CreditCard   | 0.05 | 0.01 | 300     | 2026-02-09       |
    ///
    /// # Returns
    /// BiasDeclaration with empirically measured error rates
    fn bias_declaration(&self) -> BiasDeclaration;
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPER: Validar se BiasDeclaration é válido (não default)
// ═══════════════════════════════════════════════════════════════════════════

/// Valida se BiasDeclaration foi calibrado (não é default)
///
/// **Usage**: Gatekeeper pode usar para detectar validators não calibrados
///
/// # Returns
/// - `true`: Calibração válida
/// - `false`: Default ou expirada
pub fn is_bias_declaration_valid(bias: &BiasDeclaration) -> bool {
    // Não pode ser default (0.0, 0.0, 0, 0)
    if bias.false_positive_rate == 0.0
        && bias.false_negative_rate == 0.0
        && bias.calibration_date == 0
        && bias.test_dataset_size == 0
    {
        return false;
    }

    // FPR/FNR devem estar entre 0.0 e 1.0
    if bias.false_positive_rate < 0.0 || bias.false_positive_rate > 1.0 {
        return false;
    }

    if bias.false_negative_rate < 0.0 || bias.false_negative_rate > 1.0 {
        return false;
    }

    // Dataset deve ter pelo menos 50 samples
    if bias.test_dataset_size < 50 {
        return false;
    }

    // Calibração deve estar válida (dentro de 90 dias)
    bias.is_calibration_valid()
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bias_declaration_default_invalid() {
        let bias = BiasDeclaration::default();
        assert!(!is_bias_declaration_valid(&bias));
    }

    #[test]
    fn test_bias_declaration_valid() {
        let bias = BiasDeclaration::new(0.08, 0.02, 20260209, 500);
        assert!(is_bias_declaration_valid(&bias));
    }

    #[test]
    fn test_bias_declaration_invalid_fpr() {
        let bias = BiasDeclaration::new(1.5, 0.02, 20260209, 500); // FPR > 1.0
        assert!(!is_bias_declaration_valid(&bias));
    }

    #[test]
    fn test_bias_declaration_invalid_dataset_size() {
        let bias = BiasDeclaration::new(0.08, 0.02, 20260209, 10); // < 50 samples
        assert!(!is_bias_declaration_valid(&bias));
    }

    #[test]
    fn test_bias_declaration_expired() {
        let bias = BiasDeclaration::new(0.08, 0.02, 20250101, 500); // > 90 dias atrás
        assert!(!is_bias_declaration_valid(&bias));
    }
}
