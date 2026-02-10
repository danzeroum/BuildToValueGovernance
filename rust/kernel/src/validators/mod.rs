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
pub use analysis::{StatisticalValidator};

// ═══════════════════════════════════════════════════════════════════════════
// TRAIT UNIFICADO
// ═══════════════════════════════════════════════════════════════════════════

use crate::Finding;
use crate::ValidatorModule;
use crate::core::types::BiasDeclaration;

/// Trait comum para todos os validators.
///
/// **BREAKING CHANGE v2.4.0 (ADR-010)**: Adicionado bias_declaration() obrigatório.
///
/// Garante interface uniforme para Gatekeeper e documenta limitações técnicas.
pub trait Validator: Send + Sync {
    /// Valida input e retorna findings.
    fn validate(&self, input: &str) -> Vec<Finding>;

    /// Nome do validator (para logging/metrics).
    fn name(&self) -> &'static str;

    /// Módulo ao qual pertence (para evidence).
    fn module(&self) -> ValidatorModule;

    /// **NOVO v2.4.0**: Declaração obrigatória de viés.
    ///
    /// DEVE retornar valores reais calibrados empiricamente.
    /// PROIBIDO retornar Default::default() em produção.
    ///
    /// Filosofia (Jonas, 1984): Responsabilidade sobre consequências
    /// imprevisíveis exige documentação honesta de limitações.
    ///
    /// # Example
    /// ```rust
    /// fn bias_declaration(&self) -> BiasDeclaration {
    ///     BiasDeclaration::new(
    ///         0.08, // FPR medido empiricamente
    ///         0.02, // FNR medido empiricamente
    ///         20260209, // Data da calibração
    ///         500,   // Tamanho do dataset de teste
    ///     )
    ///     .with_limitations("Algorithm validation only; does not check CPF registry")
    ///     .with_affected_groups("Non-standard formatting (spaces, symbols)")
    /// }
    /// ```
    fn bias_declaration(&self) -> BiasDeclaration;
}
