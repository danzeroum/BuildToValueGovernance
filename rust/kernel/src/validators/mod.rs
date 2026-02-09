//! Validators Module v2.3.1
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

/// Trait comum para todos os validators.
///
/// Garante interface uniforme para Gatekeeper.
pub trait Validator: Send + Sync {
    /// Valida input e retorna findings.
    fn validate(&self, input: &str) -> Vec<Finding>;

    /// Nome do validator (para logging/metrics).
    fn name(&self) -> &'static str;

    /// Módulo ao qual pertence (para evidence).
    fn module(&self) -> ValidatorModule;
}