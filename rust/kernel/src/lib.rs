//! BuildToValue Sovereign Kernel v2.3.1
//!
//! **CHANGELOG v2.3.1**:
//! - ✅ Consolidação de validators (brazilian/)
//! - ✅ Remoção de duplicações (CPF, penalty_calculator)
//! - ✅ Estrutura modular por domínio (Core, Evidence, Validators)
//!
//! O núcleo de aplicação da lei digital. Responsável pela validação de fatos,
//! geração de evidências forenses e aplicação de políticas imutáveis.
//!
//! # Arquitetura
//! - **Fail-Secure**: Padrão de bloqueio em caso de erro.
//! - **Zero-Allocation**: Alocação fixa no hot-path.
//! - **Auditabilidade**: Todo veredito gera um hash no Ledger.

// ═══════════════════════════════════════════════════════════════════════════
// MÓDULOS CORE (A Fundação)
// ═══════════════════════════════════════════════════════════════════════════

pub mod core;             // Contém types.rs e errors.rs
pub mod api;              // Contém response.rs
pub mod evidence;         // Contém technical.rs e finding.rs
pub mod gatekeeper;       // Orquestrador principal

// ═══════════════════════════════════════════════════════════════════════════
// SUBSISTEMAS (Domínios de Lógica)
// ═══════════════════════════════════════════════════════════════════════════

pub mod validators;       // Detectores especializados (contém o trait Validator)
pub mod statistics;       // Análise estatística
pub mod deobfuscator;     // Detecção de ofuscação
pub mod compliance;       // Conformidade regulatória
pub mod security;         // Módulos de segurança
pub mod ledger;           // Sistema de logging durável
pub mod observability;    // Métricas e tracing
pub mod policy;           // Policy engine

// ═══════════════════════════════════════════════════════════════════════════
// FFI (Conditional Compilation)
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "ffi-bindings")]
pub mod ffi;

// ═══════════════════════════════════════════════════════════════════════════
// RE-EXPORTS (Facade Pattern)
// ═══════════════════════════════════════════════════════════════════════════
// Facilita o uso externo, expondo os tipos principais na raiz do crate.

// Orquestrador
pub use gatekeeper::Gatekeeper;

// Tipos de Evidência (Vindos do módulo evidence)
pub use evidence::{TechnicalEvidence, Finding};

// Tipos Fundamentais (Vindos do módulo core)
// Nota: Redirecionamos core::types para parecer que estão na raiz
pub use core::types::{ValidatorModule, TechnicalSeverity, Action, RiskLevel};

// Interfaces (Vindas do módulo validators)
pub use validators::Validator;

// ═══════════════════════════════════════════════════════════════════════════
// VERSION INFO
// ═══════════════════════════════════════════════════════════════════════════

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PROTOCOL_VERSION: u16 = 2;

/// Retorna informações de versão completas
pub fn version_info() -> String {
    format!(
        "BuildToValue Kernel v{} (protocol v{})",
        VERSION,
        PROTOCOL_VERSION
    )
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_info() {
        let info = version_info();
        assert!(info.contains("BuildToValue"));
        assert!(info.contains("2.3"));
    }
}