//! BuildToValue Sovereign Kernel v2.3.1 (Projeto v3.0)
//!
//! **PROTOCOLO**: Kernel de governança digital soberana
//! **VERSÃO DO PROJETO**: BuildToValue v3.0
//! **VERSÃO DO KERNEL**: v2.3.1
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
pub use core::types::{ValidatorModule, TechnicalSeverity, Action, RiskLevel};

// Interfaces (Vindas do módulo validators)
pub use validators::Validator;

// ═══════════════════════════════════════════════════════════════════════════
// VERSION INFO (Sincronizado com Cargo.toml e PROJECT_CONTEXT.md)
// ═══════════════════════════════════════════════════════════════════════════

/// Versão do kernel (sincronizada com Cargo.toml)
pub const KERNEL_VERSION: &str = "2.3.1";

/// Versão do projeto BuildToValue (PROJECT_CONTEXT.md)
pub const PROJECT_VERSION: &str = "3.0";

/// Versão do protocolo de evidência
pub const PROTOCOL_VERSION: u16 = 3;

/// Retorna informações de versão completas
pub fn version_info() -> String {
    format!(
        "BuildToValue v{} (Kernel v{}, Protocol v{})",
        PROJECT_VERSION,
        KERNEL_VERSION,
        PROTOCOL_VERSION
    )
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTES
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_info() {
        let info = version_info();
        assert!(info.contains("BuildToValue v3.0"));
        assert!(info.contains("Kernel v2.3.1"));
    }
}