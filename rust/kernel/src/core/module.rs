//! Trait unificado para todos os módulos de escaneamento (ADR-017).

use crate::evidence::Finding;
use crate::core::types::{BiasDeclaration, InputStatistics, ValidatorModule};

/// Contexto compartilhado durante um scan.
///
/// Alocado na stack e passado por referência mutável para todos os módulos.
#[derive(Debug)]
pub struct ScanContext {
    pub stats: InputStatistics,
    // Espaço reservado para futuras extensões (ex: flags de execução)
    pub _reserved: [u8; 64],
}

impl Default for ScanContext {
    fn default() -> Self {
        Self {
            stats: InputStatistics::default(),
            _reserved: [0u8; 64],
        }
    }
}

/// Trait unificado para todos os módulos de escaneamento.
pub trait Module: Send + Sync {
    /// Executa o módulo sobre o input, preenchendo o contexto conforme necessário.
    fn scan(&self, input: &str, ctx: &mut ScanContext) -> Vec<Finding>;

    /// Nome legível para logs e métricas.
    fn name(&self) -> &'static str;

    /// Identificador do módulo para a bitmask `executed_modules`.
    fn module_id(&self) -> ValidatorModule;

    /// Declaração de viés obrigatória (ADR-010).
    fn bias_declaration(&self) -> BiasDeclaration;
}