//! Security Module v2.6.0
//!
//! Componentes:
//! - `audit`: Detector de probing e análise de timing
//! - `session_guard`: Proteção contra hijacking de sessão
//! - `output_guard`: Sanitização de output (XSS, injection) + PII masking
//! - `prompt_injection`: Heuristic prompt injection detection (ADR-028)
//! - `supply_guard`: Verificação de proveniência de skills via MAC (PROP-031)

pub mod audit;
pub mod session_guard;
pub mod output_guard;
pub mod pattern_registry;
pub mod prompt_injection;
pub mod skill_registry;
pub mod supply_guard;

pub use audit::{ProbingDetector, ProbingStats};
pub use session_guard::{SessionGuard, SessionToken, SessionError, SessionStats};
pub use output_guard::{OutputGuard, ContentAnalysis, OutputError, PiiMaskResult};
pub use prompt_injection::PromptInjectionDetector;
pub use pattern_registry::{PatternRegistry, PatternSnapshot, REGISTRY};
pub use supply_guard::{verify_skill, SupplyGuardResult, SupplyGuardReason};

pub fn init_security() {
    log::info!("Security module initialized (v2.6.0)");
    log::info!("- Probing detection: Enabled");
    log::info!("- Session guard: Enabled (30min timeout)");
    log::info!("- Output sanitization: Enabled");
    log::info!("- PII masking: Enabled");
    log::info!("- Prompt injection detection: Enabled (ADR-028)");
    log::info!("- Pattern registry: Enabled (ADR-033, epoch={})", pattern_registry::REGISTRY.current_epoch());
    log::info!("- Supply guard: Enabled (PROP-031, BLAKE3-MAC)");
}
