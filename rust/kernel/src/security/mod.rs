//! Security Module v2.5.0
//!
//! Componentes:
//! - `audit`: Detector de probing e análise de timing
//! - `session_guard`: Proteção contra hijacking de sessão
//! - `output_guard`: Sanitização de output (XSS, injection) + PII masking
//! - `prompt_injection`: Heuristic prompt injection detection (ADR-028)

pub mod audit;
pub mod session_guard;
pub mod output_guard;
pub mod pattern_registry;
pub mod prompt_injection;

pub use audit::{ProbingDetector, ProbingStats};
pub use session_guard::{SessionGuard, SessionToken, SessionError, SessionStats};
pub use output_guard::{OutputGuard, ContentAnalysis, OutputError, PiiMaskResult};
pub use prompt_injection::PromptInjectionDetector;
pub use pattern_registry::{PatternRegistry, PatternSnapshot, REGISTRY};

pub fn init_security() {
    log::info!("Security module initialized (v2.5.0)");
    log::info!("- Probing detection: Enabled");
    log::info!("- Session guard: Enabled (30min timeout)");
    log::info!("- Output sanitization: Enabled");
    log::info!("- PII masking: Enabled");
    log::info!("- Prompt injection detection: Enabled (ADR-028)");
    log::info!("- Pattern registry: Enabled (ADR-033, epoch={})", pattern_registry::REGISTRY.current_epoch());
}pub mod skill_registry;
