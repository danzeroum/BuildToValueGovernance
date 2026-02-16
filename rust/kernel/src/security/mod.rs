//! Security Module v2.4.0
//!
//! Componentes:
//! - `audit`: Detector de probing e análise de timing
//! - `session_guard`: Proteção contra hijacking de sessão
//! - `output_guard`: Sanitização de output (XSS, injection) + PII masking

pub mod audit;
pub mod session_guard;
pub mod output_guard;

// Re-exports
pub use audit::{ProbingDetector, ProbingStats};
pub use session_guard::{SessionGuard, SessionToken, SessionError, SessionStats};
pub use output_guard::{OutputGuard, ContentAnalysis, OutputError, PiiMaskResult};

/// Inicializa todos os componentes de segurança
pub fn init_security() {
    log::info!("Security module initialized (v2.4.0)");
    log::info!("- Probing detection: Enabled");
    log::info!("- Session guard: Enabled (30min timeout)");
    log::info!("- Output sanitization: Enabled");
    log::info!("- PII masking: Enabled");
}