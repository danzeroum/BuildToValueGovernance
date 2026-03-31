//! `DecisionError` — fail-secure por construção.
//!
//! Nenhuma variante contém um resultado parcial.
//! `Paper 5, Theorem 3.5`: se o pipeline falha, nada é produzido.

/// Every error variant means "no decision produced."
/// There is intentionally no `PartialResult` variant — the type system
/// prevents partial delivery (Paper 2, Corollary IV-B).
#[derive(Debug, thiserror::Error)]
pub enum DecisionError {
    /// Gatekeeper scan failed → BLOCK (sem evidência, sem decisão)
    #[error("Gatekeeper scan failed: {0}")]
    GatekeeperFailed(String),

    /// Compliance registry unavailable → BLOCK (sem ComplianceToken)
    #[error("Compliance registry unavailable: {0}")]
    ComplianceUnavailable(String),

    /// Log server (btv-sigma) unavailable → BLOCK (Paper 2: sem receipt = sem delivery)
    #[error("Transparency log unavailable: {0}")]
    LogUnavailable(String),

    /// Verdict HMAC integrity check failed → BLOCK (adulteração detectada)
    #[error("Verdict integrity check failed — possible tampering")]
    IntegrityFailure,

    /// Input violates structural constraints (size, encoding) → BLOCK
    #[error("Input violation: {0}")]
    InputViolation(String),
}
