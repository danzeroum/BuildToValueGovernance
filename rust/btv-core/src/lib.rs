//! `btv-core` — Legislative layer: linear resource types for AI accountability.
//!
//! **Phase 1**: Implements the Constitutional Enclosure Theorem (4.6) from Paper 1.
//! **Phase 2**: Adds the Transparency Persistence layer (Paper 2, Theorem IV):
//!   `InclusionReceipt`, `DeliveryToken`, `LogClient`.
//!
//! No well-typed program in Safe Rust can deliver a decision without:
//! 1. Consuming exactly one `EvidenceToken ⊗ ComplianceToken` (Phase 1)
//! 2. Obtaining a signed `InclusionReceipt` from Σ (Phase 2)
//!
//! Architecture:
//! - `btv-sigma` is a separate binary operating under independent custody (Paper 2, Axiom III-C).
//! - `LogClient` lives here because `btv-executive` (Phase 3) calls it.
//! - `btv-sigma` depends ONLY on `btv-types`, NEVER on `btv-core`.
#![deny(unsafe_code)]
#![deny(unused_must_use)]

// Phase 1 modules
mod hash;
mod hmac;
mod evidence_token;
mod compliance_token;
mod compliance_authority;
mod verdict;
mod operator_token;
mod escalated_verdict;
mod attestable;

// Phase 2 modules
mod inclusion_receipt;
mod delivery_token;
#[cfg(feature = "log-client")]
mod log_client;

// ADR-062 — appeal persistence (feature-gated)
#[cfg(feature = "appeal-writer")]
pub mod appeal_writer;

// ── Public API ────────────────────────────────────────────────────────────────────

// Phase 1
pub use evidence_token::EvidenceToken;
pub use compliance_token::ComplianceToken;
pub use compliance_authority::{ComplianceAuthority, ComplianceRegistry, ComplianceError};
pub use verdict::Verdict;
pub use operator_token::OperatorToken;
pub use escalated_verdict::EscalatedVerdict;
pub use attestable::{AttestableContext, AttestedEvidenceToken};

// Phase 2
pub use inclusion_receipt::InclusionReceipt;
pub use delivery_token::{DeliveryToken, DeliveryPayload, SealError};
#[cfg(feature = "log-client")]
pub use log_client::{LogClient, LogClientError};

// ADR-062
#[cfg(feature = "appeal-writer")]
pub use appeal_writer::{AppealWriter, AppealWriteError};

// Re-export wire types for convenience
pub use btv_types::{
    Decision, VerdictRecord, Blake3Hash as Blake3HashWire,
    BiasDeclaration, KnownDisparity,
    NegotiationDeadlockReason, AppealRecord,
};
