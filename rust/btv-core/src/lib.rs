//! `btv-core` — Legislative layer: linear resource types for AI accountability.
//!
//! Implements the **Constitutional Enclosure Theorem (4.6)** from Paper 1:
//! no well-typed program in Safe Rust can produce a `Verdict` without consuming
//! exactly one `EvidenceToken ⊗ ComplianceToken`.
//!
//! This crate is the **Legislativo** in the Algorithmic Republic:
//! - It defines the rules that the Executivo (`btv-executive`) must obey.
//! - It contains the `pub(crate)` constructors that are capability-guarded.
//! - `btv-judicial` must import only `btv-types`, never this crate.
#![deny(unsafe_code)]
#![deny(unused_must_use)]

mod hash;
mod hmac;
mod evidence_token;
mod compliance_token;
mod compliance_authority;
mod verdict;
mod operator_token;
mod escalated_verdict;
mod attestable;

// ── Public API — carefully curated ───────────────────────────────────────────

pub use evidence_token::EvidenceToken;
pub use compliance_token::ComplianceToken;
pub use compliance_authority::{ComplianceAuthority, ComplianceRegistry, ComplianceError};
pub use verdict::Verdict;
pub use operator_token::OperatorToken;
pub use escalated_verdict::EscalatedVerdict;
pub use attestable::{AttestableContext, AttestedEvidenceToken};

// Re-export wire types for convenience
pub use btv_types::{Decision, VerdictRecord, Blake3Hash as Blake3HashWire};
