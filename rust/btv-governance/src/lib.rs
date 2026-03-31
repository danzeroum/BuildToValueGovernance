//! btv-governance — Pouvoir Constituant of the Algorithmic Republic.
//!
//! Implements Paper 6: "The Living Constitution: Formalizing Protocol Upgrades
//! as Democratic Processes" — MandateToken, Tripartite Ratification,
//! Stone Clauses, Sunset Clauses, Constitutional Interregnum.
//!
//! Invariants:
//! - `MandateToken` is `#[must_use]`, no `Clone`/`Copy`  (linear resource)
//! - Every `Verdict::new` requires a live `&MandateWire`
//! - `btv-governance` NEVER imports `btv-executive`     (T3 via Σ)
//! - `#![deny(unsafe_code)]`
#![deny(unsafe_code)]
#![deny(unused_must_use)]

pub mod amendment;
pub mod constitutional_state;
pub mod error;
pub mod governance_bridge;
pub mod legislative_versioning;
pub mod mandate;
pub mod ratification;
pub mod stone_clauses;
pub mod sunset;

pub use amendment::{Amendment, AmendmentKind, ConstitutionalDelta, PolicyDelta};
pub use constitutional_state::{ConstitutionalState, SystemState};
pub use error::GovernanceError;
pub use governance_bridge::GovernanceBridge;
pub use mandate::{AmendmentId, MandateToken, RatificationProof};
pub use ratification::{verify_tripartite_signatures, Branch, BranchKeys};
pub use stone_clauses::{canonical_stone_clauses, is_stone_clause_modification, StoneClause};
pub use sunset::SunsetPolicy;
