//! Session Guard v1.7.0 (ADR-014)
pub mod drift;
pub use drift::{SessionDrift, SessionVector, DriftResult, DriftLevel};