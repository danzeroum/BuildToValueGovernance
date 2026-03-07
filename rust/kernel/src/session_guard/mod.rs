//! Session Guard v1.7.0 (ADR-014)
pub mod drift;
mod tracker;
pub(crate) mod accumulator;

pub use drift::{SessionDrift, SessionVector, DriftResult, DriftLevel};

pub use tracker::{SessionTracker, TrackerMetrics};

pub use accumulator::{SensitivityAccumulator, AccumulatorConfig, AccumulatorVerdict};