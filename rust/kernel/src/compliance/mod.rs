//! Compliance Module v2.3.1
//!
//! **CHANGELOG v2.3.1**:
//! - ✅ penalty_calculator_v2 promovido para versão oficial
//! - ✅ Remoção de penalty_calculator (v1)

pub mod ajl_metrics;
pub mod penalty_calculator;  // Agora é a v2 (phf_map)

pub use penalty_calculator::PenaltyCalculator;
pub use ajl_metrics::{AJLMetricsEngine, BiasMetric, DemographicGroup};