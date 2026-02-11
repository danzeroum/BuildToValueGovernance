//! Compliance Module v2.3.2
//!
//! Módulo responsável pela conformidade regulatória e métricas de viés.
//!
//! Estrutura:
//! - `penalty_calculator`: Motor de cálculo de multas regulatórias (LGPD/GDPR/etc).
//! - `ajl_metrics`: Métricas de Justiça Algorítmica (Algorithmic Justice League).

pub mod ajl_metrics;
pub mod penalty_calculator;

pub use penalty_calculator::PenaltyCalculator;
pub use ajl_metrics::{AJLMetricsEngine, BiasMetric, DemographicGroup};