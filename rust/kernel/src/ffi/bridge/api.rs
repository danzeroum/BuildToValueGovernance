//! Module-level PyO3 functions: version, update_accumulator_config.
//! PR-5 will add create_session_accumulator / PySessionAccumulator here.
use pyo3::prelude::*;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use serde::Deserialize;
use crate::session_guard::accumulator::{AccumulatorConfig, SensitivityAccumulator};
use super::GLOBAL_ACCUMULATOR;

// ── AccumulatorConfigJson ─────────────────────────────────────────────────

#[derive(Deserialize)]
pub(super) struct AccumulatorConfigJson {
    #[serde(default = "default_threshold")]
    pub intervention_threshold: f32,
    #[serde(default = "default_decay")]
    pub temporal_decay_factor: f32,
    #[serde(default = "default_history")]
    pub max_history_size: usize,
}

fn default_threshold() -> f32 { 75.0 }
fn default_decay() -> f32 { 0.95 }
fn default_history() -> usize { 100 }

// ── Public functions ──────────────────────────────────────────────────────

#[pyfunction]
pub fn version() -> String {
    format!("BuildToValue Kernel v{}", env!("CARGO_PKG_VERSION"))
}

/// Update SensitivityAccumulator config from Python.
#[pyfunction]
pub fn update_accumulator_config(json_str: &str) -> PyResult<()> {
    let config: AccumulatorConfigJson = serde_json::from_str(json_str)
        .map_err(|e| PyValueError::new_err(format!("JSON parse error: {}", e)))?;

    let rust_config = AccumulatorConfig {
        intervention_threshold: config.intervention_threshold,
        temporal_decay_factor: config.temporal_decay_factor,
        max_history_size: config.max_history_size,
    };

    let mut accumulator = GLOBAL_ACCUMULATOR.lock()
        .map_err(|_| PyRuntimeError::new_err("Accumulator lock poisoned (fail-secure)"))?;
    *accumulator = SensitivityAccumulator::new(rust_config);

    log::info!("Accumulator config updated via FFI");
    Ok(())
}
