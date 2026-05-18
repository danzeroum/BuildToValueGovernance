//! Module-level PyO3 functions: version, update_accumulator_config,
//! create_session_accumulator (PR-5).
use pyo3::prelude::*;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use serde::Deserialize;
use std::sync::Mutex;
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

// ── PySessionAccumulator (PR-5) ───────────────────────────────────────────

/// Per-session accumulator — isolates state between sessions and test runs.
/// The GLOBAL_ACCUMULATOR remains as a deprecated fallback (removal: ADR-040).
#[pyclass]
pub struct PySessionAccumulator {
    inner: Mutex<SensitivityAccumulator>,
}

#[pymethods]
impl PySessionAccumulator {
    fn add_event(&self, session_id: u128, category: &str, raw_score: f32) -> PyResult<bool> {
        let mut acc = self.inner.lock()
            .map_err(|_| PyRuntimeError::new_err("SessionAccumulator lock poisoned"))?;
        let verdict = acc.add_event(session_id, category, raw_score);
        Ok(verdict.safe)
    }

    fn reset(&self, session_id: u128) -> PyResult<()> {
        let mut acc = self.inner.lock()
            .map_err(|_| PyRuntimeError::new_err("SessionAccumulator lock poisoned"))?;
        acc.reset(session_id);
        Ok(())
    }
}

#[pyfunction]
pub fn create_session_accumulator(json_config: &str) -> PyResult<PySessionAccumulator> {
    let config: AccumulatorConfigJson = serde_json::from_str(json_config)
        .map_err(|e| PyValueError::new_err(format!("Config parse error: {e}")))?;
    let rust_config = AccumulatorConfig {
        intervention_threshold: config.intervention_threshold,
        temporal_decay_factor: config.temporal_decay_factor,
        max_history_size: config.max_history_size,
    };
    Ok(PySessionAccumulator { inner: Mutex::new(SensitivityAccumulator::new(rust_config)) })
}

/// Test-only: reset GLOBAL_ACCUMULATOR between test runs.
#[cfg(test)]
#[pyfunction]
pub fn reset_global_accumulator_for_testing() {
    if let Ok(mut acc) = GLOBAL_ACCUMULATOR.lock() {
        *acc = SensitivityAccumulator::new(AccumulatorConfig::default());
    }
}

// ── Public functions ──────────────────────────────────────────────────────

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
