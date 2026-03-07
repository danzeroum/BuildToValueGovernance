//! FFI Entrypoints for PyO3
//!
//! Pontos de entrada seguros para o Python interagir com o Kernel.

use pyo3::prelude::*;
use serde::Deserialize;
use crate::session_guard::accumulator::{AccumulatorConfig, SensitivityAccumulator};
use std::sync::Mutex;

// Estado Global do Kernel (simplificação)
// Em produção, usar Arc<RwLock<KernelState>>
lazy_static::lazy_static! {
    pub static ref GLOBAL_ACCUMULATOR: Mutex<SensitivityAccumulator> = Mutex::new(
        SensitivityAccumulator::new(AccumulatorConfig::default())
    );
}

/// Estrutura para deserializar o JSON do Python.
#[derive(Debug, Deserialize)]
struct AccumulatorConfigJson {
    #[serde(default = "default_threshold")]
    intervention_threshold: f32,
    #[serde(default = "default_decay")]
    temporal_decay_factor: f32,
    #[serde(default = "default_history")]
    max_history_size: usize,
}

fn default_threshold() -> f32 { 75.0 }
fn default_decay() -> f32 { 0.95 }
fn default_history() -> usize { 100 }

/// Função Python: Atualiza configuração do Acumulador.
///
/// Uso em Python:
///   btv_kernel.update_accumulator_config('{"intervention_threshold": 80.0, ...}')
#[pyfunction]
fn update_accumulator_config(json_str: &str) -> PyResult<()> {
    // 1. Parse JSON
    let config: AccumulatorConfigJson = serde_json::from_str(json_str)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("JSON Error: {}", e)))?;

    // 2. Converte para struct Rust
    let rust_config = AccumulatorConfig {
        intervention_threshold: config.intervention_threshold,
        temporal_decay_factor: config.temporal_decay_factor,
        max_history_size: config.max_history_size,
    };

    // 3. Atualiza estado global
    // Nota: SensitivityAccumulator precisa ser re-criado ou ter método `reconfigure`
    let mut accumulator = GLOBAL_ACCUMULATOR.lock().unwrap();
    *accumulator = SensitivityAccumulator::new(rust_config);

    log::info!("Accumulator config updated via FFI.");
    Ok(())
}

/// Módulo Python
#[pymodule]
fn btv_kernel(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(update_accumulator_config, m)?)?;
    Ok(())
}