#![cfg(feature = "ffi-bindings")]
//! FFI Bridge v3.0 — CONSOLIDATED PyO3 Entry Point
//!
//! Phase 4: This is the SINGLE #[pymodule] for the kernel crate.
//! Previously, kernel_ffi.rs had a competing `btv_kernel` module.
//! `update_accumulator_config` is now registered HERE.
//!
//! Exports:
//! - RustKernel class (scan, persist, batch)
//! - PyTechnicalEvidence, PyBiasDeclaration, PyBatchResult
//! - update_accumulator_config() function (merged from kernel_ffi.rs)
//! - version() function

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use crate::gatekeeper::Gatekeeper;
use crate::batch::{BatchProcessor, BatchConfig, BatchItemStatus};
use crate::ledger::{DurableLedger, LedgerEntry};
use crate::ledger::remote::S3Config;
use crate::evidence::TechnicalEvidence;
use crate::core::types::BiasDeclaration;
use crate::session_guard::accumulator::{AccumulatorConfig, SensitivityAccumulator};
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use serde::Deserialize;

// ═══════════════════════════════════════════════════════════════════════════
// ACCUMULATOR STATE (moved from kernel_ffi.rs)
// ═══════════════════════════════════════════════════════════════════════════

lazy_static::lazy_static! {
    pub static ref GLOBAL_ACCUMULATOR: Mutex<SensitivityAccumulator> = Mutex::new(
        SensitivityAccumulator::new(AccumulatorConfig::default())
    );
}

#[derive(Deserialize)]
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

// ═══════════════════════════════════════════════════════════════════════════
// PYMODULE — SINGLE ENTRY POINT (consolidated)
// ═══════════════════════════════════════════════════════════════════════════

#[pymodule]
fn buildtovalue_kernel(_py: Python, m: &PyModule) -> PyResult<()> {
    // Classes
    m.add_class::<RustKernel>()?;
    m.add_class::<PyTechnicalEvidence>()?;
    m.add_class::<PyBiasDeclaration>()?;
    m.add_class::<PyBatchResult>()?;

    // Functions (consolidated from kernel_ffi.rs)
    m.add_function(wrap_pyfunction!(update_accumulator_config, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;

    // Constants
    m.add("VERSION", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}

/// Module version (consolidated).
#[pyfunction]
fn version() -> String {
    format!("BuildToValue Kernel v{}", env!("CARGO_PKG_VERSION"))
}

/// Update SensitivityAccumulator config from Python.
/// Merged from kernel_ffi.rs — was previously in a separate `btv_kernel` module.
#[pyfunction]
fn update_accumulator_config(json_str: &str) -> PyResult<()> {
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

    log::info!("Accumulator config updated via FFI (consolidated bridge)");
    Ok(())
}

// =====================================================================
// RUST KERNEL (main entry point)
// =====================================================================
#[pyclass]
pub struct RustKernel {
    gatekeeper: Arc<Mutex<Gatekeeper>>,
    ledger: Arc<Mutex<DurableLedger>>,
}

#[allow(non_local_definitions)]
#[pymethods]
impl RustKernel {
    #[new]
    fn new(ledger_path: Option<String>) -> PyResult<Self> {
        let disk_path = ledger_path.map(Into::into).unwrap_or_else(|| "ledger.data".into());
        let s3_config = S3Config::default();

        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| PyRuntimeError::new_err(format!("Tokio runtime: {}", e)))?;
        let ledger = runtime.block_on(DurableLedger::new(disk_path, s3_config))
            .map_err(|e| PyRuntimeError::new_err(format!("Ledger init: {}", e)))?;

        Ok(Self {
            gatekeeper: Arc::new(Mutex::new(Gatekeeper::new())),
            ledger: Arc::new(Mutex::new(ledger)),
        })
    }

    fn scan_for_evidence(&self, input: &str) -> PyResult<PyTechnicalEvidence> {
        let mut gatekeeper = self.gatekeeper.lock().unwrap();
        let audit_trail_id = Uuid::new_v4().as_u128();
        let evidence = gatekeeper.scan_for_evidence(input, audit_trail_id);
        Ok(PyTechnicalEvidence { inner: Arc::new(evidence) })
    }

    fn append_to_ledger(&self, evidence: &PyTechnicalEvidence) -> PyResult<u64> {
        let mut entry = LedgerEntry::default();
        entry.audit_trail_id = evidence.inner.audit_trail_id;
        entry.timestamp = evidence.inner.timestamp;
        entry.risk_level = evidence.inner.risk_level;

        let ledger = self.ledger.lock().unwrap();
        let seq = ledger.append(entry, &evidence.inner)
            .map_err(|e| PyRuntimeError::new_err(format!("Append failed: {}", e)))?;
        Ok(seq)
    }

    fn scan_and_persist(&self, input: &str) -> PyResult<(PyTechnicalEvidence, u64)> {
        let evidence = self.scan_for_evidence(input)?;
        let seq = self.append_to_ledger(&evidence)?;
        Ok((evidence, seq))
    }

    /// Batch scan: multiple inputs in one call.
    /// Returns PyBatchResult with per-item status.
    #[pyo3(signature = (inputs, max_batch_size=100, item_timeout_ms=10, batch_timeout_ms=1000))]
    fn batch_scan(
        &self,
        inputs: Vec<String>,
        max_batch_size: usize,
        item_timeout_ms: u64,
        batch_timeout_ms: u64,
    ) -> PyResult<PyBatchResult> {
        if inputs.is_empty() {
            return Err(PyValueError::new_err("Empty inputs list"));
        }

        let config = BatchConfig {
            max_batch_size,
            item_timeout_us: item_timeout_ms * 1000,
            batch_timeout_us: batch_timeout_ms * 1000,
        };
        let bp = BatchProcessor::new(config);

        let ids: Vec<u128> = (0..inputs.len())
            .map(|_| Uuid::new_v4().as_u128())
            .collect();
        let input_refs: Vec<&str> = inputs.iter().map(|s| s.as_str()).collect();

        let mut gatekeeper = self.gatekeeper.lock().unwrap();
        let result = bp.process(&mut gatekeeper, &input_refs, &ids)
            .map_err(|e| PyValueError::new_err(format!("Batch error: {}", e)))?;

        let items: Vec<PyBatchItem> = result.items.into_iter().map(|item| {
            PyBatchItem {
                index: item.index,
                evidence: item.evidence.map(|e| PyTechnicalEvidence { inner: Arc::new(e) }),
                status: match item.status {
                    BatchItemStatus::Ok => "ok".to_string(),
                    BatchItemStatus::Timeout => "timeout".to_string(),
                    BatchItemStatus::Error(e) => format!("error: {}", e),
                },
                processing_time_us: item.processing_time_us,
            }
        }).collect();

        Ok(PyBatchResult {
            items,
            total_time_us: result.total_time_us,
            succeeded: result.succeeded,
            timed_out: result.timed_out,
            failed: result.failed,
        })
    }

    fn get_gatekeeper_metrics(&self) -> PyResult<PyObject> {
        let gatekeeper = self.gatekeeper.lock().unwrap();
        let metrics = gatekeeper.get_metrics();

        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            dict.set_item("scans_total", metrics.scans_total)?;
            dict.set_item("findings_total", metrics.findings_total)?;
            dict.set_item("critical_findings", metrics.critical_findings)?;
            dict.set_item("avg_latency_ms", metrics.avg_latency_ms)?;
            dict.set_item("p99_latency_ms", metrics.p99_latency_ms)?;
            Ok(dict.into())
        })
    }
}

// =====================================================================
// PY TECHNICAL EVIDENCE
// =====================================================================
#[pyclass]
#[derive(Clone)]
pub struct PyTechnicalEvidence {
    // Arc allows cheap Clone without requiring TechnicalEvidence: Clone
    pub(crate) inner: Arc<TechnicalEvidence>,
}

#[pymethods]
impl PyTechnicalEvidence {
    #[getter]
    fn version(&self) -> u32 { self.inner.version }

    #[getter]
    fn timestamp(&self) -> u128 { self.inner.timestamp }

    #[getter]
    fn audit_trail_id(&self) -> String { self.inner.audit_trail_id.to_string() }

    #[getter]
    fn composite_risk(&self) -> f32 { self.inner.composite_risk }

    #[getter]
    fn risk_level(&self) -> String { format!("{}", self.inner.risk_level) }

    #[getter]
    fn finding_count(&self) -> u8 { self.inner.finding_count }

    #[getter]
    fn critical_count(&self) -> u8 { self.inner.critical_count }

    #[getter]
    fn entropy(&self) -> f32 { self.inner.stats.entropy }

    #[getter]
    fn input_size(&self) -> u32 { self.inner.input_size }

    #[getter]
    fn executed_modules(&self) -> u32 { self.inner.executed_modules }

    #[getter]
    fn processing_time_us(&self) -> u64 { self.inner.processing_time_us }

    /// ADR-046: max severity across all findings for Medium-zone SLM trigger.
    #[getter]
    fn max_severity(&self) -> String {
        let mut max = 0u8;
        for i in 0..self.inner.finding_count.min(crate::core::types::MAX_FINDINGS as u8) as usize {
            let s = self.inner.findings[i].severity.to_score();
            let mapped = if s >= 0.9 { 4 } else if s >= 0.7 { 3 } else if s >= 0.4 { 2 } else if s > 0.0 { 1 } else { 0 };
            if mapped > max { max = mapped; }
        }
        for i in 0..self.inner.critical_count.min(crate::core::types::MAX_CRITICAL_FINDINGS as u8) as usize {
            let s = self.inner.critical_findings[i].severity.to_score();
            let mapped = if s >= 0.9 { 4 } else if s >= 0.7 { 3 } else if s >= 0.4 { 2 } else if s > 0.0 { 1 } else { 0 };
            if mapped > max { max = mapped; }
        }
        match max {
            0 => "Safe".to_string(),
            1 => "Low".to_string(),
            2 => "Medium".to_string(),
            3 => "High".to_string(),
            _ => "Critical".to_string(),
        }
    }

    #[getter]
    fn hash(&self) -> String { hex::encode(&self.inner.hash) }

    #[getter]
    fn bias(&self) -> PyBiasDeclaration {
        PyBiasDeclaration { inner: self.inner.bias.clone() }
    }

    fn validate_hash(&self) -> bool { self.inner.validate_hash() }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|e| PyRuntimeError::new_err(format!("JSON failed: {}", e)))
    }

    fn to_dict(&self) -> PyResult<PyObject> {
        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            dict.set_item("version", self.inner.version)?;
            dict.set_item("timestamp", self.inner.timestamp)?;
            dict.set_item("audit_trail_id", self.inner.audit_trail_id.to_string())?;
            dict.set_item("composite_risk", self.inner.composite_risk)?;
            dict.set_item("risk_level", format!("{}", self.inner.risk_level))?;
            dict.set_item("finding_count", self.inner.finding_count)?;
            dict.set_item("critical_count", self.inner.critical_count)?;
            dict.set_item("entropy", self.inner.stats.entropy)?;
            dict.set_item("input_size", self.inner.input_size)?;
            dict.set_item("executed_modules", self.inner.executed_modules)?;
            dict.set_item("processing_time_us", self.inner.processing_time_us)?;
            dict.set_item("hash", hex::encode(&self.inner.hash))?;
            dict.set_item("max_severity", self.max_severity())?;
            dict.set_item("bias_fpr", self.inner.bias.false_positive_rate)?;
            dict.set_item("bias_fnr", self.inner.bias.false_negative_rate)?;
            dict.set_item("bias_calibration_date", self.inner.bias.calibration_date)?;
            Ok(dict.into())
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "TechnicalEvidence(risk={:.2}, findings={}, critical={}, modules={:b})",
            self.inner.composite_risk,
            self.inner.finding_count,
            self.inner.critical_count,
            self.inner.executed_modules
        )
    }
}

// =====================================================================
// PY BIAS DECLARATION
// =====================================================================
#[pyclass]
#[derive(Clone)]
pub struct PyBiasDeclaration {
    inner: BiasDeclaration,
}

#[pymethods]
impl PyBiasDeclaration {
    #[getter]
    fn false_positive_rate(&self) -> f32 { self.inner.false_positive_rate }

    #[getter]
    fn false_negative_rate(&self) -> f32 { self.inner.false_negative_rate }

    #[getter]
    fn calibration_date(&self) -> u32 { self.inner.calibration_date }

    #[getter]
    fn test_dataset_size(&self) -> u32 { self.inner.test_dataset_size }

    #[getter]
    fn is_valid(&self) -> bool { self.inner.is_calibration_valid() }

    fn __repr__(&self) -> String {
        format!(
            "BiasDeclaration(fpr={:.3}, fnr={:.3}, calibration={}, valid={})",
            self.inner.false_positive_rate,
            self.inner.false_negative_rate,
            self.inner.calibration_date,
            self.inner.is_calibration_valid()
        )
    }
}

// =====================================================================
// PY BATCH RESULT
// =====================================================================
#[pyclass]
pub struct PyBatchItem {
    #[pyo3(get)]
    index: usize,
    evidence: Option<PyTechnicalEvidence>,
    #[pyo3(get)]
    status: String,
    #[pyo3(get)]
    processing_time_us: u64,
}

#[pymethods]
impl PyBatchItem {
    #[getter]
    fn evidence(&self) -> Option<PyTechnicalEvidence> {
        self.evidence.clone()
    }
}

#[pyclass]
pub struct PyBatchResult {
    items: Vec<PyBatchItem>,
    #[pyo3(get)]
    total_time_us: u64,
    #[pyo3(get)]
    succeeded: usize,
    #[pyo3(get)]
    timed_out: usize,
    #[pyo3(get)]
    failed: usize,
}

#[pymethods]
impl PyBatchResult {
    #[getter]
    fn items(&self) -> PyResult<PyObject> {
        Python::with_gil(|py| {
            let list = PyList::empty(py);
            for item in &self.items {
                let dict = PyDict::new(py);
                dict.set_item("index", item.index)?;
                dict.set_item("status", &item.status)?;
                dict.set_item("processing_time_us", item.processing_time_us)?;
                if let Some(ev) = &item.evidence {
                    dict.set_item("evidence", ev.to_dict()?)?;
                }
                list.append(dict)?;
            }
            Ok(list.into())
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "BatchResult(succeeded={}, timed_out={}, failed={}, total_us={})",
            self.succeeded, self.timed_out, self.failed, self.total_time_us
        )
    }
}