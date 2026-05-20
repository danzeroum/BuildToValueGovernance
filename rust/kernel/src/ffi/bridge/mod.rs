#![cfg(feature = "ffi-bindings")]
//! FFI Bridge v3.2 — modularized per ADR-009 (<200 lines/file).
//! ADR-040: GLOBAL_ACCUMULATOR removed; session state via PySessionAccumulator.
//!
//! Sub-modules:
//!   types.rs         — PyTechnicalEvidence, PyBiasDeclaration
//!   serialization.rs — evidence_to_pydict with full findings[]
//!   api.rs           — version, create_session_accumulator (PR-5)

pub mod types;
pub(crate) mod serialization;
pub mod api;
pub(crate) mod batch;

pub use types::{PyTechnicalEvidence, PyBiasDeclaration, PyBatchResult, PyBatchItem};
pub use api::version;

use pyo3::prelude::*;
use pyo3::types::PyDict;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use crate::gatekeeper::Gatekeeper;
use crate::batch::{BatchProcessor, BatchConfig, BatchItemStatus};
use crate::ledger::{DurableLedger, LedgerEntry};
use crate::ledger::remote::S3Config;
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use pyo3::types::PyBytes;

// ── PyModule entry point ──────────────────────────────────────────────────

#[pymodule]
fn buildtovalue_kernel(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<RustKernel>()?;
    m.add_class::<types::PyTechnicalEvidence>()?;
    m.add_class::<types::PyBiasDeclaration>()?;
    m.add_class::<types::PyBatchResult>()?;
    m.add_class::<api::PySessionAccumulator>()?;
    m.add_function(wrap_pyfunction!(api::version, m)?)?;
    m.add_function(wrap_pyfunction!(api::create_session_accumulator, m)?)?;
    m.add("VERSION", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// RustKernel
// ═══════════════════════════════════════════════════════════════════════════

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
        let mut gatekeeper = self.gatekeeper.lock()
            .map_err(|_| PyRuntimeError::new_err("Gatekeeper lock poisoned — BLOCK"))?;
        let audit_trail_id = Uuid::new_v4().as_u128();
        let evidence = gatekeeper.scan_for_evidence(input, audit_trail_id);
        Ok(PyTechnicalEvidence { inner: Arc::new(evidence) })
    }

    fn append_to_ledger(&self, evidence: &PyTechnicalEvidence) -> PyResult<u64> {
        let mut entry = LedgerEntry::default();
        entry.audit_trail_id = evidence.inner.audit_trail_id;
        entry.timestamp = evidence.inner.timestamp;
        entry.risk_level = evidence.inner.risk_level;
        // ADR-060: bias declaration packed into _reserved
        entry.set_bias(
            evidence.inner.bias.false_positive_rate,
            evidence.inner.bias.false_negative_rate,
            evidence.inner.bias.calibration_date,
        );
        // ADR-064: full 32-byte BLAKE3 regime_hash — zero until PolicyWatcher is live
        entry.set_regime_hash_full(&[0u8; 32]);
        // ADR-062: explanation_hash from evidence hash (full explanation in appeals.db)
        entry.set_explanation_hash(&evidence.inner.hash);
        let ledger = self.ledger.lock()
            .map_err(|_| PyRuntimeError::new_err("Ledger lock poisoned — BLOCK"))?;
        let seq = ledger.append(entry, &evidence.inner)
            .map_err(|e| PyRuntimeError::new_err(format!("Append failed: {}", e)))?;
        Ok(seq)
    }

    fn scan_and_persist(&self, input: &str) -> PyResult<(PyTechnicalEvidence, u64)> {
        let evidence = self.scan_for_evidence(input)?;
        let seq = self.append_to_ledger(&evidence)?;
        Ok((evidence, seq))
    }

    /// Batch scan returning JSON bytes — Orchestrator-mandated pure-Rust serialization.
    /// Validation here; serialization logic in batch::scan_batch_to_bytes (ADR-009).
    fn scan_for_evidence_batch(
        &self,
        py: Python<'_>,
        inputs: Vec<String>,
        trail_ids: Vec<u128>,
    ) -> PyResult<PyObject> {
        if inputs.len() != trail_ids.len() {
            return Err(PyValueError::new_err(
                "inputs and trail_ids must have equal length [fail-secure]",
            ));
        }
        if trail_ids.iter().any(|&id| id > u128::from(u64::MAX)) {
            return Err(PyValueError::new_err("trail_id exceeds u64::MAX — overflow risk"));
        }
        let bytes = batch::scan_batch_to_bytes(&self.gatekeeper, &inputs, &trail_ids)?;
        Ok(PyBytes::new(py, &bytes).into())
    }

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
        let ids: Vec<u128> = (0..inputs.len()).map(|_| Uuid::new_v4().as_u128()).collect();
        let input_refs: Vec<&str> = inputs.iter().map(|s| s.as_str()).collect();
        let mut gatekeeper = self.gatekeeper.lock()
            .map_err(|_| PyRuntimeError::new_err("Gatekeeper lock poisoned — BLOCK"))?;
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
        let mut gatekeeper = self.gatekeeper.lock()
            .map_err(|_| PyRuntimeError::new_err("Gatekeeper lock poisoned — BLOCK"))?;
        let metrics = gatekeeper.get_metrics();
        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            dict.set_item("scans_total", metrics.scans_total)?;
            dict.set_item("findings_total", metrics.findings_total)?;
            dict.set_item("critical_findings", metrics.critical_findings)?;
            dict.set_item("avg_latency_ms", metrics.avg_latency_ms)?;
            dict.set_item("p50_latency_ms", metrics.p50_latency_ms)?;
            dict.set_item("p95_latency_ms", metrics.p95_latency_ms)?;
            dict.set_item("p99_latency_ms", metrics.p99_latency_ms)?;
            dict.set_item("p999_latency_ms", metrics.p999_latency_ms)?;
            Ok(dict.into())
        })
    }
}

// PyBatchItem and PyBatchResult are defined in types.rs to stay under ADR-009 limit.
