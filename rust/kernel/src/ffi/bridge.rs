#![cfg(feature = "ffi-bindings")]

use pyo3::prelude::*;
use pyo3::types::{PyDict};
use pyo3::exceptions::PyRuntimeError;
use crate::gatekeeper::Gatekeeper;
use crate::ledger::{DurableLedger};
use crate::evidence::TechnicalEvidence;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use log;
use crate::ledger::wal::WalConfig;

#[pymodule]
fn buildtovalue_kernel(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<RustKernel>()?;
    m.add_class::<PyTechnicalEvidence>()?;
    m.add("VERSION", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}

#[pyclass]
pub struct RustKernel {
    gatekeeper: Arc<Mutex<Gatekeeper>>,
    ledger: Arc<Mutex<DurableLedger>>,
}

#[pymethods]
impl RustKernel {
    #[new]
    fn new(wal_path: Option<String>) -> PyResult<Self> {
        let config = WalConfig {
            wal_path: wal_path
                .map(Into::into)
                .unwrap_or_else(|| "ledger.wal".into()),
            fsync_enabled: true,
            max_size_bytes: 100 * 1024 * 1024, // 100MB
        };

        // Ledger sem sync remoto (por enquanto)
        let ledger = DurableLedger::new(config)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to create ledger: {}", e)))?;

        Ok(Self {
            gatekeeper: Arc::new(Mutex::new(Gatekeeper::new())),
            ledger: Arc::new(Mutex::new(ledger)),
        })
    }

    fn scan_for_evidence(&self, input: &str) -> PyResult<PyTechnicalEvidence> {
        let mut gatekeeper = self.gatekeeper.lock().unwrap();
        let audit_trail_id = Uuid::new_v4().as_u128();
        let evidence = gatekeeper.scan_for_evidence(input, audit_trail_id);
        Ok(PyTechnicalEvidence { inner: evidence })
    }

    fn append_to_ledger(&self, evidence: &PyTechnicalEvidence) -> PyResult<u64> {
        let ledger = self.ledger.lock().unwrap();
        ledger.append(&evidence.inner)
            .map_err(|e| PyRuntimeError::new_err(format!("Append failed: {}", e)))
    }

    fn scan_and_persist(&self, input: &str) -> PyResult<(PyTechnicalEvidence, u64)> {
        let evidence = self.scan_for_evidence(input)?;
        let seq = self.append_to_ledger(&evidence)?;
        Ok((evidence, seq))
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

    fn get_ledger_metrics(&self) -> PyResult<PyObject> {
        let ledger = self.ledger.lock().unwrap();
        let metrics = ledger.get_metrics();

        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            dict.set_item("entries_total", metrics.entries_total)?;
            dict.set_item("bytes_written", metrics.bytes_written)?;
            dict.set_item("fsync_count", metrics.fsync_count)?;
            dict.set_item("fsync_failures", metrics.fsync_failures)?;
            dict.set_item("avg_append_ms", metrics.avg_append_ms)?;
            Ok(dict.into())
        })
    }
}

#[pyclass]
#[derive(Clone)]
pub struct PyTechnicalEvidence {
    inner: TechnicalEvidence,
}

#[pymethods]
impl PyTechnicalEvidence {
    #[getter]
    fn version(&self) -> u32 { self.inner.version }

    #[getter]
    fn timestamp(&self) -> u128 { self.inner.timestamp }

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
    fn hash(&self) -> String { hex::encode(&self.inner.hash) }

    fn validate_hash(&self) -> bool { self.inner.validate_hash() }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|e| PyRuntimeError::new_err(format!("JSON serialization failed: {}", e)))
    }

    fn to_dict(&self) -> PyResult<PyObject> {
        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            dict.set_item("version", self.inner.version)?;
            dict.set_item("timestamp", self.inner.timestamp)?;
            dict.set_item("composite_risk", self.inner.composite_risk)?;
            dict.set_item("risk_level", format!("{}", self.inner.risk_level))?;
            dict.set_item("finding_count", self.inner.finding_count)?;
            dict.set_item("critical_count", self.inner.critical_count)?;
            dict.set_item("entropy", self.inner.stats.entropy)?;
            dict.set_item("input_size", self.inner.input_size)?;
            dict.set_item("hash", hex::encode(&self.inner.hash))?;
            dict.set_item("audit_trail_id", self.inner.audit_trail_id.to_string())?;
            Ok(dict.into())
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "TechnicalEvidence(risk={:.2}, findings={}, critical={}, entropy={:.2})",
            self.inner.composite_risk,
            self.inner.finding_count,
            self.inner.critical_count,
            self.inner.stats.entropy
        )
    }
}