//! PyO3 wrapper types: PyTechnicalEvidence, PyBiasDeclaration, PyBatchResult, PyBatchItem.
use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;
use pyo3::types::{PyDict, PyList};
use crate::evidence::TechnicalEvidence;
use crate::core::types::{BiasDeclaration, MAX_FINDINGS, MAX_CRITICAL_FINDINGS};
use std::sync::Arc;

// ═══════════════════════════════════════════════════════════════════════════
// PyTechnicalEvidence
// ═══════════════════════════════════════════════════════════════════════════

#[pyclass]
#[derive(Clone)]
pub struct PyTechnicalEvidence {
    pub(crate) inner: Arc<TechnicalEvidence>,
}

#[pymethods]
impl PyTechnicalEvidence {
    #[getter] fn version(&self) -> u32 { self.inner.version }
    #[getter] fn timestamp(&self) -> u128 { self.inner.timestamp }
    #[getter] fn audit_trail_id(&self) -> String { self.inner.audit_trail_id.to_string() }
    #[getter] fn composite_risk(&self) -> f32 { self.inner.composite_risk }
    #[getter] fn risk_level(&self) -> String { format!("{}", self.inner.risk_level) }
    #[getter] fn finding_count(&self) -> u8 { self.inner.finding_count }
    #[getter] fn critical_count(&self) -> u8 { self.inner.critical_count }
    #[getter] fn entropy(&self) -> f32 { self.inner.stats.entropy }
    #[getter] fn input_size(&self) -> u32 { self.inner.input_size }
    #[getter] fn executed_modules(&self) -> u32 { self.inner.executed_modules }
    #[getter] fn processing_time_us(&self) -> u64 { self.inner.processing_time_us }
    #[getter] fn hash(&self) -> String { hex::encode(&self.inner.hash) }

    /// Max severity across all findings (ADR-046: SLM trigger in medium zone).
    #[getter]
    fn max_severity(&self) -> String {
        let mut max = 0u8;
        for i in 0..self.inner.finding_count.min(MAX_FINDINGS as u8) as usize {
            let s = self.inner.findings[i].severity.to_score();
            let mapped = if s >= 0.9 { 4 } else if s >= 0.7 { 3 } else if s >= 0.4 { 2 } else if s > 0.0 { 1 } else { 0 };
            if mapped > max { max = mapped; }
        }
        for i in 0..self.inner.critical_count.min(MAX_CRITICAL_FINDINGS as u8) as usize {
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
    fn bias(&self) -> PyBiasDeclaration {
        PyBiasDeclaration { inner: self.inner.bias.clone() }
    }

    fn validate_hash(&self) -> bool { self.inner.validate_hash() }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(self.inner.as_ref())
            .map_err(|e| PyRuntimeError::new_err(format!("JSON failed: {}", e)))
    }

    fn to_dict(&self) -> PyResult<PyObject> {
        Python::with_gil(|py| super::serialization::evidence_to_pydict(py, &self.inner))
    }

    fn __repr__(&self) -> String {
        format!(
            "TechnicalEvidence(risk={:.2}, findings={}, critical={}, modules={:b})",
            self.inner.composite_risk,
            self.inner.finding_count,
            self.inner.critical_count,
            self.inner.executed_modules,
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PyBiasDeclaration
// ═══════════════════════════════════════════════════════════════════════════

#[pyclass]
#[derive(Clone)]
pub struct PyBiasDeclaration {
    pub(crate) inner: BiasDeclaration,
}

#[pymethods]
impl PyBiasDeclaration {
    #[getter] fn false_positive_rate(&self) -> f32 { self.inner.false_positive_rate }
    #[getter] fn false_negative_rate(&self) -> f32 { self.inner.false_negative_rate }
    #[getter] fn calibration_date(&self) -> u32 { self.inner.calibration_date }
    #[getter] fn test_dataset_size(&self) -> u32 { self.inner.test_dataset_size }
    #[getter] fn is_valid(&self) -> bool { self.inner.is_calibration_valid() }

    fn __repr__(&self) -> String {
        format!(
            "BiasDeclaration(fpr={:.3}, fnr={:.3}, calibration={}, valid={})",
            self.inner.false_positive_rate,
            self.inner.false_negative_rate,
            self.inner.calibration_date,
            self.inner.is_calibration_valid(),
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PyBatchResult / PyBatchItem
// ═══════════════════════════════════════════════════════════════════════════

#[pyclass]
pub struct PyBatchItem {
    #[pyo3(get)]
    pub(crate) index: usize,
    pub(crate) evidence: Option<PyTechnicalEvidence>,
    #[pyo3(get)]
    pub(crate) status: String,
    #[pyo3(get)]
    pub(crate) processing_time_us: u64,
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
    pub(crate) items: Vec<PyBatchItem>,
    #[pyo3(get)]
    pub(crate) total_time_us: u64,
    #[pyo3(get)]
    pub(crate) succeeded: usize,
    #[pyo3(get)]
    pub(crate) timed_out: usize,
    #[pyo3(get)]
    pub(crate) failed: usize,
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
            self.succeeded, self.timed_out, self.failed, self.total_time_us,
        )
    }
}
