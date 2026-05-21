//! Bridge Python→Kernel v2.1 — DT-006
//!
//! Usa buildtovalue_kernel::gatekeeper::Gatekeeper real.
//! Exporta tanto a função `scan_for_evidence_batch` (API funcional)
//! quanto a classe `RustKernel` (API orientada a objeto, usada pelo ffi_client).
//!
//! Serializacao: JSON via serde_json (sem fake protobuf manual).
//! Fail-secure: erros retornam PyRuntimeError, nunca .unwrap().

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::exceptions::{PyValueError, PyRuntimeError};
use buildtovalue_kernel::gatekeeper::Gatekeeper;
use uuid::Uuid;

/// Escaneia multiplas entradas em lote para evidencias tecnicas.
/// Retorna bytes JSON: array de EvidenceSummary por item.
#[pyfunction]
pub fn scan_for_evidence_batch(
    py: Python,
    inputs: Vec<String>,
    audit_trail_ids: Vec<u128>,
) -> PyResult<PyObject> {
    if inputs.len() != audit_trail_ids.len() {
        return Err(PyValueError::new_err(format!(
            "inputs ({}) e audit_trail_ids ({}) devem ter mesmo tamanho",
            inputs.len(), audit_trail_ids.len()
        )));
    }
    if inputs.is_empty() {
        return Err(PyValueError::new_err("lista de inputs vazia"));
    }

    let mut gatekeeper = Gatekeeper::new();
    let mut batch: Vec<serde_json::Value> = Vec::with_capacity(inputs.len());

    for (i, (input, trail_id)) in inputs.iter().zip(audit_trail_ids.iter()).enumerate() {
        let ev = gatekeeper.scan_for_evidence(input, *trail_id);
        batch.push(serde_json::json!({
            "index": i,
            "audit_trail_id": trail_id.to_string(),
            "composite_risk": ev.composite_risk,
            "risk_level": format!("{}", ev.risk_level),
            "finding_count": ev.finding_count,
            "critical_count": ev.critical_count,
            "processing_time_us": ev.processing_time_us,
            "hash": hex::encode(ev.hash),
            "bias_fpr": ev.bias.false_positive_rate,
            "bias_fnr": ev.bias.false_negative_rate,
        }));

        if i % 100 == 0 {
            log::info!("bridge: batch {}/{}", i + 1, inputs.len());
        }
    }

    let bytes = serde_json::to_vec(&batch)
        .map_err(|e| PyRuntimeError::new_err(format!("serializacao falhou: {e}")))?;
    Ok(PyBytes::new(py, &bytes).into())
}

/// Smoke test: verifica bridge com Gatekeeper real.
#[pyfunction]
pub fn test_bridge(py: Python) -> PyResult<PyObject> {
    scan_for_evidence_batch(
        py,
        vec!["test input".to_string()],
        vec![Uuid::new_v4().as_u128()],
    )
}

/// Classe RustKernel — API orientada a objeto para o ffi_client Python.
///
/// Wrapper stateful do Gatekeeper. Cada instância carrega um Gatekeeper
/// dedicado, permitindo reuso sem realocação por chamada.
///
/// # Exemplo Python:
/// ```python
/// import buildtovalue_kernel as btv
/// kernel = btv.RustKernel()
/// result = kernel.scan_for_evidence_batch(["texto"], [123456])
/// ```
#[pyclass]
pub struct RustKernel {
    gatekeeper: Gatekeeper,
}

#[allow(non_local_definitions)] // pyo3 macro generates non-local impl, known issue pre-pyo3 0.22
#[pymethods]
impl RustKernel {
    /// Cria uma nova instância do kernel Rust.
    #[new]
    pub fn new() -> Self {
        RustKernel {
            gatekeeper: Gatekeeper::new(),
        }
    }

    /// Escaneia múltiplas entradas em lote.
    /// Retorna bytes JSON compatíveis com o protocolo do ffi_client.
    pub fn scan_for_evidence_batch(
        &mut self,
        py: Python,
        inputs: Vec<String>,
        audit_trail_ids: Vec<u128>,
    ) -> PyResult<PyObject> {
        if inputs.len() != audit_trail_ids.len() {
            return Err(PyValueError::new_err(format!(
                "inputs ({}) e audit_trail_ids ({}) devem ter mesmo tamanho",
                inputs.len(), audit_trail_ids.len()
            )));
        }
        if inputs.is_empty() {
            return Err(PyValueError::new_err("lista de inputs vazia"));
        }

        let mut batch: Vec<serde_json::Value> = Vec::with_capacity(inputs.len());

        for (i, (input, trail_id)) in inputs.iter().zip(audit_trail_ids.iter()).enumerate() {
            let ev = self.gatekeeper.scan_for_evidence(input, *trail_id);
            batch.push(serde_json::json!({
                "index": i,
                "audit_trail_id": trail_id.to_string(),
                "composite_risk": ev.composite_risk,
                "risk_level": format!("{}", ev.risk_level),
                "finding_count": ev.finding_count,
                "critical_count": ev.critical_count,
                "processing_time_us": ev.processing_time_us,
                "hash": hex::encode(ev.hash),
                "bias_fpr": ev.bias.false_positive_rate,
                "bias_fnr": ev.bias.false_negative_rate,
            }));

            if i % 100 == 0 {
                log::info!("RustKernel: batch {}/{}", i + 1, inputs.len());
            }
        }

        let bytes = serde_json::to_vec(&batch)
            .map_err(|e| PyRuntimeError::new_err(format!("serializacao falhou: {e}")))?;
        Ok(PyBytes::new(py, &bytes).into())
    }

    /// Retorna a versão do kernel.
    pub fn version(&self) -> String {
        format!("BuildToValue Kernel v{}", env!("CARGO_PKG_VERSION"))
    }
}
