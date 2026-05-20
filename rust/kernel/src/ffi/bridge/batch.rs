//! Pure-Rust batch scan helper — ADR-009: extracted from mod.rs.
//!
//! Takes a gatekeeper reference and returns serialized JSON bytes.
//! PyO3 wrapping (PyBytes) happens in the caller (mod.rs) to keep
//! this function testable without the GIL.
use pyo3::exceptions::PyRuntimeError;
use pyo3::PyResult;
use crate::gatekeeper::Gatekeeper;
use crate::evidence::TechnicalEvidence;
use std::sync::{Arc, Mutex};

pub fn scan_batch_to_bytes(
    gatekeeper: &Arc<Mutex<Gatekeeper>>,
    inputs: &[String],
    trail_ids: &[u128],
) -> PyResult<Vec<u8>> {
    debug_assert_eq!(inputs.len(), trail_ids.len(), "caller must validate lengths");
    let mut gk = gatekeeper.lock()
        .map_err(|_| PyRuntimeError::new_err("Gatekeeper lock poisoned — BLOCK"))?;
    let mut batch: Vec<TechnicalEvidence> = Vec::with_capacity(inputs.len());
    for (input, trail_id) in inputs.iter().zip(trail_ids.iter()) {
        batch.push(gk.scan_for_evidence(input, *trail_id));
    }
    serde_json::to_vec(&batch)
        .map_err(|e| PyRuntimeError::new_err(format!("JSON serialization failed: {e}")))
}
