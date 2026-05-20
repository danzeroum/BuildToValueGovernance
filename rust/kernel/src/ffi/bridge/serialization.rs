//! Evidence serialization — full findings + bias dict, fail-secure UTF-8.
//!
//! All PyDict allocations happen in a single GIL-holding call.
//! No .clone() on TechnicalEvidence fields — all accesses by reference.
use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;
use pyo3::types::{PyDict, PyList};
use crate::evidence::TechnicalEvidence;

/// Serialize a `TechnicalEvidence` into a Python dict.
///
/// Preserves all existing flat keys (no regression for current consumers).
/// Adds `findings[]`, `critical[]`, and a `bias` sub-dict.
pub fn evidence_to_pydict(py: Python<'_>, ev: &TechnicalEvidence) -> PyResult<PyObject> {
    let dict = PyDict::new(py);

    // ── scalars (same keys as bridge.rs — no consumer regression) ────────
    dict.set_item("version", ev.version)?;
    dict.set_item("timestamp", ev.timestamp)?;
    dict.set_item("audit_trail_id", ev.audit_trail_id.to_string())?;
    dict.set_item("composite_risk", ev.composite_risk)?;
    dict.set_item("risk_level", format!("{}", ev.risk_level))?;
    dict.set_item("finding_count", ev.finding_count)?;
    dict.set_item("critical_count", ev.critical_count)?;
    dict.set_item("entropy", ev.stats.entropy)?;
    dict.set_item("input_size", ev.input_size)?;
    dict.set_item("executed_modules", ev.executed_modules)?;
    dict.set_item("processing_time_us", ev.processing_time_us)?;
    dict.set_item("hash", hex::encode(&ev.hash))?;
    // flat bias keys preserved — ffi_client.py reads these; removed in PR-7
    dict.set_item("bias_fpr", ev.bias.false_positive_rate)?;
    dict.set_item("bias_fnr", ev.bias.false_negative_rate)?;
    dict.set_item("bias_calibration_date", ev.bias.calibration_date)?;

    // ── bias sub-dict (additive — does not replace flat keys) ─────────────
    let bias = PyDict::new(py);
    bias.set_item("false_positive_rate", ev.bias.false_positive_rate)?;
    bias.set_item("false_negative_rate", ev.bias.false_negative_rate)?;
    bias.set_item("calibration_date", ev.bias.calibration_date)?;
    bias.set_item("test_dataset_size", ev.bias.test_dataset_size)?;
    bias.set_item("is_valid", ev.bias.is_calibration_valid())?;
    dict.set_item("bias", bias)?;

    // ── findings[] ────────────────────────────────────────────────────────
    let count = (ev.finding_count as usize).min(ev.findings.len());
    let findings_list = PyList::empty(py);
    for i in 0..count {
        let f = &ev.findings[i];
        let fd = PyDict::new(py);

        let title_end = f.matched_text.iter().position(|&b| b == 0).unwrap_or(f.matched_text.len());
        let title = std::str::from_utf8(&f.matched_text[..title_end])
            .map_err(|_| PyRuntimeError::new_err("matched_text: invalid UTF-8 — BLOCK"))?;
        fd.set_item("title", title)?;

        let cat_end = f.threat_category.iter().position(|&b| b == 0).unwrap_or(f.threat_category.len());
        let category = std::str::from_utf8(&f.threat_category[..cat_end])
            .map_err(|_| PyRuntimeError::new_err("threat_category: invalid UTF-8 — BLOCK"))?;
        fd.set_item("category", category)?;

        fd.set_item("severity", f.severity.to_score())?;
        fd.set_item("confidence", f.confidence as f32 / 255.0)?;
        fd.set_item("description", format!("{:?}", f.module))?;
        findings_list.append(fd)?;
    }
    dict.set_item("findings", findings_list)?;

    // ── critical[] ────────────────────────────────────────────────────────
    let crit_count = (ev.critical_count as usize).min(ev.critical_findings.len());
    let crit_list = PyList::empty(py);
    for i in 0..crit_count {
        let f = &ev.critical_findings[i];
        let fd = PyDict::new(py);

        let title_end = f.matched_text.iter().position(|&b| b == 0).unwrap_or(f.matched_text.len());
        let title = std::str::from_utf8(&f.matched_text[..title_end])
            .map_err(|_| PyRuntimeError::new_err("matched_text: invalid UTF-8 — BLOCK"))?;
        fd.set_item("title", title)?;
        fd.set_item("severity", f.severity.to_score())?;
        fd.set_item("confidence", f.confidence as f32 / 255.0)?;
        crit_list.append(fd)?;
    }
    dict.set_item("critical", crit_list)?;

    Ok(dict.into())
}
