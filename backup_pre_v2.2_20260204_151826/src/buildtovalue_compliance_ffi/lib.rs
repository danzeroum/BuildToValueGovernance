
use pyo3::prelude::*;
use pyo3::types::PyDict;
use crate::penalty_calculator::{PenaltyCalculator, ThreatType, RegulatoryFramework};
use crate::ajl_metrics::{AJLMetricsEngine, BiasMetric};

/// Python-accessible penalty calculation
#[pyfunction]
fn calculate_penalty(
    threat_type: String,
    framework: String,
) -> PyResult<PyObject> {
    let threat = match threat_type.as_str() {
        "pii_leakage" => ThreatType::PIILeakage,
        "prompt_injection" => ThreatType::PromptInjection,
        _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Unknown threat type")),
    };
    
    let fw = match framework.as_str() {
        "LGPD" => RegulatoryFramework::LGPD,
        "GDPR" => RegulatoryFramework::GDPR,
        _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Unknown framework")),
    };
    
    // Load calculator (cached in production)
    let calc = PenaltyCalculator::from_yaml("").unwrap();
    
    if let Some(result) = calc.calculate(threat, fw) {
        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            dict.set_item("max_penalty_usd", result.max_penalty_usd.to_string())?;
            dict.set_item("per_incident_usd", result.per_incident_usd.to_string())?;
            dict.set_item("confidence", result.confidence)?;
            Ok(dict.into())
        })
    } else {
        Err(PyErr::new::<pyo3::exceptions::PyKeyError, _>("Penalty not found"))
    }
}

/// Python-accessible AJL metrics
#[pyfunction]
fn get_ajl_metrics(py: Python) -> PyResult<PyObject> {
    let engine = AJLMetricsEngine::new();
    
    // Mock data (in production, load from database)
    let metrics = vec![
        BiasMetric {
            group_a: DemographicGroup::Gender("Female".to_string()),
            group_b: DemographicGroup::Gender("Male".to_string()),
            dir: 0.94,
            pass_threshold: 0.8,
            compliant: true,
            sample_size: 200,
            timestamp: chrono::Utc::now().timestamp(),
        },
    ];
    
    let report = engine.generate_report(metrics);
    
    // Convert to Python dict
    let dict = PyDict::new(py);
    dict.set_item("total_metrics", report.total_metrics)?;
    dict.set_item("compliant_metrics", report.compliant_metrics)?;
    dict.set_item("compliance_rate", report.compliance_rate)?;
    dict.set_item("certification_eligible", report.certification_eligible)?;
    
    Ok(dict.into())
}

/// Module registration
#[pymodule]
fn buildtovalue_compliance_ffi(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(calculate_penalty, m)?)?;
    m.add_function(wrap_pyfunction!(get_ajl_metrics, m)?)?;
    Ok(())
}