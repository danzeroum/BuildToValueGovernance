
use pyo3::prelude::*;
use pyo3::types::{PyList, PyDict};
use crate::penalty_calculator_v2::{PenaltyCalculatorV2, ThreatType, RegulatoryFramework};

/// Batch request structure
#[derive(Debug)]
struct BatchPenaltyRequest {
    threats: Vec<(ThreatType, RegulatoryFramework)>,
}

/// Batch response structure
#[derive(Debug)]
struct BatchPenaltyResponse {
    results: Vec<Option<i64>>, // Per-incident USD in cents
    total_roi_cents: i64,
}

/// Python-accessible batch penalty calculation
#[pyfunction]
fn calculate_penalties_batch(
    py: Python,
    threats: &PyList,
) -> PyResult<PyObject> {
    // Parse Python list of dicts
    let mut parsed_threats = Vec::with_capacity(threats.len());
    
    for item in threats.iter() {
        let dict = item.downcast::<PyDict>()?;
        
        let threat_str: String = dict.get_item("threat_type")
            .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyKeyError, _>("Missing threat_type"))?
            .extract()?;
        
        let framework_str: String = dict.get_item("framework")
            .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyKeyError, _>("Missing framework"))?
            .extract()?;
        
        let threat = parse_threat_type(&threat_str)?;
        let framework = parse_framework(&framework_str)?;
        
        parsed_threats.push((threat, framework));
    }
    
    // Batch calculation (single Rust call, zero Python overhead)
    let total_roi = PenaltyCalculatorV2::calculate_roi_batch(&parsed_threats);
    
    // Build response
    let response = PyDict::new(py);
    response.set_item("total_roi_usd", PenaltyCalculatorV2::cents_to_decimal(total_roi).to_string())?;
    response.set_item("count", parsed_threats.len())?;
    
    Ok(response.into())
}

fn parse_threat_type(s: &str) -> PyResult<ThreatType> {
    match s {
        "pii_leakage" => Ok(ThreatType::PIILeakage),
        "prompt_injection" => Ok(ThreatType::PromptInjection),
        "shadow_ai" => Ok(ThreatType::ShadowAI),
        "denial_of_wallet" => Ok(ThreatType::DenialOfWallet),
        "toxicity" => Ok(ThreatType::Toxicity),
        "bias_violation" => Ok(ThreatType::BiasViolation),
        _ => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Unknown threat: {}", s))),
    }
}

fn parse_framework(s: &str) -> PyResult<RegulatoryFramework> {
    match s {
        "LGPD" => Ok(RegulatoryFramework::LGPD),
        "GDPR" => Ok(RegulatoryFramework::GDPR),
        "EU_AI_ACT" => Ok(RegulatoryFramework::EUAIAct),
        "CCPA" => Ok(RegulatoryFramework::CCPA),
        "HIPAA" => Ok(RegulatoryFramework::HIPAA),
        "PCI_DSS" => Ok(RegulatoryFramework::PCIDSS),
        _ => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Unknown framework: {}", s))),
    }
}

#[pymodule]
fn buildtovalue_compliance_ffi(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(calculate_penalties_batch, m)?)?;
    Ok(())
}