//! Batch penalty calculations for Python
//! Placeholder – será substituído na v1.6+.

use pyo3::prelude::*;
use pyo3::types::{PyList, PyDict};
use pyo3::exceptions::{PyKeyError, PyValueError};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThreatType {
    PIILeakage,
    PromptInjection,
    ShadowAI,
    DenialOfWallet,
    Toxicity,
    BiasViolation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegulatoryFramework {
    LGPD,
    GDPR,
    EUAIAct,
    CCPA,
    HIPAA,
    PCIDSS,
}

pub struct PenaltyCalculatorV2;

impl PenaltyCalculatorV2 {
    pub fn calculate_roi_batch(threats: &[(ThreatType, RegulatoryFramework)]) -> i64 {
        let penalty_table: HashMap<(ThreatType, RegulatoryFramework), i64> = [
            ((ThreatType::PIILeakage, RegulatoryFramework::GDPR), 2_000_000),
            ((ThreatType::PIILeakage, RegulatoryFramework::LGPD), 5_000_000),
            ((ThreatType::PromptInjection, RegulatoryFramework::EUAIAct), 10_000_000),
            ((ThreatType::ShadowAI, RegulatoryFramework::GDPR), 30_000_00),
            ((ThreatType::DenialOfWallet, RegulatoryFramework::CCPA), 5_000_00),
            ((ThreatType::Toxicity, RegulatoryFramework::EUAIAct), 75_000_00),
            ((ThreatType::BiasViolation, RegulatoryFramework::EUAIAct), 150_000_00),
        ].iter().cloned().collect();

        threats.iter()
            .filter_map(|pair| penalty_table.get(pair))
            .sum()
    }

    pub fn cents_to_decimal(cents: i64) -> f64 {
        cents as f64 / 100.0
    }
}

#[pyfunction]
pub fn calculate_penalties_batch(py: Python, threats: &PyList) -> PyResult<PyObject> {
    if threats.is_empty() {
        return Err(PyValueError::new_err("Empty threats list"));
    }

    let mut parsed_threats = Vec::with_capacity(threats.len());
    let mut breakdown = Vec::with_capacity(threats.len());

    for (index, item) in threats.iter().enumerate() {
        let dict = item.downcast::<PyDict>()
            .map_err(|_| PyValueError::new_err(format!("Item {} is not a dictionary", index)))?;

        let threat_str = dict.get_item("threat_type")?
            .ok_or_else(|| PyKeyError::new_err("Missing 'threat_type' key"))?
            .extract::<String>()
            .map_err(|e| PyValueError::new_err(format!("Invalid threat_type: {}", e)))?;

        let framework_str = dict.get_item("framework")?
            .ok_or_else(|| PyKeyError::new_err("Missing 'framework' key"))?
            .extract::<String>()
            .map_err(|e| PyValueError::new_err(format!("Invalid framework: {}", e)))?;

        let threat = parse_threat_type(&threat_str)
            .map_err(PyValueError::new_err)?;
        let framework = parse_framework(&framework_str)
            .map_err(PyValueError::new_err)?;

        parsed_threats.push((threat, framework));

        let item_dict = PyDict::new(py);
        item_dict.set_item("index", index)?;
        item_dict.set_item("threat_type", threat_str)?;
        item_dict.set_item("framework", framework_str)?;
        item_dict.set_item("status", "processed")?;
        breakdown.push(item_dict);
    }

    let total_roi_cents = PenaltyCalculatorV2::calculate_roi_batch(&parsed_threats);
    let total_roi_usd = PenaltyCalculatorV2::cents_to_decimal(total_roi_cents);

    let response = PyDict::new(py);
    response.set_item("total_roi_usd", total_roi_usd)?;
    response.set_item("total_roi_cents", total_roi_cents)?;
    response.set_item("count", parsed_threats.len())?;
    response.set_item("breakdown", breakdown)?;
    response.set_item("currency", "USD")?;

    Ok(response.into())
}
fn parse_threat_type(s: &str) -> Result<ThreatType, String> {
    match s.to_lowercase().replace("_", "").as_str() {
        "piileakage" | "pii" | "dataleak" => Ok(ThreatType::PIILeakage),
        "promptinjection" | "injection" | "prompt" => Ok(ThreatType::PromptInjection),
        "shadowai" | "shadow" | "unauthorizedai" => Ok(ThreatType::ShadowAI),
        "denialofwallet" | "wallet" | "dosfinancial" => Ok(ThreatType::DenialOfWallet),
        "toxicity" | "toxic" | "harmful" => Ok(ThreatType::Toxicity),
        "biasviolation" | "bias" | "discrimination" => Ok(ThreatType::BiasViolation),
        _ => Err(format!("Unknown threat type: '{}'", s)),
    }
}

fn parse_framework(s: &str) -> Result<RegulatoryFramework, String> {
    match s.to_uppercase().replace("_", "").as_str() {
        "LGPD" => Ok(RegulatoryFramework::LGPD),
        "GDPR" => Ok(RegulatoryFramework::GDPR),
        "EUAIACT" | "EUAI" | "AIA" => Ok(RegulatoryFramework::EUAIAct),
        "CCPA" => Ok(RegulatoryFramework::CCPA),
        "HIPAA" => Ok(RegulatoryFramework::HIPAA),
        "PCIDSS" | "PCI" => Ok(RegulatoryFramework::PCIDSS),
        _ => Err(format!("Unknown framework: '{}'", s)),
    }
}