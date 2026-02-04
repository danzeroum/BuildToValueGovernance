
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use prost::Message;

/// Converte TechnicalEvidence para Protobuf
pub fn evidence_to_proto(evidence: &TechnicalEvidence) -> EvidenceProto {
    // Converte findings
    let findings: Vec<FindingProto> = evidence.get_all_findings()
        .iter()
        .filter(|f| !f.severity.is_critical())
        .map(|f| finding_to_proto(f))
        .collect();
    
    let critical: Vec<FindingProto> = evidence.get_all_findings()
        .iter()
        .filter(|f| f.severity.is_critical())
        .map(|f| finding_to_proto(f))
        .collect();
    
    EvidenceProto {
        protocol_version: evidence.protocol_version as u32,
        audit_trail_id: evidence.audit_trail_id.to_le_bytes().to_vec(),
        timestamp: evidence.timestamp as u64,
        evidence_hash: evidence.evidence_hash,
        composite_risk: evidence.composite_risk as u32,
        findings,
        critical,
        stats: Some(stats_to_proto(&evidence.stats)),
        bias: Some(bias_to_proto(&evidence.bias)),
        original_request_hash: evidence.original_request_hash,
        input_size: evidence.input_size,
        processing_time_us: evidence.processing_time_us,
    }
}

fn finding_to_proto(finding: &Finding) -> FindingProto {
    let rule_id = std::str::from_utf8(&finding.rule_id)
        .unwrap_or("")
        .trim_end_matches('\0')
        .to_string();
    
    let title = std::str::from_utf8(&finding.title)
        .unwrap_or("")
        .trim_end_matches('\0')
        .to_string();
    
    let description = std::str::from_utf8(&finding.description)
        .unwrap_or("")
        .trim_end_matches('\0')
        .to_string();
    
    FindingProto {
        module: finding.module as u32,
        severity: finding.severity as u32,
        rule_id,
        title,
        description,
        matched_text_hash: finding.matched_text_hash,
        confidence: finding.confidence as u32,
        position_start: finding.position_start as u32,
        position_end: finding.position_end as u32,
    }
}

fn stats_to_proto(stats: &InputStatistics) -> InputStatisticsProto {
    InputStatisticsProto {
        entropy: stats.entropy,
        z_score: stats.z_score,
        unique_chars: stats.unique_chars as u32,
        total_chars: stats.total_chars,
        digit_ratio: stats.digit_ratio,
        letter_ratio: stats.letter_ratio,
        symbol_ratio: stats.symbol_ratio,
    }
}

fn bias_to_proto(bias: &BiasDeclaration) -> BiasDeclarationProto {
    BiasDeclarationProto {
        false_positive_rate: bias.false_positive_rate,
        calibration_date: bias.calibration_date,
        limitations: bias.get_limitations().to_string(),
        affected_groups: "".to_string(),  // TODO
    }
}

/// Expõe função para Python via PyO3
#[pyfunction]
fn scan_for_evidence_batch(
    py: Python,
    inputs: Vec<String>,
    audit_trail_ids: Vec<u128>,
) -> PyResult<PyObject> {
    // Cria gatekeeper (reutilizável)
    let gatekeeper = Gatekeeper::new();
    
    // Processa batch
    let mut evidences = Vec::new();
    for (input, trail_id) in inputs.iter().zip(audit_trail_ids.iter()) {
        let evidence = gatekeeper.scan_for_evidence(input, *trail_id);
        evidences.push(evidence_to_proto(&evidence));
    }
    
    // Cria batch proto
    let batch = EvidenceBatch { evidences };
    
    // Serializa para bytes
    let mut buf = Vec::new();
    batch.encode(&mut buf)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            format!("Protobuf encoding failed: {}", e)
        ))?;
    
    // Retorna como PyBytes
    Ok(PyBytes::new(py, &buf).into())
}

/// Registra módulo Python
#[pymodule]
fn buildtovalue_kernel(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan_for_evidence_batch, m)?)?;
    Ok(())
}