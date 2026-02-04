
import pytest
from buildtovalue.compliance.translator import ComplianceTranslator
from buildtovalue.compliance.ajl_exporter import AJLExporter
from buildtovalue_compliance_ffi import calculate_penalties_batch, get_ajl_metrics

def test_full_compliance_workflow():
    """
    E2E test: PDF → Policy → Enforcement → ROI → AJL Report
    """
    # 1. Translate PDF to YAML (LLM)
    translator = ComplianceTranslator()
    yaml_policy = translator.translate_pdf(
        pdf_path="tests/fixtures/LGPD_Art20.pdf",
        framework="LGPD",
    )
    
    assert "policy-LGPD" in yaml_policy
    assert "action: BLOCK" in yaml_policy
    
    # 2. Calculate penalties (Rust FFI)
    threats = [
        {"threat_type": "pii_leakage", "framework": "LGPD"},
        {"threat_type": "prompt_injection", "framework": "GDPR"},
    ]
    roi = calculate_penalties_batch(threats)
    
    assert float(roi["total_roi_usd"]) > 0
    
    # 3. Get AJL metrics (Rust FFI)
    ajl_metrics = get_ajl_metrics()
    
    assert ajl_metrics["compliance_rate"] >= 0.95
    assert ajl_metrics["certification_eligible"] is True
    
    # 4. Export AJL report (Python)
    exporter = AJLExporter()
    report = exporter.generate_report(
        rust_metrics=ajl_metrics,
        system_info={"name": "BuildToValue v2.1"},
    )
    
    assert report["certification_status"]["eligible"] is True
    
    print("✅ Full compliance workflow validated")