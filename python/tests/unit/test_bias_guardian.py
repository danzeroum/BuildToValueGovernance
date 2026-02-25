"""Tests ADR-036: BiasGuardian"""
import json
import pytest
from pathlib import Path
from buildtovalue.governance.bias_guardian import (
    BiasGuardian, DivergenceLevel
)

REPORT_OK = {
    "script_id": "RT-001",
    "bias_declaration_comparison": {
        "declared_fnr_pct": 18.0, "measured_bypass_rate_pct": 20.0,
        "declared_fpr_pct": 8.0,  "measured_fpr_pct": 9.0,
    }
}
REPORT_WARNING = {
    "script_id": "RT-001",
    "bias_declaration_comparison": {
        "declared_fnr_pct": 18.0, "measured_bypass_rate_pct": 24.0,
        "declared_fpr_pct": 8.0,  "measured_fpr_pct": 11.5,
    }
}
REPORT_BLOCK = {
    "script_id": "RT-001",
    "bias_declaration_comparison": {
        "declared_fnr_pct": 18.0, "measured_bypass_rate_pct": 30.0,
        "declared_fpr_pct": 8.0,  "measured_fpr_pct": 15.0,
    }
}

def guardian():
    return BiasGuardian()

def test_ok_within_tolerance():
    e = guardian().evaluate_report(REPORT_OK)
    assert e.level == DivergenceLevel.OK
    assert e.passed

def test_warning_moderate_divergence():
    e = guardian().evaluate_report(REPORT_WARNING)
    assert e.level == DivergenceLevel.WARNING
    assert e.passed  # warning não bloqueia

def test_block_critical_divergence():
    e = guardian().evaluate_report(REPORT_BLOCK)
    assert e.level == DivergenceLevel.BLOCK
    assert not e.passed

def test_real_rt001_report_is_block():
    """RT-001 real: FNR +8.7pp, FPR +3.1pp → BLOCK."""
    real = {
        "script_id": "RT-001",
        "bias_declaration_comparison": {
            "declared_fnr_pct": 18.0, "measured_bypass_rate_pct": 26.7,
            "declared_fpr_pct": 8.0,  "measured_fpr_pct": 11.1,
        }
    }
    e = guardian().evaluate_report(real)
    assert e.level == DivergenceLevel.BLOCK
    assert e.fnr_divergence_pp == pytest.approx(8.7, abs=0.1)

def test_evaluate_latest_from_disk(tmp_path):
    (tmp_path / "RT-001-20260224.json").write_text(json.dumps(REPORT_OK))
    g = BiasGuardian(reports_dir=tmp_path)
    result = g.evaluate_latest()
    assert len(result.evaluations) == 1
    assert result.passed

def test_guardian_result_passed_all_ok():
    from buildtovalue.governance.bias_guardian import GuardianResult
    e = guardian().evaluate_report(REPORT_OK)
    r = GuardianResult(evaluations=[e])
    assert r.passed
    assert len(r.blocks) == 0
