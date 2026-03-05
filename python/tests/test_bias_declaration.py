"""
Tests — BiasDeclarationV2 v2.0 (ADR-0049 D1)

20 testes:
  - Construção e defaults (3)
  - to_explain_dict() (6)
  - _validate_bias_declaration() (4)
  - _normalize_family() (4)
  - Integração com DurableLedger (3)
"""

import pytest
from buildtovalue.governance.persuasion_guard import (
    BiasDeclarationV2,
    _validate_bias_declaration,
    _normalize_family,
)


def _make_bd(**kwargs) -> BiasDeclarationV2:
    defaults = {
        "model_id":             "gpt-4-turbo",
        "model_family":         "gpt",
        "checker_model_id":     "llama3-8b",
        "checker_model_family": "llama3",
        "declared_at_iso":      "2026-03-04T00:00:00Z",
    }
    defaults.update(kwargs)
    return BiasDeclarationV2(**defaults)


# ─── Construção e defaults ────────────────────────────────────────────────────────

def test_construction_rate_defaults():
    bd = _make_bd()
    assert bd.false_positive_rate == 0.05
    assert bd.false_negative_rate == 0.02


def test_construction_calibration_date_none_by_default():
    bd = _make_bd()
    assert bd.calibration_date is None


def test_construction_frozen():
    bd = _make_bd()
    with pytest.raises((AttributeError, TypeError)):
        bd.model_id = "other"  # type: ignore


# ─── to_explain_dict() ───────────────────────────────────────────────────────────────

def test_to_explain_dict_model_id():
    bd = _make_bd()
    assert bd.to_explain_dict()["model_id"] == "gpt-4-turbo"


def test_to_explain_dict_checker_family():
    bd = _make_bd()
    assert bd.to_explain_dict()["checker_model_family"] == "llama3"


def test_to_explain_dict_false_positive_rate():
    bd = _make_bd(false_positive_rate=0.12)
    assert bd.to_explain_dict()["false_positive_rate"] == 0.12


def test_to_explain_dict_known_limitations_as_list():
    bd = _make_bd(known_limitations=("ctx_limit", "no_multilingual"))
    result = bd.to_explain_dict()["known_limitations"]
    assert isinstance(result, list)
    assert result == ["ctx_limit", "no_multilingual"]


def test_to_explain_dict_calibration_date_none():
    bd = _make_bd()
    assert bd.to_explain_dict()["calibration_date"] is None


def test_to_explain_dict_calibration_date_present():
    bd = _make_bd(calibration_date="2026-01-15")
    assert bd.to_explain_dict()["calibration_date"] == "2026-01-15"


# ─── _validate_bias_declaration() ───────────────────────────────────────────────────

def test_validate_passes_different_families():
    bd = _make_bd()
    _validate_bias_declaration(bd)  # sem raise


def test_validate_raises_same_family_prefix():
    bd = _make_bd(model_family="gpt", checker_model_family="gpt-4-turbo")
    with pytest.raises(ValueError, match="checker_model_family"):
        _validate_bias_declaration(bd)


def test_validate_raises_empty_checker_family():
    bd = _make_bd(checker_model_family="")
    with pytest.raises(ValueError, match="checker_model_family"):
        _validate_bias_declaration(bd)


def test_validate_same_family_case_insensitive():
    bd = _make_bd(model_family="GPT", checker_model_family="gpt-4")
    with pytest.raises(ValueError):
        _validate_bias_declaration(bd)


# ─── _normalize_family() ──────────────────────────────────────────────────────────────

def test_normalize_strips_after_hyphen():
    assert _normalize_family("llama3-70b") == "llama3"


def test_normalize_strips_after_dot():
    assert _normalize_family("mistral.v2") == "mistral"


def test_normalize_case_insensitive():
    assert _normalize_family("GPT-4") == "gpt"


def test_normalize_no_separator():
    assert _normalize_family("claude") == "claude"


# ─── Integração com DurableLedger ────────────────────────────────────────────────

_LEDGER_KEY = b"test-key-32-bytes-bias-decl-v2--"


def test_bias_declaration_appended_to_ledger():
    from buildtovalue.governance.durable_ledger import DurableLedger
    bd = _make_bd(calibration_date="2026-01-15")
    ledger = DurableLedger(hmac_key=_LEDGER_KEY)
    entry = ledger.append({
        "decision_id":    "DEC-bias-001",
        "explain_decision": bd.to_explain_dict(),
    })
    assert entry.sequence == 1
    assert entry.payload["explain_decision"]["checker_model_family"] == "llama3"


def test_bias_declaration_calibration_in_ledger():
    from buildtovalue.governance.durable_ledger import DurableLedger
    bd = _make_bd(calibration_date="2026-02-01")
    ledger = DurableLedger(hmac_key=_LEDGER_KEY)
    ledger.append({"decision_id": "DEC-1", "explain_decision": bd.to_explain_dict()})
    entry = ledger.entries()[0]
    assert entry.payload["explain_decision"]["calibration_date"] == "2026-02-01"


def test_verify_after_bias_declaration_appends():
    from buildtovalue.governance.durable_ledger import DurableLedger
    bd = _make_bd()
    ledger = DurableLedger(hmac_key=_LEDGER_KEY)
    for i in range(1, 4):
        ledger.append({"decision_id": f"D{i}", "explain_decision": bd.to_explain_dict()})
    result = ledger.verify()
    assert result.valid
    assert result.entries_checked == 3
