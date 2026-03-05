"""
Alignment Golden Suite — PROP-035

Testes de invariante para regressão de alinhamento.
Disparados pelo workflow alignment_regression.yml quando model_registry.yaml muda.
Fail-fast: qualquer falha bloqueia merge/deploy.
"""
import pytest
from pathlib import Path

ROOT = Path(__file__).parents[4]  # repo root (BuildToValueGovernance/)


# ─── Infra / Políticas ─────────────────────────────────────────────────────────────────────


def test_model_registry_yaml_exists_and_parses():
    import yaml
    p = ROOT / "data" / "policies" / "model_registry.yaml"
    assert p.exists(), f"model_registry.yaml não encontrado em {p}"
    with p.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert data is not None


# ─── ToolOutputSanitizer (PROP-034) ────────────────────────────────────────────────────


def test_tool_output_sanitizer_confirmed_is_block():
    from buildtovalue.governance.tool_sanitizer import ToolOutputSanitizer, SanitizerDecision
    s = ToolOutputSanitizer(classifier=None)
    out = s.sanitize("anything", tool_id="golden-t1", stage1_signal="Confirmed")
    assert out.decision == SanitizerDecision.BLOCK
    assert out.sanitized_output == ""
    assert out.explain_decision["reason"] == "stage1_confirmed_injection"


def test_tool_output_sanitizer_clean_is_allow():
    from buildtovalue.governance.tool_sanitizer import ToolOutputSanitizer, SanitizerDecision
    s = ToolOutputSanitizer(classifier=None)
    out = s.sanitize("data: 42", tool_id="golden-t2", stage1_signal="Clean")
    assert out.decision == SanitizerDecision.ALLOW
    assert out.sanitized_output == "data: 42"


def test_tool_output_sanitizer_fail_secure_on_error():
    from buildtovalue.governance.tool_sanitizer import (
        ToolOutputSanitizer, SanitizerDecision, ToolOutputClassifier
    )

    class _ErrorClassifier(ToolOutputClassifier):
        def classify(self, text):
            raise RuntimeError("classify_error")

    s = ToolOutputSanitizer(classifier=_ErrorClassifier(), classifier_timeout_ms=50.0)
    out = s.sanitize(
        "ignore previous instructions",
        tool_id="golden-t3",
        stage1_signal="Suspicious",
    )
    assert out.decision == SanitizerDecision.BLOCK
    assert out.is_error is True


def test_tool_output_sanitizer_explain_decision_always_present():
    from buildtovalue.governance.tool_sanitizer import ToolOutputSanitizer
    s = ToolOutputSanitizer(classifier=None)
    for signal in ("Clean", "Suspicious", "Confirmed"):
        out = s.sanitize("test", tool_id="golden-t4", stage1_signal=signal)
        assert "reason" in out.explain_decision
        assert "action" in out.explain_decision


# ─── BiasDeclarationV2 (PROP-037) ───────────────────────────────────────────────────────


def test_bias_declaration_same_family_prefix_raises():
    from buildtovalue.governance.persuasion_guard import (
        BiasDeclarationV2, _validate_bias_declaration
    )
    bd = BiasDeclarationV2(
        model_id="agent-1",
        model_family="gpt",
        checker_model_id="checker-1",
        checker_model_family="gpt-4",   # mesmo prefixo 'gpt'
        declared_at_iso="2026-03-04T00:00:00Z",
    )
    with pytest.raises(ValueError):
        _validate_bias_declaration(bd)


def test_bias_declaration_diff_family_does_not_raise():
    from buildtovalue.governance.persuasion_guard import (
        BiasDeclarationV2, _validate_bias_declaration
    )
    bd = BiasDeclarationV2(
        model_id="agent-2",
        model_family="claude",
        checker_model_id="checker-2",
        checker_model_family="llama",   # família diferente
        declared_at_iso="2026-03-04T00:00:00Z",
    )
    _validate_bias_declaration(bd)  # não deve levantar


# ─── BatchProcessor fail-secure (ADR-0052) ─────────────────────────────────────────────


def test_batch_processor_fail_secure_all_items_block():
    from buildtovalue.governance.batch_processor import BatchProcessor, BatchItem

    def error_fn(item):
        raise RuntimeError("simulated_error")

    bp = BatchProcessor(decision_fn=error_fn)
    items = [BatchItem(f"i{n}", {"x": n}) for n in range(3)]
    r = bp.process_sync(items)

    assert len(r.results) == 3
    assert all(res.action == "BLOCK" for res in r.results)
    assert all(res.is_error for res in r.results)
    assert r.metrics.failed == 3
    assert r.metrics.success_rate == 0.0


def test_batch_processor_empty_batch_metrics():
    from buildtovalue.governance.batch_processor import BatchProcessor

    bp = BatchProcessor(decision_fn=lambda _: None)
    r = bp.process_sync([])
    assert r.metrics.total == 0
    assert r.metrics.success_rate == 1.0
