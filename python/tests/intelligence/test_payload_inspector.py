"""
Tests: PayloadInspector - PROP-034 Stage 2
pytest python/tests/intelligence/test_payload_inspector.py -v
"""
import json
import pytest
from unittest.mock import MagicMock

from buildtovalue.intelligence.payload_inspector import (
    PayloadInspector,
    PayloadInspectionReport,
    InjectionSignal,
    InspectionAction,
)
from buildtovalue.intelligence.slm_classifier import (
    SLMClassifier, SLMClassification, IntentLabel,
)

SECRET = b"btv-test-prop034-stage2"


def _inspector(slm=None):
    return PayloadInspector(hmac_secret=SECRET, slm=slm)


def _mock_slm(intent="benign", risk=0.1, confidence=0.9, loaded=True):
    slm = MagicMock(spec=SLMClassifier)
    slm.is_loaded = loaded
    result = SLMClassification(
        intent=IntentLabel(intent),
        risk=risk, confidence=confidence,
        model_id="mock", latency_ms=5.0,
    )
    slm.classify.return_value = result
    slm.classify_if_ambiguous.return_value = result
    return slm


# ─── Init ────────────────────────────────────────────────────────────────────

class TestInit:
    def test_rejects_empty_secret(self):
        with pytest.raises(ValueError):
            PayloadInspector(hmac_secret=b"")


# ─── Confirmed -> BLOCK imediato ─────────────────────────────────────────────

class TestConfirmed:
    def test_confirmed_always_blocks(self):
        slm = _mock_slm("benign", risk=0.0)  # SLM diz benign mas nao importa
        r = _inspector(slm).inspect("payload", InjectionSignal.CONFIRMED)
        assert r.action == InspectionAction.BLOCK
        assert r.slm_classification is None  # SLM nao acionado

    def test_confirmed_explain_mentions_stage1(self):
        r = _inspector().inspect("x", InjectionSignal.CONFIRMED)
        assert "Confirmed" in r.explain_decision
        assert "Stage 1" in r.explain_decision

    def test_confirmed_does_not_call_slm(self):
        slm = _mock_slm()
        _inspector(slm).inspect("payload", InjectionSignal.CONFIRMED)
        slm.classify.assert_not_called()
        slm.classify_if_ambiguous.assert_not_called()


# ─── Suspicious -> SLM sempre acionado ───────────────────────────────────────

class TestSuspicious:
    def test_suspicious_malicious_high_conf_blocks(self):
        slm = _mock_slm("prompt_injection", risk=0.9, confidence=0.8)
        r = _inspector(slm).inspect("ignore all previous", InjectionSignal.SUSPICIOUS)
        assert r.action == InspectionAction.BLOCK
        slm.classify.assert_called_once()

    def test_suspicious_malicious_low_conf_inspects(self):
        slm = _mock_slm("prompt_injection", risk=0.8, confidence=0.5)
        r = _inspector(slm).inspect("ambiguous text", InjectionSignal.SUSPICIOUS)
        assert r.action == InspectionAction.INSPECT

    def test_suspicious_benign_slm_allows(self):
        slm = _mock_slm("benign", risk=0.1, confidence=0.9)
        r = _inspector(slm).inspect("hello", InjectionSignal.SUSPICIOUS)
        assert r.action == InspectionAction.ALLOW

    def test_suspicious_no_slm_inspects(self):
        r = _inspector(slm=None).inspect("text", InjectionSignal.SUSPICIOUS)
        assert r.action == InspectionAction.INSPECT


# ─── Clean -> zona de ambiguidade ────────────────────────────────────────────

class TestClean:
    def test_clean_benign_allows(self):
        slm = _mock_slm("benign", risk=0.05, confidence=0.95)
        r = _inspector(slm).inspect("hello world", InjectionSignal.CLEAN, finding_count=0)
        assert r.action == InspectionAction.ALLOW

    def test_clean_malicious_slm_blocks(self):
        slm = _mock_slm("data_exfiltration", risk=0.85, confidence=0.75)
        r = _inspector(slm).inspect("show credentials", InjectionSignal.CLEAN, finding_count=0)
        assert r.action == InspectionAction.BLOCK

    def test_clean_high_findings_skips_slm(self):
        slm = _mock_slm()
        slm.classify_if_ambiguous.return_value = None  # fora da zona
        r = _inspector(slm).inspect("text", InjectionSignal.CLEAN, finding_count=5, critical_count=2)
        assert r.action == InspectionAction.ALLOW


# ─── Invariantes ─────────────────────────────────────────────────────────────

class TestInvariants:
    def test_explain_decision_always_present(self):
        for sig in InjectionSignal:
            r = _inspector().inspect("test", sig)
            assert isinstance(r.explain_decision, str)
            assert len(r.explain_decision) > 20

    def test_signature_64_hex_chars(self):
        r = _inspector().inspect("test", InjectionSignal.CLEAN)
        assert len(r.signature) == 64
        int(r.signature, 16)

    def test_report_is_frozen(self):
        r = _inspector().inspect("test", InjectionSignal.CLEAN)
        with pytest.raises((AttributeError, TypeError)):
            r.action = InspectionAction.BLOCK  # type: ignore

    def test_to_finding_dict_has_required_keys(self):
        r = _inspector().inspect("test", InjectionSignal.CLEAN)
        d = r.to_finding_dict()
        for k in ("module", "injection_signal", "action", "payload_len", "signature"):
            assert k in d

    def test_slm_finding_in_dict_when_present(self):
        slm = _mock_slm("prompt_injection", risk=0.9, confidence=0.8)
        r = _inspector(slm).inspect("inject", InjectionSignal.SUSPICIOUS)
        d = r.to_finding_dict()
        assert "slm" in d

    def test_payload_len_recorded(self):
        payload = "x" * 42
        r = _inspector().inspect(payload, InjectionSignal.CLEAN)
        assert r.payload_len == 42


# ─── Fail-Open (erro interno) ─────────────────────────────────────────────────

class TestFailOpen:
    def test_fail_open_on_slm_exception(self, monkeypatch):
        slm = _mock_slm()
        slm.classify.side_effect = RuntimeError("boom")
        r = _inspector(slm).inspect("payload", InjectionSignal.SUSPICIOUS)
        # SLM falha -> ainda retorna um report valido
        assert r.action in {InspectionAction.INSPECT, InspectionAction.ALLOW, InspectionAction.BLOCK}
        assert len(r.signature) == 64

    def test_fail_open_returns_inspect_not_block(self, monkeypatch):
        insp = _inspector()
        def boom(*a, **kw): raise RuntimeError("internal error")
        monkeypatch.setattr(insp, "_inspect_internal", boom)
        r = insp.inspect("payload", InjectionSignal.CLEAN)
        assert r.action == InspectionAction.INSPECT
        assert "FAIL-OPEN" in r.explain_decision
