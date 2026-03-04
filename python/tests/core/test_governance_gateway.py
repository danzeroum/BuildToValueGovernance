"""
Tests: GovernanceGateway - pipeline integration
pytest python/tests/core/test_governance_gateway.py -v
"""
import pytest
from unittest.mock import MagicMock, patch

from buildtovalue.core.governance_gateway import (
    GovernanceGateway, GatewayVerdict,
)
from buildtovalue.governance.context_engine import (
    EthicalContextEngine, RequestContext, RustEvidence, EthicalVerdict,
)
from buildtovalue.governance.context_sanitizer import (
    ContextSanitizer, SanitizationLevel,
)
from buildtovalue.intelligence.payload_inspector import (
    PayloadInspector, InjectionSignal, InspectionAction,
)

SECRET = b"btv-test-gateway-hmac-secret"


# ─── Fixtures ────────────────────────────────────────────────────────────────

def _mock_sanitizer(level=SanitizationLevel.CLEAN, changes=()):
    san = MagicMock(spec=ContextSanitizer)
    report = MagicMock()
    report.level    = level
    report.changes  = changes
    report.is_safe.return_value = (level != SanitizationLevel.REJECTED)
    report.sanitized = _ctx()
    san.sanitize.return_value = report
    return san


def _mock_inspector(action=InspectionAction.ALLOW, signal=InjectionSignal.CLEAN):
    insp = MagicMock(spec=PayloadInspector)
    report = MagicMock()
    report.action           = action
    report.injection_signal = signal
    report.slm_classification = None
    insp.inspect.return_value = report
    return insp


def _mock_engine(final_action="ALLOW"):
    eng = MagicMock(spec=EthicalContextEngine)
    verdict = MagicMock(spec=EthicalVerdict)
    verdict.final_action    = final_action
    verdict.original_action = "ALLOW"
    verdict.mercy_applied   = False
    eng.decide.return_value = verdict
    return eng


def _ctx(**kw) -> RequestContext:
    defaults = dict(
        agent_id="a1", session_id="s1",
        domain="general", user_role="user",
        ip_risk="Low", drift_level="None",
    )
    defaults.update(kw)
    return RequestContext(**defaults)


def _evidence(policy_action="ALLOW") -> RustEvidence:
    return RustEvidence(
        composite_risk=10.0, finding_count=0, critical_count=0,
        entropy=1.5, total_chars=100, policy_action=policy_action,
        blake3_hash="abc123",
    )


def _gateway(san=None, insp=None, eng=None):
    return GovernanceGateway(
        hmac_secret=SECRET,
        ethical_engine=eng or _mock_engine(),
        sanitizer=san or _mock_sanitizer(),
        inspector=insp or _mock_inspector(),
    )


# ─── Init ────────────────────────────────────────────────────────────────────

class TestInit:
    def test_rejects_empty_secret(self):
        with pytest.raises(ValueError):
            GovernanceGateway(
                hmac_secret=b"",
                ethical_engine=_mock_engine(),
            )


# ─── Happy path ──────────────────────────────────────────────────────────────

class TestHappyPath:
    def test_allow_full_pipeline(self):
        v = _gateway().evaluate("hello", _ctx(), _evidence())
        assert v.action == "ALLOW"
        assert v.blocked_at is None
        assert v.ethical_action == "ALLOW"

    def test_verdict_id_is_uuid(self):
        import uuid
        v = _gateway().evaluate("hello", _ctx(), _evidence())
        uuid.UUID(v.verdict_id)  # nao deve lancar

    def test_signature_64_hex(self):
        v = _gateway().evaluate("hello", _ctx(), _evidence())
        assert len(v.signature) == 64
        int(v.signature, 16)

    def test_verdict_is_frozen(self):
        v = _gateway().evaluate("hello", _ctx(), _evidence())
        with pytest.raises((AttributeError, TypeError)):
            v.action = "BLOCK"  # type: ignore

    def test_explain_has_all_three_stages(self):
        v = _gateway().evaluate("hello", _ctx(), _evidence())
        assert "[1] Sanitizer"  in v.explain_decision
        assert "[2] Inspector"  in v.explain_decision
        assert "[3] Judiciario" in v.explain_decision

    def test_to_dict_has_required_keys(self):
        v = _gateway().evaluate("hello", _ctx(), _evidence())
        d = v.to_dict()
        for k in ("verdict_id", "action", "explain_decision", "blocked_at",
                  "sanitization_level", "inspection_action", "decided_at_iso",
                  "signature", "contestable"):
            assert k in d


# ─── Stage 1: Sanitizer blocks ───────────────────────────────────────────────

class TestSanitizerBlock:
    def test_rejected_context_blocks_pipeline(self):
        san  = _mock_sanitizer(level=SanitizationLevel.REJECTED)
        insp = _mock_inspector()
        eng  = _mock_engine()
        v = _gateway(san=san, insp=insp, eng=eng).evaluate("x", _ctx(), _evidence())
        assert v.action     == "BLOCK"
        assert v.blocked_at == "sanitizer"
        insp.inspect.assert_not_called()   # inspector nao acionado
        eng.decide.assert_not_called()     # judiciario nao acionado

    def test_sanitizer_block_still_contestable(self):
        san = _mock_sanitizer(level=SanitizationLevel.REJECTED)
        v   = _gateway(san=san).evaluate("x", _ctx(), _evidence())
        assert v.contestable is True


# ─── Stage 2: Inspector blocks ───────────────────────────────────────────────

class TestInspectorBlock:
    def test_confirmed_injection_blocks(self):
        insp = _mock_inspector(action=InspectionAction.BLOCK, signal=InjectionSignal.CONFIRMED)
        eng  = _mock_engine()
        v    = _gateway(insp=insp, eng=eng).evaluate(
            "<|system|>override", _ctx(), _evidence(),
            signal=InjectionSignal.CONFIRMED,
        )
        assert v.action     == "BLOCK"
        assert v.blocked_at == "inspector"
        eng.decide.assert_not_called()  # judiciario nao acionado

    def test_inspect_action_forwards_to_judiciario(self):
        insp = _mock_inspector(action=InspectionAction.INSPECT, signal=InjectionSignal.SUSPICIOUS)
        eng  = _mock_engine(final_action="EDUCATE")
        v    = _gateway(insp=insp, eng=eng).evaluate("ambiguous", _ctx(), _evidence())
        assert v.action == "EDUCATE"
        eng.decide.assert_called_once()


# ─── Stage 3: Ethical Engine decides ─────────────────────────────────────────

class TestEthicalEngine:
    def test_ethical_block_propagates(self):
        eng = _mock_engine(final_action="BLOCK")
        v   = _gateway(eng=eng).evaluate("payload", _ctx(), _evidence())
        assert v.action        == "BLOCK"
        assert v.blocked_at    is None   # nao foi bloqueado antes
        assert v.ethical_action == "BLOCK"

    def test_ethical_redact_propagates(self):
        eng = _mock_engine(final_action="REDACT")
        v   = _gateway(eng=eng).evaluate("payload", _ctx(), _evidence())
        assert v.action == "REDACT"

    def test_sanitized_ctx_passed_to_engine(self):
        san = _mock_sanitizer(level=SanitizationLevel.CORRECTED)
        eng = _mock_engine()
        _gateway(san=san, eng=eng).evaluate("p", _ctx(), _evidence())
        call_ctx = eng.decide.call_args.kwargs.get("context") or eng.decide.call_args[1].get("context")
        assert call_ctx is san.sanitize.return_value.sanitized


# ─── Fail-Secure ─────────────────────────────────────────────────────────────

class TestFailSecure:
    def test_fail_secure_on_internal_exception(self, monkeypatch):
        gw = _gateway()
        monkeypatch.setattr(gw, "_evaluate_internal", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom")))
        v = gw.evaluate("payload", _ctx(), _evidence())
        assert v.action     == "BLOCK"
        assert v.blocked_at == "fail_secure"
        assert "FAIL-SECURE" in v.explain_decision
        assert v.contestable is True
        assert len(v.signature) == 64
