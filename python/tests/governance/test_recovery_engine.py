"""
Tests: RecoveryEngine — PROP-030
pytest python/tests/governance/test_recovery_engine.py -v
"""
import pytest
from unittest.mock import MagicMock

from buildtovalue.governance.recovery_engine import (
    RecoveryEngine,
    RecoveryOutcome,
    RecoveryStrategy,
    _MERCY_ALLOW_THRESHOLD,
    _QUARANTINE_VIOLATIONS,
    _SLA_HOURS,
)

SECRET = b"btv-test-hmac-secret-prop030"


def _ev(*, critical_count=0, composite_risk=10, has_pii=False):
    ev = MagicMock()
    ev.critical_count  = critical_count
    ev.composite_risk  = composite_risk
    ev.stats.has_pii   = has_pii
    ev.findings        = []
    ev.critical        = []
    return ev


def _meta(session_id="sess-001", request_id="req-abc"):
    m = MagicMock()
    m.session_id = session_id
    m.request_id = request_id
    return m


def _engine():
    return RecoveryEngine(hmac_secret=SECRET)


# ─── Init ────────────────────────────────────────────────────────────────────

class TestInit:
    def test_rejects_empty_secret(self):
        with pytest.raises(ValueError):
            RecoveryEngine(hmac_secret=b"")


# ─── Estratégias ─────────────────────────────────────────────────────────────

class TestStrategies:
    def test_allow_with_audit_low_risk(self):
        outcome = _engine().evaluate(
            _ev(), _meta(), trust_score=0.9, context={"domain": "development"}
        )
        assert outcome.strategy == RecoveryStrategy.ALLOW_WITH_AUDIT

    def test_maintain_block_critical_risk(self):
        outcome = _engine().evaluate(
            _ev(critical_count=3, composite_risk=90, has_pii=True),
            _meta(), trust_score=0.0, context={"domain": "finance"},
        )
        assert outcome.strategy == RecoveryStrategy.MAINTAIN_BLOCK

    def test_quarantine_after_repeated_violations(self):
        engine = _engine()
        ev  = _ev(composite_risk=40)
        meta = _meta(session_id="repeat-sess")
        ctx = {"domain": "general"}
        for _ in range(_QUARANTINE_VIOLATIONS - 1):
            engine.evaluate(ev, meta, trust_score=0.3, context=ctx)
        outcome = engine.evaluate(ev, meta, trust_score=0.3, context=ctx)
        assert outcome.strategy == RecoveryStrategy.QUARANTINE_SESSION

    def test_non_critical_can_degrade_or_redirect(self):
        outcome = _engine().evaluate(
            _ev(composite_risk=50, has_pii=True),
            _meta(session_id="s2"), trust_score=0.35,
            context={"domain": "general"},
        )
        assert outcome.strategy in {
            RecoveryStrategy.DEGRADE_GRACEFUL,
            RecoveryStrategy.REDIRECT_HUMAN,
            RecoveryStrategy.MAINTAIN_BLOCK,
        }


# ─── Invariantes ─────────────────────────────────────────────────────────────

class TestInvariants:
    def test_explain_decision_present_and_non_empty(self):
        outcome = _engine().evaluate(_ev(), _meta(), 0.5, {})
        assert isinstance(outcome.explain_decision, str)
        assert len(outcome.explain_decision) > 30

    def test_signature_is_64_hex_chars(self):
        outcome = _engine().evaluate(_ev(), _meta(), 0.9, {"domain": "development"})
        assert len(outcome.signature) == 64
        int(outcome.signature, 16)          # deve ser hex válido

    def test_outcome_is_frozen(self):
        outcome = _engine().evaluate(_ev(), _meta(), 0.9, {"domain": "development"})
        with pytest.raises((AttributeError, TypeError)):
            outcome.strategy = RecoveryStrategy.MAINTAIN_BLOCK  # type: ignore

    def test_non_block_contestable(self):
        outcome = _engine().evaluate(_ev(), _meta(), 0.9, {"domain": "development"})
        if outcome.strategy != RecoveryStrategy.MAINTAIN_BLOCK:
            assert outcome.contestable is True

    def test_maintain_block_not_contestable_normal_path(self):
        outcome = _engine().evaluate(
            _ev(critical_count=5, composite_risk=95, has_pii=True),
            _meta(session_id="critical"), trust_score=0.0,
            context={"domain": "finance"},
        )
        assert outcome.strategy == RecoveryStrategy.MAINTAIN_BLOCK
        assert outcome.contestable is False

    def test_sla_present_in_iso_format(self):
        outcome = _engine().evaluate(_ev(), _meta(), 0.9, {})
        from datetime import datetime
        datetime.fromisoformat(outcome.sla_deadline_iso)  # não deve lançar

    def test_to_dict_has_all_required_keys(self):
        outcome = _engine().evaluate(_ev(), _meta(), 0.5, {})
        d = outcome.to_dict()
        required = {
            "strategy", "explain_decision", "mercy_score",
            "contestable", "sla_deadline_iso", "session_id",
            "request_id", "decided_at_iso", "signature",
        }
        assert required.issubset(d.keys())


# ─── Fail-Secure ─────────────────────────────────────────────────────────────

class TestFailSecure:
    def test_fail_secure_on_internal_exception(self, monkeypatch):
        engine = _engine()
        def boom(*a, **kw):
            raise RuntimeError("simulação de falha interna")
        monkeypatch.setattr(engine._mercy, "calculate", boom)
        outcome = engine.evaluate(_ev(), _meta(), 0.5, {})
        assert outcome.strategy   == RecoveryStrategy.MAINTAIN_BLOCK
        assert "FAIL-SECURE"      in outcome.explain_decision
        assert outcome.contestable is True  # erro do sistema → Rawls exige contestabilidade
        assert len(outcome.signature) == 64
