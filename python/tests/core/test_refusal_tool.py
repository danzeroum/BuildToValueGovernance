"""
Tests: RefusalGate + REFUSE action — GovernanceGateway v1.1.0
MOSAIC-inspired refusal como ação terminal auditável (ICLR 2026).

pytest python/tests/core/test_refusal_tool.py -v
"""
import json
import pytest
from unittest.mock import MagicMock

from buildtovalue.core.governance_gateway import (
    GovernanceGateway,
    GatewayVerdict,
    RefusalConfig,
)
from buildtovalue.governance.context_engine import (
    EthicalContextEngine,
    RequestContext,
    RustEvidence,
    EthicalVerdict,
)
from buildtovalue.governance.context_sanitizer import (
    ContextSanitizer,
    SanitizationLevel,
)
from buildtovalue.governance.durable_ledger import DurableLedger
from buildtovalue.intelligence.payload_inspector import (
    PayloadInspector,
    InjectionSignal,
    InspectionAction,
)

SECRET = b"btv-test-refusal-hmac"


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _mock_sanitizer(safe: bool = True) -> MagicMock:
    san = MagicMock(spec=ContextSanitizer)
    report = MagicMock()
    report.level = SanitizationLevel.CLEAN if safe else SanitizationLevel.REJECTED
    report.changes = ()
    report.is_safe.return_value = safe
    report.sanitized = _ctx()
    san.sanitize.return_value = report
    return san


def _mock_inspector(action: InspectionAction = InspectionAction.ALLOW) -> MagicMock:
    insp = MagicMock(spec=PayloadInspector)
    report = MagicMock()
    report.action = action
    report.injection_signal = InjectionSignal.CLEAN
    report.slm_classification = None
    insp.inspect.return_value = report
    return insp


def _mock_engine(final_action: str = "ALLOW") -> MagicMock:
    eng = MagicMock(spec=EthicalContextEngine)
    verdict = MagicMock(spec=EthicalVerdict)
    verdict.final_action = final_action
    verdict.original_action = "ALLOW"
    verdict.mercy_applied = False
    eng.decide.return_value = verdict
    return eng


def _ctx(**kw) -> RequestContext:
    defaults = dict(
        agent_id="a1", session_id="s1",
        domain="general", user_role="user",
    )
    defaults.update(kw)
    return RequestContext(**defaults)


def _evidence(critical_count: int = 0) -> RustEvidence:
    return RustEvidence(
        composite_risk=0.5,
        finding_count=max(critical_count, 0),
        critical_count=critical_count,
        entropy=3.5,
        total_chars=100,
        policy_action="ALLOW",
        blake3_hash="a" * 64,
    )


def _gateway(
    refusal_config: RefusalConfig = None,
    ledger=None,
    sanitizer=None,
    inspector=None,
    engine=None,
) -> GovernanceGateway:
    return GovernanceGateway(
        hmac_secret=SECRET,
        ethical_engine=engine or _mock_engine(),
        sanitizer=sanitizer or _mock_sanitizer(),
        inspector=inspector or _mock_inspector(),
        refusal_config=refusal_config,
        ledger=ledger,
    )


# ─── RefusalConfig ────────────────────────────────────────────────────────────

class TestRefusalConfig:
    def test_default_config_enabled(self):
        """RefusalConfig padrão tem gate habilitado."""
        cfg = RefusalConfig()
        assert cfg.enabled is True

    def test_default_min_critical_findings_one(self):
        """RefusalConfig padrão requer apenas 1 finding crítico."""
        cfg = RefusalConfig()
        assert cfg.min_critical_findings == 1

    def test_default_persist_to_ledger(self):
        """RefusalConfig padrão persiste no ledger."""
        cfg = RefusalConfig()
        assert cfg.persist_to_ledger is True

    def test_refusal_config_is_frozen(self):
        """RefusalConfig é imutável (frozen=True)."""
        cfg = RefusalConfig()
        with pytest.raises((AttributeError, TypeError)):
            cfg.enabled = False  # type: ignore


# ─── Gate desabilitado ────────────────────────────────────────────────────────

class TestRefusalGateDisabled:
    def test_no_refuse_when_config_none(self):
        """Sem RefusalConfig → gate inativo, ALLOW passa."""
        gw = _gateway(refusal_config=None)
        r = gw.evaluate("payload", _ctx(), _evidence(critical_count=5))
        assert r.action != "REFUSE"

    def test_no_refuse_when_config_disabled(self):
        """RefusalConfig(enabled=False) → gate inativo."""
        cfg = RefusalConfig(enabled=False)
        gw = _gateway(refusal_config=cfg)
        r = gw.evaluate("payload", _ctx(), _evidence(critical_count=5))
        assert r.action != "REFUSE"

    def test_no_refuse_when_below_threshold(self):
        """critical_count=0 < min_critical_findings=1 → sem recusa."""
        cfg = RefusalConfig(enabled=True, min_critical_findings=1)
        gw = _gateway(refusal_config=cfg)
        r = gw.evaluate("payload", _ctx(), _evidence(critical_count=0))
        assert r.action != "REFUSE"

    def test_threshold_custom_not_reached(self):
        """critical_count=2, min_critical_findings=3 → sem recusa."""
        cfg = RefusalConfig(enabled=True, min_critical_findings=3)
        gw = _gateway(refusal_config=cfg)
        r = gw.evaluate("payload", _ctx(), _evidence(critical_count=2))
        assert r.action != "REFUSE"


# ─── Gate disparado ───────────────────────────────────────────────────────────

class TestRefusalGateTriggered:
    def test_refuse_on_critical_findings(self):
        """critical_count >= threshold → ação REFUSE."""
        cfg = RefusalConfig(enabled=True, min_critical_findings=1)
        gw = _gateway(refusal_config=cfg)
        r = gw.evaluate("payload", _ctx(), _evidence(critical_count=1))
        assert r.action == "REFUSE"

    def test_refuse_blocked_at_refusal_gate(self):
        """Veredicto REFUSE tem blocked_at='refusal_gate'."""
        cfg = RefusalConfig(enabled=True, min_critical_findings=1)
        gw = _gateway(refusal_config=cfg)
        r = gw.evaluate("payload", _ctx(), _evidence(critical_count=2))
        assert r.blocked_at == "refusal_gate"

    def test_refuse_explain_contains_refusal_gate(self):
        """explain_decision menciona RefusalGate."""
        cfg = RefusalConfig(enabled=True, min_critical_findings=1)
        gw = _gateway(refusal_config=cfg)
        r = gw.evaluate("payload", _ctx(), _evidence(critical_count=1))
        assert "RefusalGate" in r.explain_decision

    def test_refuse_explain_contains_jonas(self):
        """explain_decision menciona Jonas (invariante filosófico)."""
        cfg = RefusalConfig(enabled=True, min_critical_findings=1)
        gw = _gateway(refusal_config=cfg)
        r = gw.evaluate("payload", _ctx(), _evidence(critical_count=1))
        assert "Jonas" in r.explain_decision

    def test_refuse_explain_contains_contestable(self):
        """explain_decision menciona contestabilidade (Rawls)."""
        cfg = RefusalConfig(enabled=True, min_critical_findings=1)
        gw = _gateway(refusal_config=cfg)
        r = gw.evaluate("payload", _ctx(), _evidence(critical_count=1))
        assert "contestation" in r.explain_decision.lower() or "contestável" in r.explain_decision.lower()

    def test_refuse_signature_is_64_hex(self):
        """Assinatura HMAC-SHA256 de 64 caracteres hex."""
        cfg = RefusalConfig(enabled=True, min_critical_findings=1)
        gw = _gateway(refusal_config=cfg)
        r = gw.evaluate("payload", _ctx(), _evidence(critical_count=1))
        assert len(r.signature) == 64
        int(r.signature, 16)

    def test_refuse_verdict_is_frozen(self):
        """GatewayVerdict com REFUSE é imutável."""
        cfg = RefusalConfig(enabled=True, min_critical_findings=1)
        gw = _gateway(refusal_config=cfg)
        r = gw.evaluate("payload", _ctx(), _evidence(critical_count=1))
        with pytest.raises((AttributeError, TypeError)):
            r.action = "ALLOW"  # type: ignore

    def test_refuse_requires_irreversible_flag_when_configured(self):
        """require_irreversible_flag=True: sem flag → não recusa."""
        cfg = RefusalConfig(
            enabled=True,
            min_critical_findings=1,
            require_irreversible_flag=True,
        )
        gw = _gateway(refusal_config=cfg)
        # irreversible=False (padrão) → gate não dispara
        r = gw.evaluate("payload", _ctx(), _evidence(critical_count=5))
        assert r.action != "REFUSE"

    def test_refuse_with_irreversible_flag_when_required(self):
        """require_irreversible_flag=True + irreversible=True → recusa."""
        cfg = RefusalConfig(
            enabled=True,
            min_critical_findings=1,
            require_irreversible_flag=True,
        )
        gw = _gateway(refusal_config=cfg)
        r = gw.evaluate(
            "payload", _ctx(), _evidence(critical_count=1),
            irreversible=True,
        )
        assert r.action == "REFUSE"

    def test_refuse_skips_ethical_engine(self):
        """Quando REFUSE dispara, EthicalContextEngine não é chamado."""
        cfg = RefusalConfig(enabled=True, min_critical_findings=1)
        eng = _mock_engine()
        gw = _gateway(refusal_config=cfg, engine=eng)
        gw.evaluate("payload", _ctx(), _evidence(critical_count=1))
        eng.decide.assert_not_called()

    def test_threshold_at_boundary(self):
        """critical_count == min_critical_findings → recusa (limite inclusivo)."""
        cfg = RefusalConfig(enabled=True, min_critical_findings=3)
        gw = _gateway(refusal_config=cfg)
        r = gw.evaluate("payload", _ctx(), _evidence(critical_count=3))
        assert r.action == "REFUSE"

    def test_above_threshold_also_refuses(self):
        """critical_count > min_critical_findings → recusa."""
        cfg = RefusalConfig(enabled=True, min_critical_findings=2)
        gw = _gateway(refusal_config=cfg)
        r = gw.evaluate("payload", _ctx(), _evidence(critical_count=10))
        assert r.action == "REFUSE"


# ─── Persistência no DurableLedger ────────────────────────────────────────────

class TestRefusalLedgerPersistence:
    def test_refusal_persisted_to_ledger(self):
        """Recusa é persistida no DurableLedger quando configurado."""
        cfg = RefusalConfig(enabled=True, min_critical_findings=1)
        ledger = DurableLedger(hmac_key=SECRET)
        gw = _gateway(refusal_config=cfg, ledger=ledger)
        gw.evaluate("payload", _ctx(), _evidence(critical_count=1))
        assert len(ledger) == 1

    def test_ledger_entry_has_explain_decision(self):
        """Entrada no ledger tem explain_decision (Levinas)."""
        cfg = RefusalConfig(enabled=True, min_critical_findings=1)
        ledger = DurableLedger(hmac_key=SECRET)
        gw = _gateway(refusal_config=cfg, ledger=ledger)
        gw.evaluate("payload", _ctx(), _evidence(critical_count=1))
        entry = ledger.entries()[0]
        assert "explain_decision" in entry.payload

    def test_ledger_entry_type_is_refusal_record(self):
        """Entrada no ledger tem type='refusal_record'."""
        cfg = RefusalConfig(enabled=True, min_critical_findings=1)
        ledger = DurableLedger(hmac_key=SECRET)
        gw = _gateway(refusal_config=cfg, ledger=ledger)
        gw.evaluate("payload", _ctx(), _evidence(critical_count=1))
        entry = ledger.entries()[0]
        assert entry.payload["type"] == "refusal_record"

    def test_ledger_entry_has_verdict_id(self):
        """Entrada no ledger referencia verdict_id."""
        cfg = RefusalConfig(enabled=True, min_critical_findings=1)
        ledger = DurableLedger(hmac_key=SECRET)
        gw = _gateway(refusal_config=cfg, ledger=ledger)
        r = gw.evaluate("payload", _ctx(), _evidence(critical_count=1))
        entry = ledger.entries()[0]
        assert entry.payload["verdict_id"] == r.verdict_id

    def test_ledger_entry_has_critical_count(self):
        """Entrada no ledger registra o critical_count."""
        cfg = RefusalConfig(enabled=True, min_critical_findings=1)
        ledger = DurableLedger(hmac_key=SECRET)
        gw = _gateway(refusal_config=cfg, ledger=ledger)
        gw.evaluate("payload", _ctx(), _evidence(critical_count=3))
        entry = ledger.entries()[0]
        assert entry.payload["critical_count"] == 3

    def test_no_ledger_no_error(self):
        """Sem ledger configurado → sem erro, REFUSE ainda funciona."""
        cfg = RefusalConfig(enabled=True, min_critical_findings=1, persist_to_ledger=True)
        gw = _gateway(refusal_config=cfg, ledger=None)
        r = gw.evaluate("payload", _ctx(), _evidence(critical_count=1))
        assert r.action == "REFUSE"

    def test_persist_disabled_no_ledger_entry(self):
        """persist_to_ledger=False → ledger não recebe entrada."""
        cfg = RefusalConfig(enabled=True, min_critical_findings=1, persist_to_ledger=False)
        ledger = DurableLedger(hmac_key=SECRET)
        gw = _gateway(refusal_config=cfg, ledger=ledger)
        gw.evaluate("payload", _ctx(), _evidence(critical_count=1))
        assert len(ledger) == 0

    def test_ledger_chain_valid_after_refusal(self):
        """DurableLedger permanece íntegro após persistir recusa."""
        cfg = RefusalConfig(enabled=True, min_critical_findings=1)
        ledger = DurableLedger(hmac_key=SECRET)
        gw = _gateway(refusal_config=cfg, ledger=ledger)
        gw.evaluate("payload", _ctx(), _evidence(critical_count=2))
        result = ledger.verify()
        assert result.valid is True


# ─── Fail-secure ──────────────────────────────────────────────────────────────

class TestRefusalFailSecure:
    def test_fail_secure_when_refusal_check_raises(self):
        """Erro interno no gate → BLOCK fail-secure (nunca silêncio)."""
        cfg = RefusalConfig(enabled=True, min_critical_findings=1)
        gw = _gateway(refusal_config=cfg)
        # Força erro interno via monkeypath indireto (injeção no sanitizer)
        san = _mock_sanitizer(safe=True)
        san.sanitize.side_effect = RuntimeError("boom")
        gw._san = san
        r = gw.evaluate("payload", _ctx(), _evidence(critical_count=1))
        assert r.action == "BLOCK"
        assert r.blocked_at == "fail_secure"

    def test_ledger_persistence_error_does_not_block_refuse(self):
        """Erro ao persistir no ledger não impede o veredicto REFUSE."""
        cfg = RefusalConfig(enabled=True, min_critical_findings=1)
        bad_ledger = MagicMock()
        bad_ledger.append.side_effect = RuntimeError("ledger error")
        gw = _gateway(refusal_config=cfg, ledger=bad_ledger)
        r = gw.evaluate("payload", _ctx(), _evidence(critical_count=1))
        assert r.action == "REFUSE"


# ─── to_dict ──────────────────────────────────────────────────────────────────

class TestRefusalVerdictDict:
    def test_to_dict_has_action_refuse(self):
        """to_dict() expõe action=REFUSE."""
        cfg = RefusalConfig(enabled=True, min_critical_findings=1)
        gw = _gateway(refusal_config=cfg)
        r = gw.evaluate("payload", _ctx(), _evidence(critical_count=1))
        d = r.to_dict()
        assert d["action"] == "REFUSE"
        assert d["blocked_at"] == "refusal_gate"

    def test_to_dict_has_all_gateway_fields(self):
        """to_dict() inclui todos os campos de GatewayVerdict."""
        cfg = RefusalConfig(enabled=True, min_critical_findings=1)
        gw = _gateway(refusal_config=cfg)
        r = gw.evaluate("payload", _ctx(), _evidence(critical_count=1))
        d = r.to_dict()
        for k in ("verdict_id", "action", "explain_decision", "blocked_at",
                  "signature", "contestable", "decided_at_iso"):
            assert k in d
