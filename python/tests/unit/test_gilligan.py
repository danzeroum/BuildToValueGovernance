"""
tests/unit/test_gilligan.py — Testes de unidade para GilliganStage (PROP-030).

Cobertura:
- Cenário baixo risco + alta confiança → soften
- Cenário alto risco + PII → block
- explain_decision() obrigatório com tags [Gilligan/Care P-030]
- Fail-secure em evidência None
- first_offense aumenta mercy
- Campos result bem tipados
"""
from unittest.mock import MagicMock
import pytest

from buildtovalue.governance.gilligan import GilliganStage, GilliganStageResult


def _make_evidence(critical_count: int = 0, composite_risk: float = 20.0, has_pii: bool = False):
    """Cria TechnicalEvidence mockado para testes."""
    ev = MagicMock()
    ev.critical_count = critical_count
    ev.composite_risk = composite_risk
    ev.findings = []
    ev.critical = []
    ev.stats = MagicMock()
    ev.stats.has_pii = has_pii
    return ev


class TestGilliganStage:
    def test_low_harm_high_trust_soften(self):
        stage = GilliganStage()
        ev = _make_evidence(critical_count=0, composite_risk=5.0)
        result = stage.evaluate(ev, {"domain": "development", "session_id": "s_dev_1"}, trust_score=0.9)
        assert result.passed
        assert result.mercy_score > 0.5
        assert result.care_focus == "soften"

    def test_high_harm_pii_blocks(self):
        stage = GilliganStage()
        ev = _make_evidence(critical_count=2, composite_risk=90.0, has_pii=True)
        result = stage.evaluate(ev, {"domain": "finance", "session_id": "s_fin_2"}, trust_score=0.1)
        assert result.passed
        assert result.care_focus == "block"

    def test_explain_decision_format(self):
        stage = GilliganStage()
        ev = _make_evidence()
        result = stage.evaluate(ev, {"domain": "general", "session_id": "s_gen_3"})
        explanation = result.explain_decision()
        assert "[Gilligan/Care P-030]" in explanation
        assert "care_focus=" in explanation
        assert "mercy_score=" in explanation
        assert "passed=" in explanation

    def test_fail_secure_on_none_evidence(self):
        stage = GilliganStage()
        result = stage.evaluate(None, {}, trust_score=0.5)
        assert not result.passed
        assert result.care_focus == "block"
        assert result.mercy_score == 0.0
        assert result.error is not None

    def test_first_offense_flagged(self):
        stage = GilliganStage()
        ev = _make_evidence(critical_count=0, composite_risk=25.0)
        result = stage.evaluate(ev, {"domain": "general", "session_id": "unique_session_xyz"}, trust_score=0.5)
        assert result.factors is not None
        assert result.factors.first_offense is True

    def test_result_is_well_typed(self):
        stage = GilliganStage()
        ev = _make_evidence()
        result = stage.evaluate(ev, {"domain": "testing", "session_id": "s_test_4"}, trust_score=0.7)
        assert isinstance(result, GilliganStageResult)
        assert isinstance(result.mercy_score, float)
        assert result.care_focus in ("soften", "maintain", "block")
        assert result.explanation != ""
        assert result.error is None
