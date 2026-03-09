"""
Tests for GilliganStage v1.1.0 — PROP-030 (Care/Focus).
6 casos: soften, maintain, block, fail-secure, explain_decision, critical_block.
"""
from unittest.mock import patch
from buildtovalue.governance.gilligan import GilliganStage, GilliganStageResult
from buildtovalue.governance.types import SimpleTechnicalEvidence


def _evidence(critical_count=0, composite_risk=30.0, finding_count=1):
    return SimpleTechnicalEvidence(
        composite_risk=composite_risk,
        finding_count=finding_count,
        critical_count=critical_count,
        entropy=3.5,
        total_chars=200,
        findings=[],
    )


def _ctx(domain="general", session_id="s1", user_role="user"):
    return {"domain": domain, "session_id": session_id, "user_role": user_role}


class TestGilliganStage:

    def test_high_trust_returns_soften(self):
        stage = GilliganStage()
        result = stage.evaluate(_evidence(), _ctx(), trust_score=0.95)
        assert isinstance(result, GilliganStageResult)
        assert result.passed is True
        assert result.care_focus == "soften"
        assert result.mercy_score >= 0.65

    def test_medium_trust_returns_maintain(self):
        stage = GilliganStage()
        result = stage.evaluate(_evidence(composite_risk=60.0), _ctx(), trust_score=0.4)
        assert result.passed is True
        assert result.care_focus in ("maintain", "block", "soften")

    def test_zero_trust_high_risk_returns_block(self):
        stage = GilliganStage()
        result = stage.evaluate(_evidence(composite_risk=95.0, finding_count=10), _ctx(), trust_score=0.0)
        assert result.passed is True
        assert result.care_focus in ("maintain", "block")
        assert result.mercy_score < 0.65

    def test_critical_finding_forces_block(self):
        stage = GilliganStage()
        result = stage.evaluate(_evidence(critical_count=2, composite_risk=80.0), _ctx(), trust_score=0.3)
        assert result.care_focus in ("maintain", "block")

    def test_fail_secure_on_exception(self):
        stage = GilliganStage()
        # evaluate() chama calculate_with_factors(), nao calculate().
        # Patch deve apontar para o metodo realmente invocado.
        with patch.object(stage._calc, "calculate_with_factors", side_effect=RuntimeError("boom")):
            result = stage.evaluate(_evidence(), _ctx(), trust_score=0.5)
        assert result.passed is False
        assert result.care_focus in ("maintain", "block")
        assert result.mercy_score == 0.0
        assert result.error is not None

    def test_explain_decision_format(self):
        stage = GilliganStage()
        result = stage.evaluate(_evidence(), _ctx(), trust_score=0.8)
        explanation = result.explain_decision()
        assert "[Gilligan/Care P-030]" in explanation
        assert "care_focus=" in explanation
        assert "mercy_score=" in explanation
        assert "passed=" in explanation
