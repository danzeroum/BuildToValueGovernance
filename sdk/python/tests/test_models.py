"""
Unit tests for Pydantic models — validates field parsing and computed properties.
"""
import pytest
from buildtovalue.models import (
    Verdict,
    ValidateVerdict,
    Appeal,
    TrustScore,
    SanitizeResult,
    ExplainDecision,
    VerdictAction,
    AppealStatus,
)


EXPLAIN_DATA = {
    "summary": "No concerns.",
    "rawls_rationale": "Policy passed.",
    "levinas_rationale": "No duty-of-care issue.",
    "jonas_rationale": "No long-term risk.",
    "gilligan_rationale": "No mercy needed.",
    "trust_score": 0.85,
    "mercy_score": 0.0,
    "pipeline_stages": ["rawls", "levinas", "jonas", "gilligan"],
}

VERDICT_DATA = {
    "verdict_id": "VRD-01ARZ3NDEKTSV4RRFFQ69G5FAV",
    "action": "ALLOW",
    "original_action": "ALLOW",
    "mercy_applied": False,
    "finding_count": 0,
    "critical_count": 0,
    "composite_risk": 0.01,
    "hard_blocked": False,
    "contestable": False,
    "appeal_deadline_hours": 0,
    "signature": "abc123",
    "rationale": "Clean input.",
    "jurisdiction_bitmask": 1,
    "latency_ms": 12.5,
    "explain": EXPLAIN_DATA,
}

VALIDATE_DATA = {
    "verdict_id": "VRD-VAL-001",
    "action": "BLOCK",
    "original_action": "BLOCK",
    "mercy_applied": False,
    "finding_count": 2,
    "critical_count": 1,
    "composite_risk": 0.88,
    "hard_blocked": True,
    "hard_block_term": "sql_injection",
    "contestable": False,
    "appeal_deadline_hours": 0,
    "message": "SQL injection detected.",
    "matched_policies": ["sql_injection_hard_block"],
    "max_finding_confidence": 0.99,
    "entropy": 3.2,
    "total_chars": 50,
    "blake3_hash": "deadbeef",
    "drift_level": "High",
    "signature": "sig123",
    "latency_ms": 8.0,
}

APPEAL_DATA = {
    "appeal_id": "APL-001",
    "verdict_id": "VRD-01ARZ3NDEKTSV4RRFFQ69G5FAV",
    "user_id": "user-001",
    "reason": "False positive — test data only.",
    "grounds": ["false_positive", "technical_error"],
    "status": "pending",
    "submitted_at": "2026-03-20T12:00:00Z",
    "resolved_at": None,
    "resolution": None,
    "mediator_recommendation": None,
    "sla_deadline": "2026-03-21T12:00:00Z",
    "evidence_hash": None,
}


class TestExplainDecision:
    def test_parses_all_fields(self):
        explain = ExplainDecision.model_validate(EXPLAIN_DATA)
        assert explain.trust_score == 0.85
        assert explain.mercy_score == 0.0
        assert len(explain.pipeline_stages) == 4

    def test_trust_score_bounds(self):
        with pytest.raises(Exception):
            ExplainDecision.model_validate({**EXPLAIN_DATA, "trust_score": 1.5})

    def test_mercy_score_bounds(self):
        with pytest.raises(Exception):
            ExplainDecision.model_validate({**EXPLAIN_DATA, "mercy_score": -0.1})


class TestVerdict:
    def test_parses_full_verdict(self):
        v = Verdict.model_validate(VERDICT_DATA)
        assert v.action == VerdictAction.ALLOW
        assert v.verdict_id == "VRD-01ARZ3NDEKTSV4RRFFQ69G5FAV"
        assert v.explain.trust_score == 0.85

    def test_is_allowed_property(self):
        v = Verdict.model_validate(VERDICT_DATA)
        assert v.is_allowed
        assert not v.is_blocked

    def test_is_blocked_property(self):
        v = Verdict.model_validate({**VERDICT_DATA, "action": "BLOCK"})
        assert v.is_blocked
        assert not v.is_allowed

    def test_explanation_property(self):
        v = Verdict.model_validate(VERDICT_DATA)
        explanation = v.explanation
        assert "Clean input." in explanation
        assert "No concerns." in explanation

    def test_composite_risk_bounds(self):
        with pytest.raises(Exception):
            Verdict.model_validate({**VERDICT_DATA, "composite_risk": 1.5})

    def test_action_enum_validation(self):
        with pytest.raises(Exception):
            Verdict.model_validate({**VERDICT_DATA, "action": "INVALID_ACTION"})


class TestValidateVerdict:
    def test_parses_validate_verdict(self):
        v = ValidateVerdict.model_validate(VALIDATE_DATA)
        assert v.action == VerdictAction.BLOCK
        assert v.hard_blocked is True
        assert v.hard_block_term == "sql_injection"
        assert v.matched_policies == ["sql_injection_hard_block"]
        assert v.drift_level == "High"

    def test_is_blocked_property(self):
        v = ValidateVerdict.model_validate(VALIDATE_DATA)
        assert v.is_blocked
        assert not v.is_allowed

    def test_defaults_for_optional_fields(self):
        minimal = {
            "verdict_id": "VRD-MIN",
            "action": "ALLOW",
            "original_action": "ALLOW",
            "mercy_applied": False,
            "finding_count": 0,
            "critical_count": 0,
            "composite_risk": 0.0,
            "hard_blocked": False,
            "contestable": False,
            "appeal_deadline_hours": 0,
            "message": "",
            "matched_policies": [],
            "signature": "",
            "latency_ms": 1.0,
        }
        v = ValidateVerdict.model_validate(minimal)
        assert v.max_finding_confidence == 0.0
        assert v.entropy == 0.0
        assert v.total_chars == 0
        assert v.blake3_hash == ""
        assert v.drift_level == "None"
        assert v.hard_block_term is None


class TestAppeal:
    def test_parses_appeal(self):
        a = Appeal.model_validate(APPEAL_DATA)
        assert a.appeal_id == "APL-001"
        assert a.status == AppealStatus.PENDING
        assert a.is_pending
        assert not a.is_accepted
        assert "false_positive" in a.grounds

    def test_accepted_status(self):
        a = Appeal.model_validate({**APPEAL_DATA, "status": "accepted"})
        assert a.is_accepted
        assert not a.is_pending

    def test_optional_fields_default(self):
        minimal = {
            "appeal_id": "APL-MIN",
            "reason": "Test",
            "status": "pending",
        }
        a = Appeal.model_validate(minimal)
        assert a.verdict_id == ""
        assert a.grounds == []
        assert a.resolution is None


class TestTrustScore:
    def test_parses_trust_score(self):
        ts = TrustScore.model_validate({
            "session_id": "sess-001",
            "trust_score": 0.82,
            "total_requests": 10,
            "offenses": 0,
        })
        assert ts.trust_score == 0.82
        assert ts.level == "high"

    def test_level_medium(self):
        ts = TrustScore.model_validate({"session_id": "s", "trust_score": 0.65})
        assert ts.level == "medium"

    def test_level_low(self):
        ts = TrustScore.model_validate({"session_id": "s", "trust_score": 0.3})
        assert ts.level == "low"

    def test_trust_score_bounds(self):
        with pytest.raises(Exception):
            TrustScore.model_validate({"session_id": "s", "trust_score": 1.1})


class TestSanitizeResult:
    def test_parses_sanitize_result(self):
        sr = SanitizeResult.model_validate({
            "sanitized": "My [REDACTED] is hidden.",
            "redactions": 1,
            "latency_ms": 3.0,
        })
        assert sr.redactions == 1
        assert "[REDACTED]" in sr.sanitized
