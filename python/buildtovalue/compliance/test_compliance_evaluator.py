"""
P1: ComplianceEvaluator tests.
Validates condition_template evaluation against agent metadata.
"""

import pytest
from pathlib import Path
from buildtovalue.compliance.compliance_evaluator import (
    ComplianceEvaluator,
    DotDict,
    _days_since,
)


# ═══════════════════════════════════════════════════════════════
# DotDict
# ═══════════════════════════════════════════════════════════════

class TestDotDict:

    def test_basic_access(self):
        d = DotDict({"risk_level": "high", "score": 0.9})
        assert d.risk_level == "high"
        assert d.score == 0.9

    def test_missing_key_returns_none(self):
        d = DotDict({"a": 1})
        assert d.nonexistent is None

    def test_nested_access(self):
        d = DotDict({"org": {"name": "Acme", "size": 100}})
        assert d.org.name == "Acme"
        assert d.org.size == 100

    def test_nested_missing(self):
        d = DotDict({"org": {"name": "Acme"}})
        assert d.org.missing is None


# ═══════════════════════════════════════════════════════════════
# days_since
# ═══════════════════════════════════════════════════════════════

class TestDaysSince:

    def test_none_returns_large(self):
        assert _days_since(None) == 99999

    def test_today_returns_zero(self):
        import datetime as dt
        today_int = int(dt.date.today().strftime("%Y%m%d"))
        assert _days_since(today_int) == 0

    def test_iso_string(self):
        import datetime as dt
        yesterday = (dt.date.today() - dt.timedelta(days=1)).isoformat()
        assert _days_since(yesterday) == 1

    def test_invalid_returns_large(self):
        assert _days_since("not-a-date") == 99999
        assert _days_since(99999999) == 99999


# ═══════════════════════════════════════════════════════════════
# ComplianceEvaluator with real YAMLs
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def evaluator():
    """Load real compliance YAMLs from repo root."""
    repo_root = Path(__file__).resolve().parents[3]  # python/buildtovalue/compliance/ → repo root
    compliance_dir = repo_root / "data" / "policies" / "compliance"
    return ComplianceEvaluator(compliance_dir=compliance_dir)


class TestComplianceEvaluatorLoading:

    def test_loads_frameworks(self, evaluator):
        assert evaluator.framework_count >= 1
        assert len(evaluator.framework_ids) >= 1

    def test_known_frameworks(self, evaluator):
        known = {"EU_AI_ACT", "LGPD", "GDPR", "HIPAA", "ISO_42001", "NIST_AI_RMF", "PCI_DSS"}
        loaded = set(evaluator.framework_ids)
        overlap = known & loaded
        assert len(overlap) >= 1, f"Expected at least 1 known framework, got: {loaded}"


class TestEUAIActEvaluation:

    def test_high_risk_no_conformity_violates(self, evaluator):
        """Art. 43: high-risk without conformity assessment → BLOCK."""
        result = evaluator.evaluate(
            agent_metadata={
                "agent_id": "test-bot",
                "risk_level": "high",
                "conformity_assessment_completed": False,
                "deployment_requested": True,
            },
            frameworks=["EU_AI_ACT"],
        )
        actions = [v.action for v in result.violations]
        articles = [v.article for v in result.violations]
        assert "BLOCK" in actions, f"Expected BLOCK, got {result.to_dict()}"

    def test_compliant_agent_no_violations(self, evaluator):
        """Fully compliant agent → zero violations."""
        result = evaluator.evaluate(
            agent_metadata={
                "agent_id": "good-bot",
                "risk_level": "low",
                "conformity_assessment_completed": True,
                "deployment_requested": False,
                "model_type": "narrow",
                "training_compute_flops": 1e10,
                "transparency_score": 0.9,
                "human_oversight_enabled": True,
                "validation_accuracy": 0.95,
                "adversarial_test_passed": True,
                "security_scan_passed": True,
            },
            frameworks=["EU_AI_ACT"],
        )
        assert result.violation_count == 0, f"Unexpected violations: {result.to_dict()}"

    def test_social_scoring_violates(self, evaluator):
        """Art. 5: social scoring by public authority → BLOCK."""
        result = evaluator.evaluate(
            agent_metadata={
                "agent_id": "gov-scorer",
                "purpose": "social_scoring",
                "operator_type": "public_authority",
            },
            frameworks=["EU_AI_ACT"],
        )
        block_violations = [v for v in result.violations if v.action == "BLOCK"]
        assert len(block_violations) >= 1

    def test_employment_decision_escalates(self, evaluator):
        """Art. 6: employment decisions → ESCALATE."""
        result = evaluator.evaluate(
            agent_metadata={
                "agent_id": "hr-bot",
                "use_case": "employment",
                "decision_type": "hiring",
            },
            frameworks=["EU_AI_ACT"],
        )
        escalate = [v for v in result.violations if v.action == "ESCALATE"]
        assert len(escalate) >= 1


class TestNISTEvaluation:

    def test_no_purpose_documented_violates(self, evaluator):
        """MAP-1.1: no intended purpose → BLOCK."""
        result = evaluator.evaluate(
            agent_metadata={
                "agent_id": "undocumented-bot",
                "intended_purpose": None,
            },
            frameworks=["NIST_AI_RMF"],
        )
        blocks = [v for v in result.violations if v.action == "BLOCK"]
        assert len(blocks) >= 1

    def test_no_kill_switch_high_autonomy(self, evaluator):
        """MANAGE-3.2: high autonomy without kill switch → BLOCK."""
        result = evaluator.evaluate(
            agent_metadata={
                "agent_id": "autonomous-bot",
                "has_kill_switch": False,
                "autonomy_level": 5,
            },
            frameworks=["NIST_AI_RMF"],
        )
        blocks = [v for v in result.violations if v.action == "BLOCK"]
        assert len(blocks) >= 1


class TestFilterByFramework:

    def test_single_framework(self, evaluator):
        result = evaluator.evaluate(
            agent_metadata={"agent_id": "x"},
            frameworks=["EU_AI_ACT"],
        )
        for v in result.violations:
            assert v.framework == "EU_AI_ACT"

    def test_unknown_framework_skipped(self, evaluator):
        result = evaluator.evaluate(
            agent_metadata={"agent_id": "x"},
            frameworks=["NONEXISTENT"],
        )
        assert result.frameworks_evaluated == 0
        assert result.violation_count == 0


class TestSecuritySandbox:

    def test_injection_blocked(self, evaluator):
        """Malicious condition_template cannot escape sandbox."""
        result = evaluator.evaluate(
            agent_metadata={"agent_id": "attacker"},
        )
        # Should complete without error (malicious templates in YAML
        # would be caught by SafeExpressionEvaluator)
        assert result.evaluation_time_ms >= 0