"""
B1: Risk Classifier tests — EU AI Act Annex III classification.
"""

import pytest
from buildtovalue.compliance.risk_classifier import (
    RiskClassifier,
    RiskLevel,
    PROHIBITED_CAPABILITIES,
    LIMITED_RISK_CAPABILITIES,
    OBLIGATIONS,
)


@pytest.fixture
def classifier():
    return RiskClassifier()


# ═══════════════════════════════════════════════════════════════
# PROHIBITED (Art. 5)
# ═══════════════════════════════════════════════════════════════

class TestProhibited:

    def test_subliminal_manipulation(self, classifier):
        r = classifier.classify(
            "agent-1", "marketing",
            capabilities=["subliminal_manipulation"],
        )
        assert r.risk_level == RiskLevel.PROHIBITED
        assert "subliminal_manipulation" in r.prohibited_detected
        assert "EUR 35M" in r.obligations[1]

    def test_social_scoring(self, classifier):
        r = classifier.classify(
            "agent-2", "general",
            capabilities=["social_scoring_public"],
        )
        assert r.risk_level == RiskLevel.PROHIBITED

    def test_multiple_prohibited(self, classifier):
        r = classifier.classify(
            "agent-3", "general",
            capabilities=[
                "real_time_biometric_public",
                "predictive_policing_profiling",
            ],
        )
        assert r.risk_level == RiskLevel.PROHIBITED
        assert len(r.prohibited_detected) == 2

    def test_prohibited_overrides_high_risk_sector(self, classifier):
        """Even if sector is high-risk, prohibited wins."""
        r = classifier.classify(
            "agent-4", "healthcare",
            capabilities=["emotion_recognition_workplace"],
        )
        assert r.risk_level == RiskLevel.PROHIBITED


# ═══════════════════════════════════════════════════════════════
# HIGH RISK (Art. 6 + Annex III)
# ═══════════════════════════════════════════════════════════════

class TestHighRisk:

    def test_healthcare_sector(self, classifier):
        r = classifier.classify("agent-5", "healthcare")
        assert r.risk_level == RiskLevel.HIGH_RISK
        assert r.annex_iii is True
        assert "Annex III" in r.reasons[0]

    def test_employment_sector(self, classifier):
        r = classifier.classify("agent-6", "employment")
        assert r.risk_level == RiskLevel.HIGH_RISK

    def test_education_sector(self, classifier):
        r = classifier.classify("agent-7", "education")
        assert r.risk_level == RiskLevel.HIGH_RISK

    def test_law_enforcement(self, classifier):
        r = classifier.classify("agent-8", "law_enforcement")
        assert r.risk_level == RiskLevel.HIGH_RISK

    def test_banking(self, classifier):
        r = classifier.classify("agent-9", "banking")
        assert r.risk_level == RiskLevel.HIGH_RISK

    def test_justice(self, classifier):
        r = classifier.classify("agent-10", "justice")
        assert r.risk_level == RiskLevel.HIGH_RISK

    def test_safety_component(self, classifier):
        """Non-Annex-III sector but safety component."""
        r = classifier.classify(
            "agent-11", "general",
            deployment_context={"safety_component": True},
        )
        assert r.risk_level == RiskLevel.HIGH_RISK
        assert r.annex_iii is False

    def test_affects_fundamental_rights(self, classifier):
        r = classifier.classify(
            "agent-12", "marketing",
            deployment_context={"affects_fundamental_rights": True},
        )
        assert r.risk_level == RiskLevel.HIGH_RISK

    def test_high_risk_has_obligations(self, classifier):
        r = classifier.classify("agent-13", "healthcare")
        assert len(r.obligations) >= 10
        assert any("Art. 9" in o for o in r.obligations)
        assert any("Art. 14" in o for o in r.obligations)
        assert any("Art. 27" in o for o in r.obligations)


# ═══════════════════════════════════════════════════════════════
# LIMITED RISK (Art. 50)
# ═══════════════════════════════════════════════════════════════

class TestLimitedRisk:

    def test_chatbot(self, classifier):
        r = classifier.classify(
            "agent-14", "general",
            capabilities=["chatbot"],
        )
        assert r.risk_level == RiskLevel.LIMITED_RISK

    def test_deepfake(self, classifier):
        r = classifier.classify(
            "agent-15", "marketing",
            capabilities=["deepfake_generation"],
        )
        assert r.risk_level == RiskLevel.LIMITED_RISK

    def test_synthetic_content(self, classifier):
        r = classifier.classify(
            "agent-16", "general_commercial",
            capabilities=["synthetic_content"],
        )
        assert r.risk_level == RiskLevel.LIMITED_RISK

    def test_limited_risk_obligations(self, classifier):
        r = classifier.classify(
            "agent-17", "general",
            capabilities=["chatbot"],
        )
        assert any("Art. 50" in o for o in r.obligations)


# ═══════════════════════════════════════════════════════════════
# MINIMAL RISK
# ═══════════════════════════════════════════════════════════════

class TestMinimalRisk:

    def test_general_no_capabilities(self, classifier):
        r = classifier.classify("agent-18", "general")
        assert r.risk_level == RiskLevel.MINIMAL_RISK
        assert r.annex_iii is False

    def test_marketing_no_capabilities(self, classifier):
        r = classifier.classify("agent-19", "marketing")
        assert r.risk_level == RiskLevel.MINIMAL_RISK

    def test_unknown_sector(self, classifier):
        """Unknown sector defaults to minimal."""
        r = classifier.classify("agent-20", "unknown_sector")
        assert r.risk_level == RiskLevel.MINIMAL_RISK

    def test_minimal_obligations(self, classifier):
        r = classifier.classify("agent-21", "general")
        assert any("Voluntary" in o for o in r.obligations)


# ═══════════════════════════════════════════════════════════════
# SERIALIZATION
# ═══════════════════════════════════════════════════════════════

class TestSerialization:

    def test_to_dict(self, classifier):
        r = classifier.classify("agent-22", "healthcare")
        d = r.to_dict()
        assert d["risk_level"] == "HIGH_RISK"
        assert d["annex_iii"] is True
        assert isinstance(d["obligations"], list)

    def test_prohibited_to_dict(self, classifier):
        r = classifier.classify(
            "agent-23", "general",
            capabilities=["social_scoring_public"],
        )
        d = r.to_dict()
        assert d["risk_level"] == "PROHIBITED"
        assert "social_scoring_public" in d["prohibited_detected"]


# ═══════════════════════════════════════════════════════════════
# PRIORITY ORDER
# ═══════════════════════════════════════════════════════════════

class TestPriority:

    def test_prohibited_beats_everything(self, classifier):
        """Prohibited + high-risk sector + limited caps → PROHIBITED."""
        r = classifier.classify(
            "agent-24", "healthcare",
            capabilities=[
                "subliminal_manipulation",
                "chatbot",
            ],
        )
        assert r.risk_level == RiskLevel.PROHIBITED

    def test_high_risk_beats_limited(self, classifier):
        """High-risk sector + limited caps → HIGH_RISK."""
        r = classifier.classify(
            "agent-25", "healthcare",
            capabilities=["chatbot"],
        )
        assert r.risk_level == RiskLevel.HIGH_RISK

    def test_sector_count(self, classifier):
        assert classifier.sector_count == 15