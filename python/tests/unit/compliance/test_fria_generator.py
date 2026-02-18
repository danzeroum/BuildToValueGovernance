"""
B3: FRIA Generator tests.
"""

import pytest
from buildtovalue.compliance.fria_generator import FRIAGenerator, FRIADocument


@pytest.fixture
def gen():
    return FRIAGenerator()


class TestFRIABasic:

    def test_generates_10_sections(self, gen):
        doc = gen.generate("agent-1", "HIGH_RISK", "healthcare")
        assert doc.total_sections == 10

    def test_agent_id_preserved(self, gen):
        doc = gen.generate("my-agent", "HIGH_RISK", "employment")
        assert doc.agent_id == "my-agent"

    def test_generated_at_present(self, gen):
        doc = gen.generate("a", "MINIMAL_RISK", "general")
        assert "T" in doc.generated_at  # ISO format

    def test_summary_contains_agent(self, gen):
        doc = gen.generate("bot-x", "HIGH_RISK", "banking")
        assert "bot-x" in doc.summary


class TestAutoFill:

    def test_transparency_auto_filled(self, gen):
        doc = gen.generate("a", "HIGH_RISK", "healthcare", compliance_rate=0.9)
        s3 = next(s for s in doc.sections if s.section_id == "FRIA-3")
        assert not s3.manual_required
        assert "90%" in s3.auto_answer

    def test_oversight_auto_filled(self, gen):
        doc = gen.generate(
            "a", "HIGH_RISK", "healthcare",
            obligations=["Human oversight mechanisms (Art. 14)"],
        )
        s4 = next(s for s in doc.sections if s.section_id == "FRIA-4")
        assert "applicable" in s4.auto_answer

    def test_contestability_auto_filled(self, gen):
        doc = gen.generate("a", "HIGH_RISK", "general")
        s9 = next(s for s in doc.sections if s.section_id == "FRIA-9")
        assert not s9.manual_required
        assert "24h" in s9.auto_answer


class TestRiskIndicators:

    def test_healthcare_data_high(self, gen):
        doc = gen.generate("a", "HIGH_RISK", "healthcare")
        s2 = next(s for s in doc.sections if s.section_id == "FRIA-2")
        assert s2.risk_indicator == "HIGH"

    def test_general_data_low(self, gen):
        doc = gen.generate("a", "MINIMAL_RISK", "general")
        s2 = next(s for s in doc.sections if s.section_id == "FRIA-2")
        assert s2.risk_indicator == "LOW"

    def test_bias_violations_raise_risk(self, gen):
        viols = [{"requirement": "Bias testing required", "framework": "NIST", "article": "2.3"}]
        doc = gen.generate("a", "HIGH_RISK", "employment", violations=viols)
        s5 = next(s for s in doc.sections if s.section_id == "FRIA-5")
        assert s5.risk_indicator == "HIGH"
        assert s5.manual_required

    def test_prohibited_mitigation_high(self, gen):
        doc = gen.generate("a", "PROHIBITED", "general")
        s10 = next(s for s in doc.sections if s.section_id == "FRIA-10")
        assert s10.risk_indicator == "HIGH"


class TestOverallRisk:

    def test_minimal_no_violations(self, gen):
        doc = gen.generate("a", "MINIMAL_RISK", "general")
        assert doc.overall_risk in ("LOW", "MEDIUM")

    def test_healthcare_higher_risk(self, gen):
        doc = gen.generate("a", "HIGH_RISK", "healthcare")
        assert doc.overall_risk in ("MEDIUM", "HIGH")


class TestSerialization:

    def test_to_dict(self, gen):
        doc = gen.generate("a", "HIGH_RISK", "healthcare")
        d = doc.to_dict()
        assert d["agent_id"] == "a"
        assert d["total_sections"] == 10
        assert len(d["sections"]) == 10
        assert "section_id" in d["sections"][0]

    def test_manual_count(self, gen):
        doc = gen.generate("a", "HIGH_RISK", "healthcare")
        assert doc.manual_pending > 0
        assert doc.auto_filled + doc.manual_pending == 10