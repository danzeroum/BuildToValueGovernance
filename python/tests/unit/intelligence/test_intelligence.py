"""Tests for Intelligence Hub v2.0."""

import pytest
from buildtovalue.intelligence.misp_ingestor import MispIngestor, ThreatEvent
from buildtovalue.intelligence.threat_classifier import ThreatClassifier
from buildtovalue.intelligence.policy_generator import PolicyGenerator


@pytest.fixture
def ingestor():
    return MispIngestor()


@pytest.fixture
def classifier():
    return ThreatClassifier()


@pytest.fixture
def generator():
    return PolicyGenerator()


class TestMispIngestor:

    def test_ingest_and_hash(self, ingestor):
        event = ThreatEvent(id="t-001", threat_type="prompt_injection", severity=9, source="OWASP")
        result = ingestor.ingest(event)
        assert result.hash != ""
        assert result.verify_integrity()

    def test_query_by_type(self, ingestor):
        ingestor.ingest(ThreatEvent(id="t-001", threat_type="pii_leakage", severity=8, source="MISP"))
        ingestor.ingest(ThreatEvent(id="t-002", threat_type="pii_leakage", severity=7, source="STIX"))
        ingestor.ingest(ThreatEvent(id="t-003", threat_type="prompt_injection", severity=9, source="OWASP"))

        results = ingestor.query_by_type("pii_leakage")
        assert len(results) == 2

    def test_query_by_severity(self, ingestor):
        ingestor.ingest(ThreatEvent(id="t-001", threat_type="a", severity=3, source="X"))
        ingestor.ingest(ThreatEvent(id="t-002", threat_type="b", severity=8, source="X"))
        ingestor.ingest(ThreatEvent(id="t-003", threat_type="c", severity=9, source="X"))

        results = ingestor.query_by_severity(7)
        assert len(results) == 2
        assert results[0].severity >= results[1].severity

    def test_count(self, ingestor):
        assert ingestor.count() == 0
        ingestor.ingest(ThreatEvent(id="t-001", threat_type="x", severity=5, source="X"))
        assert ingestor.count() == 1


class TestThreatClassifier:

    def test_known_threat(self, classifier):
        event = ThreatEvent(id="t-001", threat_type="prompt_injection", severity=9, source="OWASP")
        c = classifier.classify(event)
        assert c.category == "AI_ATTACK"
        assert c.recommended_action == "BLOCK"
        assert c.confidence == 0.9

    def test_unknown_threat(self, classifier):
        event = ThreatEvent(id="t-001", threat_type="alien_attack", severity=5, source="?")
        c = classifier.classify(event)
        assert c.category == "UNKNOWN"
        assert c.confidence == 0.3

    def test_batch(self, classifier):
        events = [
            ThreatEvent(id="1", threat_type="pii_leakage", severity=8, source="X"),
            ThreatEvent(id="2", threat_type="denial_of_service", severity=6, source="X"),
        ]
        results = classifier.classify_batch(events)
        assert len(results) == 2


class TestPolicyGenerator:

    def test_generate_single(self, generator, classifier):
        event = ThreatEvent(id="t-001", threat_type="prompt_injection", severity=9, source="OWASP")
        c = classifier.classify(event)
        yaml_out = generator.generate(c)
        assert "prompt_injection" in yaml_out
        assert "BLOCK" in yaml_out

    def test_generate_batch(self, generator, classifier):
        events = [
            ThreatEvent(id="1", threat_type="pii_leakage", severity=8, source="X"),
            ThreatEvent(id="2", threat_type="data_exfiltration", severity=9, source="X"),
        ]
        classifications = classifier.classify_batch(events)
        yaml_out = generator.generate_batch(classifications)
        assert "policies:" in yaml_out
        assert "pii_leakage" in yaml_out
