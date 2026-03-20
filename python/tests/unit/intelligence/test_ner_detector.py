"""Tests for NER Detector (ADR-047)."""

import pytest
from unittest.mock import MagicMock

from buildtovalue.intelligence.ner_entities import (
    NEREntityType,
    NERFinding,
    parse_entity_type,
    ENTITY_SEVERITY,
)
from buildtovalue.intelligence.ner_detector import (
    NERDetector,
    NERInspectionResult,
)
from buildtovalue.intelligence.slm_classifier import SLMClassifier


class TestNEREntityType:
    def test_all_entity_types(self):
        types = [t.value for t in NEREntityType]
        assert "PERSON_NAME" in types
        assert "ADDRESS" in types
        assert "PARTIAL_CARD" in types
        assert "PARTIAL_DOC" in types
        assert "PHONE_NATURAL" in types
        assert "DATE_OF_BIRTH" in types
        assert "HEALTH_INFO" in types
        assert "FINANCIAL_INFO" in types

    def test_severity_mapping(self):
        assert ENTITY_SEVERITY[NEREntityType.HEALTH_INFO] == 0.8
        assert ENTITY_SEVERITY[NEREntityType.PARTIAL_CARD] == 0.7
        assert ENTITY_SEVERITY[NEREntityType.PERSON_NAME] == 0.4


class TestParseEntityType:
    def test_exact_match(self):
        assert parse_entity_type("ADDRESS") == NEREntityType.ADDRESS
        assert parse_entity_type("PERSON_NAME") == NEREntityType.PERSON_NAME

    def test_case_insensitive(self):
        assert parse_entity_type("address") == NEREntityType.ADDRESS

    def test_aliases(self):
        assert parse_entity_type("NAME") == NEREntityType.PERSON_NAME
        assert parse_entity_type("CPF") == NEREntityType.PARTIAL_DOC
        assert parse_entity_type("SSN") == NEREntityType.PARTIAL_DOC
        assert parse_entity_type("PHONE") == NEREntityType.PHONE_NATURAL
        assert parse_entity_type("SALARY") == NEREntityType.FINANCIAL_INFO

    def test_unknown_returns_unknown(self):
        assert parse_entity_type("FOOBAR") == NEREntityType.UNKNOWN


class TestNERFinding:
    def test_severity_from_type(self):
        f = NERFinding(
            entity_type=NEREntityType.HEALTH_INFO,
            text="diabetes tipo 2",
            confidence=0.9,
        )
        assert f.severity == 0.8

    def test_is_high_risk(self):
        f = NERFinding(
            entity_type=NEREntityType.PARTIAL_CARD,
            text="4532",
            confidence=0.85,
        )
        assert f.is_high_risk is True

    def test_not_high_risk_low_confidence(self):
        f = NERFinding(
            entity_type=NEREntityType.PARTIAL_CARD,
            text="4532",
            confidence=0.3,
        )
        assert f.is_high_risk is False

    def test_to_finding_dict(self):
        f = NERFinding(
            entity_type=NEREntityType.ADDRESS,
            text="Rua Augusta 1200",
            confidence=0.9,
            start=10,
            end=27,
        )
        d = f.to_finding_dict()
        assert d["module"] == "NER_DETECTOR"
        assert d["rule_id"] == "NER_SEMANTIC_ADDRESS"
        assert d["matched_text"] == "Rua Augusta 1200"
        assert d["start"] == 10
        assert d["end"] == 27


class TestNERInspectionResult:
    def test_has_pii(self):
        result = NERInspectionResult(
            findings=[NERFinding(NEREntityType.ADDRESS, "Rua X", 0.9)],
            latency_ms=10.0,
            model_id="test",
            input_len=50,
        )
        assert result.has_pii is True

    def test_no_pii(self):
        result = NERInspectionResult(
            findings=[],
            latency_ms=5.0,
            model_id="test",
            input_len=50,
        )
        assert result.has_pii is False

    def test_high_risk_findings(self):
        result = NERInspectionResult(
            findings=[
                NERFinding(NEREntityType.ADDRESS, "Rua X", 0.9),
                NERFinding(NEREntityType.HEALTH_INFO, "diabetes", 0.85),
                NERFinding(NEREntityType.PERSON_NAME, "João", 0.5),
            ],
            latency_ms=10.0,
            model_id="test",
            input_len=100,
        )
        high_risk = result.high_risk_findings
        assert len(high_risk) == 1  # Only HEALTH_INFO (severity 0.8 * confidence 0.85)

    def test_to_dict(self):
        result = NERInspectionResult(
            findings=[NERFinding(NEREntityType.ADDRESS, "Rua X", 0.9)],
            latency_ms=10.0,
            model_id="test",
            input_len=50,
        )
        d = result.to_dict()
        assert d["has_pii"] is True
        assert d["finding_count"] == 1
        assert len(d["findings"]) == 1


class TestNERDetector:
    def test_fail_open_when_slm_not_loaded(self):
        slm = SLMClassifier(model_path=None)
        detector = NERDetector(slm)
        result = detector.detect("moro na Rua Augusta 1200")
        assert result.has_pii is False
        assert result.findings == []

    def test_short_input_returns_empty(self):
        slm = SLMClassifier(model_path=None)
        detector = NERDetector(slm)
        result = detector.detect("ab")
        assert result.findings == []

    def test_metrics_tracking(self):
        slm = SLMClassifier(model_path=None)
        detector = NERDetector(slm)
        detector.detect("test input text")
        metrics = detector.get_metrics()
        assert "detections" in metrics
        assert "avg_latency_ms" in metrics

    def test_parse_entities_valid(self):
        slm = SLMClassifier(model_path=None)
        detector = NERDetector(slm)
        raw = [
            {"type": "ADDRESS", "text": "Rua Augusta 1200", "confidence": 0.9},
            {"type": "PERSON_NAME", "text": "João", "confidence": 0.8},
        ]
        findings = detector._parse_entities(raw, "moro na Rua Augusta 1200, sou João")
        assert len(findings) == 2
        assert findings[0].entity_type == NEREntityType.ADDRESS
        assert findings[1].entity_type == NEREntityType.PERSON_NAME

    def test_parse_entities_skips_empty_text(self):
        slm = SLMClassifier(model_path=None)
        detector = NERDetector(slm)
        raw = [{"type": "ADDRESS", "text": "", "confidence": 0.9}]
        findings = detector._parse_entities(raw, "some text")
        assert len(findings) == 0
