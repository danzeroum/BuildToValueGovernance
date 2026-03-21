"""Tests for SLM Medium-Zone Classification (ADR-046)."""

import pytest
from unittest.mock import MagicMock, patch

from buildtovalue.intelligence.slm_classifier import (
    SLMClassifier,
    SLMClassification,
    IntentLabel,
    MEDIUM_ZONE_PROMPT,
    NER_EXTRACTION_PROMPT,
)


class TestIntentLabel:
    def test_evasion_attempt_exists(self):
        assert IntentLabel.EVASION_ATTEMPT == "evasion_attempt"

    def test_all_labels(self):
        labels = [l.value for l in IntentLabel]
        assert "evasion_attempt" in labels
        assert "prompt_injection" in labels
        assert "benign" in labels


class TestMediumZonePrompt:
    def test_prompt_contains_evasion_keywords(self):
        assert "semantic evasion" in MEDIUM_ZONE_PROMPT
        assert "paraphrasing" in MEDIUM_ZONE_PROMPT.lower() or "Paraphrased" in MEDIUM_ZONE_PROMPT

    def test_prompt_has_input_placeholder(self):
        assert "{input_text}" in MEDIUM_ZONE_PROMPT


class TestNERPrompt:
    def test_prompt_contains_entity_types(self):
        assert "PERSON_NAME" in NER_EXTRACTION_PROMPT
        assert "ADDRESS" in NER_EXTRACTION_PROMPT
        assert "PARTIAL_CARD" in NER_EXTRACTION_PROMPT

    def test_prompt_has_input_placeholder(self):
        assert "{input_text}" in NER_EXTRACTION_PROMPT


class TestClassifyMediumZone:
    def test_returns_fail_open_when_not_loaded(self):
        classifier = SLMClassifier(model_path=None)
        result = classifier.classify_medium_zone("test input")
        assert result.intent == IntentLabel.BENIGN
        assert result.confidence == 0.0

    def test_returns_fail_open_for_short_input(self):
        classifier = SLMClassifier(model_path=None)
        result = classifier.classify_medium_zone("ab")
        assert result.intent == IntentLabel.BENIGN
        assert result.confidence == 0.0

    def test_metrics_updated_on_fail_open(self):
        classifier = SLMClassifier(model_path=None)
        classifier.classify_medium_zone("test")
        metrics = classifier.get_metrics()
        # No classifications counted for fail-open
        assert metrics["model_loaded"] is False


class TestExtractEntities:
    def test_returns_empty_when_not_loaded(self):
        classifier = SLMClassifier(model_path=None)
        result = classifier.extract_entities("moro na Rua Augusta 1200")
        assert result == []

    def test_returns_empty_for_short_input(self):
        classifier = SLMClassifier(model_path=None)
        result = classifier.extract_entities("ab")
        assert result == []


class TestClassificationResult:
    def test_evasion_is_malicious(self):
        result = SLMClassification(
            intent=IntentLabel.EVASION_ATTEMPT,
            risk=0.85,
            confidence=0.9,
            model_id="test",
            latency_ms=10.0,
        )
        assert result.is_malicious is True

    def test_evasion_low_risk_not_malicious(self):
        result = SLMClassification(
            intent=IntentLabel.EVASION_ATTEMPT,
            risk=0.3,
            confidence=0.9,
            model_id="test",
            latency_ms=10.0,
        )
        assert result.is_malicious is False

    def test_to_finding_dict(self):
        result = SLMClassification(
            intent=IntentLabel.EVASION_ATTEMPT,
            risk=0.85,
            confidence=0.9,
            model_id="test-model",
            latency_ms=10.0,
        )
        finding = result.to_finding_dict()
        assert finding["module"] == "SLM_CLASSIFIER"
        assert finding["rule_id"] == "SLM_SEMANTIC_EVASION_ATTEMPT"
        assert finding["label"] == "evasion_attempt"
