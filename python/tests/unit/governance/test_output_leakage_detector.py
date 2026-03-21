"""Tests for OutputLeakageDetector — Gap G."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from buildtovalue.governance.output_leakage_detector import (
    OutputLeakageDetector,
    _ngram_similarity,
)
from buildtovalue.governance.types import ActionType


@pytest.fixture
def policy_path(tmp_path: Path) -> Path:
    policy = {
        "schema_version": "1.0",
        "ngram_similarity_threshold": 0.35,
        "ngram_size": 3,
        "indicator_phrases": [
            "my instructions are",
            "here is my prompt",
        ],
        "structural_patterns": [
            r"system\s*prompt\s*:.*\n",
            r"You are a .{10,200} assistant",
        ],
    }
    p = tmp_path / "leakage_patterns.yaml"
    p.write_text(yaml.dump(policy))
    return p


@pytest.fixture
def detector(policy_path: Path) -> OutputLeakageDetector:
    return OutputLeakageDetector(policy_path=policy_path)


class TestExactSubstring:
    def test_exact_prompt_leaked(self, detector: OutputLeakageDetector) -> None:
        prompt = "You must always respond in JSON format with strict validation"
        output = f"Sure! {prompt} That's what I do."
        r = detector.detect(output, [prompt])
        assert r.leaked is True
        assert r.confidence == 1.0
        assert r.action == ActionType.BLOCK

    def test_short_prompt_not_matched(self, detector: OutputLeakageDetector) -> None:
        r = detector.detect("Hello world", ["Hi"])
        assert r.leaked is False


class TestNgramSimilarity:
    def test_high_similarity_detected(self, detector: OutputLeakageDetector) -> None:
        prompt = "always respond carefully and validate all user input before processing"
        output = "I always respond carefully and validate all user input before sending"
        r = detector.detect(output, [prompt])
        assert r.leaked is True
        assert r.confidence >= 0.35

    def test_low_similarity_passes(self, detector: OutputLeakageDetector) -> None:
        prompt = "You are a medical assistant with deep knowledge"
        output = "The weather today is sunny and warm"
        r = detector.detect(output, [prompt])
        assert r.action == ActionType.ALLOW


class TestIndicatorPhrases:
    def test_indicator_detected(self, detector: OutputLeakageDetector) -> None:
        r = detector.detect("Well, my instructions are to help users", [])
        assert r.leaked is True
        assert "indicator" in r.explain.lower()

    def test_no_indicator_passes(self, detector: OutputLeakageDetector) -> None:
        r = detector.detect("Here is your answer: 42", [])
        assert r.leaked is False


class TestStructuralPatterns:
    def test_system_prompt_structure(self, detector: OutputLeakageDetector) -> None:
        output = "You are a helpful medical diagnosis assistant that provides care"
        r = detector.detect(output, [])
        assert r.leaked is True
        assert r.action == ActionType.BLOCK

    def test_normal_output_passes(self, detector: OutputLeakageDetector) -> None:
        r = detector.detect("The test results show normal values.", [])
        assert r.leaked is False


class TestEdgeCases:
    def test_empty_output(self, detector: OutputLeakageDetector) -> None:
        r = detector.detect("", [])
        assert r.leaked is False
        assert r.action == ActionType.ALLOW

    def test_no_policy(self) -> None:
        d = OutputLeakageDetector()
        r = d.detect("Some output text", [])
        assert r.leaked is False

    def test_hmac_present(self, detector: OutputLeakageDetector) -> None:
        r = detector.detect("test", [])
        assert len(r.hmac_sha256) == 64


class TestNgramFunction:
    def test_identical_texts(self) -> None:
        assert _ngram_similarity("a b c d e", "a b c d e", 3) == 1.0

    def test_empty_text(self) -> None:
        assert _ngram_similarity("", "a b c", 3) == 0.0

    def test_disjoint_texts(self) -> None:
        assert _ngram_similarity("a b c d", "x y z w", 3) == 0.0


class TestDetectAndSanitize:
    def test_sanitize_exact_match(self, detector: OutputLeakageDetector) -> None:
        prompt = "You must always respond in JSON format with strict validation"
        output = f"Sure! {prompt} That's what I do."
        r = detector.detect_and_sanitize(output, [prompt])
        assert r.leaked is True
        assert "[SYSTEM CONTENT REDACTED]" in r.sanitized_output
        assert prompt not in r.sanitized_output

    def test_sanitize_no_leak(self, detector: OutputLeakageDetector) -> None:
        r = detector.detect_and_sanitize("Normal output", [])
        assert r.leaked is False
        assert r.sanitized_output == "Normal output"

    def test_sanitize_indicator_replaces_all(self, detector: OutputLeakageDetector) -> None:
        r = detector.detect_and_sanitize("Well, my instructions are to help", [])
        assert r.leaked is True
        assert r.sanitized_output == "[SYSTEM CONTENT REDACTED]"

    def test_sanitized_output_has_hmac(self, detector: OutputLeakageDetector) -> None:
        r = detector.detect_and_sanitize("test output", [])
        assert len(r.hmac_sha256) == 64
