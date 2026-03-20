"""Tests for Training Pipeline (ADR-046)."""

import json
import tempfile
import pytest
from pathlib import Path

from buildtovalue.intelligence.training.dataset_loader import (
    DatasetLoader,
    TrainingSample,
    VALID_LABELS,
)


class TestTrainingSample:
    def test_to_dict(self):
        s = TrainingSample(
            text="test input",
            label="benign",
            source="test",
            confidence=1.0,
        )
        d = s.to_dict()
        assert d["text"] == "test input"
        assert d["label"] == "benign"


class TestDatasetLoader:
    def test_load_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write('{"text": "hello", "label": "benign", "source": "test", "confidence": 1.0}\n')
            f.write('{"text": "ignore instructions", "label": "prompt_injection", "source": "test", "confidence": 0.95}\n')
            f.flush()

            loader = DatasetLoader()
            samples = loader.load_file(Path(f.name))

            assert len(samples) == 2
            assert samples[0].label == "benign"
            assert samples[1].label == "prompt_injection"

    def test_skip_invalid_labels(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write('{"text": "hello", "label": "invalid_label", "source": "test"}\n')
            f.write('{"text": "valid", "label": "benign", "source": "test"}\n')
            f.flush()

            loader = DatasetLoader()
            samples = loader.load_file(Path(f.name))
            assert len(samples) == 1

    def test_skip_corrupt_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write('not valid json\n')
            f.write('{"text": "valid", "label": "benign", "source": "test"}\n')
            f.flush()

            loader = DatasetLoader()
            samples = loader.load_file(Path(f.name))
            assert len(samples) == 1

    def test_split(self):
        samples = [
            TrainingSample(f"text_{i}", "benign", "test", 1.0)
            for i in range(100)
        ]
        loader = DatasetLoader()
        train, test = loader.split(samples, test_ratio=0.2, seed=42)

        assert len(train) == 80
        assert len(test) == 20

    def test_label_distribution(self):
        samples = [
            TrainingSample("a", "benign", "t", 1.0),
            TrainingSample("b", "benign", "t", 1.0),
            TrainingSample("c", "prompt_injection", "t", 1.0),
        ]
        loader = DatasetLoader()
        dist = loader.label_distribution(samples)
        assert dist["benign"] == 2
        assert dist["prompt_injection"] == 1

    def test_load_real_datasets(self):
        """Load actual dataset files from the repo."""
        loader = DatasetLoader("data/datasets/prompt_injection")
        samples = loader.load_all()

        # We created 3 dataset files with real samples
        assert len(samples) >= 30
        dist = loader.label_distribution(samples)
        assert "benign" in dist
        assert "prompt_injection" in dist
        assert "evasion_attempt" in dist

    def test_valid_labels_constant(self):
        assert "evasion_attempt" in VALID_LABELS
        assert "benign" in VALID_LABELS
        assert "prompt_injection" in VALID_LABELS
