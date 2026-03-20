"""
Dataset Loader v1.0 — Unified loader for prompt injection training data (ADR-046).

Loads and merges datasets from multiple sources:
- OWASP LLM Top 10 (curated examples)
- Tensor Trust (academic dataset)
- BTV Red-Team (internal red-team scripts)

All datasets use JSONL format with schema:
    {"text": str, "label": str, "source": str, "confidence": float}

Labels: benign, prompt_injection, evasion_attempt, pii_extraction,
        data_exfiltration, social_engineering
"""

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Optional

logger = logging.getLogger("btv.training.dataset")

DATASET_DIR = Path("data/datasets/prompt_injection")

VALID_LABELS = {
    "benign", "prompt_injection", "evasion_attempt",
    "pii_extraction", "data_exfiltration", "social_engineering",
}


@dataclass(frozen=True)
class TrainingSample:
    """Single training sample."""
    text: str
    label: str
    source: str
    confidence: float

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "label": self.label,
            "source": self.source,
            "confidence": self.confidence,
        }


class DatasetLoader:
    """
    Loads and validates training datasets from JSONL files.

    Usage:
        loader = DatasetLoader()
        samples = loader.load_all()
        train, test = loader.split(samples, test_ratio=0.2)
    """

    def __init__(self, dataset_dir: Optional[str] = None) -> None:
        self._dir = Path(dataset_dir) if dataset_dir else DATASET_DIR

    def load_file(self, path: Path) -> List[TrainingSample]:
        """Load a single JSONL file, skipping invalid lines."""
        samples = []
        if not path.is_file():
            logger.warning("Dataset file not found: %s", path)
            return samples

        with open(path, encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    data = json.loads(stripped)
                    text = data.get("text", "").strip()
                    label = data.get("label", "").strip()
                    if not text or label not in VALID_LABELS:
                        logger.warning(
                            "%s:%d — invalid sample (text=%r, label=%r)",
                            path.name, line_num, text[:50], label,
                        )
                        continue
                    samples.append(TrainingSample(
                        text=text,
                        label=label,
                        source=data.get("source", path.stem),
                        confidence=float(data.get("confidence", 1.0)),
                    ))
                except (json.JSONDecodeError, KeyError, TypeError) as exc:
                    logger.warning("%s:%d — parse error: %s", path.name, line_num, exc)

        logger.info("Loaded %d samples from %s", len(samples), path.name)
        return samples

    def load_all(self) -> List[TrainingSample]:
        """Load all JSONL files from dataset directory."""
        all_samples: List[TrainingSample] = []
        if not self._dir.is_dir():
            logger.error("Dataset directory not found: %s", self._dir)
            return all_samples

        for path in sorted(self._dir.glob("*.jsonl")):
            all_samples.extend(self.load_file(path))

        logger.info(
            "Total samples loaded: %d from %s",
            len(all_samples), self._dir,
        )
        return all_samples

    def split(
        self,
        samples: List[TrainingSample],
        test_ratio: float = 0.2,
        seed: int = 42,
    ) -> tuple:
        """Split samples into train/test sets. Returns (train, test)."""
        import random
        rng = random.Random(seed)
        shuffled = list(samples)
        rng.shuffle(shuffled)
        split_idx = int(len(shuffled) * (1 - test_ratio))
        return shuffled[:split_idx], shuffled[split_idx:]

    def label_distribution(self, samples: List[TrainingSample]) -> dict:
        """Return label counts for dataset analysis."""
        dist: dict = {}
        for s in samples:
            dist[s.label] = dist.get(s.label, 0) + 1
        return dist
