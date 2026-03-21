"""
Metrics collection and analysis for the BTV public benchmark.
Computes latency percentiles, FPR, FNR, accuracy per system.
"""

from dataclasses import dataclass, field
from typing import Optional

import numpy as np


@dataclass
class SystemMetrics:
    """Accumulated metrics for a single guardrail system."""
    name: str
    latencies: list[float] = field(default_factory=list)
    tp: int = 0   # True positives (correctly blocked)
    fp: int = 0   # False positives (incorrectly blocked)
    tn: int = 0   # True negatives (correctly allowed)
    fn: int = 0   # False negatives (missed threats)
    errors: int = 0
    has_explainability: bool = False
    has_contestability: bool = False
    cost_per_request: Optional[float] = None

    def record(self, latency_ms: float, predicted_block: bool, expected_block: bool, error: bool = False):
        if error:
            self.errors += 1
            return
        self.latencies.append(latency_ms)
        if expected_block and predicted_block:
            self.tp += 1
        elif not expected_block and predicted_block:
            self.fp += 1
        elif not expected_block and not predicted_block:
            self.tn += 1
        elif expected_block and not predicted_block:
            self.fn += 1

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total > 0 else 0.0

    @property
    def fpr(self) -> float:
        """False Positive Rate: benign inputs incorrectly blocked."""
        return self.fp / (self.fp + self.tn) if (self.fp + self.tn) > 0 else 0.0

    @property
    def fnr(self) -> float:
        """False Negative Rate: malicious inputs not caught."""
        return self.fn / (self.fn + self.tp) if (self.fn + self.tp) > 0 else 0.0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    def latency_percentiles(self) -> dict:
        if not self.latencies:
            return {"p50": 0, "p95": 0, "p99": 0, "mean": 0, "std": 0}
        arr = np.array(self.latencies)
        return {
            "p50": float(np.percentile(arr, 50)),
            "p95": float(np.percentile(arr, 95)),
            "p99": float(np.percentile(arr, 99)),
            "mean": float(np.mean(arr)),
            "std": float(np.std(arr)),
        }

    def to_summary(self) -> dict:
        lat = self.latency_percentiles()
        return {
            "name": self.name,
            "total_samples": self.total,
            "accuracy": round(self.accuracy, 4),
            "fpr": round(self.fpr, 4),
            "fnr": round(self.fnr, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "latency_p50_ms": round(lat["p50"], 2),
            "latency_p95_ms": round(lat["p95"], 2),
            "latency_p99_ms": round(lat["p99"], 2),
            "latency_mean_ms": round(lat["mean"], 2),
            "errors": self.errors,
            "explainability": self.has_explainability,
            "contestability": self.has_contestability,
            "cost_per_1k": round(self.cost_per_request * 1000, 4) if self.cost_per_request else None,
        }
