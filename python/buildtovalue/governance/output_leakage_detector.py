"""OutputLeakageDetector — Gap G: System Prompt Leakage Detection.

Detects when an agent's output leaks its system prompt or instructions.
Three detection layers:
  1. Exact substring match against registered prompts
  2. N-gram overlap similarity scoring
  3. Known leakage indicator phrases and structural patterns

Invariants:
- Fail-secure: detection error -> BLOCK
- explain_decision in every LeakageResult
- HMAC-SHA256 signed results
- Functions <= 50 lines, file <= 200 lines
"""
from __future__ import annotations

import hashlib
import hmac as hmac_lib
import logging
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

import yaml

from .types import ActionType

logger = logging.getLogger("btv.governance.output_leakage_detector")

_DEFAULT_NGRAM_SIZE = 3
_DEFAULT_THRESHOLD = 0.35


@dataclass(frozen=True)
class LeakageResult:
    leaked: bool
    confidence: float
    action: ActionType
    explain: str
    hmac_sha256: str = ""


def _ngrams(text: str, n: int) -> Counter:
    tokens = text.lower().split()
    return Counter(
        tuple(tokens[i : i + n]) for i in range(len(tokens) - n + 1)
    )


def _ngram_similarity(text_a: str, text_b: str, n: int) -> float:
    if not text_a or not text_b:
        return 0.0
    ng_a = _ngrams(text_a, n)
    ng_b = _ngrams(text_b, n)
    if not ng_a or not ng_b:
        return 0.0
    overlap = sum((ng_a & ng_b).values())
    total = min(sum(ng_a.values()), sum(ng_b.values()))
    return overlap / total if total > 0 else 0.0


def _sign(result_str: str, key: bytes) -> str:
    return hmac_lib.new(key, result_str.encode(), hashlib.sha256).hexdigest()


class OutputLeakageDetector:
    """Detects system prompt leakage in agent outputs."""

    def __init__(
        self,
        policy_path: Optional[Path] = None,
        hmac_key: bytes = b"btv-leakage-default-key",
    ) -> None:
        raw = self._load(policy_path) if policy_path else {}
        self._indicators = [
            p.lower() for p in raw.get("indicator_phrases", [])
        ]
        patterns = raw.get("structural_patterns", [])
        self._structural_re = (
            re.compile("|".join(patterns), re.IGNORECASE)
            if patterns
            else None
        )
        self._ngram_size = raw.get("ngram_size", _DEFAULT_NGRAM_SIZE)
        self._threshold = raw.get(
            "ngram_similarity_threshold", _DEFAULT_THRESHOLD
        )
        self._key = hmac_key

    @staticmethod
    def _load(path: Path) -> dict:
        if not path.exists():
            return {}
        with open(path) as f:
            return yaml.safe_load(f) or {}

    def detect(
        self,
        output_text: str,
        registered_prompts: Optional[List[str]] = None,
    ) -> LeakageResult:
        """Check output for system prompt leakage."""
        if not output_text:
            return self._result(False, 0.0, "Empty output")

        lower = output_text.lower()

        # Layer 1: exact substring of registered prompts
        for prompt in (registered_prompts or []):
            if len(prompt) > 20 and prompt.lower() in lower:
                return self._result(
                    True, 1.0, "Exact prompt substring found in output"
                )

        # Layer 2: n-gram similarity
        for prompt in (registered_prompts or []):
            sim = _ngram_similarity(
                output_text, prompt, self._ngram_size
            )
            if sim >= self._threshold:
                return self._result(
                    True, sim, f"N-gram similarity {sim:.2f} >= {self._threshold}"
                )

        # Layer 3: indicator phrases
        for phrase in self._indicators:
            if phrase in lower:
                return self._result(
                    True, 0.85, f"Leakage indicator: '{phrase}'"
                )

        # Layer 4: structural patterns
        if self._structural_re and self._structural_re.search(output_text):
            return self._result(
                True, 0.80, "Structural leakage pattern detected"
            )

        return self._result(False, 0.0, "No leakage detected")

    def _result(
        self, leaked: bool, confidence: float, explain: str
    ) -> LeakageResult:
        action = ActionType.BLOCK if leaked else ActionType.ALLOW
        sig = _sign(f"{leaked}|{confidence}|{explain}", self._key)
        return LeakageResult(
            leaked=leaked,
            confidence=confidence,
            action=action,
            explain=f"[output_leakage_detector] {explain}",
            hmac_sha256=sig,
        )
