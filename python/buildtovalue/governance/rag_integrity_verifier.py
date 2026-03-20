"""RagIntegrityVerifier — Gap H: Embedding/RAG Poisoning Detection.

Verifies RAG chunk integrity: source hash, injection patterns,
embedding drift, and chunk size limits.

Invariants:
- Fail-secure: verification error -> BLOCK
- Reuses tool_sanitizer injection patterns
- Functions <= 50 lines, file <= 200 lines
"""
from __future__ import annotations

import hashlib
import logging
import math
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import yaml

from .agent_pdp import AgentVerdict
from .chatbot_gates import GateResult
from .tool_sanitizer import _RE_SCREEN

logger = logging.getLogger("btv.governance.rag_integrity_verifier")

_MAX_CHUNK = 4000
_DRIFT_THRESHOLD = 0.3


@dataclass(frozen=True)
class IntegrityResult:
    valid: bool
    reason: str
    gate_result: GateResult


class RagIntegrityVerifier:
    """Verifies RAG chunk integrity before injection."""

    def __init__(self, policy_path: Optional[Path] = None) -> None:
        raw = self._load(policy_path) if policy_path else {}
        self._max_chunk = raw.get("max_chunk_size", _MAX_CHUNK)
        self._drift_thresh = raw.get(
            "embedding_drift_threshold", _DRIFT_THRESHOLD
        )
        self._require_hash = raw.get("require_source_hash", True)
        self._injection_check = raw.get("injection_detection", True)

    @staticmethod
    def _load(path: Path) -> dict:
        if not path.exists():
            return {}
        with open(path) as f:
            return yaml.safe_load(f) or {}

    def verify_chunk(
        self,
        chunk_text: str,
        source_hash: Optional[str] = None,
        embedding_vector: Optional[List[float]] = None,
        expected_embedding: Optional[List[float]] = None,
    ) -> IntegrityResult:
        """Verify a RAG chunk before injection into context."""
        if not chunk_text:
            return self._ok("Empty chunk — no verification needed")

        if len(chunk_text) > self._max_chunk:
            return self._fail(
                f"Chunk size {len(chunk_text)} exceeds max {self._max_chunk}"
            )

        if self._require_hash and source_hash:
            actual = hashlib.sha256(chunk_text.encode()).hexdigest()
            if actual != source_hash:
                return self._fail("Source hash mismatch — chunk tampered")

        if self._injection_check and _RE_SCREEN.search(chunk_text):
            return self._fail("Injection pattern detected in RAG chunk")

        if (
            embedding_vector is not None
            and expected_embedding is not None
        ):
            drift = _cosine_distance(embedding_vector, expected_embedding)
            if drift > self._drift_thresh:
                return self._fail(
                    f"Embedding drift {drift:.3f} > {self._drift_thresh}"
                )

        return self._ok("Chunk integrity verified")

    def _fail(self, reason: str) -> IntegrityResult:
        logger.warning("RAG integrity FAIL: %s", reason)
        return IntegrityResult(
            valid=False,
            reason=reason,
            gate_result=GateResult(
                verdict=AgentVerdict.BLOCK,
                evidence_id=None,
                explain=f"[rag_integrity] {reason}",
                gate="rag_integrity_verifier",
            ),
        )

    def _ok(self, reason: str) -> IntegrityResult:
        return IntegrityResult(
            valid=True,
            reason=reason,
            gate_result=GateResult(
                verdict=AgentVerdict.ALLOW,
                evidence_id=None,
                explain=f"[rag_integrity] {reason}",
                gate="rag_integrity_verifier",
            ),
        )


def _cosine_distance(a: List[float], b: List[float]) -> float:
    """Cosine distance between two vectors. Returns 0-2."""
    if len(a) != len(b) or not a:
        return 2.0  # max distance on mismatch
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0 or norm_b == 0:
        return 2.0
    similarity = dot / (norm_a * norm_b)
    return 1.0 - similarity
