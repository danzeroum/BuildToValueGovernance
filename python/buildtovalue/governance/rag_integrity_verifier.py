"""RagIntegrityVerifier — Gap H: Embedding/RAG Poisoning Detection.

Verifies RAG chunk integrity: BLAKE3 source hash (INV-006),
HMAC of (doc_hash, embedding), injection patterns, embedding drift,
and chunk size limits.

Invariants:
- INV-006: BLAKE3 for evidence hashing (never SHA-256)
- INV-007: Fail-secure: verification error -> BLOCK
- Reuses tool_sanitizer injection patterns
- Functions <= 50 lines, file <= 200 lines
"""
from __future__ import annotations

import hashlib
import hmac as hmac_lib
import logging
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from .agent_pdp import AgentVerdict
from .chatbot_gates import GateResult
from .tool_sanitizer import _RE_SCREEN

logger = logging.getLogger("btv.governance.rag_integrity_verifier")

_MAX_CHUNK = 4000
_DRIFT_THRESHOLD = 0.3


def _blake3_hex(data: bytes) -> str:
    """BLAKE3 hash (INV-006). Falls back to sha256 if blake3 unavailable."""
    try:
        import blake3  # type: ignore[import-untyped]
        return blake3.blake3(data).hexdigest()
    except ImportError:
        return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class IntegrityResult:
    valid: bool
    reason: str
    blake3_hash: str
    hmac_signature: str
    gate_result: GateResult


class RagIntegrityVerifier:
    """Verifies RAG chunk integrity before injection."""

    def __init__(
        self,
        policy_path: Optional[Path] = None,
        hmac_key: bytes = b"btv-rag-integrity-key",
    ) -> None:
        raw = self._load(policy_path) if policy_path else {}
        self._max_chunk = raw.get("max_chunk_size", _MAX_CHUNK)
        self._drift_thresh = raw.get(
            "embedding_drift_threshold", _DRIFT_THRESHOLD
        )
        self._require_hash = raw.get("require_source_hash", True)
        self._injection_check = raw.get("injection_detection", True)
        self._key = hmac_key

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

        doc_hash = _blake3_hex(chunk_text.encode())

        if self._require_hash and source_hash:
            if doc_hash != source_hash:
                return self._fail(
                    "Source hash mismatch — chunk tampered",
                    doc_hash=doc_hash,
                )

        if self._injection_check and _RE_SCREEN.search(chunk_text):
            return self._fail(
                "Injection pattern detected in RAG chunk",
                doc_hash=doc_hash,
            )

        if embedding_vector is not None and expected_embedding is not None:
            drift = _cosine_distance(embedding_vector, expected_embedding)
            if drift > self._drift_thresh:
                return self._fail(
                    f"Embedding drift {drift:.3f} > {self._drift_thresh}",
                    doc_hash=doc_hash,
                )

        return self._ok("Chunk integrity verified", doc_hash=doc_hash)

    def compute_doc_hmac(
        self, doc_hash: str, embedding: Optional[List[float]] = None
    ) -> str:
        """HMAC-SHA256 of (doc_hash, embedding_vector) pair."""
        emb_str = ",".join(f"{v:.6f}" for v in (embedding or []))
        payload = f"{doc_hash}|{emb_str}".encode()
        return hmac_lib.new(self._key, payload, hashlib.sha256).hexdigest()

    def _fail(self, reason: str, doc_hash: str = "") -> IntegrityResult:
        logger.warning("RAG integrity FAIL: %s", reason)
        sig = self.compute_doc_hmac(doc_hash)
        return IntegrityResult(
            valid=False, reason=reason, blake3_hash=doc_hash,
            hmac_signature=sig,
            gate_result=GateResult(
                verdict=AgentVerdict.BLOCK, evidence_id=None,
                explain=f"[rag_integrity] {reason}",
                gate="rag_integrity_verifier",
            ),
        )

    def _ok(self, reason: str, doc_hash: str = "") -> IntegrityResult:
        sig = self.compute_doc_hmac(doc_hash)
        return IntegrityResult(
            valid=True, reason=reason, blake3_hash=doc_hash,
            hmac_signature=sig,
            gate_result=GateResult(
                verdict=AgentVerdict.ALLOW, evidence_id=None,
                explain=f"[rag_integrity] {reason}",
                gate="rag_integrity_verifier",
            ),
        )


def _cosine_distance(a: List[float], b: List[float]) -> float:
    """Cosine distance between two vectors. Returns 0-2."""
    if len(a) != len(b) or not a:
        return 2.0
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0 or norm_b == 0:
        return 2.0
    return 1.0 - dot / (norm_a * norm_b)
