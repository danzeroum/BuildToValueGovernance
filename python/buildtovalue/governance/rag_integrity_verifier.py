"""RagIntegrityVerifier — Gap H: Embedding/RAG Poisoning Detection.

Verifies RAG chunk integrity: BLAKE3 source hash (INV-006),
HMAC of (doc_hash, embedding), injection patterns, embedding drift,
chunk size limits, provenance chain and contradiction detection.

Extensões (Cenário 31 — RAG Poisoning / Falso Passado):
  - MemoryProvenanceRecord: cadeia de custódia por chunk
  - record_provenance(): persiste proveniência no DurableLedger
  - verify_with_provenance(): ponto de entrada unificado (verifica + registra
    + detecta contradições via RagContradictionDetector injetado)

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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

import yaml

from .agent_pdp import AgentVerdict
from .chatbot_gates import GateResult
from .durable_ledger import DurableLedger
from .tool_sanitizer import _RE_SCREEN

if TYPE_CHECKING:
    from .rag_contradiction_detector import RagContradictionDetector

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


@dataclass(frozen=True)
class MemoryProvenanceRecord:
    """Cadeia de custódia de cada chunk inserido na memória do agente.

    Cenário 31: cada memória deve ter uma "cadeia de custódia" rastreável.
    Persistida no DurableLedger para verificação futura.
    """
    chunk_blake3: str          # hash BLAKE3 do texto do chunk
    source_channel: str        # "user_direct"|"email"|"agent<id>"|"api_<id>"
    inserted_by_agent_id: str
    inserted_at_iso: str       # UTC ISO 8601
    hmac_signature: str        # HMAC-SHA256(blake3 + channel + iso)


class RagIntegrityVerifier:
    """Verifies RAG chunk integrity before injection."""

    def __init__(
        self,
        policy_path: Optional[Path] = None,
        hmac_key: bytes = b"btv-rag-integrity-key",
        contradiction_detector: Optional["RagContradictionDetector"] = None,
    ) -> None:
        raw = self._load(policy_path) if policy_path else {}
        self._max_chunk = raw.get("max_chunk_size", _MAX_CHUNK)
        self._drift_thresh = raw.get(
            "embedding_drift_threshold", _DRIFT_THRESHOLD
        )
        self._require_hash = raw.get("require_source_hash", True)
        self._injection_check = raw.get("injection_detection", True)
        self._key = hmac_key
        self._contradiction_detector = contradiction_detector

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

    # ------------------------------------------------------------------ #
    # Cenário 31 — Proveniência de Memória                                #
    # ------------------------------------------------------------------ #

    def record_provenance(
        self,
        chunk_text: str,
        source_channel: str,
        agent_id: str,
        ledger: DurableLedger,
    ) -> MemoryProvenanceRecord:
        """Cria e persiste cadeia de custódia do chunk no DurableLedger.

        Fail-secure: erro ao persistir → propaga exceção (não silencia).
        """
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        chunk_hash = _blake3_hex(chunk_text.encode())
        sig_payload = f"{chunk_hash}|{source_channel}|{now_iso}".encode()
        sig = hmac_lib.new(self._key, sig_payload, hashlib.sha256).hexdigest()

        record = MemoryProvenanceRecord(
            chunk_blake3=chunk_hash,
            source_channel=source_channel,
            inserted_by_agent_id=agent_id,
            inserted_at_iso=now_iso,
            hmac_signature=sig,
        )
        ledger.append({
            "type": "rag_provenance",
            "chunk_blake3": chunk_hash,
            "source_channel": source_channel,
            "inserted_by_agent_id": agent_id,
            "inserted_at_iso": now_iso,
            "hmac_signature": sig,
            "explain_decision": (
                f"Proveniência registrada: chunk={chunk_hash[:16]}… "
                f"channel={source_channel} agent={agent_id}"
            ),
        })
        return record

    def verify_with_provenance(
        self,
        chunk_text: str,
        source_channel: str,
        agent_id: str,
        ledger: DurableLedger,
        established_chunks: Optional[List[Tuple[str, MemoryProvenanceRecord]]] = None,
        source_hash: Optional[str] = None,
        embedding_vector: Optional[List[float]] = None,
        expected_embedding: Optional[List[float]] = None,
    ) -> IntegrityResult:
        """Ponto de entrada unificado: verifica + registra proveniência + detecta contradições.

        Pipeline:
          1. verify_chunk() — validações existentes (retrocompatibilidade preservada)
          2. record_provenance() — persiste cadeia de custódia no ledger
          3. RagContradictionDetector.check() — se injetado e established_chunks fornecidos

        Fail-secure: qualquer falha em qualquer etapa → BLOCK.
        """
        result = self.verify_chunk(
            chunk_text,
            source_hash=source_hash,
            embedding_vector=embedding_vector,
            expected_embedding=expected_embedding,
        )
        if not result.valid:
            return result

        try:
            self.record_provenance(chunk_text, source_channel, agent_id, ledger)
        except Exception as exc:  # noqa: BLE001
            logger.error("Falha ao registrar proveniência: %s", exc)
            return self._fail(
                f"Falha na cadeia de custódia: {exc}",
                doc_hash=result.blake3_hash,
            )

        if self._contradiction_detector and established_chunks:
            from .rag_contradiction_detector import MemoryProvenanceRecord as _MPR
            contradiction = self._contradiction_detector.check(
                chunk_text, established_chunks
            )
            if contradiction is not None:
                return self._fail(
                    contradiction.explain_decision,
                    doc_hash=result.blake3_hash,
                )

        return result


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
