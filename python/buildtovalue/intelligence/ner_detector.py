"""
NER Detector v1.0 — Semantic PII detection via SLM (ADR-047).

Uses the local SLM (Phi-4 Mini) with a specialized NER prompt to extract
PII entities from natural language text. Runs in parallel with the Rust
deterministic scan pipeline.

Filosofia (Jonas): Data never leaves the perimeter (local SLM).
Filosofia (Levinas): NER output is a Finding, not a Verdict.
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .ner_entities import NEREntityType, NERFinding, parse_entity_type
from .slm_classifier import SLMClassifier

logger = logging.getLogger("btv.intelligence.ner")


@dataclass
class NERBiasDeclaration:
    """BiasDeclaration for NER detector (ADR-010)."""
    fpr: float = 0.0
    fnr: float = 0.0
    calibration_date: int = 0
    sample_size: int = 0
    model_id: str = ""
    limitations: str = (
        "SLM-based NER is probabilistic. Entity boundaries may be "
        "imprecise compared to dedicated NER models. Confidence varies "
        "by language (PT-BR > EN for Brazilian PII patterns)."
    )
    affected_groups: str = (
        "Indigenous names and non-Western name patterns may have higher FNR. "
        "Long compound addresses may be partially extracted."
    )


@dataclass
class NERInspectionResult:
    """Result of NER inspection on a text input."""
    findings: List[NERFinding]
    latency_ms: float
    model_id: str
    input_len: int

    @property
    def has_pii(self) -> bool:
        return len(self.findings) > 0

    @property
    def high_risk_findings(self) -> List[NERFinding]:
        return [f for f in self.findings if f.is_high_risk]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "finding_count": len(self.findings),
            "high_risk_count": len(self.high_risk_findings),
            "has_pii": self.has_pii,
            "latency_ms": round(self.latency_ms, 2),
            "model_id": self.model_id,
            "input_len": self.input_len,
        }

    def to_finding_dicts(self) -> List[Dict[str, Any]]:
        """Convert all findings to Finding-compatible dicts."""
        return [f.to_finding_dict() for f in self.findings]


class NERDetector:
    """
    Semantic PII detector using local SLM (ADR-047).

    Reutiliza o SLMClassifier com prompt NER especializado.
    Fail-open: SLM indisponivel ou erro -> retorna resultado vazio.

    Usage:
        slm = SLMClassifier(model_path="/models/phi-4-mini-q4.gguf")
        slm.load_model()
        detector = NERDetector(slm)
        result = detector.detect("moro na Rua Augusta 1200, SP")
    """

    def __init__(self, slm: SLMClassifier) -> None:
        self._slm = slm
        self._metrics = {
            "detections": 0,
            "pii_found": 0,
            "empty_results": 0,
            "errors": 0,
            "total_latency_ms": 0.0,
        }
        self._bias = NERBiasDeclaration()

    def detect(self, text: str) -> NERInspectionResult:
        """
        Detect PII entities in text using SLM NER.

        Fail-open: returns empty result on any error (Jonas).
        """
        start = time.perf_counter()
        input_len = len(text)

        if not self._slm.is_loaded:
            return self._empty_result(input_len, start)

        text_stripped = text.strip()
        if len(text_stripped) < 5:
            return self._empty_result(input_len, start)

        try:
            raw_entities = self._slm.extract_entities(text_stripped)
            elapsed = (time.perf_counter() - start) * 1000

            findings = self._parse_entities(raw_entities, text_stripped)

            self._metrics["detections"] += 1
            self._metrics["total_latency_ms"] += elapsed
            if findings:
                self._metrics["pii_found"] += 1
            else:
                self._metrics["empty_results"] += 1

            return NERInspectionResult(
                findings=findings,
                latency_ms=elapsed,
                model_id=self._slm._model_id,
                input_len=input_len,
            )

        except Exception as exc:
            self._metrics["errors"] += 1
            logger.error("NER detection error: %s", exc)
            return self._empty_result(input_len, start)

    def _parse_entities(
        self,
        raw_entities: list,
        original_text: str,
    ) -> List[NERFinding]:
        """Parse SLM entity output into NERFinding objects."""
        findings = []
        for ent in raw_entities:
            entity_type = parse_entity_type(ent.get("type", ""))
            text = ent.get("text", "")
            confidence = float(ent.get("confidence", 0.5))

            if not text:
                continue

            # Try to find position in original text
            start = original_text.find(text)
            end = start + len(text) if start >= 0 else None
            if start < 0:
                start = None

            findings.append(NERFinding(
                entity_type=entity_type,
                text=text,
                confidence=confidence,
                start=start,
                end=end,
            ))

        return findings

    def _empty_result(self, input_len: int, start: float) -> NERInspectionResult:
        elapsed = (time.perf_counter() - start) * 1000
        return NERInspectionResult(
            findings=[],
            latency_ms=elapsed,
            model_id=self._slm._model_id if self._slm else "none",
            input_len=input_len,
        )

    def get_metrics(self) -> Dict[str, Any]:
        avg = 0.0
        if self._metrics["detections"] > 0:
            avg = self._metrics["total_latency_ms"] / self._metrics["detections"]
        return {
            **self._metrics,
            "avg_latency_ms": round(avg, 2),
            "model_loaded": self._slm.is_loaded if self._slm else False,
        }

    def get_bias_declaration(self) -> NERBiasDeclaration:
        return self._bias
