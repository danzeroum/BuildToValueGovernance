"""
Threat Classifier v2.0
Classifies threat events into taxonomy categories.
"""

from dataclasses import dataclass
from typing import List, Optional
from .misp_ingestor import ThreatEvent


TAXONOMY = {
    "prompt_injection": {"category": "AI_ATTACK", "default_action": "BLOCK", "base_severity": 9},
    "pii_leakage": {"category": "DATA_PROTECTION", "default_action": "REDACT", "base_severity": 8},
    "data_exfiltration": {"category": "DATA_PROTECTION", "default_action": "BLOCK", "base_severity": 9},
    "model_extraction": {"category": "AI_ATTACK", "default_action": "BLOCK", "base_severity": 7},
    "denial_of_service": {"category": "AVAILABILITY", "default_action": "BLOCK", "base_severity": 6},
    "social_engineering": {"category": "HUMAN_FACTOR", "default_action": "EDUCATE", "base_severity": 5},
    "unauthorized_access": {"category": "ACCESS_CONTROL", "default_action": "BLOCK", "base_severity": 8},
}


@dataclass
class Classification:
    threat_type: str
    category: str
    recommended_action: str
    severity: int
    confidence: float
    indicators_matched: int


class ThreatClassifier:
    """Classifies threats using predefined taxonomy."""

    def __init__(self) -> None:
        self.taxonomy = TAXONOMY.copy()

    def classify(self, event: ThreatEvent) -> Classification:
        entry = self.taxonomy.get(event.threat_type)

        if entry:
            severity = max(entry["base_severity"], event.severity)
            return Classification(
                threat_type=event.threat_type,
                category=entry["category"],
                recommended_action=entry["default_action"],
                severity=min(10, severity),
                confidence=0.9,
                indicators_matched=len(event.indicators),
            )

        return Classification(
            threat_type=event.threat_type,
            category="UNKNOWN",
            recommended_action="LOG",
            severity=event.severity,
            confidence=0.3,
            indicators_matched=len(event.indicators),
        )

    def classify_batch(self, events: List[ThreatEvent]) -> List[Classification]:
        return [self.classify(e) for e in events]