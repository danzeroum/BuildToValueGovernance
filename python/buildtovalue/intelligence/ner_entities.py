"""
NER Entity Types v1.0 — Semantic PII entity definitions (ADR-047).

Defines entity types for PII detected via SLM NER extraction.
Maps SLM output to Finding-compatible structures.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional


class NEREntityType(str, Enum):
    """PII entity types detected by semantic NER."""
    PERSON_NAME = "PERSON_NAME"
    ADDRESS = "ADDRESS"
    PARTIAL_CARD = "PARTIAL_CARD"
    PARTIAL_DOC = "PARTIAL_DOC"
    PHONE_NATURAL = "PHONE_NATURAL"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    HEALTH_INFO = "HEALTH_INFO"
    FINANCIAL_INFO = "FINANCIAL_INFO"
    UNKNOWN = "UNKNOWN"


# Severity mapping for NER entity types (0.0-1.0)
ENTITY_SEVERITY = {
    NEREntityType.PERSON_NAME: 0.4,
    NEREntityType.ADDRESS: 0.6,
    NEREntityType.PARTIAL_CARD: 0.7,
    NEREntityType.PARTIAL_DOC: 0.7,
    NEREntityType.PHONE_NATURAL: 0.5,
    NEREntityType.DATE_OF_BIRTH: 0.5,
    NEREntityType.HEALTH_INFO: 0.8,
    NEREntityType.FINANCIAL_INFO: 0.6,
    NEREntityType.UNKNOWN: 0.3,
}


@dataclass(frozen=True)
class NERFinding:
    """Single NER-detected PII entity."""
    entity_type: NEREntityType
    text: str
    confidence: float
    start: Optional[int] = None
    end: Optional[int] = None

    @property
    def severity(self) -> float:
        return ENTITY_SEVERITY.get(self.entity_type, 0.3)

    @property
    def is_high_risk(self) -> bool:
        return self.severity >= 0.7 and self.confidence >= 0.7

    def to_finding_dict(self) -> Dict[str, Any]:
        """Convert to Finding-compatible dict for pipeline integration."""
        return {
            "module": "NER_DETECTOR",
            "rule_id": f"NER_SEMANTIC_{self.entity_type.value}",
            "severity": self.severity,
            "confidence": self.confidence,
            "matched_text": self.text,
            "entity_type": self.entity_type.value,
            "start": self.start,
            "end": self.end,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_type": self.entity_type.value,
            "text": self.text,
            "confidence": self.confidence,
            "severity": self.severity,
            "start": self.start,
            "end": self.end,
        }


def parse_entity_type(type_str: str) -> NEREntityType:
    """Parse entity type string from SLM output. Fail-safe to UNKNOWN."""
    try:
        return NEREntityType(type_str.upper())
    except ValueError:
        # Map common aliases
        aliases = {
            "NAME": NEREntityType.PERSON_NAME,
            "FULL_NAME": NEREntityType.PERSON_NAME,
            "STREET_ADDRESS": NEREntityType.ADDRESS,
            "ADDR": NEREntityType.ADDRESS,
            "CREDIT_CARD": NEREntityType.PARTIAL_CARD,
            "CARD_NUMBER": NEREntityType.PARTIAL_CARD,
            "DOCUMENT": NEREntityType.PARTIAL_DOC,
            "CPF": NEREntityType.PARTIAL_DOC,
            "SSN": NEREntityType.PARTIAL_DOC,
            "PHONE": NEREntityType.PHONE_NATURAL,
            "PHONE_NUMBER": NEREntityType.PHONE_NATURAL,
            "DOB": NEREntityType.DATE_OF_BIRTH,
            "BIRTH_DATE": NEREntityType.DATE_OF_BIRTH,
            "MEDICAL": NEREntityType.HEALTH_INFO,
            "HEALTH": NEREntityType.HEALTH_INFO,
            "SALARY": NEREntityType.FINANCIAL_INFO,
            "INCOME": NEREntityType.FINANCIAL_INFO,
        }
        return aliases.get(type_str.upper(), NEREntityType.UNKNOWN)
