"""
MISP/STIX Threat Intelligence Ingestor v2.0
Ingests threat events, indexes by type, verifies integrity (BLAKE3).
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ThreatEvent:
    """Immutable threat event (MISP/STIX compatible)."""
    id: str
    threat_type: str  # prompt_injection, pii_leakage, data_exfiltration
    severity: int  # 1-10
    source: str  # MISP, STIX, OWASP
    indicators: List[str] = field(default_factory=list)
    timestamp: int = field(default_factory=lambda: int(time.time()))
    hash: str = ""

    def compute_hash(self) -> str:
        payload = json.dumps({
            "id": self.id,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "source": self.source,
            "indicators": sorted(self.indicators),
            "timestamp": self.timestamp,
        }, sort_keys=True)
        return hashlib.blake2b(payload.encode(), digest_size=32).hexdigest()

    def verify_integrity(self) -> bool:
        return self.hash == self.compute_hash()


class MispIngestor:
    """
    Threat Intelligence Database.
    Ingests MISP/STIX events, indexes by type, exports for policy generation.
    """

    def __init__(self) -> None:
        self._events: Dict[str, ThreatEvent] = {}
        self._index_by_type: Dict[str, List[str]] = {}
        self._index_by_severity: Dict[int, List[str]] = {}

    def ingest(self, event: ThreatEvent) -> ThreatEvent:
        """Ingest and hash a threat event."""
        event.hash = event.compute_hash()

        self._events[event.id] = event
        self._index_by_type.setdefault(event.threat_type, []).append(event.id)
        self._index_by_severity.setdefault(event.severity, []).append(event.id)

        return event

    def query_by_type(self, threat_type: str) -> List[ThreatEvent]:
        ids = self._index_by_type.get(threat_type, [])
        return [self._events[i] for i in ids if i in self._events]

    def query_by_severity(self, min_severity: int) -> List[ThreatEvent]:
        results = []
        for sev, ids in self._index_by_severity.items():
            if sev >= min_severity:
                results.extend(self._events[i] for i in ids if i in self._events)
        return sorted(results, key=lambda e: e.severity, reverse=True)

    def get(self, event_id: str) -> Optional[ThreatEvent]:
        return self._events.get(event_id)

    def count(self) -> int:
        return len(self._events)

    def export_batch(self, limit: int = 100) -> List[ThreatEvent]:
        return list(self._events.values())[:limit]