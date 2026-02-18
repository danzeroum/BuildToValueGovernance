"""
Intelligence Bridge API routes v2.1
POST /v1/intelligence/bridge/sync — trigger sync
GET  /v1/intelligence/bridge/status — last sync status

Hydrates MispIngestor from SQLite on startup so the bridge
sees threats ingested via /v1/intelligence/ingest.
"""

import json
import logging
from fastapi import APIRouter, HTTPException

from buildtovalue.intelligence import (
    MispIngestor,
    ThreatClassifier,
    ThreatPolicyBridge,
)
from buildtovalue.intelligence.misp_ingestor import ThreatEvent

logger = logging.getLogger("btv.api.intelligence")
router = APIRouter(prefix="/v1/intelligence/bridge", tags=["intelligence"])

# Module-level singleton (initialized on first use)
_ingestor = MispIngestor()
_bridge = ThreatPolicyBridge(ingestor=_ingestor)


def get_ingestor() -> MispIngestor:
    """Access the shared ingestor (for ingest endpoints and hydration)."""
    return _ingestor


def get_bridge() -> ThreatPolicyBridge:
    """Access the shared bridge."""
    return _bridge


def hydrate_from_sqlite() -> int:
    """
    Load existing threats from SQLite into MispIngestor on startup.

    This bridges the gap between threat_feed.py (SQLite persistence)
    and MispIngestor (in-memory, used by ThreatPolicyBridge).

    Returns number of threats loaded.
    """
    try:
        from buildtovalue.intelligence.threat_feed import query_threats
        threats = query_threats(limit=10000)
    except Exception as exc:
        logger.warning("Could not hydrate from SQLite: %s", exc)
        return 0

    count = 0
    for t in threats:
        try:
            indicators = t.get("indicators", [])
            if isinstance(indicators, str):
                indicators = json.loads(indicators)

            _ingestor.ingest(ThreatEvent(
                id=t["id"],
                threat_type=t["threat_type"],
                severity=t["severity"],
                source=t["source"],
                indicators=indicators if isinstance(indicators, list) else [],
            ))
            count += 1
        except Exception as exc:
            logger.warning("Skipped threat %s during hydration: %s", t.get("id"), exc)

    if count > 0:
        logger.info("Hydrated MispIngestor with %d threats from SQLite", count)
    return count


@router.post("/sync")
def sync_bridge(min_severity: int = 1):
    """
    Trigger threat→policy sync.

    All generated policies are born disabled and require
    human review before activation (Rawls).
    """
    try:
        result = _bridge.sync(min_severity=min_severity)
        return {
            "status": "ok",
            "result": result.to_dict(),
        }
    except Exception as exc:
        logger.error("Bridge sync failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/status")
def bridge_status():
    """Return last sync result + pending review count."""
    last = _bridge.last_sync
    return {
        "last_sync": last.to_dict() if last else None,
        "pending_review": _bridge.pending_review_count(),
    }