"""
Intelligence Bridge API routes v2.1
POST /v1/intelligence/bridge/sync — trigger sync
GET  /v1/intelligence/bridge/status — last sync status
"""

import logging
from fastapi import APIRouter, HTTPException

from buildtovalue.intelligence import (
    MispIngestor,
    ThreatClassifier,
    ThreatPolicyBridge,
)

logger = logging.getLogger("btv.api.intelligence")
router = APIRouter(prefix="/v1/intelligence/bridge", tags=["intelligence"])

# Module-level singleton (initialized on first use)
_ingestor = MispIngestor()
_bridge = ThreatPolicyBridge(ingestor=_ingestor)


def get_ingestor() -> MispIngestor:
    """Access the shared ingestor (for ingest endpoints)."""
    return _ingestor


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