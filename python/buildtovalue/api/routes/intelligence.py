"""
Intelligence Bridge API routes v2.1
POST /v1/intelligence/bridge/sync — trigger sync
GET  /v1/intelligence/bridge/status — last sync status

Hydrates MispIngestor from SQLite on startup so the bridge
sees threats ingested via /v1/intelligence/ingest.
"""

import json
import logging
from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException

from buildtovalue.api._models import ThreatIngestRequest, ThreatQueryRequest
from buildtovalue.api.auth import require_api_key
from buildtovalue.intelligence import (
    MispIngestor,
    ThreatClassifier,
    ThreatPolicyBridge,
)
from buildtovalue.intelligence.misp_ingestor import ThreatEvent
from buildtovalue.intelligence.threat_feed import (
    get_stats,
    get_threat,
    ingest_threat,
    query_threats,
)

logger = logging.getLogger("btv.api.intelligence")
router = APIRouter(prefix="/v1/intelligence/bridge", tags=["intelligence"])

# Module-level singleton (initialized on first use)
_ingestor = MispIngestor()
import os
_bridge = ThreatPolicyBridge(
    ingestor=_ingestor,
    policies_dir=os.environ.get("BTV_AUTOGEN_DIR", "data/policies/auto-generated"),
)

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


# ═════════════════════════════════════════════════════════════════
# INTELLIGENCE HUB — /v1/intelligence (SQLite-backed)
# ADR-0093 Phase 2, Passo 3 — router 6. Fundido neste arquivo (não em
# arquivo novo) por mandato de governança (ADR-009). Router separado
# (sem o prefixo /bridge) registrado em app.py ao lado de `router`.
# ═════════════════════════════════════════════════════════════════

hub_router = APIRouter(prefix="/v1/intelligence", tags=["intelligence"])


@hub_router.post("/ingest")
def intelligence_ingest(
    req: ThreatIngestRequest, _: None = Depends(require_api_key)
) -> Dict[str, object]:
    result = ingest_threat(
        req.id, req.threat_type, req.severity, req.source,
        req.indicators, req.description, req.mitre_id,
    )
    try:
        get_ingestor().ingest(ThreatEvent(
            id=req.id,
            threat_type=req.threat_type,
            severity=req.severity,
            source=req.source,
            indicators=req.indicators or [],
        ))
    except Exception as exc:
        logger.warning("Bridge ingestor feed failed (non-blocking): %s", exc)
    return result


@hub_router.post("/ingest/batch")
def intelligence_ingest_batch(
    threats: List[ThreatIngestRequest], _: None = Depends(require_api_key)
) -> Dict[str, object]:
    results = [
        ingest_threat(t.id, t.threat_type, t.severity, t.source,
                      t.indicators, t.description, t.mitre_id)
        for t in threats
    ]
    return {"ingested": len(results), "results": results}


@hub_router.post("/query")
def intelligence_query(
    req: ThreatQueryRequest, _: None = Depends(require_api_key)
) -> Dict[str, object]:
    threats = query_threats(req.threat_type, req.min_severity, req.source, req.limit)
    return {"count": len(threats), "threats": threats}


@hub_router.get("/threat/{threat_id}")
def intelligence_get(
    threat_id: str, _: None = Depends(require_api_key)
) -> Dict[str, object]:
    threat = get_threat(threat_id)
    if not threat:
        return {"error": f"Threat {threat_id} not found"}
    return threat


@hub_router.get("/stats")
def intelligence_stats(_: None = Depends(require_api_key)) -> Dict[str, object]:
    return get_stats()