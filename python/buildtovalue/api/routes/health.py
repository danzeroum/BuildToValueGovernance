"""Health & trust routes (ADR-0093 Phase 2, Passo 3 — router 1).

`/health` e `/v1/trust/{session_id}`. Sem import reverso de `app.py`: estado é
lido de `request.app.state.*` (singletons do lifespan) e a persistência via
`api._db`. Singletons stateful são obtidos por provedores `Depends` que falham
em modo Fail-Secure (503) se o lifespan não os inicializou.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Request

from buildtovalue.api._db import DB_PATH, db_get_session
from buildtovalue.api.auth import require_api_key
from buildtovalue.governance.contestability_loop import ContestabilityLoop
from buildtovalue.security import sqlite_connect_wal

router = APIRouter()


def get_contestability_loop_optional(request: Request) -> Optional[ContestabilityLoop]:
    """Provedor tolerante — /health reporta o estado sem falhar se ausente."""
    loop = getattr(request.app.state, "contestability_loop", None)
    return loop if isinstance(loop, ContestabilityLoop) else None


@router.get("/health")
def health(
    request: Request,
    loop: Optional[ContestabilityLoop] = Depends(get_contestability_loop_optional),
) -> dict[str, object]:
    conn = sqlite_connect_wal(DB_PATH)
    sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    conn.close()
    state = request.app.state
    slm = getattr(state, "slm", None)
    return {
        "status": "healthy",
        "service": "btv-governance",
        "version": "2.3.0",
        "sessions_tracked": sessions,
        "persistence": "sqlite",
        "slm_loaded": slm is not None and slm.is_loaded,
        "ethical_engine": getattr(state, "ethical_engine", None) is not None,
        "trust_calculator_singleton": getattr(state, "trust_calculator", None) is not None,
        "goal_drift_sentinel": getattr(state, "goal_drift_sentinel", None) is not None,
        "appeals_pending": len(loop.list_pending_appeals()) if loop else 0,
    }


@router.get("/v1/trust/{session_id}")
def get_trust(
    session_id: str, _: None = Depends(require_api_key)
) -> dict[str, object]:
    session = db_get_session(session_id)
    return {
        "session_id": session_id,
        "trust_score": session["trust_score"],
        "offenses": session["offenses"],
        "total_requests": session["total_requests"],
    }
