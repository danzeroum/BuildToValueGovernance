"""
Ledger Query API routes v1.0
GET /v1/ledger/query — query audit ledger with filters + pagination

ADR: 0024-ledger-query-api.md
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query

from buildtovalue.api.auth import require_api_key
from buildtovalue.api.ledger_reader import (
    LedgerQuery,
    LedgerReader,
)

logger = logging.getLogger("btv.api.ledger")
# CRITICO-03: ledger reads require an API key (router-level dependency).
router = APIRouter(
    prefix="/v1/ledger", tags=["ledger"], dependencies=[Depends(require_api_key)]
)

_reader = LedgerReader()


@router.get("/query")
def query_ledger(
    session_id: Optional[str] = Query(None, description="Filter by session"),
    verdict_id: Optional[str] = Query(None, description="Filter by verdict"),
    action: Optional[str] = Query(None, description="ALLOW|EDUCATE|BLOCK|LOG"),
    start_ts: Optional[int] = Query(None, description="Min timestamp (ms)"),
    end_ts: Optional[int] = Query(None, description="Max timestamp (ms)"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(100, ge=10, le=1000, description="Results per page"),
):
    """
    Query the immutable audit ledger.

    Filters are optional and combinable. Returns paginated results.
    Read-only: this endpoint never modifies the ledger.
    """
    q = LedgerQuery(
        session_id=session_id,
        verdict_id=verdict_id,
        action=action,
        start_ts=start_ts,
        end_ts=end_ts,
        page=page,
        page_size=page_size,
    )
    result = _reader.query(q)
    return result.to_dict()


@router.get("/stats")
def ledger_stats():
    """Ledger summary: existence and entry count."""
    return {
        "exists": _reader.exists(),
        "entry_count": _reader.entry_count(),
        "ledger_file": _reader.ledger_path,
    }