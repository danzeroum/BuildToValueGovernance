"""Appeals routes (ADR-0093 Phase 2, Passo 3 — router 2).

`/v1/appeals/*` — submissão, métricas, consulta, listagem e resolução de
recursos (ADR-017, Levinas/Jonas). Sem import reverso de `app.py`: o singleton
`ContestabilityLoop` é obtido de `request.app.state.contestability_loop` via
provedor `Depends` fail-secure (503 se não inicializado no lifespan).
"""
from __future__ import annotations

import math
from typing import List, Optional, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from buildtovalue.api._decide_helpers import _appeal_to_response
from buildtovalue.api._models import (
    AppealListResponse,
    AppealMetricsResponse,
    AppealPageResponse,
    AppealResolveRequest,
    AppealResponse,
    AppealSubmitRequest,
    PaginationMeta,
)
from buildtovalue.api.auth import require_api_key
from buildtovalue.api.routes.auth import require_jwt
from buildtovalue.governance.contestability_loop import (
    AppealStatus,
    ContestabilityLoop,
)

router = APIRouter()


def get_contestability_loop(request: Request) -> ContestabilityLoop:
    """Provedor estrito — barreira Fail-Secure (503) contra estado nulo."""
    loop = getattr(request.app.state, "contestability_loop", None)
    if not isinstance(loop, ContestabilityLoop):
        raise HTTPException(
            status_code=503,
            detail="FAIL-SECURE: ContestabilityLoop nao inicializado no lifespan.",
        )
    return loop


@router.post(
    "/v1/appeals",
    response_model=AppealResponse,
    status_code=201,
    dependencies=[Depends(require_jwt)],  # CRITICO-03: write requires JWT
)
def submit_appeal(
    req: AppealSubmitRequest,
    loop: ContestabilityLoop = Depends(get_contestability_loop),
) -> AppealResponse:
    try:
        appeal = loop.submit_appeal(
            audit_trail_id=req.audit_trail_id,
            user_id=req.user_id,
            reason=req.reason,
            evidence=req.evidence,
        )
        if req.evidence_hash:
            appeal.evidence_hash = req.evidence_hash
        if req.grounds:
            appeal.grounds = req.grounds
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _appeal_to_response(appeal)


@router.get(
    "/v1/appeals/metrics",
    response_model=AppealMetricsResponse,
    dependencies=[Depends(require_api_key)],  # CRITICO-03: read requires API key
)
def appeals_metrics(
    loop: ContestabilityLoop = Depends(get_contestability_loop),
) -> AppealMetricsResponse:
    loop.list_expired_appeals()
    # get_metrics() devolve Dict[str, object]; cast explícito mantém o contrato
    # tipado (mypy --strict). Pydantic valida/coage os tipos no construtor.
    m = loop.get_metrics()
    return AppealMetricsResponse(
        appeals_submitted=cast(int, m["appeals_submitted"]),
        appeals_accepted=cast(int, m["appeals_accepted"]),
        appeals_rejected=cast(int, m["appeals_rejected"]),
        sla_violations=cast(int, m["sla_violations"]),
        pending_appeals=cast(int, m["pending_appeals"]),
        sla_compliance_rate=cast(float, m["sla_compliance_rate"]),
        appeal_success_rate=cast(float, m["appeal_success_rate"]),
    )


@router.get(
    "/v1/appeals/{appeal_id}",
    response_model=AppealResponse,
    dependencies=[Depends(require_api_key)],  # CRITICO-03: read requires API key
)
def get_appeal(
    appeal_id: str,
    loop: ContestabilityLoop = Depends(get_contestability_loop),
) -> AppealResponse:
    appeal = loop.get_appeal(appeal_id)
    if appeal is None:
        raise HTTPException(status_code=404, detail=f"Appeal not found: {appeal_id}")
    return _appeal_to_response(appeal)


_SORT_FIELDS = {"timestamp", "status", "user_id"}
_SORT_ORDERS = {"asc", "desc"}


@router.get(
    "/v1/appeals",
    response_model=AppealPageResponse,
    dependencies=[Depends(require_api_key)],  # CRITICO-03: read requires API key
)
def list_appeals(
    status: Optional[str] = None,
    user_id: Optional[str] = None,
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    limit: int = Query(20, ge=1, le=100, description="Results per page (default 20)"),
    sort_by: Optional[str] = Query(None, description="Sort field: timestamp|status|user_id"),
    order: str = Query("asc", description="Sort order: asc|desc"),
    loop: ContestabilityLoop = Depends(get_contestability_loop),
) -> AppealPageResponse:
    loop.list_expired_appeals()
    if sort_by is not None and sort_by not in _SORT_FIELDS:
        raise HTTPException(status_code=400, detail=f"Invalid sort_by: {sort_by}. Must be one of {sorted(_SORT_FIELDS)}")
    if order not in _SORT_ORDERS:
        raise HTTPException(status_code=400, detail=f"Invalid order: {order}. Must be 'asc' or 'desc'")

    # Filter
    appeals = list(loop.appeals.values())
    if status:
        try:
            target_status = AppealStatus(status)
            appeals = [a for a in appeals if a.status == target_status]
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
    if user_id:
        appeals = [a for a in appeals if a.user_id == user_id]

    # Sort
    if sort_by:
        reverse = order == "desc"
        appeals = sorted(appeals, key=lambda a: getattr(a, sort_by, 0), reverse=reverse)

    # Paginate
    total = len(appeals)
    pages = max(1, math.ceil(total / limit))
    start = (page - 1) * limit
    page_items: List[AppealResponse] = [_appeal_to_response(a) for a in appeals[start:start + limit]]

    return AppealPageResponse(
        data=page_items,
        pagination=PaginationMeta(page=page, limit=limit, total=total, pages=pages),
    )


@router.post(
    "/v1/appeals/{appeal_id}/resolve",
    response_model=AppealResponse,
    dependencies=[Depends(require_jwt)],  # CRITICO-03: write requires JWT
)
def resolve_appeal(
    appeal_id: str,
    req: AppealResolveRequest,
    loop: ContestabilityLoop = Depends(get_contestability_loop),
) -> AppealResponse:
    existing = loop.get_appeal(appeal_id)
    if existing is None:
        raise HTTPException(
            status_code=404, detail=f"Appeal not found: {appeal_id}"
        )
    if existing.status in (AppealStatus.ACCEPTED, AppealStatus.REJECTED):
        raise HTTPException(
            status_code=409,
            detail=f"Already resolved: {existing.status.value}",
        )
    try:
        resolved = loop.resolve_appeal(
            appeal_id=appeal_id,
            accepted=req.accepted,
            reviewer_notes=req.reviewer_notes,
            reviewer_id=req.reviewer_id,
            mediator_recommendation=req.mediator_recommendation,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _appeal_to_response(resolved)
