"""Appeals routes (ADR-0093 Phase 2, Passo 3 — router 2).

`/v1/appeals/*` — submissão, métricas, consulta, listagem e resolução de
recursos (ADR-017, Levinas/Jonas). Sem import reverso de `app.py`: o singleton
`ContestabilityLoop` é obtido de `request.app.state.contestability_loop` via
provedor `Depends` fail-secure (503 se não inicializado no lifespan).
"""
from __future__ import annotations

from typing import Optional, cast

from fastapi import APIRouter, Depends, HTTPException, Request

from buildtovalue.api._decide_helpers import _appeal_to_response
from buildtovalue.api._models import (
    AppealListResponse,
    AppealMetricsResponse,
    AppealResolveRequest,
    AppealResponse,
    AppealSubmitRequest,
)
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


@router.post("/v1/appeals", response_model=AppealResponse, status_code=201)
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


@router.get("/v1/appeals/metrics", response_model=AppealMetricsResponse)
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


@router.get("/v1/appeals/{appeal_id}", response_model=AppealResponse)
def get_appeal(
    appeal_id: str,
    loop: ContestabilityLoop = Depends(get_contestability_loop),
) -> AppealResponse:
    appeal = loop.get_appeal(appeal_id)
    if appeal is None:
        raise HTTPException(status_code=404, detail=f"Appeal not found: {appeal_id}")
    return _appeal_to_response(appeal)


@router.get("/v1/appeals", response_model=AppealListResponse)
def list_appeals(
    status: Optional[str] = None,
    user_id: Optional[str] = None,
    loop: ContestabilityLoop = Depends(get_contestability_loop),
) -> AppealListResponse:
    loop.list_expired_appeals()
    # TODO(Governance): encapsular valores de apelação via getter público na
    # próxima sprint de refatoração do domínio. `appeals` é atributo público
    # de ContestabilityLoop hoje — mantemos o acesso direto (fidelidade).
    appeals = list(loop.appeals.values())
    if status:
        try:
            target_status = AppealStatus(status)
            appeals = [a for a in appeals if a.status == target_status]
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
    if user_id:
        appeals = [a for a in appeals if a.user_id == user_id]
    return AppealListResponse(
        appeals=[_appeal_to_response(a) for a in appeals],
        total=len(appeals),
    )


@router.post("/v1/appeals/{appeal_id}/resolve", response_model=AppealResponse)
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
