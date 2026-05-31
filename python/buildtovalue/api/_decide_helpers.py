"""Helpers sem estado do pipeline de decisão (ADR-0093 Phase 2, Passo 2).

Funções puras extraídas de `app.py`: recebem todos os dados por argumento e
**não leem nenhum dos 11 singletons de lifespan**. Não importam `app.py` —
portanto sem risco de import circular. `app.py` reimporta estes nomes.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Optional

from buildtovalue.api._models import (
    AppealResponse,
    AppealStatusEnum,
    BiasDeclaration,
)
from buildtovalue.governance.contestability_loop import Appeal
from buildtovalue.security import get_hmac_key


def _impact_label(risk: float) -> str:
    """Jonas — mapeia risco ajustado para rótulo de impacto de longo prazo."""
    if risk >= 0.7:
        return "high"
    if risk >= 0.4:
        return "moderate"
    return "low"


def _build_bias_declaration(
    *,
    trust_score: float,
    adjusted_risk: float,
    mercy_applied: bool,
    pii_redacted: bool,
    explain: str,
) -> BiasDeclaration:
    """Monta a BiasDeclaration a partir de sinais já computados do veredicto."""
    return BiasDeclaration(
        equity_score=round(trust_score, 2),
        pii_redacted=pii_redacted,
        long_term_impact=_impact_label(adjusted_risk),
        mercy_applied=mercy_applied,
        explain=explain,
    )


def sign_verdict(verdict_id: str, action: str, risk: float) -> str:
    """Assina o veredicto com HMAC-SHA256 (S-09).

    Busca a chave atual a cada chamada para que a rotação via SIGHUP
    (`rotate_hmac_key()`) tenha efeito no próximo request do hot path
    `/v1/decide` sem reinício do processo.
    """
    payload = f"{verdict_id}:{action}:{risk:.4f}"
    return hmac.new(get_hmac_key(), payload.encode(), hashlib.sha256).hexdigest()


def _appeal_to_response(appeal: Appeal) -> AppealResponse:
    """Converte um Appeal (governance) no schema de resposta da API."""
    return AppealResponse(
        appeal_id=appeal.appeal_id,
        audit_trail_id=appeal.audit_trail_id,
        user_id=appeal.user_id,
        timestamp=appeal.timestamp,
        reason=appeal.reason,
        evidence_provided=appeal.evidence_provided,
        status=AppealStatusEnum(appeal.status.value),
        reviewer_notes=appeal.reviewer_notes,
        resolution_timestamp=appeal.resolution_timestamp,
        sla_deadline=appeal.sla_deadline,
        is_overdue=appeal.is_overdue(),
        evidence_hash=getattr(appeal, "evidence_hash", None),
        grounds=getattr(appeal, "grounds", []) or [],
        mediator_recommendation=getattr(appeal, "mediator_recommendation", None),
    )


def _resolve_domain(profile: Optional[str]) -> str:
    """Mapeia o profile do agente para o domínio ético do pipeline."""
    mapping = {
        "medical": "medical",
        "healthcare": "medical",
        "financial": "finance",
        "legal": "legal",
        "research": "research",
        "education": "education",
    }
    return mapping.get(profile or "", "general")


def _resolve_role(request) -> str:
    """Resolve the caller's role from a validated JWT Bearer token (HIGH-04).

    Returns the ``role`` claim of a valid token, or ``"anonymous"`` when no
    Bearer token is present or the token is missing/invalid/expired. Fails
    closed to ``"anonymous"`` (least privilege) on any decode error.

    ``request`` only needs a ``headers`` mapping with ``.get`` (FastAPI
    ``Request`` or any compatible object).
    """
    headers = getattr(request, "headers", None)
    if headers is None:
        return "anonymous"
    auth = headers.get("Authorization") or headers.get("authorization")
    if not auth or not auth.startswith("Bearer "):
        return "anonymous"
    token = auth[len("Bearer "):].strip()
    if not token:
        return "anonymous"
    # Lazy import keeps this "pure" helper module free of import-time coupling
    # to the route layer while reusing the canonical JWT secret (DRY).
    try:
        import jwt

        from buildtovalue.api.routes.auth import JWT_ALGORITHM, JWT_SECRET

        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except Exception:  # noqa: BLE001 — fail closed to anonymous on any error
        return "anonymous"
    role = payload.get("role")
    return role if isinstance(role, str) and role else "anonymous"

