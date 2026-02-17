"""
Pydantic schemas for Appeals API (ADR-023).

Separados de app.py para manter < 200 linhas por arquivo.
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum


# ═══════════════════════════════════════════════════════════════
# Appeals Schemas
# ═══════════════════════════════════════════════════════════════

class AppealStatusEnum(str, Enum):
    """Mirror of governance.contestability_loop.AppealStatus."""
    PENDING = "pending"
    UNDER_REVIEW = "under_review"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    EXPIRED = "expired"


class AppealSubmitRequest(BaseModel):
    """POST /v1/appeals — submit new appeal."""
    audit_trail_id: int = Field(..., description="ID da decisão contestada")
    user_id: str = Field(..., min_length=1, description="ID do usuário")
    reason: str = Field(..., min_length=20, description="Justificativa (min 20 chars)")
    evidence: Optional[str] = Field(None, description="URL ou texto de evidência")


class AppealResponse(BaseModel):
    """Appeal representation in API responses."""
    appeal_id: str
    audit_trail_id: int
    user_id: str
    timestamp: int
    reason: str
    evidence_provided: Optional[str] = None
    status: AppealStatusEnum
    reviewer_notes: Optional[str] = None
    resolution_timestamp: Optional[int] = None
    sla_deadline: int
    is_overdue: bool


class AppealListResponse(BaseModel):
    """GET /v1/appeals — list with filtering."""
    appeals: List[AppealResponse]
    total: int


class AppealResolveRequest(BaseModel):
    """POST /v1/appeals/{id}/resolve — human decision."""
    accepted: bool
    reviewer_notes: str = Field(..., min_length=10, description="Notas do revisor (min 10 chars)")
    reviewer_id: str = Field(..., min_length=1, description="ID do revisor")


class AppealMetricsResponse(BaseModel):
    """GET /v1/appeals/metrics."""
    appeals_submitted: int
    appeals_accepted: int
    appeals_rejected: int
    sla_violations: int
    pending_appeals: int
    sla_compliance_rate: float
    appeal_success_rate: float