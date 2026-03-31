"""
POST /v1/compliance/evaluate — Evaluate agent against compliance frameworks.
P1: Condition template evaluation (activates EU AI Act, LGPD, NIST rules).

NOTE: GET /v1/compliance/report/{framework} is intentionally NOT defined here.
The canonical handler lives in app.py and returns the shape expected by E2E tests:
{"framework", "version", "total_requirements", "compliant", "partial",
 "non_compliant", "compliance_rate", "generated_at", "artifacts"}.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional

from buildtovalue.compliance.compliance_evaluator import ComplianceEvaluator
from buildtovalue.api.auth import require_api_key

router = APIRouter(prefix="/v1/compliance", tags=["compliance"])

_evaluator: Optional[ComplianceEvaluator] = None


def _get_evaluator() -> ComplianceEvaluator:
    global _evaluator
    if _evaluator is None:
        _evaluator = ComplianceEvaluator()
    return _evaluator


class EvaluateRequest(BaseModel):
    agent_metadata: Dict[str, Any] = Field(
        ...,
        description="Agent properties: risk_level, capabilities, etc.",
        examples=[{
            "agent_id": "chatbot-prod-01",
            "risk_level": "high",
            "use_case": "employment",
            "conformity_assessment_completed": False,
            "deployment_requested": True,
            "human_oversight_enabled": True,
            "transparency_score": 0.8,
        }],
    )
    frameworks: Optional[List[str]] = Field(
        None,
        description="Framework IDs to evaluate. None = all.",
    )


@router.post("/evaluate")
def evaluate_compliance(
    req: EvaluateRequest,
    _=Depends(require_api_key),
):
    evaluator = _get_evaluator()
    result = evaluator.evaluate(
        agent_metadata=req.agent_metadata,
        frameworks=req.frameworks,
    )
    return result.to_dict()
