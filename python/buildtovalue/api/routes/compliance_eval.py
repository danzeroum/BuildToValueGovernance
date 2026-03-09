"""
POST /v1/compliance/evaluate — Evaluate agent against compliance frameworks.
GET  /v1/compliance/report/{framework_id} — Summary report for a framework.
P1: Condition template evaluation (activates EU AI Act, LGPD, NIST rules).
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional

from buildtovalue.compliance.compliance_evaluator import ComplianceEvaluator
from buildtovalue.api.app import require_api_key

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


@router.get("/report/{framework_id}")
def compliance_report(
    framework_id: str,
    _=Depends(require_api_key),
):
    """Summary report for a registered compliance framework.

    Returns framework metadata and all articles so external tools
    (e2e, dashboards) can inspect rules without running a full evaluation.
    """
    evaluator = _get_evaluator()
    try:
        fw = evaluator.registry.get_framework(framework_id)
        articles = evaluator.registry.get_all_articles(framework_id)
    except (KeyError, ValueError):
        raise HTTPException(
            status_code=404,
            detail=f"Unknown compliance framework: {framework_id}",
        )
    serialised_articles = [
        a.to_dict() if hasattr(a, "to_dict") else {"id": str(a)}
        for a in articles
    ]
    return {
        "framework": framework_id,
        "name": getattr(fw, "name", framework_id),
        "article_count": len(serialised_articles),
        "articles": serialised_articles,
    }
