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

    # ComplianceEvaluator stores frameworks in self._frameworks dict directly.
    # There is no separate .registry object — access via internal dict.
    fw_data = evaluator._frameworks.get(framework_id)
    if fw_data is None:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown compliance framework: {framework_id}",
        )

    articles_raw = fw_data.get("articles", {})
    serialised_articles = []
    for article_key, rules in articles_raw.items():
        if isinstance(rules, list):
            for rule in rules:
                serialised_articles.append({
                    "article": str(article_key),
                    "policy_name": rule.get("policy_name", ""),
                    "requirement_text": rule.get("requirement_text", ""),
                    "action": rule.get("policy_action", "LOG"),
                    "confidence": rule.get("confidence", 0.5),
                })

    metadata = fw_data.get("_metadata", {})
    return {
        "framework": framework_id,
        "name": metadata.get("framework_name", framework_id),
        "article_count": len(serialised_articles),
        "articles": serialised_articles,
    }
