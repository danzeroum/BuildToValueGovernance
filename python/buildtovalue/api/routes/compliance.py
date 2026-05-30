"""Compliance routes (ADR-0093 Phase 2, Passo 3 — router 3).

`/v1/compliance/*` — 8 rotas (check, frameworks, report, classify-risk,
fria/generate, ropa/generate, art20/report, documents/export).

Decisão de estado (documentada no commit):
- `_risk_classifier`: **app.state** — compartilhado com o hot path
  `_decide_compliance()`; lido via `Depends(get_risk_classifier)` para garantir
  a MESMA instância. Sem import reverso de `app.py`.
- `COMPLIANCE_PLUGINS`, `_fria_generator`, `_ledger_analytics`,
  `_ropa_generator`, `_art20_generator`, `_doc_exporter`: **module-level local**
  — exclusivos do domínio de compliance (nenhum outro módulo os consome) e sem
  estado compartilhado; instanciá-los aqui evita sobrecarga do lifespan.
"""
from __future__ import annotations

from typing import Dict, Union

from fastapi import APIRouter, Depends, HTTPException, Request

from buildtovalue.api._models import (
    Art20Request,
    ComplianceRequest,
    DocumentExportRequest,
    FRIARequest,
    RiskClassifyRequest,
    ROPARequest,
)
from buildtovalue.api.auth import require_api_key
from buildtovalue.compliance.art20_report import Art20ReportGenerator
from buildtovalue.compliance.document_exporter import DocumentExporter
from buildtovalue.compliance.eu_ai_act_plugin import EUAIActPlugin
from buildtovalue.compliance.fria_generator import FRIAGenerator
from buildtovalue.compliance.ledger_analytics import LedgerAnalytics
from buildtovalue.compliance.lgpd_plugin import LGPDPlugin
from buildtovalue.compliance.ropa_generator import ROPAGenerator
from buildtovalue.compliance.risk_classifier import RiskClassifier

router = APIRouter()

# Instâncias module-level (compliance-only, sem estado compartilhado externo).
COMPLIANCE_PLUGINS: Dict[str, Union[LGPDPlugin, EUAIActPlugin]] = {
    "LGPD": LGPDPlugin(),
    "EU_AI_ACT": EUAIActPlugin(),
}
_fria_generator = FRIAGenerator()
_ledger_analytics = LedgerAnalytics()
_ropa_generator = ROPAGenerator(_ledger_analytics)
_art20_generator = Art20ReportGenerator(_ledger_analytics)
_doc_exporter = DocumentExporter()


def get_risk_classifier(request: Request) -> RiskClassifier:
    """Provedor estrito — MESMA instância do hot path. Fail-Secure (503)."""
    rc = getattr(request.app.state, "risk_classifier", None)
    if not isinstance(rc, RiskClassifier):
        raise HTTPException(
            status_code=503,
            detail="FAIL-SECURE: RiskClassifier nao inicializado no lifespan.",
        )
    return rc


@router.post("/v1/compliance/check")
def compliance_check(
    req: ComplianceRequest, _: None = Depends(require_api_key)
) -> Dict[str, object]:
    # Guard de integridade: lista de plugins vazia → recusa (Fail-Secure).
    if not COMPLIANCE_PLUGINS:
        raise HTTPException(status_code=503, detail="No compliance plugins loaded")
    plugin = COMPLIANCE_PLUGINS.get(req.framework)
    if not plugin:
        return {"error": f"Unknown framework: {req.framework}. Available: {list(COMPLIANCE_PLUGINS.keys())}"}
    artifacts = plugin.generate_artifacts(req.evidence, req.verdict)
    compliant = sum(1 for a in artifacts if a.status.value == "COMPLIANT")
    return {
        "framework": req.framework,
        "total": len(artifacts),
        "compliant": compliant,
        "compliance_rate": compliant / len(artifacts) if artifacts else 0,
        "artifacts": [
            {"article": a.article, "requirement": a.requirement,
             "status": a.status.value, "evidence": a.evidence,
             "recommendation": a.recommendation}
            for a in artifacts
        ],
    }


@router.get("/v1/compliance/frameworks")
def list_frameworks(_: None = Depends(require_api_key)) -> Dict[str, object]:
    return {
        "frameworks": [
            {"id": p.framework_id(), "name": p.framework_name()}
            for p in COMPLIANCE_PLUGINS.values()
        ]
    }


@router.get("/v1/compliance/report/{framework}")
def compliance_report(
    framework: str, _: None = Depends(require_api_key)
) -> Dict[str, object]:
    plugin = COMPLIANCE_PLUGINS.get(framework)
    if not plugin:
        return {"error": f"Unknown framework: {framework}"}
    report = plugin.validate_requirements()
    return {
        "framework": report.framework,
        "version": report.version,
        "total_requirements": report.total_requirements,
        "compliant": report.compliant,
        "partial": report.partial,
        "non_compliant": report.non_compliant,
        "compliance_rate": report.compliance_rate,
        "generated_at": report.generated_at,
        "artifacts": [
            {"article": a.article, "requirement": a.requirement,
             "status": a.status.value, "evidence": a.evidence,
             "recommendation": a.recommendation}
            for a in report.artifacts
        ],
    }


@router.post("/v1/compliance/classify-risk")
def classify_risk(
    req: RiskClassifyRequest,
    rc: RiskClassifier = Depends(get_risk_classifier),
    _: None = Depends(require_api_key),
) -> Dict[str, object]:
    result = rc.classify(
        agent_id=req.agent_id,
        sector=req.sector,
        capabilities=req.capabilities,
        deployment_context=req.deployment_context,
    )
    return result.to_dict()


@router.post("/v1/compliance/fria/generate")
def generate_fria(
    req: FRIARequest,
    rc: RiskClassifier = Depends(get_risk_classifier),
    _: None = Depends(require_api_key),
) -> Dict[str, object]:
    classification = rc.classify(
        agent_id=req.agent_id,
        sector=req.sector,
        capabilities=req.capabilities,
        deployment_context=req.deployment_context,
    )
    viols: list[dict[str, object]] = []
    rate = 1.0
    if classification.risk_level.value in ("HIGH_RISK", "PROHIBITED"):
        from buildtovalue.compliance.compliance_evaluator import ComplianceEvaluator
        evaluator = ComplianceEvaluator()
        result = evaluator.evaluate({
            "agent_id": req.agent_id,
            "sector": req.sector,
            "risk_level": classification.risk_level.value,
            "capabilities": req.capabilities,
            "risk_score": 0.5,
            "use_case": req.sector,
            "conformity_assessment_completed": False,
        })
        viols = [
            {"framework": v.framework, "article": v.article,
             "requirement": v.requirement, "action": v.action}
            for v in result.violations
        ]
        rate = result.compliance_rate

    doc = _fria_generator.generate(
        agent_id=req.agent_id,
        risk_level=classification.risk_level.value,
        sector=req.sector,
        obligations=classification.obligations,
        violations=viols,
        compliance_rate=rate,
        capabilities=req.capabilities,
        ledger_analytics=_ledger_analytics,
    )
    return doc.to_dict()


@router.post("/v1/compliance/ropa/generate")
def generate_ropa(
    req: ROPARequest, _: None = Depends(require_api_key)
) -> Dict[str, object]:
    """Generate ROPA document from ledger data (LGPD Art. 37, ADR-048)."""
    ropa = _ropa_generator.generate(
        controller=req.controller,
        dpo_name=req.dpo_name,
        dpo_contact=req.dpo_contact,
        start_ts=req.start_ts,
        end_ts=req.end_ts,
    )
    return ropa.to_dict()


@router.post("/v1/compliance/art20/report")
def generate_art20(
    req: Art20Request, _: None = Depends(require_api_key)
) -> Dict[str, object]:
    """Generate Art. 20 automated decision report (LGPD, ADR-048)."""
    report = _art20_generator.generate(
        start_ts=req.start_ts,
        end_ts=req.end_ts,
        include_decisions=req.include_decisions,
        max_decisions=req.max_decisions,
    )
    return report.to_dict()


@router.post("/v1/compliance/documents/export")
def export_compliance_document(
    req: DocumentExportRequest, _: None = Depends(require_api_key)
) -> Dict[str, object]:
    """Export compliance document to PDF (ADR-048)."""
    if req.type not in ("ropa", "fria", "art20"):
        raise HTTPException(status_code=400, detail="type must be ropa, fria, or art20")
    if not req.data:
        raise HTTPException(status_code=400, detail="data is required")

    if req.format == "pdf":
        try:
            path = _doc_exporter.export_pdf(data=req.data, template_name=req.type)
            return {"status": "ok", "format": "pdf", "path": path}
        except ImportError as e:
            raise HTTPException(status_code=503, detail=str(e))
    path = _doc_exporter.export_json(data=req.data, template_name=req.type)
    return {"status": "ok", "format": "json", "path": path}
