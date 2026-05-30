"""SLM / NER routes (ADR-0093 Phase 2, Passo 3 — router 5).

4 rotas do domínio de modelos locais (SLM) e detecção semântica de PII (NER):
- GET  /v1/slm/metrics    — métricas do classificador SLM
- GET  /v1/slm/bias       — declaração de viés do SLM (FPR/FNR, ADR)
- POST /v1/scan/semantic  — detecção semântica de PII via NER (ADR-047)
- GET  /v1/ner/metrics    — métricas do detector NER (ADR-047)

Decisão de estado (documentada no commit):
- `_slm` (SLMClassifier) e `_ner` (NERDetector): **app.state** — instanciados no
  lifespan e lidos via `Depends(...)`. `_slm` já era promovido a `app.state.slm`;
  `_ner` foi adicionado a `app.state.ner` no lifespan neste passo (era apenas
  reinjetado no shim). Sem import reverso de `app.py`.

Nota de comportamento (back-compat — preservado, NÃO endurecido neste refactor):
- `/v1/slm/metrics`, `/v1/slm/bias`, `/v1/ner/metrics` retornam HTTP 200 com
  `{"enabled": False, ...}` quando o modelo não está carregado (degradação
  graciosa, contrato legado). Apenas `/v1/scan/semantic` é Fail-Secure (503).
  Por isso os provedores são **opcionais** (retornam None) em vez de levantar
  503 incondicionalmente — preservar o contrato legado tem precedência sobre a
  diretriz genérica de 503, do mesmo modo que no Router 4.
"""
from __future__ import annotations

from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request

from buildtovalue.api.auth import require_api_key
from buildtovalue.intelligence.ner_detector import NERDetector
from buildtovalue.intelligence.slm_classifier import SLMClassifier

router = APIRouter()


def get_slm_optional(request: Request) -> Optional[SLMClassifier]:
    """Provedor opcional — retorna None se o SLM não foi carregado no lifespan."""
    slm = getattr(request.app.state, "slm", None)
    return slm if isinstance(slm, SLMClassifier) else None


def get_ner_optional(request: Request) -> Optional[NERDetector]:
    """Provedor opcional — retorna None se o NER não foi carregado no lifespan."""
    ner = getattr(request.app.state, "ner", None)
    return ner if isinstance(ner, NERDetector) else None


# ═════════════════════════════════════════════════════════════════
# SLM METRICS — /v1/slm
# ═════════════════════════════════════════════════════════════════

@router.get("/v1/slm/metrics")
def slm_metrics(
    slm: Optional[SLMClassifier] = Depends(get_slm_optional),
    _: None = Depends(require_api_key),
) -> Dict[str, object]:
    if slm is None:
        return {"enabled": False, "message": "SLM not loaded"}
    return {"enabled": True, **slm.get_metrics()}


@router.get("/v1/slm/bias")
def slm_bias(
    slm: Optional[SLMClassifier] = Depends(get_slm_optional),
    _: None = Depends(require_api_key),
) -> Dict[str, object]:
    if slm is None:
        return {"enabled": False, "message": "SLM not loaded"}
    b = slm.get_bias_declaration()
    return {
        "enabled": True,
        "fpr": b.fpr, "fnr": b.fnr,
        "calibration_date": b.calibration_date,
        "sample_size": b.sample_size,
        "model_id": b.model_id,
        "limitations": b.limitations,
        "affected_groups": b.affected_groups,
    }


# ═════════════════════════════════════════════════════════════════
# NER SEMANTIC SCAN — /v1/scan/semantic (ADR-047)
# ═════════════════════════════════════════════════════════════════

@router.post("/v1/scan/semantic")
def scan_semantic(
    # TODO(Governance): Tipar payload semântico via Pydantic para mitigar risco de injeção.
    # Mantido como dict não-Pydantic (back-compat sancionado); Dict[str, object]
    # satisfaz mypy --strict sem introduzir um schema.
    req: Dict[str, object],
    ner: Optional[NERDetector] = Depends(get_ner_optional),
    _: None = Depends(require_api_key),
) -> Dict[str, object]:
    """Semantic PII detection via SLM NER (ADR-047)."""
    if ner is None:
        raise HTTPException(status_code=503, detail="NER detector not available (SLM not loaded)")
    text = req.get("text", "")
    # Comportamento legado preservado: `len(text)` sobre payload não-tipado
    # (back-compat sancionado — ver TODO acima).
    if not text or len(text) < 3:  # type: ignore[arg-type]
        raise HTTPException(status_code=400, detail="Text must be at least 3 characters")
    result = ner.detect(text)  # type: ignore[arg-type]  # text é object (req:dict); legado passa direto
    return result.to_dict()


@router.get("/v1/ner/metrics")
def ner_metrics(
    ner: Optional[NERDetector] = Depends(get_ner_optional),
    _: None = Depends(require_api_key),
) -> Dict[str, object]:
    """NER detector metrics (ADR-047)."""
    if ner is None:
        return {"enabled": False, "message": "NER not loaded"}
    return {"enabled": True, **ner.get_metrics()}
