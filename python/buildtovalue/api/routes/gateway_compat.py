"""Aliases compatíveis com o gateway Rust — /v1/validate e /v1/sanitize.

Os SDKs Python/JS falam o contrato do gateway Rust (porta 8080). Antes deste
módulo, esses dois endpoints não existiam na API Python (porta 8000), então
`BTVClient.validate()`/`sanitize()` retornavam 404 contra a governança.

- /v1/validate: mesma superfície do `rust/gateway/src/routes/validate.rs`,
  servida pelo pipeline /v1/decide existente (FFI scan quando o kernel está
  instalado; fallback textual degradado quando não está).
- /v1/sanitize: mesma superfície do `rust/gateway/src/routes/sanitize.rs`,
  com os MESMOS padrões de máscara de PII do kernel
  (`rust/kernel/src/security/output_guard.rs`) portados para Python — manter
  os dois em sincronia ao alterar qualquer um.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from buildtovalue.api._models import DecideRequest
from buildtovalue.api.auth import require_api_key
from buildtovalue.api.routes.decide import (
    _DecideCtx,
    decide,
    get_decide_singletons,
)

router = APIRouter()


# ── /v1/validate ─────────────────────────────────────────────────────────

class ValidateRequest(BaseModel):
    input: str = Field(max_length=50000)
    session_id: Optional[str] = None
    profile: Optional[str] = None


@router.post("/v1/validate")
def validate(
    req: ValidateRequest,
    request: Request,
    ctx: _DecideCtx = Depends(get_decide_singletons),
    _: None = Depends(require_api_key),
) -> Dict[str, object]:
    dreq = DecideRequest(
        input_text=req.input,
        session_id=req.session_id,
        profile=req.profile,
    )
    resp = decide(dreq, request, ctx, None)

    # Superfície idêntica ao ValidateResponse do gateway Rust. Os campos de
    # evidência vêm de `dreq`, que o pipeline muta durante o scan FFI.
    return {
        "finding_count": dreq.finding_count,
        "critical_count": dreq.critical_count,
        "composite_risk": dreq.composite_risk,
        "action": resp.action,
        "original_action": resp.original_action,
        "mercy_applied": resp.mercy_applied,
        "latency_ms": resp.latency_ms,
        "contestable": resp.contestable,
        "appeal_deadline_hours": resp.appeal_deadline_hours,
        "message": resp.rationale,
        "hard_blocked": dreq.hard_blocked,
        "matched_policies": dreq.matched_policies,
        "verdict_id": resp.verdict_id,
        "signature": resp.signature,
        "rationale": resp.rationale,
        # Extras que o SDK modela com default (presentes no fluxo Rust):
        "max_finding_confidence": dreq.max_finding_confidence,
        "entropy": dreq.entropy,
        "total_chars": dreq.total_chars or len(req.input),
        "blake3_hash": dreq.blake3_hash,
        "drift_level": dreq.drift_level,
        "hard_block_term": None,
    }


# ── /v1/sanitize ─────────────────────────────────────────────────────────
# Padrões portados de rust/kernel/src/security/output_guard.rs (PII_*).

_PII_CPF = re.compile(r"\b(\d{3})\.?(\d{3})\.?(\d{3})-?(\d{2})\b")
_PII_CNPJ = re.compile(r"\b(\d{2})\.?(\d{3})\.?(\d{3})/?(\d{4})-?(\d{2})\b")
_PII_EMAIL = re.compile(
    r"\b([a-zA-Z0-9._%+-])([a-zA-Z0-9._%+-]*)@([a-zA-Z0-9])([a-zA-Z0-9.-]*\.[a-zA-Z]{2,})\b"
)
_PII_PHONE = re.compile(r"\b(\d{2})\s?9?\d{4}-?\d{4}\b")
_PII_CC = re.compile(r"\b(\d{4})\s?\d{4}\s?\d{4}\s?(\d{4})\b")
_PII_SSN = re.compile(r"\b(\d{3})[-\s](\d{2})[-\s](\d{4})\b")


class SanitizeRequest(BaseModel):
    text: str = Field(max_length=100000)


@router.post("/v1/sanitize")
def sanitize(
    req: SanitizeRequest, _: None = Depends(require_api_key)
) -> Dict[str, object]:
    start = time.perf_counter()
    result = req.text
    masked_count = 0
    masked_types: List[str] = []

    # Mesma ordem e mesmos replacements do kernel (CC antes de SSN não é
    # necessário aqui porque a ordem do kernel é preservada abaixo).
    if _PII_CPF.search(result):
        result = _PII_CPF.sub(r"***.***.***-\4", result)
        masked_count += 1
        masked_types.append("cpf")

    if _PII_CNPJ.search(result):
        result = _PII_CNPJ.sub(r"**.***.***/\4-\5", result)
        masked_count += 1
        masked_types.append("cnpj")

    if _PII_EMAIL.search(result):
        result = _PII_EMAIL.sub(r"\1***@\3***", result)
        masked_count += 1
        masked_types.append("email")

    if _PII_PHONE.search(result):
        result = _PII_PHONE.sub(r"\1 ****-****", result)
        masked_count += 1
        masked_types.append("phone")

    if _PII_CC.search(result):
        result = _PII_CC.sub(r"\1 **** **** \2", result)
        masked_count += 1
        masked_types.append("credit_card")

    if _PII_SSN.search(result):
        result = _PII_SSN.sub(r"***-**-\3", result)
        masked_count += 1
        masked_types.append("ssn")

    latency_ms = (time.perf_counter() - start) * 1000.0

    return {
        "original_length": len(req.text),
        "sanitized_text": result,
        "masked_count": masked_count,
        "masked_types": masked_types,
        "latency_ms": latency_ms,
    }
