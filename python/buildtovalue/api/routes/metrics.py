"""Metrics route (Lab v3.0) — GET /v1/metrics?range=24h|7d|30d.

Agrega o ledger imutável de decisões (``data/ledger/decisions.jsonl`` via
``LedgerReader``) numa janela temporal e devolve KPIs + heatmap (7×24) +
top vetores + feed de atividade para o ``demo/dashboard.html``.

O ``LedgerReader`` é append-only/JSONL e suporta filtro temporal por
``start_ts``/``end_ts`` (ms). Quando o ledger está ausente ou esparso, a
resposta retorna séries zeradas estruturadas — **nunca** 500.

Pilar de Gilligan: ``EDUCATE``/``REDACT`` e decisões com misericórdia são
contabilizados à parte de ``BLOCK`` duro, preservando a exatidão do trust.
"""
from __future__ import annotations

import time
from collections import Counter
from typing import Dict, List

Entry = Dict[str, object]


def _as_float(v: object, default: float = 0.0) -> float:
    return float(v) if isinstance(v, (int, float)) else default


def _as_int(v: object, default: int = 0) -> int:
    return int(v) if isinstance(v, (int, float)) else default

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from buildtovalue.api.ledger_reader import LedgerQuery, LedgerReader

router = APIRouter()

_reader = LedgerReader()

_WINDOW_MS: Dict[str, int] = {
    "24h": 24 * 3600_000,
    "7d": 7 * 24 * 3600_000,
    "30d": 30 * 24 * 3600_000,
}
_MERCY_ACTIONS = {"EDUCATE", "REDACT"}


class VectorCount(BaseModel):
    name: str
    count: int


class ActivityItem(BaseModel):
    action: str
    label: str
    risk: float
    ago_s: int


class MetricsResponse(BaseModel):
    range: str
    total_decisions: int
    block_rate: float
    trust_avg: float
    heatmap: List[List[int]] = Field(default_factory=list)  # 7 dias × 24 horas
    top_vectors: List[VectorCount] = Field(default_factory=list)
    activity: List[ActivityItem] = Field(default_factory=list)


def _collect_window(since_ms: int) -> List[Entry]:
    """Lê todas as entradas do ledger na janela (loop de páginas, fail-soft)."""
    out: List[Dict[str, object]] = []
    page = 1
    while True:
        res = _reader.query(LedgerQuery(start_ts=since_ms, page=page, page_size=1000))
        out.extend(res.entries)
        if page >= res.total_pages or not res.entries:
            break
        page += 1
    return out


def _empty_heatmap() -> List[List[int]]:
    return [[0] * 24 for _ in range(7)]


def _heatmap(entries: List[Dict[str, object]]) -> List[List[int]]:
    grid = _empty_heatmap()
    for e in entries:
        ts = e.get("ts")
        if not isinstance(ts, (int, float)):
            continue
        lt = time.gmtime(ts / 1000.0)
        grid[lt.tm_wday][lt.tm_hour] += 1
    return grid


def _is_hard_block(e: Entry) -> bool:
    """BLOCK duro = final_action BLOCK sem misericórdia (Gilligan)."""
    return e.get("final_action") == "BLOCK" and not e.get("mercy")


def _trust_avg(entries: List[Entry]) -> float:
    """Trust ≈ 1 - risk médio (o ledger registra risk, não trust direto)."""
    risks = [_as_float(e.get("risk")) for e in entries if isinstance(e.get("risk"), (int, float))]
    if not risks:
        return 0.0
    return round(max(0.0, min(1.0, 1.0 - sum(risks) / len(risks))), 2)


def _top_vectors(entries: List[Entry], limit: int = 9) -> List[VectorCount]:
    """Top categorias disponíveis no ledger (policy_action) — proxy de vetor."""
    counter: "Counter[str]" = Counter(
        str(e.get("policy_action") or e.get("final_action") or "UNKNOWN") for e in entries
    )
    return [VectorCount(name=n, count=c) for n, c in counter.most_common(limit)]


def _activity(entries: List[Entry], now_ms: int, limit: int = 12) -> List[ActivityItem]:
    recent = sorted(entries, key=lambda e: _as_int(e.get("ts")), reverse=True)[:limit]
    items: List[ActivityItem] = []
    for e in recent:
        ts = _as_int(e.get("ts"), now_ms)
        items.append(ActivityItem(
            action=str(e.get("final_action", "ALLOW")),
            label=str(e.get("profile") or e.get("verdict_id") or "decision"),
            risk=_as_float(e.get("risk")),
            ago_s=max(0, int((now_ms - ts) / 1000)),
        ))
    return items


@router.get("/v1/metrics", response_model=MetricsResponse)
async def get_metrics(range: str = Query("7d")) -> MetricsResponse:
    """Agrega métricas do ledger na janela pedida (default 7d)."""
    window = _WINDOW_MS.get(range, _WINDOW_MS["7d"])
    norm_range = range if range in _WINDOW_MS else "7d"
    now_ms = int(time.time() * 1000)
    entries = _collect_window(now_ms - window)

    total = len(entries)
    hard_blocks = sum(1 for e in entries if _is_hard_block(e))
    return MetricsResponse(
        range=norm_range,
        total_decisions=total,
        block_rate=round(hard_blocks / total, 4) if total else 0.0,
        trust_avg=_trust_avg(entries),
        heatmap=_heatmap(entries),
        top_vectors=_top_vectors(entries),
        activity=_activity(entries, now_ms),
    )
