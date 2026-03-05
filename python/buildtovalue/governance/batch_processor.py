"""
BatchProcessor v1.0.0 — Decisões em Lote
Algorithmic Republic — Executivo/Judiciário Branch (ADR-0052)

Invariantes:
  - decision_fn plugável: zero dep de TechnicalEvidence v2.1
  - Fail-secure por item: exceção ou timeout → BLOCK, sem propagação
  - explain_decision obrigatório em todo BatchItemResult (Levinas)
  - DurableLedger opcional: registra toda decisão em append-only
  - asyncio.Semaphore: max_concurrency limita paralelismo
  - Timeout: hard-cap por item (default 50ms), Semaphore por batch
  - Métricas: total, processed, failed, blocked_by_error, success_rate

Filosofia: Jonas (responsabilidade por cada item), Rawls (BLOCK contestável).
"""

import asyncio
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from buildtovalue.governance.types import ActionType


# ─── Constantes ────────────────────────────────────────────────────────────────────

ITEM_TIMEOUT_DEFAULT_MS: float = 50.0
MAX_CONCURRENCY_DEFAULT: int   = 8
_FAIL_SECURE_ACTION:     str   = ActionType.BLOCK.value


# ─── Dataclasses ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class BatchItem:
    """Item de entrada para processamento em lote."""
    item_id: str
    payload: Dict[str, Any]


@dataclass(frozen=True)
class BatchItemResult:
    """
    Resultado de processamento de um item.

    explain_decision obrigatório (Levinas: todo julgamento é auditável).
    is_error=True implica action=BLOCK por fail-secure.
    """
    item_id:            str
    action:             str               # ActionType.value
    confidence:         float
    explain_decision:   Dict[str, Any]
    error:              Optional[str]  = None
    processing_time_ms: float         = 0.0

    @property
    def is_error(self) -> bool:
        return self.error is not None


@dataclass
class BatchMetrics:
    """Métricas agragadas do lote processado."""
    total:            int
    processed:        int
    failed:           int
    blocked_by_error: int
    total_time_ms:    float

    @property
    def success_rate(self) -> float:
        """Fração de items processados sem erro. 1.0 para lote vazio."""
        if self.total == 0:
            return 1.0
        return self.processed / self.total


@dataclass
class BatchResult:
    """Resultado completo do processamento em lote."""
    results:          Tuple[BatchItemResult, ...]
    metrics:          BatchMetrics
    batch_id:         str
    completed_at_iso: str


# ─── Helper interno ─────────────────────────────────────────────────────────────

def _error_result(item_id: str, error: str, elapsed_ms: float) -> BatchItemResult:
    """Fail-secure: qualquer falha → BLOCK com explain_decision auditável."""
    return BatchItemResult(
        item_id            = item_id,
        action             = _FAIL_SECURE_ACTION,
        confidence         = 0.0,
        explain_decision   = {
            "action":     _FAIL_SECURE_ACTION,
            "confidence": 0.0,
            "reason":     "fail_secure_on_error",
            "error":      error[:200],
        },
        error              = error,
        processing_time_ms = elapsed_ms,
    )


# ─── BatchProcessor ───────────────────────────────────────────────────────────────

class BatchProcessor:
    """
    Processador de decisões de governança em lote (ADR-0052).

    Uso:
        def decide(item: BatchItem) -> BatchItemResult:
            ...  # qualquer lógica de decisão

        bp     = BatchProcessor(decision_fn=decide, ledger=ledger)
        result = bp.process_sync([BatchItem("id1", {...}), ...])

    decision_fn pode ser síncrona ou assíncrona (coroutine).
    """

    def __init__(
        self,
        decision_fn: Callable[[BatchItem], Any],
        ledger:          Optional[Any]   = None,
        item_timeout_ms: float           = ITEM_TIMEOUT_DEFAULT_MS,
        max_concurrency: int             = MAX_CONCURRENCY_DEFAULT,
    ) -> None:
        self._decision_fn    = decision_fn
        self._ledger         = ledger
        self._item_timeout_s = item_timeout_ms / 1000.0
        self._max_concurrency = max(1, max_concurrency)

    # ── API pública ───────────────────────────────────────────────────────────

    async def process(self, items: List[BatchItem]) -> BatchResult:
        """
        Processa items em lote de forma concorrente.

        Ordem de results preserva ordem de items.
        Erros individuais não propagam — fail-secure por item.
        """
        t0       = time.perf_counter()
        batch_id = str(uuid.uuid4())

        if not items:
            return _empty_result(batch_id)

        sem     = asyncio.Semaphore(self._max_concurrency)
        tasks   = [self._run_item(item, sem) for item in items]
        results: List[BatchItemResult] = await asyncio.gather(*tasks)

        if self._ledger is not None:
            self._record_ledger(results, batch_id)

        total_ms = (time.perf_counter() - t0) * 1000.0
        return BatchResult(
            results          = tuple(results),
            metrics          = _build_metrics(results, total_ms),
            batch_id         = batch_id,
            completed_at_iso = datetime.utcnow().isoformat() + "Z",
        )

    def process_sync(self, items: List[BatchItem]) -> BatchResult:
        """Interface síncrona para contextos sem event loop ativo."""
        return asyncio.run(self.process(items))

    # ── Internos ──────────────────────────────────────────────────────────────

    async def _run_item(
        self,
        item: BatchItem,
        sem: asyncio.Semaphore,
    ) -> BatchItemResult:
        """Executa item com semáforo, timeout e fail-secure."""
        async with sem:
            t0 = time.perf_counter()
            try:
                result = await asyncio.wait_for(
                    self._invoke(item),
                    timeout=self._item_timeout_s,
                )
                return result
            except asyncio.TimeoutError:
                elapsed = (time.perf_counter() - t0) * 1000.0
                return _error_result(item.item_id, "timeout_exceeded", elapsed)
            except Exception as exc:
                elapsed = (time.perf_counter() - t0) * 1000.0
                return _error_result(item.item_id, str(exc), elapsed)

    async def _invoke(self, item: BatchItem) -> BatchItemResult:
        """Suporta decision_fn síncrona e assíncrona."""
        result = self._decision_fn(item)
        if asyncio.iscoroutine(result):
            return await result
        return result

    def _record_ledger(
        self,
        results: List[BatchItemResult],
        batch_id: str,
    ) -> None:
        """Registra resultados no DurableLedger. Fail-silent: não propaga erro."""
        for r in results:
            try:
                self._ledger.append({
                    "decision_id":      r.item_id,
                    "batch_id":         batch_id,
                    "explain_decision": r.explain_decision,
                })
            except Exception:
                pass


# ─── Funções puras (testáveis) ───────────────────────────────────────────────────────

def _build_metrics(
    results: List[BatchItemResult],
    total_ms: float,
) -> BatchMetrics:
    failed         = sum(1 for r in results if r.is_error)
    blocked_by_err = sum(
        1 for r in results
        if r.is_error and r.action == _FAIL_SECURE_ACTION
    )
    return BatchMetrics(
        total            = len(results),
        processed        = len(results) - failed,
        failed           = failed,
        blocked_by_error = blocked_by_err,
        total_time_ms    = total_ms,
    )


def _empty_result(batch_id: str) -> BatchResult:
    return BatchResult(
        results          = (),
        metrics          = BatchMetrics(0, 0, 0, 0, 0.0),
        batch_id         = batch_id,
        completed_at_iso = datetime.utcnow().isoformat() + "Z",
    )
