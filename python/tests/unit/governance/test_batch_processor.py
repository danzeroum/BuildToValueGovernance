"""
Tests — BatchProcessor v1.0.0 (ADR-0052)

20 testes:
  - Lote vazio (2)
  - Processamento básico (3)
  - Fail-secure por erro (3)
  - Timeout fail-secure (2)
  - Métricas (5)
  - process_sync() (1)
  - batch_id e timestamp (2)
  - Integração com DurableLedger (2)
"""

import asyncio
import time
import pytest
from buildtovalue.governance.batch_processor import (
    BatchItem,
    BatchItemResult,
    BatchMetrics,
    BatchProcessor,
    BatchResult,
    _FAIL_SECURE_ACTION,
    _build_metrics,
    _error_result,
)
from buildtovalue.governance.types import ActionType


# ─── Fixtures ─────────────────────────────────────────────────────────────────

def _allow_fn(item: BatchItem) -> BatchItemResult:
    return BatchItemResult(
        item_id          = item.item_id,
        action           = ActionType.ALLOW.value,
        confidence       = 0.95,
        explain_decision = {"action": "ALLOW", "confidence": 0.95, "reason": "test"},
    )


def _error_fn(item: BatchItem) -> BatchItemResult:
    raise RuntimeError("decision_fn_error")


def _make_items(n: int) -> list:
    return [BatchItem(f"item-{i:03d}", {"seq": i}) for i in range(1, n + 1)]


def _make_processor(**kwargs) -> BatchProcessor:
    return BatchProcessor(decision_fn=_allow_fn, **kwargs)


# ─── Lote vazio ───────────────────────────────────────────────────────────────

def test_empty_batch_results_empty():
    bp = _make_processor()
    r  = bp.process_sync([])
    assert r.results == ()


def test_empty_batch_metrics_zero():
    bp = _make_processor()
    r  = bp.process_sync([])
    assert r.metrics.total == 0
    assert r.metrics.processed == 0
    assert r.metrics.failed == 0


# ─── Processamento básico ─────────────────────────────────────────────────────

def test_single_item_processed():
    bp = _make_processor()
    r  = bp.process_sync(_make_items(1))
    assert len(r.results) == 1
    assert r.results[0].action == ActionType.ALLOW.value


def test_multiple_items_all_processed():
    bp = _make_processor()
    r  = bp.process_sync(_make_items(5))
    assert len(r.results) == 5
    assert all(res.action == ActionType.ALLOW.value for res in r.results)


def test_item_ids_preserved_in_results():
    bp    = _make_processor()
    items = _make_items(3)
    r     = bp.process_sync(items)
    ids   = {res.item_id for res in r.results}
    assert ids == {"item-001", "item-002", "item-003"}


# ─── Fail-secure por erro ─────────────────────────────────────────────────────

def test_error_fn_produces_block():
    bp = BatchProcessor(decision_fn=_error_fn)
    r  = bp.process_sync(_make_items(1))
    assert r.results[0].action == _FAIL_SECURE_ACTION


def test_error_fn_is_error_true():
    bp = BatchProcessor(decision_fn=_error_fn)
    r  = bp.process_sync(_make_items(1))
    assert r.results[0].is_error is True


def test_error_fn_explain_decision_has_reason():
    bp = BatchProcessor(decision_fn=_error_fn)
    r  = bp.process_sync(_make_items(1))
    assert r.results[0].explain_decision["reason"] == "fail_secure_on_error"


# ─── Timeout fail-secure ──────────────────────────────────────────────────────

def test_timeout_produces_block():
    async def slow_fn(item: BatchItem) -> BatchItemResult:
        await asyncio.sleep(0.2)
        return _allow_fn(item)

    bp = BatchProcessor(decision_fn=slow_fn, item_timeout_ms=10.0)
    r  = bp.process_sync(_make_items(1))
    assert r.results[0].action == _FAIL_SECURE_ACTION


def test_timeout_is_error():
    async def slow_fn(item: BatchItem) -> BatchItemResult:
        await asyncio.sleep(0.2)
        return _allow_fn(item)

    bp = BatchProcessor(decision_fn=slow_fn, item_timeout_ms=10.0)
    r  = bp.process_sync(_make_items(1))
    assert r.results[0].is_error is True


# ─── Métricas ─────────────────────────────────────────────────────────────────

def test_metrics_total():
    bp = _make_processor()
    r  = bp.process_sync(_make_items(5))
    assert r.metrics.total == 5


def test_metrics_processed_vs_failed():
    call_count = [0]

    def mixed_fn(item: BatchItem) -> BatchItemResult:
        call_count[0] += 1
        if call_count[0] % 2 == 0:
            raise RuntimeError("forced")
        return _allow_fn(item)

    bp = BatchProcessor(decision_fn=mixed_fn)
    r  = bp.process_sync(_make_items(4))
    assert r.metrics.processed == 2
    assert r.metrics.failed == 2


def test_metrics_blocked_by_error():
    bp = BatchProcessor(decision_fn=_error_fn)
    r  = bp.process_sync(_make_items(3))
    assert r.metrics.blocked_by_error == 3


def test_metrics_success_rate_all_ok():
    bp = _make_processor()
    r  = bp.process_sync(_make_items(4))
    assert r.metrics.success_rate == 1.0


def test_metrics_success_rate_empty():
    bp = _make_processor()
    r  = bp.process_sync([])
    assert r.metrics.success_rate == 1.0


# ─── process_sync() ───────────────────────────────────────────────────────────

def test_process_sync_returns_batch_result():
    bp = _make_processor()
    r  = bp.process_sync(_make_items(2))
    assert isinstance(r, BatchResult)


# ─── batch_id e timestamp ─────────────────────────────────────────────────────

def test_batch_ids_are_unique():
    bp = _make_processor()
    r1 = bp.process_sync(_make_items(1))
    r2 = bp.process_sync(_make_items(1))
    assert r1.batch_id != r2.batch_id


def test_completed_at_iso_utc():
    bp = _make_processor()
    r  = bp.process_sync(_make_items(1))
    assert r.completed_at_iso.endswith("Z")


# ─── Integração com DurableLedger ─────────────────────────────────────────────

_LEDGER_KEY = b"test-key-batch-processor-32bytes"


def test_ledger_records_all_results():
    from buildtovalue.governance.durable_ledger import DurableLedger
    ledger = DurableLedger(hmac_key=_LEDGER_KEY)
    bp     = BatchProcessor(decision_fn=_allow_fn, ledger=ledger)
    bp.process_sync(_make_items(5))
    assert len(ledger) == 5


def test_ledger_verify_after_batch():
    from buildtovalue.governance.durable_ledger import DurableLedger
    ledger = DurableLedger(hmac_key=_LEDGER_KEY)
    bp     = BatchProcessor(decision_fn=_allow_fn, ledger=ledger)
    bp.process_sync(_make_items(3))
    result = ledger.verify()
    assert result.valid
    assert result.entries_checked == 3
