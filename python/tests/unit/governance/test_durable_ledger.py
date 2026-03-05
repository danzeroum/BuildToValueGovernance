"""
Tests — DurableLedger v1.0.0 (ADR-0051)

24 testes:
  - Constantes e genesis (2)
  - Append básico (5)
  - explain_decision obrigatório (1)
  - Chain hash (3)
  - Verify: ledger válido (3)
  - Verify: ledger adulterado (3)
  - Imutabilidade (2)
  - Métricas len + entries snapshot (2)
  - Thread safety (1)
  - Integração com ConsensusDecision (2)
"""

import threading
import time
import pytest
from buildtovalue.governance.durable_ledger import (
    GENESIS_SEED,
    BLAKE2B_DIGEST_SIZE,
    DurableLedger,
    LedgerEntry,
    LedgerVerification,
    _genesis_hash,
    _chain_hash,
)

TEST_KEY = b"btv-ledger-test-key-adr0051-----"


def _make_ledger() -> DurableLedger:
    return DurableLedger(hmac_key=TEST_KEY)


def _payload(n: int = 1) -> dict:
    return {
        "decision_id": f"DEC-{n:04d}",
        "explain_decision": {
            "action": "BLOCK",
            "confidence": 0.9,
            "reason": f"test-{n}",
        },
        "timestamp": 1700000000 + n,
    }


# ─── Constantes e genesis ──────────────────────────────────────────────────────

def test_genesis_seed_value():
    assert GENESIS_SEED == b"BTV-LEDGER-GENESIS-v1.0"


def test_genesis_hash_deterministic():
    assert _genesis_hash() == _genesis_hash()
    assert len(_genesis_hash()) == BLAKE2B_DIGEST_SIZE


# ─── Append básico ────────────────────────────────────────────────────────────

def test_append_returns_ledger_entry():
    ledger = _make_ledger()
    entry = ledger.append(_payload(1))
    assert isinstance(entry, LedgerEntry)


def test_append_sequence_starts_at_one():
    ledger = _make_ledger()
    entry = ledger.append(_payload(1))
    assert entry.sequence == 1


def test_append_sequence_monotonic():
    ledger = _make_ledger()
    e1 = ledger.append(_payload(1))
    e2 = ledger.append(_payload(2))
    e3 = ledger.append(_payload(3))
    assert (e1.sequence, e2.sequence, e3.sequence) == (1, 2, 3)


def test_append_hmac_length():
    ledger = _make_ledger()
    entry = ledger.append(_payload(1))
    assert len(entry.hmac_sha256) == 64


def test_append_recorded_at_utc():
    ledger = _make_ledger()
    entry = ledger.append(_payload(1))
    assert entry.recorded_at_iso.endswith("Z")


# ─── explain_decision obrigatório ─────────────────────────────────────────────

def test_append_without_explain_decision_raises():
    ledger = _make_ledger()
    with pytest.raises(ValueError, match="explain_decision"):
        ledger.append({"decision_id": "DEC-001", "timestamp": 1})


# ─── Chain hash ───────────────────────────────────────────────────────────────

def test_first_entry_prev_hash_is_genesis():
    ledger = _make_ledger()
    entry = ledger.append(_payload(1))
    assert entry.prev_hash == _genesis_hash().hex()


def test_second_entry_prev_hash_equals_first_entry_hash():
    ledger = _make_ledger()
    e1 = ledger.append(_payload(1))
    e2 = ledger.append(_payload(2))
    assert e2.prev_hash == e1.entry_hash


def test_different_payloads_produce_different_hashes():
    ledger = _make_ledger()
    e1 = ledger.append(_payload(1))
    e2 = ledger.append(_payload(2))
    assert e1.entry_hash != e2.entry_hash


# ─── Verify: ledger válido ────────────────────────────────────────────────────

def test_verify_empty_ledger_is_valid():
    ledger = _make_ledger()
    result = ledger.verify()
    assert result.valid
    assert result.entries_checked == 0


def test_verify_single_entry_valid():
    ledger = _make_ledger()
    ledger.append(_payload(1))
    result = ledger.verify()
    assert result.valid
    assert result.entries_checked == 1


def test_verify_ten_entries_valid():
    ledger = _make_ledger()
    for i in range(1, 11):
        ledger.append(_payload(i))
    result = ledger.verify()
    assert result.valid
    assert result.entries_checked == 10


# ─── Verify: ledger adulterado ─────────────────────────────────────────────────

def test_verify_detects_tampered_entry_hash():
    ledger = _make_ledger()
    ledger.append(_payload(1))
    ledger.append(_payload(2))
    object.__setattr__(ledger._entries[0], "entry_hash", "0" * 64)
    result = ledger.verify()
    assert not result.valid


def test_verify_tampered_reports_first_invalid_sequence():
    ledger = _make_ledger()
    ledger.append(_payload(1))
    ledger.append(_payload(2))
    object.__setattr__(ledger._entries[0], "entry_hash", "0" * 64)
    result = ledger.verify()
    assert result.first_invalid_sequence is not None


def test_verify_tampered_payload_detected():
    ledger = _make_ledger()
    ledger.append(_payload(1))
    object.__setattr__(
        ledger._entries[0],
        "payload",
        {"explain_decision": {"action": "ALLOW"}, "tampered": True},
    )
    result = ledger.verify()
    assert not result.valid
    assert result.reason is not None


# ─── Imutabilidade ────────────────────────────────────────────────────────────

def test_ledger_entry_is_frozen():
    ledger = _make_ledger()
    entry = ledger.append(_payload(1))
    with pytest.raises((AttributeError, TypeError)):
        entry.sequence = 99  # type: ignore


def test_entries_returns_tuple_snapshot():
    ledger = _make_ledger()
    ledger.append(_payload(1))
    snap = ledger.entries()
    assert isinstance(snap, tuple)
    assert len(snap) == 1


# ─── Métricas ─────────────────────────────────────────────────────────────────

def test_len_empty_ledger():
    ledger = _make_ledger()
    assert len(ledger) == 0


def test_len_after_five_appends():
    ledger = _make_ledger()
    for i in range(1, 6):
        ledger.append(_payload(i))
    assert len(ledger) == 5


# ─── Thread safety ────────────────────────────────────────────────────────────

def test_concurrent_appends_all_recorded():
    ledger = _make_ledger()
    errors: list = []

    def worker(n: int) -> None:
        try:
            ledger.append(_payload(n))
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(1, 21)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(ledger) == 20
    sequences = {e.sequence for e in ledger.entries()}
    assert sequences == set(range(1, 21))


# ─── Integração com ConsensusDecision ─────────────────────────────────────────

def test_append_with_consensus_explain_dict():
    from buildtovalue.governance.consensus_validator import (
        ConsensusDecision, ConsensusOutcome, RolloutResult,
    )
    from buildtovalue.governance.types import ActionType

    r = RolloutResult(0, ActionType.BLOCK, 0.9, "rationale", 5.0)
    cd = ConsensusDecision(
        outcome=ConsensusOutcome.UNANIMOUS_BLOCK,
        final_action=ActionType.BLOCK,
        rollout_results=(r,),
        consensus_time_ms=10.0,
        divergence_detected=False,
        escalation_reason=None,
        hmac_sha256="a" * 64,
        decided_at_iso="2026-03-04T00:00:00Z",
    )
    ledger = _make_ledger()
    payload = {
        "decision_id": "DEC-test",
        "explain_decision": cd.to_explain_dict(),
        "timestamp": int(time.time()),
    }
    entry = ledger.append(payload)
    assert entry.sequence == 1
    assert entry.payload["explain_decision"]["outcome"] == "unanimous_block"


def test_verify_after_consensus_appends():
    from buildtovalue.governance.consensus_validator import (
        ConsensusDecision, ConsensusOutcome,
    )
    from buildtovalue.governance.types import ActionType

    cd = ConsensusDecision(
        outcome=ConsensusOutcome.FAST_PATH,
        final_action=ActionType.ALLOW,
        rollout_results=(),
        consensus_time_ms=2.0,
        divergence_detected=False,
        escalation_reason=None,
        hmac_sha256="b" * 64,
        decided_at_iso="2026-03-04T00:00:00Z",
    )
    ledger = _make_ledger()
    for i in range(1, 4):
        ledger.append({
            "decision_id": f"D{i}",
            "explain_decision": cd.to_explain_dict(),
        })
    result = ledger.verify()
    assert result.valid
    assert result.entries_checked == 3
