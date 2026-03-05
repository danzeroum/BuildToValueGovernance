"""
Tests — ConsensusValidator PROP-032 (ADR-0050)

34 testes:
  - Constantes (3)
  - Reversibility / ConsensusOutcome enums (3)
  - RolloutResult / ConsensusDecision (5)
  - Fast path: reversible (3)
  - Fast path: high confidence (2)
  - Consensus: unanimous BLOCK (2)
  - Consensus: majority BLOCK 2/3 (2)
  - Consensus: unanimous ALLOW (2)
  - Consensus: divergent -> ESCALATE_HUMAN (3)
  - Consensus: timeout -> ESCALATE_HUMAN (3)
  - HMAC integridade (2)
  - Metricas (3)
  - EthicalContextEngine.judge_with_consensus (3)
  Total: 36 testes
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from buildtovalue.governance.consensus_validator import (
    CONSENSUS_N, CONSENSUS_THRESHOLD, HARD_CAP_MS, CONFIDENCE_THRESHOLD,
    Reversibility, ConsensusOutcome, RolloutResult, ConsensusDecision,
    ConsensusValidator,
)
from buildtovalue.governance.types import ActionType

TEST_KEY = b"btv-consensus-test-key-prop032--"


def _make_validator(judge_fn) -> ConsensusValidator:
    return ConsensusValidator(judge_fn=judge_fn, hmac_key=TEST_KEY)


def _judge(action: ActionType, confidence: float = 0.9):
    async def fn():
        return action, confidence, f"rationale-{action.value}"
    return fn


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ─── Constantes ───────────────────────────────────────────────────────────────

def test_consensus_n_fixed():
    assert CONSENSUS_N == 3

def test_consensus_threshold():
    assert CONSENSUS_THRESHOLD == 2

def test_hard_cap_ms():
    assert HARD_CAP_MS == 40.0


# ─── Enums ────────────────────────────────────────────────────────────────────

def test_reversibility_values():
    assert Reversibility.IRREVERSIBLE.value == "irreversible"
    assert Reversibility.REVERSIBLE.value   == "reversible"

def test_consensus_outcome_values():
    assert ConsensusOutcome.DIVERGENT.value == "divergent"
    assert ConsensusOutcome.TIMEOUT.value   == "timeout"

def test_escalate_human_in_action_type():
    assert hasattr(ActionType, "ESCALATE_HUMAN")
    assert ActionType.ESCALATE_HUMAN.value == "escalate_human"


# ─── RolloutResult / ConsensusDecision ───────────────────────────────────────

def test_rollout_result_frozen():
    r = RolloutResult(0, ActionType.BLOCK, 0.9, "r", 5.0)
    with pytest.raises((AttributeError, TypeError)):
        r.action = ActionType.ALLOW  # type: ignore

def test_consensus_decision_frozen():
    d = ConsensusDecision(
        outcome=ConsensusOutcome.FAST_PATH, final_action=ActionType.ALLOW,
        rollout_results=(), consensus_time_ms=1.0, divergence_detected=False,
        escalation_reason=None, hmac_sha256="abc", decided_at_iso="2026",
    )
    with pytest.raises((AttributeError, TypeError)):
        d.final_action = ActionType.BLOCK  # type: ignore

def test_consensus_decision_block_vote_count():
    rollouts = (
        RolloutResult(0, ActionType.BLOCK, 0.9, "", 1.0),
        RolloutResult(1, ActionType.BLOCK, 0.9, "", 1.0),
        RolloutResult(2, ActionType.ALLOW, 0.9, "", 1.0),
    )
    d = ConsensusDecision(
        outcome=ConsensusOutcome.MAJORITY_BLOCK, final_action=ActionType.BLOCK,
        rollout_results=rollouts, consensus_time_ms=5.0, divergence_detected=True,
        escalation_reason=None, hmac_sha256="h", decided_at_iso="2026",
    )
    assert d.block_vote_count == 2

def test_consensus_decision_was_fast_path_true():
    d = ConsensusDecision(
        outcome=ConsensusOutcome.FAST_PATH, final_action=ActionType.ALLOW,
        rollout_results=(), consensus_time_ms=1.0, divergence_detected=False,
        escalation_reason=None, hmac_sha256="h", decided_at_iso="2026",
    )
    assert d.was_fast_path

def test_consensus_decision_to_explain_dict_keys():
    r = RolloutResult(0, ActionType.BLOCK, 0.9, "rationale text", 10.0)
    d = ConsensusDecision(
        outcome=ConsensusOutcome.UNANIMOUS_BLOCK, final_action=ActionType.BLOCK,
        rollout_results=(r,), consensus_time_ms=15.0, divergence_detected=False,
        escalation_reason=None, hmac_sha256="abc123", decided_at_iso="2026-03-04",
    )
    explain = d.to_explain_dict()
    assert "outcome"             in explain
    assert "final_action"        in explain
    assert "rollouts"            in explain
    assert "divergence_detected" in explain
    assert explain["rollouts"][0]["action"] == "BLOCK"


# ─── Fast path: reversible ────────────────────────────────────────────────────

def test_fast_path_reversible():
    v = _make_validator(_judge(ActionType.ALLOW, 0.5))
    d = run(v.validate(Reversibility.REVERSIBLE, confidence=0.5))
    assert d.outcome      == ConsensusOutcome.FAST_PATH
    assert d.was_fast_path
    assert d.n_runs       == 1

def test_fast_path_reversible_action_preserved():
    v = _make_validator(_judge(ActionType.BLOCK, 0.9))
    d = run(v.validate(Reversibility.REVERSIBLE, confidence=0.9))
    assert d.final_action == ActionType.BLOCK

def test_fast_path_reversible_no_divergence():
    v = _make_validator(_judge(ActionType.LOG, 0.8))
    d = run(v.validate(Reversibility.REVERSIBLE, confidence=0.8))
    assert not d.divergence_detected


# ─── Fast path: high confidence ───────────────────────────────────────────────

def test_fast_path_high_confidence_irreversible():
    v = _make_validator(_judge(ActionType.ALLOW, CONFIDENCE_THRESHOLD))
    d = run(v.validate(Reversibility.IRREVERSIBLE, confidence=CONFIDENCE_THRESHOLD))
    assert d.outcome == ConsensusOutcome.FAST_PATH

def test_fast_path_above_threshold():
    v = _make_validator(_judge(ActionType.ALLOW, 0.99))
    d = run(v.validate(Reversibility.IRREVERSIBLE, confidence=0.99))
    assert d.was_fast_path


# ─── Consensus: unanimous BLOCK ───────────────────────────────────────────────

def test_consensus_unanimous_block():
    v = _make_validator(_judge(ActionType.BLOCK, 0.3))
    d = run(v.validate(Reversibility.IRREVERSIBLE, confidence=0.3))
    assert d.final_action == ActionType.BLOCK
    assert d.outcome      == ConsensusOutcome.UNANIMOUS_BLOCK
    assert d.block_vote_count == 3

def test_consensus_unanimous_block_hmac_present():
    v = _make_validator(_judge(ActionType.BLOCK, 0.3))
    d = run(v.validate(Reversibility.IRREVERSIBLE, confidence=0.3))
    assert len(d.hmac_sha256) == 64


# ─── Consensus: majority BLOCK 2/3 ───────────────────────────────────────────

def test_consensus_majority_block():
    call_count = [0]
    async def judge_fn():
        call_count[0] += 1
        action = ActionType.BLOCK if call_count[0] <= 2 else ActionType.ALLOW
        return action, 0.5, "r"

    v = _make_validator(judge_fn)
    d = run(v.validate(Reversibility.IRREVERSIBLE, confidence=0.5))
    assert d.final_action == ActionType.BLOCK
    assert d.outcome      == ConsensusOutcome.MAJORITY_BLOCK

def test_consensus_majority_block_vote_count():
    call_count = [0]
    async def judge_fn():
        call_count[0] += 1
        action = ActionType.BLOCK if call_count[0] <= 2 else ActionType.ALLOW
        return action, 0.5, "r"

    v = _make_validator(judge_fn)
    d = run(v.validate(Reversibility.IRREVERSIBLE, confidence=0.5))
    assert d.block_vote_count == 2


# ─── Consensus: unanimous ALLOW ───────────────────────────────────────────────

def test_consensus_unanimous_allow():
    v = _make_validator(_judge(ActionType.ALLOW, 0.3))
    d = run(v.validate(Reversibility.IRREVERSIBLE, confidence=0.3))
    assert d.final_action == ActionType.ALLOW
    assert d.outcome      == ConsensusOutcome.UNANIMOUS_ALLOW

def test_consensus_unanimous_allow_no_divergence():
    v = _make_validator(_judge(ActionType.ALLOW, 0.3))
    d = run(v.validate(Reversibility.IRREVERSIBLE, confidence=0.3))
    assert not d.divergence_detected


# ─── Consensus: divergent -> ESCALATE_HUMAN ──────────────────────────────────

def test_consensus_divergent_escalate():
    call_count = [0]
    async def judge_fn():
        call_count[0] += 1
        action = ActionType.BLOCK if call_count[0] == 1 else ActionType.ALLOW
        return action, 0.4, "r"

    v = _make_validator(judge_fn)
    d = run(v.validate(Reversibility.IRREVERSIBLE, confidence=0.4))
    assert d.final_action       == ActionType.ESCALATE_HUMAN
    assert d.outcome            == ConsensusOutcome.DIVERGENT
    assert d.divergence_detected

def test_consensus_divergent_has_reason():
    call_count = [0]
    async def judge_fn():
        call_count[0] += 1
        action = ActionType.BLOCK if call_count[0] == 1 else ActionType.ALLOW
        return action, 0.4, "r"

    v = _make_validator(judge_fn)
    d = run(v.validate(Reversibility.IRREVERSIBLE, confidence=0.4))
    assert d.escalation_reason is not None
    assert "Rawls" in d.escalation_reason

def test_consensus_divergent_three_actions():
    actions = [ActionType.BLOCK, ActionType.ALLOW, ActionType.LOG]
    idx = [0]
    async def judge_fn():
        a = actions[idx[0] % 3]
        idx[0] += 1
        return a, 0.4, "r"

    v = _make_validator(judge_fn)
    d = run(v.validate(Reversibility.IRREVERSIBLE, confidence=0.4))
    assert d.final_action == ActionType.ESCALATE_HUMAN


# ─── Consensus: timeout -> ESCALATE_HUMAN ────────────────────────────────────

def test_consensus_timeout_escalate():
    async def slow_judge():
        await asyncio.sleep(0.1)  # 100ms > 40ms cap
        return ActionType.ALLOW, 0.9, "r"

    v = ConsensusValidator(judge_fn=slow_judge, hmac_key=TEST_KEY)
    d = run(v.validate(Reversibility.IRREVERSIBLE, confidence=0.3))
    assert d.final_action == ActionType.ESCALATE_HUMAN
    assert d.outcome      == ConsensusOutcome.TIMEOUT

def test_consensus_timeout_fail_secure_not_allow():
    async def slow_judge():
        await asyncio.sleep(0.1)
        return ActionType.ALLOW, 0.9, "r"

    v = ConsensusValidator(judge_fn=slow_judge, hmac_key=TEST_KEY)
    d = run(v.validate(Reversibility.IRREVERSIBLE, confidence=0.3))
    assert d.final_action != ActionType.ALLOW  # fail-secure: nunca ALLOW em timeout

def test_consensus_timeout_reason_present():
    async def slow_judge():
        await asyncio.sleep(0.1)
        return ActionType.ALLOW, 0.9, "r"

    v = ConsensusValidator(judge_fn=slow_judge, hmac_key=TEST_KEY)
    d = run(v.validate(Reversibility.IRREVERSIBLE, confidence=0.3))
    assert d.escalation_reason is not None
    assert "Timeout" in d.escalation_reason


# ─── HMAC integridade ─────────────────────────────────────────────────────────

def test_hmac_length():
    v = _make_validator(_judge(ActionType.ALLOW, 0.3))
    d = run(v.validate(Reversibility.IRREVERSIBLE, confidence=0.3))
    assert len(d.hmac_sha256) == 64

def test_hmac_different_keys_different_signatures():
    import hmac as hm, hashlib
    v1 = ConsensusValidator(_judge(ActionType.BLOCK, 0.3), b"key-one-256bits-000000000000000")
    v2 = ConsensusValidator(_judge(ActionType.BLOCK, 0.3), b"key-two-256bits-000000000000000")
    d1 = run(v1.validate(Reversibility.IRREVERSIBLE, confidence=0.3))
    d2 = run(v2.validate(Reversibility.IRREVERSIBLE, confidence=0.3))
    assert d1.hmac_sha256 != d2.hmac_sha256


# ─── Metricas ─────────────────────────────────────────────────────────────────

def test_metrics_fast_path_count():
    v = _make_validator(_judge(ActionType.ALLOW, 0.9))
    run(v.validate(Reversibility.REVERSIBLE, confidence=0.9))
    run(v.validate(Reversibility.REVERSIBLE, confidence=0.9))
    assert v.get_metrics()["fast_path_calls"] == 2

def test_metrics_divergent_rate():
    call_count = [0]
    async def judge_fn():
        call_count[0] += 1
        action = ActionType.BLOCK if call_count[0] == 1 else ActionType.ALLOW
        return action, 0.4, "r"

    v = _make_validator(judge_fn)
    run(v.validate(Reversibility.IRREVERSIBLE, confidence=0.4))
    m = v.get_metrics()
    assert m["divergent_count"]          == 1
    assert m["consensus_divergence_rate"] == 1.0

def test_metrics_reset():
    v = _make_validator(_judge(ActionType.ALLOW, 0.3))
    run(v.validate(Reversibility.IRREVERSIBLE, confidence=0.3))
    v.reset_metrics()
    assert v.get_metrics()["total_calls"] == 0


# ─── EthicalContextEngine.judge_with_consensus ───────────────────────────────

def test_engine_judge_with_consensus_no_validator():
    from buildtovalue.governance.ethical_context_engine import EthicalContextEngine
    from buildtovalue.governance.ffi_client import TechnicalEvidence
    from buildtovalue.governance.types import RequestMetadata
    import time as t

    engine   = EthicalContextEngine(consensus_validator=None)
    evidence = MagicMock(spec=TechnicalEvidence)
    evidence.hash = "abc"; evidence.finding_count = 0
    evidence.critical_count = 0; evidence.composite_risk = 0.0
    evidence.findings = []; evidence.critical = []
    req = MagicMock(spec=RequestMetadata)
    req.session_id = "s"; req.agent_id = "a"
    req.user_role  = "user"; req.domain = "test"
    req.timestamp  = int(t.time())

    result = asyncio.get_event_loop().run_until_complete(
        engine.judge_with_consensus(evidence, req, Reversibility.IRREVERSIBLE)
    )
    assert result is not None

def test_engine_judge_with_consensus_has_consensus_validator():
    from buildtovalue.governance.ethical_context_engine import EthicalContextEngine
    v = _make_validator(_judge(ActionType.ALLOW, 0.5))
    engine = EthicalContextEngine(consensus_validator=v)
    assert engine.consensus_validator is v

def test_engine_judge_with_consensus_metrics_tracked():
    from buildtovalue.governance.ethical_context_engine import EthicalContextEngine
    engine = EthicalContextEngine(consensus_validator=None)
    initial = engine.metrics["decisions_total"]
    from buildtovalue.governance.ffi_client import TechnicalEvidence
    from buildtovalue.governance.types import RequestMetadata
    import time as t
    evidence = MagicMock(spec=TechnicalEvidence)
    evidence.hash = "x"; evidence.finding_count = 0
    evidence.critical_count = 0; evidence.composite_risk = 0.0
    evidence.findings = []; evidence.critical = []
    req = MagicMock(spec=RequestMetadata)
    req.session_id = "s2"; req.agent_id = "a2"
    req.user_role = "user"; req.domain = "test"
    req.timestamp = int(t.time())
    asyncio.get_event_loop().run_until_complete(
        engine.judge_with_consensus(evidence, req)
    )
    assert engine.metrics["decisions_total"] == initial + 1
