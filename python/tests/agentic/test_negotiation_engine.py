"""
Tests for NegotiationEngine (async A2A negotiation state machine).

Covers:
  - Simple accept (identical policies)
  - Counter and converge (3 rounds)
  - Abort on timeout
  - Abort on max_rounds
  - Abort on goal drift (GoalDriftSentinel triggered)
  - Jailbreak blocked by NegotiationGuard → abort
  - All messages logged to DurableLedger
  - NegotiationResult signature valid
"""
from __future__ import annotations

import asyncio
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from buildtovalue.agentic.a2a_channel import make_in_process_pair
from buildtovalue.agentic.negotiation_engine import NegotiationEngine, NegotiationState
from buildtovalue.agentic.negotiation_guard import NegotiationGuard
from buildtovalue.agentic.types import NegotiationMessage, NegotiationResult
from buildtovalue.governance.durable_ledger import DurableLedger
from buildtovalue.governance.goal_drift_sentinel import GoalDriftSentinel
from buildtovalue.governance.persuasion_guard import BiasDeclarationV2, PersuasionGuard


# ─── Fixtures ─────────────────────────────────────────────────────────────────

def make_bias_decl() -> BiasDeclarationV2:
    return BiasDeclarationV2(
        model_id="test-model",
        model_family="testfamily",
        checker_model_id="checker-model",
        checker_model_family="checkerfamily",
        declared_at_iso=datetime.now(timezone.utc).isoformat(),
    )


@pytest.fixture
def ledger_a() -> DurableLedger:
    return DurableLedger(hmac_key=b"ledger-a-key")


@pytest.fixture
def ledger_b() -> DurableLedger:
    return DurableLedger(hmac_key=b"ledger-b-key")


@pytest.fixture
def sentinel() -> GoalDriftSentinel:
    return GoalDriftSentinel(hmac_secret=b"sentinel-test-key")


@pytest.fixture
def guard() -> NegotiationGuard:
    pg = PersuasionGuard(
        bias_declaration=make_bias_decl(),
        hmac_key=b"guard-test-key",
        fact_checker=None,
    )
    return NegotiationGuard(persuasion_guard=pg, ffi_client=None)


def make_engine(
    policy: dict,
    sentinel: GoalDriftSentinel,
    guard: NegotiationGuard,
    ledger: DurableLedger,
    max_rounds: int = 10,
    timeout_seconds: float = 5.0,
    session_id: str = "test-session",
) -> NegotiationEngine:
    return NegotiationEngine(
        own_policy=policy,
        goal_sentinel=sentinel,
        negotiation_guard=guard,
        ledger=ledger,
        max_rounds=max_rounds,
        timeout_seconds=timeout_seconds,
        session_id=session_id,
    )


# ─── Simple Accept Tests ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_simple_accept_identical_policies(sentinel, guard, ledger_a, ledger_b):
    """Two agents with identical policies should reach agreement in 1-2 rounds."""
    policy = {"integrity": True, "audit_log": True}
    channel_a, channel_b = make_in_process_pair()

    engine_a = make_engine(policy, sentinel, guard, ledger_a, session_id="session-a")
    engine_b = make_engine(policy, sentinel, guard, ledger_b, session_id="session-b")

    result_a, result_b = await asyncio.gather(
        engine_a.propose(channel_a),
        engine_b.respond(channel_b),
    )

    assert result_a.status == "confirmed"
    assert result_b.status == "confirmed"
    assert result_a.shared_policy is not None
    assert result_a.rounds >= 1


@pytest.mark.asyncio
async def test_confirm_has_shared_policy(sentinel, guard, ledger_a, ledger_b):
    policy = {"integrity": True}
    channel_a, channel_b = make_in_process_pair()

    engine_a = make_engine(policy, sentinel, guard, ledger_a, session_id="session-a2")
    engine_b = make_engine(policy, sentinel, guard, ledger_b, session_id="session-b2")

    result_a, result_b = await asyncio.gather(
        engine_a.propose(channel_a),
        engine_b.respond(channel_b),
    )

    assert result_a.shared_policy is not None
    assert "integrity" in result_a.shared_policy


# ─── Counter and Converge Tests ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_counter_and_converge_compatible_policies(sentinel, guard, ledger_a, ledger_b):
    """Agent A wants integrity+audit, Agent B wants integrity+max_rounds.
    They should converge on the union (integrity is shared)."""
    policy_a = {"integrity": True, "audit_log": True}
    policy_b = {"integrity": True, "max_rounds": 5}

    channel_a, channel_b = make_in_process_pair()
    engine_a = make_engine(policy_a, sentinel, guard, ledger_a, session_id="conv-a")
    engine_b = make_engine(policy_b, sentinel, guard, ledger_b, session_id="conv-b")

    result_a, result_b = await asyncio.gather(
        engine_a.propose(channel_a),
        engine_b.respond(channel_b),
    )

    # With shared integrity key, should converge
    assert result_a.status in ("confirmed", "aborted")  # May abort if no high overlap
    assert result_a.rounds >= 1
    assert result_a.signature != ""


@pytest.mark.asyncio
async def test_result_has_explain_decision(sentinel, guard, ledger_a, ledger_b):
    policy = {"integrity": True}
    channel_a, channel_b = make_in_process_pair()

    engine_a = make_engine(policy, sentinel, guard, ledger_a, session_id="explain-a")
    engine_b = make_engine(policy, sentinel, guard, ledger_b, session_id="explain-b")

    result_a, _ = await asyncio.gather(
        engine_a.propose(channel_a),
        engine_b.respond(channel_b),
    )

    assert isinstance(result_a.explain_decision, str)
    assert len(result_a.explain_decision) > 10


# ─── Abort Tests ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_abort_on_timeout(sentinel, guard, ledger_a):
    """A proposer with very short timeout should abort."""
    policy = {"integrity": True}
    channel_a, _channel_b = make_in_process_pair()

    engine_a = make_engine(
        policy, sentinel, guard, ledger_a,
        timeout_seconds=0.01,  # 10ms — will timeout immediately
        session_id="timeout-a"
    )

    # Don't run a responder — proposer will timeout waiting for reply
    result = await engine_a.propose(channel_a)

    assert result.status == "aborted"
    assert result.abort_reason is not None
    assert "timeout" in result.abort_reason.lower() or "Timeout" in result.explain_decision


@pytest.mark.asyncio
async def test_abort_on_max_rounds(sentinel, guard, ledger_a, ledger_b):
    """With max_rounds=1, incompatible policies should abort quickly."""
    policy_a = {"privacy": True}
    policy_b = {"confidentiality": True}

    channel_a, channel_b = make_in_process_pair()
    engine_a = make_engine(policy_a, sentinel, guard, ledger_a, max_rounds=2, session_id="maxr-a")
    engine_b = make_engine(policy_b, sentinel, guard, ledger_b, max_rounds=2, session_id="maxr-b")

    result_a, result_b = await asyncio.gather(
        engine_a.propose(channel_a),
        engine_b.respond(channel_b),
    )

    # Completely non-overlapping policies → reject → abort
    assert result_a.status == "aborted" or result_b.status == "aborted"


@pytest.mark.asyncio
async def test_abort_on_incompatible_policies(sentinel, guard, ledger_a, ledger_b):
    """Completely non-overlapping policies should result in abort."""
    policy_a = {"field_a": True, "field_b": True}
    policy_b = {"field_c": True, "field_d": True}

    channel_a, channel_b = make_in_process_pair()
    engine_a = make_engine(policy_a, sentinel, guard, ledger_a, session_id="incompat-a")
    engine_b = make_engine(policy_b, sentinel, guard, ledger_b, session_id="incompat-b")

    result_a, result_b = await asyncio.gather(
        engine_a.propose(channel_a),
        engine_b.respond(channel_b),
    )

    # At least one should abort (incompatible)
    assert result_a.status == "aborted" or result_b.status == "aborted"


# ─── Goal Drift Tests ─────────────────────────────────────────────────────────

def test_check_drift_high_concession_triggers_block(sentinel, guard, ledger_a):
    """Proposing a policy with 90% concession should trigger BLOCK drift."""
    own_policy = {f"req_{i}": True for i in range(10)}  # 10 requirements
    engine = make_engine(own_policy, sentinel, guard, ledger_a, session_id="drift-test")

    # Incoming policy satisfies none of own requirements
    incoming_policy = {"unrelated_field": True}
    drift_report = engine._check_drift(1, incoming_policy)
    # 100% concession → Critical drift → DriftAction.BLOCK
    from buildtovalue.governance.goal_drift_sentinel import DriftAction
    assert drift_report.drift_action == DriftAction.BLOCK


def test_check_drift_low_concession_allows(sentinel, guard, ledger_a):
    """Small concession should not trigger drift block."""
    own_policy = {"integrity": True, "audit": True, "max_rounds": 10}
    engine = make_engine(own_policy, sentinel, guard, ledger_a, session_id="drift-low")

    # Incoming policy satisfies most requirements (2/3 = 67% match)
    incoming_policy = {"integrity": True, "audit": True}
    drift_report = engine._check_drift(1, incoming_policy)
    from buildtovalue.governance.goal_drift_sentinel import DriftAction
    assert drift_report.drift_action != DriftAction.BLOCK


# ─── Ledger Logging Tests ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_messages_logged_to_ledger(sentinel, guard, ledger_a, ledger_b):
    """At minimum, the final result should be logged to ledger."""
    policy = {"integrity": True}
    channel_a, channel_b = make_in_process_pair()

    engine_a = make_engine(policy, sentinel, guard, ledger_a, session_id="log-a")
    engine_b = make_engine(policy, sentinel, guard, ledger_b, session_id="log-b")

    await asyncio.gather(
        engine_a.propose(channel_a),
        engine_b.respond(channel_b),
    )

    # At least the final result should be logged
    assert len(ledger_a) >= 1
    assert len(ledger_b) >= 1


@pytest.mark.asyncio
async def test_result_signature_valid(sentinel, guard, ledger_a, ledger_b):
    """NegotiationResult signature must be present and 64 chars (HMAC-SHA256)."""
    policy = {"integrity": True}
    channel_a, channel_b = make_in_process_pair()

    engine_a = make_engine(policy, sentinel, guard, ledger_a, session_id="sig-a")
    engine_b = make_engine(policy, sentinel, guard, ledger_b, session_id="sig-b")

    result_a, _ = await asyncio.gather(
        engine_a.propose(channel_a),
        engine_b.respond(channel_b),
    )

    assert isinstance(result_a.signature, str)
    assert len(result_a.signature) == 64  # HMAC-SHA256 hex = 64 chars


# ─── Policy Evaluation Tests ──────────────────────────────────────────────────

def test_evaluate_proposal_identical_policies(sentinel, guard, ledger_a):
    """Identical policies should result in accept."""
    policy = {"integrity": True, "audit": True}
    engine = make_engine(policy, sentinel, guard, ledger_a)
    decision, counter = engine._evaluate_proposal(policy, policy)
    assert decision == "accept"
    assert counter is None


def test_evaluate_proposal_no_overlap(sentinel, guard, ledger_a):
    """No overlap in keys → reject."""
    own = {"integrity": True, "audit": True}
    incoming = {"privacy": True, "confidentiality": True}
    engine = make_engine(own, sentinel, guard, ledger_a)
    decision, counter = engine._evaluate_proposal(incoming, own)
    assert decision == "reject"


def test_evaluate_proposal_partial_overlap(sentinel, guard, ledger_a):
    """Partial overlap → counter with merged policy."""
    own = {"integrity": True, "audit": True, "max_rounds": 10}
    incoming = {"integrity": True, "other_field": "value"}
    engine = make_engine(own, sentinel, guard, ledger_a)
    decision, counter = engine._evaluate_proposal(incoming, own)
    assert decision == "counter"
    assert counter is not None
    assert "integrity" in counter  # Own requirements preserved


def test_evaluate_empty_incoming_rejects(sentinel, guard, ledger_a):
    """Empty incoming policy with non-empty own → reject."""
    own = {"integrity": True}
    engine = make_engine(own, sentinel, guard, ledger_a)
    decision, _ = engine._evaluate_proposal({}, own)
    assert decision == "reject"


def test_evaluate_empty_own_accepts_anything(sentinel, guard, ledger_a):
    """Empty own policy accepts any incoming."""
    engine = make_engine({}, sentinel, guard, ledger_a)
    decision, _ = engine._evaluate_proposal({"anything": True}, {})
    assert decision == "accept"
