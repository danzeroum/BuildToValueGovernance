"""Testes unitários — AgentDecisionRequest / VerdictEnvelope (ADR-029)."""
import hashlib
import hmac as hmac_lib
import pytest
from buildtovalue.governance.agent_pdp import (
    ActionImpact, AgentVerdict, AgentAction, AgentContext,
    AgentDecisionRequest, VerdictEnvelope, BiasSummary,
)

FAKE_HASH = "a" * 64
KEY = b"test-key"


def make_request(impact=ActionImpact.DESTRUCTIVE):
    return AgentDecisionRequest(
        agent_id="agent-test",
        session_id="sess-001",
        action=AgentAction(name="write_file", impact=impact),
        parameters_hash=FAKE_HASH,
    )


def make_envelope(verdict=AgentVerdict.ALLOW):
    ts = "2026-03-07T00:00:00Z"
    ev = "ev-001"
    rid = "req-001"
    payload = f"{rid}|{verdict}|{ev}|{ts}".encode()
    sig = hmac_lib.new(KEY, payload, hashlib.sha256).hexdigest()
    return VerdictEnvelope(
        request_id=rid, verdict=verdict, verdict_code=200,
        explain_decision="test", bias_declaration=BiasSummary(1.4, 0.9, "20260307"),
        contestable=True, appeal_deadline_utc=ts,
        policy_version_applied="1.0", evidence_id=ev,
        hmac_sha256=sig, timestamp_utc=ts,
    )


def test_default_impact_is_irreversible():
    action = AgentAction(name="send_email")
    assert action.impact == ActionImpact.IRREVERSIBLE


def test_irreversible_clears_preview():
    req = AgentDecisionRequest(
        agent_id="a", session_id="s",
        action=AgentAction(name="send", impact=ActionImpact.IRREVERSIBLE),
        parameters_hash=FAKE_HASH,
        parameters_preview={"key": "secret"},
    )
    assert req.parameters_preview == {}


def test_invalid_hash_raises():
    with pytest.raises(ValueError):
        AgentDecisionRequest(
            agent_id="a", session_id="s",
            action=AgentAction(name="read", impact=ActionImpact.SAFE),
            parameters_hash="short",
        )


def test_hmac_verify_valid():
    env = make_envelope()
    assert env.verify_hmac(KEY) is True


def test_hmac_verify_invalid():
    env = make_envelope()
    env.hmac_sha256 = "b" * 64
    assert env.verify_hmac(KEY) is False


def test_is_blocked_true():
    env = make_envelope(AgentVerdict.BLOCK)
    assert env.is_blocked is True


def test_is_blocked_false():
    env = make_envelope(AgentVerdict.ALLOW)
    assert env.is_blocked is False


def test_request_id_auto_generated():
    r1 = make_request()
    r2 = make_request()
    assert r1.request_id != r2.request_id
