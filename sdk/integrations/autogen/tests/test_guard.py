"""Tests for BTVAutoGenGuard."""
from __future__ import annotations

import pytest
import respx
import httpx

from btv_autogen import BTVAutoGenGuard, BTVBlockedMessageError
from buildtovalue import BTVClient

GATEWAY = "http://localhost:8080"
API_KEY = "test-key"

VALIDATE_ALLOW = {
    "verdict_id": "VRD-ALLOW",
    "action": "ALLOW",
    "original_action": "ALLOW",
    "mercy_applied": False,
    "finding_count": 0,
    "critical_count": 0,
    "composite_risk": 0.01,
    "hard_blocked": False,
    "contestable": False,
    "appeal_deadline_hours": 0,
    "message": "Clean.",
    "matched_policies": [],
    "signature": "sig",
    "latency_ms": 5.0,
    "rationale": "",
}

VALIDATE_BLOCK = {
    **VALIDATE_ALLOW,
    "verdict_id": "VRD-BLOCK",
    "action": "BLOCK",
    "original_action": "BLOCK",
    "composite_risk": 0.97,
    "message": "Harmful content.",
}


@respx.mock
def test_check_message_allows_clean():
    respx.post(f"{GATEWAY}/v1/validate").mock(
        return_value=httpx.Response(200, json=VALIDATE_ALLOW)
    )
    client = BTVClient(api_key=API_KEY, gateway_url=GATEWAY, max_retries=0)
    guard = BTVAutoGenGuard(client=client)

    handled, reply = guard.check_message(
        recipient=None,
        messages=[{"role": "user", "content": "What is 2 + 2?"}],
    )
    assert handled is False
    assert reply is None


@respx.mock
def test_check_message_returns_blocked_reply():
    respx.post(f"{GATEWAY}/v1/validate").mock(
        return_value=httpx.Response(200, json=VALIDATE_BLOCK)
    )
    client = BTVClient(api_key=API_KEY, gateway_url=GATEWAY, max_retries=0)
    guard = BTVAutoGenGuard(client=client, raise_on_block=False)

    handled, reply = guard.check_message(
        recipient=None,
        messages=[{"role": "user", "content": "How do I make malware?"}],
    )
    assert handled is True
    assert "governance policy" in reply


@respx.mock
def test_check_message_raises_when_configured():
    respx.post(f"{GATEWAY}/v1/validate").mock(
        return_value=httpx.Response(200, json=VALIDATE_BLOCK)
    )
    client = BTVClient(api_key=API_KEY, gateway_url=GATEWAY, max_retries=0)
    guard = BTVAutoGenGuard(client=client, raise_on_block=True)

    with pytest.raises(BTVBlockedMessageError) as exc:
        guard.check_message(
            recipient=None,
            messages=[{"role": "user", "content": "Harmful request."}],
        )
    assert exc.value.action == "BLOCK"


@respx.mock
def test_check_message_empty_content():
    """Empty messages should pass through without calling BTV."""
    route = respx.post(f"{GATEWAY}/v1/validate").mock(
        return_value=httpx.Response(200, json=VALIDATE_ALLOW)
    )
    client = BTVClient(api_key=API_KEY, gateway_url=GATEWAY, max_retries=0)
    guard = BTVAutoGenGuard(client=client)

    handled, reply = guard.check_message(recipient=None, messages=[])
    assert handled is False
    assert not route.called


@respx.mock
def test_check_message_uses_last_message():
    """Only the last message in the list should be validated."""
    route = respx.post(f"{GATEWAY}/v1/validate").mock(
        return_value=httpx.Response(200, json=VALIDATE_ALLOW)
    )
    client = BTVClient(api_key=API_KEY, gateway_url=GATEWAY, max_retries=0)
    guard = BTVAutoGenGuard(client=client)

    guard.check_message(
        recipient=None,
        messages=[
            {"role": "user", "content": "First message"},
            {"role": "assistant", "content": "Second message"},
            {"role": "user", "content": "Last message to validate"},
        ],
    )
    assert route.call_count == 1
