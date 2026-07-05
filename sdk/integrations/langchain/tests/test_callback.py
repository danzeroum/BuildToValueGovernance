"""
Tests for BTVGuardrailCallback.
Uses unittest.mock for LangChain objects, respx for HTTP mocking.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import respx
import httpx

from btv_langchain import BTVGuardrailCallback, BTVBlockedByGuardrailError
from btv_sdk import BTVClient

GATEWAY = "http://localhost:8080"
API_KEY = "test-key"

VALIDATE_ALLOW = {
    "verdict_id": "VRD-01ARZ3NDEKTSV4RRFFQ69G5FAV",
    "action": "ALLOW",
    "original_action": "ALLOW",
    "mercy_applied": False,
    "finding_count": 0,
    "critical_count": 0,
    "composite_risk": 0.01,
    "hard_blocked": False,
    "contestable": False,
    "appeal_deadline_hours": 0,
    "message": "Clean input.",
    "matched_policies": [],
    "signature": "abc123",
    "latency_ms": 5.0,
    "rationale": "No issues found.",
}

VALIDATE_BLOCK = {
    **VALIDATE_ALLOW,
    "verdict_id": "VRD-01ARZ3NDEKTSV4RRFFQ69G5FAW",
    "action": "BLOCK",
    "original_action": "BLOCK",
    "composite_risk": 0.95,
    "finding_count": 3,
    "critical_count": 2,
    "message": "SQL injection detected.",
}

SANITIZE_RESP = {
    "sanitized": "My [REDACTED] is hidden.",
    "redactions": 1,
    "latency_ms": 3.0,
}


@respx.mock
def test_callback_allows_clean_prompt():
    respx.post(f"{GATEWAY}/v1/validate").mock(
        return_value=httpx.Response(200, json=VALIDATE_ALLOW)
    )
    client = BTVClient(api_key=API_KEY, gateway_url=GATEWAY, max_retries=0)
    cb = BTVGuardrailCallback(client=client)
    # Should not raise
    cb.on_llm_start({}, ["Hello, help me write a poem."])


@respx.mock
def test_callback_blocks_malicious_prompt():
    respx.post(f"{GATEWAY}/v1/validate").mock(
        return_value=httpx.Response(200, json=VALIDATE_BLOCK)
    )
    client = BTVClient(api_key=API_KEY, gateway_url=GATEWAY, max_retries=0)
    cb = BTVGuardrailCallback(client=client, raise_on_block=True)

    with pytest.raises(BTVBlockedByGuardrailError) as exc:
        cb.on_llm_start({}, ["DROP TABLE users; --"])

    assert exc.value.verdict_id == VALIDATE_BLOCK["verdict_id"]
    assert exc.value.action == "BLOCK"


@respx.mock
def test_callback_no_raise_when_disabled():
    respx.post(f"{GATEWAY}/v1/validate").mock(
        return_value=httpx.Response(200, json=VALIDATE_BLOCK)
    )
    client = BTVClient(api_key=API_KEY, gateway_url=GATEWAY, max_retries=0)
    cb = BTVGuardrailCallback(client=client, raise_on_block=False)
    # Should not raise even when action is BLOCK
    cb.on_llm_start({}, ["DROP TABLE users; --"])


@respx.mock
def test_callback_sanitizes_output():
    respx.post(f"{GATEWAY}/v1/sanitize").mock(
        return_value=httpx.Response(200, json=SANITIZE_RESP)
    )
    client = BTVClient(api_key=API_KEY, gateway_url=GATEWAY, max_retries=0)
    cb = BTVGuardrailCallback(client=client, sanitize_output=True)

    # Build a mock LLMResult
    generation = MagicMock()
    generation.text = "My SSN is 123-45-6789 and is hidden."
    llm_result = MagicMock()
    llm_result.generations = [[generation]]

    cb.on_llm_end(llm_result)
    assert generation.text == SANITIZE_RESP["sanitized"]


@respx.mock
def test_callback_skips_empty_prompts():
    """Empty strings should not trigger validation calls."""
    route = respx.post(f"{GATEWAY}/v1/validate").mock(
        return_value=httpx.Response(200, json=VALIDATE_ALLOW)
    )
    client = BTVClient(api_key=API_KEY, gateway_url=GATEWAY, max_retries=0)
    cb = BTVGuardrailCallback(client=client)
    cb.on_llm_start({}, ["", "   "])
    assert not route.called
