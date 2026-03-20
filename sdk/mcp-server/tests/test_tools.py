"""
Tests for BTV MCP server tools.
Calls server.call_tool() directly without stdio.
Uses respx to mock the underlying BTV SDK HTTP calls.
"""
from __future__ import annotations

import os
import pytest
import respx
import httpx

# Set env vars before importing server module
os.environ.setdefault("BTV_API_KEY", "test-key")
os.environ.setdefault("BTV_GATEWAY_URL", "http://localhost:8080")

from btv_mcp.server import call_tool

GATEWAY = "http://localhost:8080"

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
    "message": "Clean input.",
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
    "composite_risk": 0.95,
    "message": "PII detected.",
    "matched_policies": ["lgpd_cpf"],
    "finding_count": 2,
    "critical_count": 1,
}

DECIDE_RESP = {
    "verdict_id": "VRD-DECIDE",
    "action": "EDUCATE",
    "original_action": "BLOCK",
    "mercy_applied": True,
    "finding_count": 1,
    "critical_count": 0,
    "composite_risk": 0.45,
    "hard_blocked": False,
    "contestable": True,
    "appeal_deadline_hours": 24,
    "signature": "sig",
    "rationale": "First offense — educational response.",
    "jurisdiction_bitmask": 1,
    "latency_ms": 34.0,
    "explain": {
        "summary": "Sensitive PII detected. Mercy applied.",
        "rawls_rationale": "Policy violation detected.",
        "levinas_rationale": "User deserves explanation.",
        "jonas_rationale": "No irreversible harm.",
        "gilligan_rationale": "First offense → EDUCATE over BLOCK.",
        "trust_score": 0.72,
        "mercy_score": 0.83,
        "pipeline_stages": ["rawls", "levinas", "jonas", "gilligan"],
    },
}

APPEAL_RESP = {
    "appeal_id": "APL-001",
    "verdict_id": "VRD-DECIDE",
    "user_id": "anonymous",
    "reason": "Test CPF from ABNT dataset, not real PII.",
    "grounds": ["technical_error"],
    "status": "pending",
    "sla_deadline": "2026-03-21T12:00:00Z",
}

TRUST_RESP = {
    "session_id": "sess-001",
    "trust_score": 0.82,
    "total_requests": 10,
    "offenses": 0,
}


@respx.mock
@pytest.mark.asyncio
async def test_validate_input_allow():
    respx.post(f"{GATEWAY}/v1/validate").mock(
        return_value=httpx.Response(200, json=VALIDATE_ALLOW)
    )
    result = await call_tool("validate_input", {"input_text": "Hello world"})
    assert len(result) == 1
    text = result[0].text
    assert "ALLOW" in text
    assert "VRD-ALLOW" in text
    assert "Risk Score" in text


@respx.mock
@pytest.mark.asyncio
async def test_validate_input_block_shows_policies():
    respx.post(f"{GATEWAY}/v1/validate").mock(
        return_value=httpx.Response(200, json=VALIDATE_BLOCK)
    )
    result = await call_tool("validate_input", {
        "input_text": "My CPF is 123.456.789-09",
        "session_id": "sess-001",
    })
    text = result[0].text
    assert "BLOCK" in text
    assert "lgpd_cpf" in text


@respx.mock
@pytest.mark.asyncio
async def test_decide_returns_philosophical_analysis():
    respx.post(f"{GATEWAY}/v1/decide").mock(
        return_value=httpx.Response(200, json=DECIDE_RESP)
    )
    result = await call_tool("decide", {"input_text": "Meu CPF é 123.456.789-09"})
    text = result[0].text
    assert "EDUCATE" in text
    assert "Rawls" in text
    assert "VRD-DECIDE" in text
    assert "submit_appeal" in text  # appeal link shown for contestable


@respx.mock
@pytest.mark.asyncio
async def test_submit_appeal():
    respx.post(f"{GATEWAY}/v1/appeals").mock(
        return_value=httpx.Response(201, json=APPEAL_RESP)
    )
    result = await call_tool("submit_appeal", {
        "verdict_id": "VRD-DECIDE",
        "reason": "Test CPF from ABNT dataset, not real PII.",
        "grounds": ["technical_error"],
    })
    text = result[0].text
    assert "APL-001" in text
    assert "pending" in text


@respx.mock
@pytest.mark.asyncio
async def test_get_trust_score():
    respx.get(f"{GATEWAY}/v1/trust/sess-001").mock(
        return_value=httpx.Response(200, json=TRUST_RESP)
    )
    result = await call_tool("get_trust_score", {"session_id": "sess-001"})
    text = result[0].text
    assert "0.820" in text
    assert "high" in text
    assert "sess-001" in text


@respx.mock
@pytest.mark.asyncio
async def test_check_compliance_compliant():
    respx.post(f"{GATEWAY}/v1/validate").mock(
        return_value=httpx.Response(200, json=VALIDATE_ALLOW)
    )
    result = await call_tool("check_compliance", {"text": "This is a safe legal document."})
    text = result[0].text
    assert "COMPLIANT" in text
    assert "LGPD" in text


@respx.mock
@pytest.mark.asyncio
async def test_check_compliance_non_compliant():
    respx.post(f"{GATEWAY}/v1/validate").mock(
        return_value=httpx.Response(200, json=VALIDATE_BLOCK)
    )
    result = await call_tool("check_compliance", {"text": "My CPF is 123.456.789-09"})
    text = result[0].text
    assert "NON-COMPLIANT" in text
    assert "lgpd_cpf" in text


@pytest.mark.asyncio
async def test_unknown_tool():
    result = await call_tool("nonexistent_tool", {})
    assert "Unknown tool" in result[0].text
