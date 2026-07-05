"""
Unit tests for BTVClient using respx to mock httpx.
"""
import pytest
import respx
import httpx

from btv_sdk import BTVClient, AsyncBTVClient, VerdictAction, BTVAuthError, BTVBlockedError

GATEWAY = "http://localhost:8080"
API_KEY = "test-key"

VERDICT_ALLOW = {
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
    "signature": "abc123",
    "rationale": "Clean input.",
    "jurisdiction_bitmask": 1,
    "latency_ms": 12.5,
    "explain": {
        "summary": "No concerns.",
        "rawls_rationale": "Policy passed.",
        "levinas_rationale": "No duty-of-care issue.",
        "jonas_rationale": "No long-term risk.",
        "gilligan_rationale": "No mercy needed.",
        "trust_score": 0.85,
        "mercy_score": 0.0,
        "pipeline_stages": ["rawls", "levinas", "jonas", "gilligan"],
    },
}

VERDICT_BLOCK = {
    **VERDICT_ALLOW,
    "verdict_id": "VRD-01ARZ3NDEKTSV4RRFFQ69G5FAW",
    "action": "BLOCK",
    "original_action": "BLOCK",
    "contestable": True,
    "appeal_deadline_hours": 24,
    "composite_risk": 0.95,
    "finding_count": 3,
    "critical_count": 2,
}


@respx.mock
def test_decide_returns_verdict():
    respx.post(f"{GATEWAY}/v1/decide").mock(
        return_value=httpx.Response(200, json=VERDICT_ALLOW)
    )
    btv = BTVClient(api_key=API_KEY, gateway_url=GATEWAY)
    verdict = btv.decide("Hello world", session_id="sess-001")
    assert verdict.action == VerdictAction.ALLOW
    assert verdict.verdict_id == "VRD-01ARZ3NDEKTSV4RRFFQ69G5FAV"
    assert verdict.is_allowed


@respx.mock
def test_decide_sends_api_key():
    route = respx.post(f"{GATEWAY}/v1/decide").mock(
        return_value=httpx.Response(200, json=VERDICT_ALLOW)
    )
    btv = BTVClient(api_key=API_KEY, gateway_url=GATEWAY)
    btv.decide("test")
    assert route.called
    assert route.calls[0].request.headers["X-API-Key"] == API_KEY


@respx.mock
def test_decide_raise_on_block():
    respx.post(f"{GATEWAY}/v1/decide").mock(
        return_value=httpx.Response(200, json=VERDICT_BLOCK)
    )
    btv = BTVClient(api_key=API_KEY, gateway_url=GATEWAY, raise_on_block=True)
    with pytest.raises(BTVBlockedError) as exc_info:
        btv.decide("DROP TABLE users")
    assert exc_info.value.verdict.verdict_id == VERDICT_BLOCK["verdict_id"]


@respx.mock
def test_decide_no_raise_on_block_by_default():
    respx.post(f"{GATEWAY}/v1/decide").mock(
        return_value=httpx.Response(200, json=VERDICT_BLOCK)
    )
    btv = BTVClient(api_key=API_KEY, gateway_url=GATEWAY)
    verdict = btv.decide("DROP TABLE users")
    assert verdict.action == VerdictAction.BLOCK


@respx.mock
def test_auth_error_on_401():
    respx.post(f"{GATEWAY}/v1/decide").mock(
        return_value=httpx.Response(401, json={"error": "Unauthorized"})
    )
    btv = BTVClient(api_key="bad-key", gateway_url=GATEWAY)
    with pytest.raises(BTVAuthError):
        btv.decide("test")


@respx.mock
def test_session_context_manager():
    respx.post(f"{GATEWAY}/v1/decide").mock(
        return_value=httpx.Response(200, json=VERDICT_ALLOW)
    )
    btv = BTVClient(api_key=API_KEY, gateway_url=GATEWAY)
    with btv.session("sess-123") as s:
        verdict = s.decide("Hello")
    assert verdict.action == VerdictAction.ALLOW


@respx.mock
def test_appeal_submission():
    appeal_resp = {
        "appeal_id": "APL-001",
        "verdict_id": "VRD-01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "user_id": "anonymous",
        "reason": "This is a test CPF used for ABNT compliance testing.",
        "grounds": ["technical_error"],
        "status": "pending",
        "sla_deadline": "2026-03-21T00:00:00Z",
    }
    respx.post(f"{GATEWAY}/v1/appeals").mock(
        return_value=httpx.Response(201, json=appeal_resp)
    )
    btv = BTVClient(api_key=API_KEY, gateway_url=GATEWAY)
    appeal = btv.appeal(
        "VRD-01ARZ3NDEKTSV4RRFFQ69G5FAV",
        reason="This is a test CPF used for ABNT compliance testing.",
        grounds=["technical_error"],
    )
    assert appeal.appeal_id == "APL-001"
    assert appeal.is_pending


@respx.mock
def test_trust_score():
    trust_resp = {
        "session_id": "sess-001",
        "trust_score": 0.82,
        "total_requests": 10,
        "offenses": 0,
    }
    respx.get(f"{GATEWAY}/v1/trust/sess-001").mock(
        return_value=httpx.Response(200, json=trust_resp)
    )
    btv = BTVClient(api_key=API_KEY, gateway_url=GATEWAY)
    ts = btv.trust_score("sess-001")
    assert ts.trust_score == 0.82
    assert ts.level == "high"


@respx.mock
@pytest.mark.asyncio
async def test_async_decide():
    respx.post(f"{GATEWAY}/v1/decide").mock(
        return_value=httpx.Response(200, json=VERDICT_ALLOW)
    )
    async with AsyncBTVClient(api_key=API_KEY, gateway_url=GATEWAY) as btv:
        verdict = await btv.decide("Hello")
    assert verdict.action == VerdictAction.ALLOW
