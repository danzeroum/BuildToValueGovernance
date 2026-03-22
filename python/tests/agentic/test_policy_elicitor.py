"""
Tests for PolicyElicitor (ARIA sub-component 1: Requirement Gathering).

Covers:
  - Valid NL input produces valid YAML via MockBackend
  - Invalid LLM output (non-YAML) returns error ElicitedPolicy
  - Ambiguous input with gaps is flagged
  - All known domains accepted
  - Confidence decreases with gaps
  - Fail-secure on LLM exception
  - Fail-secure on unknown domain
  - LLM backend Protocol compliance
  - ElicitedPolicy.success property
"""
from __future__ import annotations

import pytest
import asyncio

from buildtovalue.agentic.policy_elicitor import (
    PolicyElicitor,
    ElicitedPolicy,
    MockBackend,
    LLMBackend,
    KNOWN_DOMAINS,
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────

CANNED_SECURITY_YAML = """
schema_version: "1.0"
domain: security
description: Integrity verification required for all agent communications
integrity: true
audit_log: true
non_repudiation: true
"""

CANNED_MINIMAL_YAML = """
schema_version: "1.0"
domain: general
"""

CANNED_AGENTS_YAML = """
schema_version: "1.0"
domain: agents
negotiation:
  max_rounds: 10
  timeout_seconds: 300
bft:
  min_consensus_fraction: 0.67
"""


@pytest.fixture
def elicitor_with_good_yaml() -> PolicyElicitor:
    return PolicyElicitor(llm=MockBackend(CANNED_SECURITY_YAML))


@pytest.fixture
def elicitor_with_minimal_yaml() -> PolicyElicitor:
    return PolicyElicitor(llm=MockBackend(CANNED_MINIMAL_YAML))


# ─── Basic Success Tests ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_valid_nl_produces_valid_yaml(elicitor_with_good_yaml: PolicyElicitor):
    result = await elicitor_with_good_yaml.elicit(
        "All agent communications must be integrity-verified with audit trail.",
        domain="security",
    )
    assert result.success
    assert isinstance(result.policy, dict)
    assert len(result.policy) > 0
    assert result.error is None
    assert result.schema_version != "unknown"


@pytest.mark.asyncio
async def test_result_preserves_nl_input(elicitor_with_good_yaml: PolicyElicitor):
    nl = "Require HMAC verification on all messages."
    result = await elicitor_with_good_yaml.elicit(nl, domain="security")
    assert result.source_nl == nl


@pytest.mark.asyncio
async def test_result_has_domain(elicitor_with_good_yaml: PolicyElicitor):
    result = await elicitor_with_good_yaml.elicit("test", domain="security")
    assert result.domain == "security"


@pytest.mark.asyncio
async def test_result_has_explain_decision(elicitor_with_good_yaml: PolicyElicitor):
    result = await elicitor_with_good_yaml.elicit("test", domain="security")
    assert isinstance(result.explain_decision, str)
    assert len(result.explain_decision) > 10


@pytest.mark.asyncio
async def test_result_has_signature(elicitor_with_good_yaml: PolicyElicitor):
    result = await elicitor_with_good_yaml.elicit("test", domain="security")
    assert isinstance(result.signature, str)
    assert len(result.signature) == 64  # HMAC-SHA256 hex


@pytest.mark.asyncio
async def test_result_is_frozen(elicitor_with_good_yaml: PolicyElicitor):
    result = await elicitor_with_good_yaml.elicit("test", domain="security")
    with pytest.raises((AttributeError, TypeError)):
        result.confidence = 0.0  # type: ignore[misc]


# ─── Confidence and Gap Tests ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_full_schema_has_high_confidence(elicitor_with_good_yaml: PolicyElicitor):
    """YAML with all expected fields → confidence = 1.0."""
    elicitor = PolicyElicitor(llm=MockBackend(CANNED_AGENTS_YAML))
    result = await elicitor.elicit("Agent negotiation policy", domain="agents")
    assert result.success
    # agents requires schema_version + negotiation + bft — all present
    assert result.confidence == 1.0
    assert len(result.gaps) == 0


@pytest.mark.asyncio
async def test_minimal_yaml_has_lower_confidence(elicitor_with_minimal_yaml: PolicyElicitor):
    """YAML with only some expected fields → confidence < 1.0."""
    result = await elicitor_with_minimal_yaml.elicit("Basic policy", domain="general")
    # general requires schema_version + domain + description — missing description
    assert result.success
    assert result.confidence < 1.0
    assert len(result.gaps) >= 1


@pytest.mark.asyncio
async def test_gaps_flagged_for_missing_fields(elicitor_with_minimal_yaml: PolicyElicitor):
    result = await elicitor_with_minimal_yaml.elicit("Basic policy", domain="general")
    assert "description" in result.gaps


@pytest.mark.asyncio
async def test_confidence_is_zero_on_failure():
    """Failed elicitation should have confidence=0."""
    elicitor = PolicyElicitor(llm=MockBackend(None))  # Simulates LLM failure
    result = await elicitor.elicit("Any input", domain="general")
    assert result.confidence == 0.0
    assert not result.success


# ─── Domain Tests ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_all_known_domains_accepted():
    """All domains in KNOWN_DOMAINS should be accepted by elicitor."""
    elicitor = PolicyElicitor(llm=MockBackend(CANNED_MINIMAL_YAML))
    for domain in KNOWN_DOMAINS:
        result = await elicitor.elicit("test requirement", domain=domain)
        # Should not return "Unknown domain" error
        assert "Unknown domain" not in (result.error or "")


@pytest.mark.asyncio
async def test_unknown_domain_fails_secure():
    elicitor = PolicyElicitor(llm=MockBackend(CANNED_SECURITY_YAML))
    result = await elicitor.elicit("test", domain="quantum_computing")
    assert not result.success
    assert result.error is not None
    assert "Unknown domain" in result.error


@pytest.mark.asyncio
async def test_domain_normalized_to_lowercase():
    elicitor = PolicyElicitor(llm=MockBackend(CANNED_SECURITY_YAML))
    result = await elicitor.elicit("test", domain="SECURITY")
    assert result.domain == "security"
    assert result.success


# ─── Fail-Secure Tests ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fail_secure_on_llm_exception():
    """LLM exception → fail-secure ElicitedPolicy with error, not raise."""
    elicitor = PolicyElicitor(llm=MockBackend(None))
    result = await elicitor.elicit("test requirement", domain="security")
    assert not result.success
    assert result.error is not None
    assert result.policy == {}
    assert result.confidence == 0.0


@pytest.mark.asyncio
async def test_fail_secure_on_non_yaml_output():
    """Non-YAML LLM output → fail-secure."""
    bad_backend = MockBackend("This is not YAML at all. { broken yaml [")
    elicitor = PolicyElicitor(llm=bad_backend)
    result = await elicitor.elicit("test", domain="general")
    assert not result.success
    assert result.error is not None


@pytest.mark.asyncio
async def test_fail_secure_on_yaml_list_not_dict():
    """YAML that parses to a list, not a dict → fail-secure."""
    list_backend = MockBackend("- item1\n- item2\n- item3")
    elicitor = PolicyElicitor(llm=list_backend)
    result = await elicitor.elicit("test", domain="general")
    assert not result.success
    assert result.error is not None


@pytest.mark.asyncio
async def test_fail_secure_has_signature():
    """Even on fail-secure path, result must have 64-char signature."""
    elicitor = PolicyElicitor(llm=MockBackend(None))
    result = await elicitor.elicit("test", domain="general")
    assert len(result.signature) == 64


# ─── Protocol Compliance Tests ────────────────────────────────────────────────

def test_mock_backend_is_llmbackend():
    """MockBackend must satisfy LLMBackend Protocol."""
    backend = MockBackend(CANNED_SECURITY_YAML)
    assert isinstance(backend, LLMBackend)


def test_elicited_policy_success_false_when_error():
    """ElicitedPolicy.success is False when error is set."""
    import time
    import hashlib
    import hmac as _hmac
    timestamp = time.time()
    result = ElicitedPolicy(
        policy={},
        gaps=(),
        confidence=0.0,
        source_nl="test",
        domain="general",
        schema_version="unknown",
        error="some error",
        explain_decision="fail-secure",
        timestamp=timestamp,
        signature="a" * 64,
    )
    assert not result.success


def test_elicited_policy_success_true_when_no_error():
    """ElicitedPolicy.success is True when policy is non-empty and no error."""
    import time
    timestamp = time.time()
    result = ElicitedPolicy(
        policy={"integrity": True},
        gaps=(),
        confidence=1.0,
        source_nl="test",
        domain="security",
        schema_version="1.0",
        error=None,
        explain_decision="ok",
        timestamp=timestamp,
        signature="a" * 64,
    )
    assert result.success
