"""
Tests for ProtocolDesigner (ARIA sub-component 3a).

Covers:
  - Requirement extraction from policy dicts
  - Protocol matching: available and unavailable
  - Unknown requirements return empty plan
  - Fail-secure on exception
  - Ledger logging
  - ProtocolRegistry structure
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from buildtovalue.agentic.protocol_designer import ProtocolDesigner, ProtocolPlan
from buildtovalue.agentic.protocol_registry import (
    PROTOCOL_REGISTRY,
    ProtocolSpec,
    get_available_protocols,
    get_protocol,
)
from buildtovalue.governance.durable_ledger import DurableLedger


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def ledger() -> DurableLedger:
    return DurableLedger(hmac_key=b"test-key-protocol-designer")


@pytest.fixture
def designer(ledger: DurableLedger) -> ProtocolDesigner:
    return ProtocolDesigner(ledger=ledger)


# ─── Registry Structure Tests ─────────────────────────────────────────────────

def test_registry_has_available_protocols():
    available = get_available_protocols()
    assert len(available) >= 4, "Expected at least 4 available protocols"
    names = {p.name for p in available}
    assert "commit_reveal" in names
    assert "hmac_evidence" in names
    assert "bft_consensus" in names
    assert "blake2b_audit" in names


def test_registry_all_specs_are_frozen():
    for spec in PROTOCOL_REGISTRY:
        assert isinstance(spec, ProtocolSpec)
        with pytest.raises((AttributeError, TypeError)):
            spec.name = "mutated"  # type: ignore[misc]


def test_registry_requirements_are_frozensets():
    for spec in PROTOCOL_REGISTRY:
        assert isinstance(spec.requirements_met, frozenset), \
            f"{spec.name}.requirements_met must be frozenset"
        assert isinstance(spec.trust_assumptions, frozenset), \
            f"{spec.name}.trust_assumptions must be frozenset"


def test_get_protocol_known_name():
    spec = get_protocol("commit_reveal")
    assert spec is not None
    assert spec.name == "commit_reveal"


def test_get_protocol_unknown_name():
    assert get_protocol("nonexistent_protocol") is None


def test_unavailable_protocols_exist():
    unavailable = [p for p in PROTOCOL_REGISTRY if not p.available]
    assert len(unavailable) >= 1, "Expected at least 1 roadmap protocol"
    names = {p.name for p in unavailable}
    assert "tee_attestation" in names or "zk_proof" in names


# ─── Requirement Extraction Tests ─────────────────────────────────────────────

def test_integrity_requirement_extracted_from_top_level(designer: ProtocolDesigner):
    policy = {"integrity": True, "session_id": "test"}
    requirements = designer._extract_requirements(policy)
    assert "integrity" in requirements


def test_requirement_in_nested_dict(designer: ProtocolDesigner):
    policy = {"security": {"integrity": True, "confidentiality": True}}
    requirements = designer._extract_requirements(policy)
    assert "integrity" in requirements
    assert "confidentiality" in requirements


def test_requirements_list_extracted(designer: ProtocolDesigner):
    policy = {"requirements": ["integrity", "non_repudiation"]}
    requirements = designer._extract_requirements(policy)
    assert "integrity" in requirements
    assert "non_repudiation" in requirements


def test_unknown_fields_not_extracted(designer: ProtocolDesigner):
    policy = {"session_id": "test", "max_tokens": 100, "random_key": "value"}
    requirements = designer._extract_requirements(policy)
    assert len(requirements) == 0


def test_requirement_false_not_extracted(designer: ProtocolDesigner):
    policy = {"integrity": False}
    requirements = designer._extract_requirements(policy)
    assert "integrity" not in requirements


# ─── Protocol Selection Tests ──────────────────────────────────────────────────

def test_integrity_requirement_selects_hmac_or_blake2b(designer: ProtocolDesigner):
    policy = {"integrity": True}
    plan = designer.select(policy)
    selected_names = {s.name for s in plan.selected}
    assert selected_names & {"hmac_evidence", "blake2b_audit", "commit_reveal"}, \
        f"Expected integrity protocol, got: {selected_names}"
    assert plan.signature != ""
    assert "integrity" in plan.explain_decision


def test_consensus_requirement_selects_bft(designer: ProtocolDesigner):
    policy = {"agreement": True, "fault_tolerance": True}
    plan = designer.select(policy)
    selected_names = {s.name for s in plan.selected}
    assert "bft_consensus" in selected_names


def test_unavailable_protocol_flagged(designer: ProtocolDesigner):
    """Privacy requirement maps to zk_proof/mpc_computation (both unavailable)."""
    policy = {"privacy": True}
    plan = designer.select(policy)
    unavailable_names = {u.name for u in plan.unavailable}
    assert unavailable_names & {"zk_proof", "mpc_computation"}, \
        f"Expected privacy roadmap protocols, got unavailable={unavailable_names}"


def test_empty_policy_returns_empty_plan(designer: ProtocolDesigner):
    plan = designer.select({})
    assert len(plan.selected) == 0
    assert len(plan.unavailable) == 0
    assert plan.explain_decision != ""


def test_unknown_requirement_returns_no_match(designer: ProtocolDesigner):
    """Made-up requirement names should not match any protocol."""
    policy = {"requirements": ["quantum_entanglement", "dark_matter_verification"]}
    plan = designer.select(policy)
    assert len(plan.selected) == 0
    assert len(plan.unavailable) == 0


def test_plan_is_frozen(designer: ProtocolDesigner):
    plan = designer.select({"integrity": True})
    with pytest.raises((AttributeError, TypeError)):
        plan.selected = ()  # type: ignore[misc]


def test_plan_has_explain_decision(designer: ProtocolDesigner):
    plan = designer.select({"integrity": True, "agreement": True})
    assert isinstance(plan.explain_decision, str)
    assert len(plan.explain_decision) > 10


def test_plan_logged_to_ledger(designer: ProtocolDesigner, ledger: DurableLedger):
    assert len(ledger) == 0
    designer.select({"integrity": True})
    assert len(ledger) == 1
    entry = ledger.entries()[0]
    assert entry.payload["event"] == "protocol_designer.select"
    assert "explain_decision" in entry.payload


def test_rationale_maps_requirements_to_protocols(designer: ProtocolDesigner):
    policy = {"integrity": True}
    plan = designer.select(policy)
    assert "integrity" in plan.rationale
    assert isinstance(plan.rationale["integrity"], str)


def test_plan_signature_not_empty(designer: ProtocolDesigner):
    plan = designer.select({"integrity": True})
    assert isinstance(plan.signature, str)
    assert len(plan.signature) == 64  # HMAC-SHA256 hex = 64 chars


# ─── Fail-Secure Tests ────────────────────────────────────────────────────────

def test_fail_secure_on_registry_exception(ledger: DurableLedger):
    """If registry raises during matching, fail-secure returns empty plan."""
    bad_registry = [None]  # type: ignore — will cause AttributeError
    designer = ProtocolDesigner(ledger=ledger, registry=bad_registry)  # type: ignore
    plan = designer.select({"integrity": True})
    assert len(plan.selected) == 0
    assert "FAIL-SECURE" in plan.explain_decision


def test_fail_secure_has_signature(ledger: DurableLedger):
    bad_registry = [None]  # type: ignore
    designer = ProtocolDesigner(ledger=ledger, registry=bad_registry)  # type: ignore
    plan = designer.select({"integrity": True})
    assert len(plan.signature) == 64
