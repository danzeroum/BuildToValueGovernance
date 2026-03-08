"""Testes unitários — chatbot_vendor_gates ADR-031."""
import pytest
from buildtovalue.governance.chatbot_vendor_gates import (
    DataClassification, VendorConfig, VendorId,
    vendor_send_gate, vendor_response_gate,
    vendor_approval_gate, rag_external_gate,
)
from buildtovalue.governance.agent_pdp import ActionImpact

VENDOR = VendorConfig(vendor_id=VendorId.OPENAI, has_dpa=True, has_zdr=False)

def test_vendor_send_always_irreversible():
    req = vendor_send_gate("hello", DataClassification.PUBLIC, "ev-001", "ws-1", VENDOR)
    assert req.action.impact == ActionImpact.IRREVERSIBLE

def test_vendor_send_clears_preview():
    req = vendor_send_gate("hello", DataClassification.INTERNAL, "ev-001", "ws-1", VENDOR)
    assert req.parameters_preview == {}

def test_vendor_send_eligible_for_training_false():
    req = vendor_send_gate("hello", DataClassification.PUBLIC, "ev-001", "ws-1", VENDOR)
    assert req.context.agent_metadata["eligible_for_training"] is False

def test_vendor_send_restricted_raises():
    with pytest.raises(ValueError):
        vendor_send_gate("secret", DataClassification.RESTRICTED, "ev-001", "ws-1", VENDOR)

def test_vendor_response_gate():
    req = vendor_response_gate("response text", "ev-send-001", "ws-1")
    assert req.action.name == "llm_vendor_response_display"

def test_vendor_approval_gate():
    req = vendor_approval_gate(VENDOR, "ws-1", "health")
    assert req.context.sector_id == "health"
    assert req.context.agent_metadata["has_zdr"] is False

def test_rag_restricted_blocked_locally():
    result = rag_external_gate("chunk", DataClassification.RESTRICTED, "ws-1")
    assert result is None

def test_rag_confidential_uses_conf_action():
    req = rag_external_gate("chunk", DataClassification.CONFIDENTIAL, "ws-1")
    assert req.action.name == "rag_chunk_inject_conf"

def test_rag_public_uses_standard_action():
    req = rag_external_gate("chunk", DataClassification.PUBLIC, "ws-1")
    assert req.action.name == "rag_chunk_inject"
