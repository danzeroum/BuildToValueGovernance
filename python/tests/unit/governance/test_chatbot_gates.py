"""Testes unitários — chatbot_gates ADR-030."""
import pytest
from buildtovalue.governance.chatbot_gates import (
    DataClassification, message_gate, indexing_gate,
    rag_gate, training_gate, lora_deploy_gate,
)
from buildtovalue.governance.agent_pdp import ActionImpact


def test_message_gate_safe_returns_none():
    assert message_gate("hello", DataClassification.PUBLIC, False, "ws-001") is None

def test_message_gate_confidential_requires_gate():
    req = message_gate("cpf: 123", DataClassification.CONFIDENTIAL, False, "ws-001")
    assert req is not None
    assert req.action.impact == ActionImpact.DESTRUCTIVE

def test_message_gate_restricted_is_irreversible():
    req = message_gate("secret", DataClassification.RESTRICTED, False, "ws-001")
    assert req.action.impact == ActionImpact.IRREVERSIBLE
    assert req.parameters_preview == {}  # cleared by __post_init__

def test_message_gate_pii_detected_requires_gate():
    req = message_gate("data", DataClassification.INTERNAL, True, "ws-001")
    assert req is not None

def test_indexing_gate_public_returns_none():
    assert indexing_gate("doc-1", DataClassification.PUBLIC, "ws-001") is None

def test_indexing_gate_confidential():
    req = indexing_gate("doc-1", DataClassification.CONFIDENTIAL, "ws-001")
    assert req.action.name == "document_index"

def test_rag_gate_always_gates():
    req = rag_gate("chunk content", "ws-001")
    assert req.action.name == "rag_chunk_inject"

def test_training_gate():
    req = training_gate("batch-42", "ws-001", "health")
    assert req.action.name == "training_cycle_start"
    assert req.context.sector_id == "health"

def test_lora_deploy_is_irreversible():
    req = lora_deploy_gate("v1.2.0", -0.03, "ws-001")
    assert req.action.impact == ActionImpact.IRREVERSIBLE
    assert req.action.name == "lora_deploy"

def test_lora_deploy_metadata():
    req = lora_deploy_gate("v1.2.0", -0.06, "ws-001")
    assert req.context.agent_metadata["benchmark_delta"] == -0.06
