"""Testes unitários — SessionSensitivityAccumulator (ADR-046)."""
import time
import pytest
from buildtovalue.governance import SessionSensitivityAccumulator, SensitivityState


@pytest.fixture
def acc():
    return SessionSensitivityAccumulator(max_sessions=100)


def test_single_finding_no_combination(acc):
    state = acc.accumulate("s1", ["cpf"])
    assert state.cumulative_risk == 0.0
    assert state.active_combinations == []


def test_two_requests_create_combination(acc):
    acc.accumulate("s2", ["cpf"])
    state = acc.accumulate("s2", ["credit_card"])
    assert state.cumulative_risk > 0.0
    assert any("PII_BRAZILIAN" in c and "FINANCIAL" in c
               for c in state.active_combinations)


def test_get_state_returns_accumulated(acc):
    acc.accumulate("s3", ["cpf"])
    acc.accumulate("s3", ["email"])
    state = acc.get_state("s3")
    assert state is not None
    assert "PII_BRAZILIAN" in state.tags
    assert "PII_CONTACT" in state.tags


def test_unknown_finding_ignored(acc):
    state = acc.accumulate("s4", ["unknown_validator"])
    assert len(state.tags) == 0


def test_max_tags_cap(acc):
    findings = ["cpf"] * 60
    state = acc.accumulate("s5", findings)
    assert len(state.tags) <= 50


def test_cumulative_risk_capped_at_1(acc):
    # Injetar todas as combinações possíveis
    all_findings = ["cpf", "credit_card", "email", "ssn", "nhs", "phone",
                    "prompt_injection", "iban", "vat"]
    state = acc.accumulate("s6", all_findings)
    assert state.cumulative_risk <= 1.0


def test_max_sessions_eviction():
    acc = SessionSensitivityAccumulator(max_sessions=3)
    for i in range(4):
        acc.accumulate(f"sess-{i}", ["cpf"])
    assert len(acc._sessions) <= 3
    assert acc.metrics["evictions"] >= 1


def test_metrics_incremented(acc):
    acc.accumulate("s7", ["cpf"])
    acc.accumulate("s7", ["credit_card"])
    assert acc.metrics["accumulations"] == 2
    assert acc.metrics["combinations_detected"] >= 1


def test_session_not_found_returns_none(acc):
    assert acc.get_state("nonexistent") is None
