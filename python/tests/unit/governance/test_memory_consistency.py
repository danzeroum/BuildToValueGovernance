"""Tests for MemoryConsistencyValidator — Cenários 31, 28, 11."""
from __future__ import annotations

import pytest

from buildtovalue.governance.durable_ledger import DurableLedger
from buildtovalue.governance.memory_consistency import (
    ConsistencyReport,
    InconsistencyType,
    MemoryConsistencyValidator,
    MemoryFact,
)


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def ledger() -> DurableLedger:
    return DurableLedger(hmac_key=b"test-key-memory-consistency")


@pytest.fixture
def validator(ledger: DurableLedger) -> MemoryConsistencyValidator:
    return MemoryConsistencyValidator(ledger=ledger)


def _seed_fact(
    ledger: DurableLedger,
    entity_key: str,
    attribute: str,
    value: str,
    source: str = "source-a",
    timestamp_iso: str = "2026-01-01T10:00:00Z",
    event_references: list | None = None,
) -> None:
    """Persiste fato de memória diretamente no ledger para testes."""
    ledger.append({
        "type":             "memory_fact",
        "entity_key":       entity_key,
        "attribute":        attribute,
        "value":            value,
        "source":           source,
        "timestamp_iso":    timestamp_iso,
        "event_references": event_references or [],
        "explain_decision": f"Seed fact: {entity_key}.{attribute}={value}",
    })


# ── TestConsistentFact — SIM-1: Fato consistente ──────────────────────────────

class TestConsistentFact:
    def test_new_fact_no_history_is_consistent(self, validator: MemoryConsistencyValidator) -> None:
        fact = MemoryFact(
            entity_key="user:001", attribute="status",
            value="active", source="agent-a",
            timestamp_iso="2026-01-01T10:00:00Z",
        )
        report = validator.validate(fact)
        assert report.consistent is True
        assert report.flagged_for_review is False
        assert report.inconsistency_type is None

    def test_same_fact_same_value_is_consistent(
        self, ledger: DurableLedger, validator: MemoryConsistencyValidator
    ) -> None:
        _seed_fact(ledger, "user:001", "status", "active")
        fact = MemoryFact(
            entity_key="user:001", attribute="status",
            value="active", source="agent-a",
            timestamp_iso="2026-01-01T11:00:00Z",
        )
        report = validator.validate(fact)
        assert report.consistent is True

    def test_different_entities_no_conflict(
        self, ledger: DurableLedger, validator: MemoryConsistencyValidator
    ) -> None:
        _seed_fact(ledger, "user:001", "status", "active")
        fact = MemoryFact(
            entity_key="user:002", attribute="status",
            value="inactive", source="agent-a",
            timestamp_iso="2026-01-01T10:00:00Z",
        )
        report = validator.validate(fact)
        assert report.consistent is True


# ── TestDirectContradiction — SIM-2: DIRECT_CONTRADICTION ────────────────────

class TestDirectContradiction:
    def test_detects_direct_contradiction(
        self, ledger: DurableLedger, validator: MemoryConsistencyValidator
    ) -> None:
        _seed_fact(ledger, "contract:abc", "status", "active", source="agent-a")
        fact = MemoryFact(
            entity_key="contract:abc", attribute="status",
            value="cancelled", source="agent-a",  # mesma fonte — contradição direta
            timestamp_iso="2026-01-01T11:00:00Z",
        )
        report = validator.validate(fact)
        assert report.consistent is False
        assert report.inconsistency_type == InconsistencyType.DIRECT_CONTRADICTION
        assert report.flagged_for_review is True
        assert report.severity == "high"

    def test_contradiction_existing_value_captured(
        self, ledger: DurableLedger, validator: MemoryConsistencyValidator
    ) -> None:
        _seed_fact(ledger, "contract:abc", "value", "100.00", source="agent-a")
        fact = MemoryFact(
            entity_key="contract:abc", attribute="value",
            value="200.00", source="agent-a",  # mesma fonte contradiz a si mesma
            timestamp_iso="2026-01-01T11:00:00Z",
        )
        report = validator.validate(fact)
        assert report.existing_value == "100.00"
        assert report.new_value == "200.00"

    def test_contradiction_explain_present(
        self, ledger: DurableLedger, validator: MemoryConsistencyValidator
    ) -> None:
        _seed_fact(ledger, "entity:x", "attr", "val-a", source="source-a")
        fact = MemoryFact(
            entity_key="entity:x", attribute="attr",
            value="val-b", source="source-a",  # mesma fonte
            timestamp_iso="2026-01-01T11:00:00Z",
        )
        report = validator.validate(fact)
        assert "DIRECT_CONTRADICTION" in report.explain_decision

    def test_contradiction_should_block(
        self, ledger: DurableLedger, validator: MemoryConsistencyValidator
    ) -> None:
        _seed_fact(ledger, "entity:x", "attr", "val-a", source="source-a")
        fact = MemoryFact(
            entity_key="entity:x", attribute="attr",
            value="val-b", source="source-a",  # mesma fonte
            timestamp_iso="2026-01-01T11:00:00Z",
        )
        report = validator.validate(fact)
        assert report.should_block is True


# ── TestTemporalViolation — SIM-3: TEMPORAL_VIOLATION ────────────────────────

class TestTemporalViolation:
    def test_detects_temporal_violation(
        self, ledger: DurableLedger, validator: MemoryConsistencyValidator
    ) -> None:
        """Novo fato ocorre antes do evento que referencia."""
        _seed_fact(
            ledger, "event:B", "occurred", "true",
            timestamp_iso="2026-01-01T12:00:00Z",
        )
        # Novo fato ocorre às 10h mas referencia event:B (12h) como pré-requisito
        fact = MemoryFact(
            entity_key="event:C", attribute="completed",
            value="true", source="agent-a",
            timestamp_iso="2026-01-01T10:00:00Z",  # antes de event:B
            event_references=["event:B"],
        )
        report = validator.validate(fact)
        assert report.consistent is False
        assert report.inconsistency_type == InconsistencyType.TEMPORAL_VIOLATION
        assert report.flagged_for_review is True

    def test_no_violation_when_fact_after_reference(
        self, ledger: DurableLedger, validator: MemoryConsistencyValidator
    ) -> None:
        _seed_fact(
            ledger, "event:B", "occurred", "true",
            timestamp_iso="2026-01-01T10:00:00Z",
        )
        fact = MemoryFact(
            entity_key="event:C", attribute="completed",
            value="true", source="agent-a",
            timestamp_iso="2026-01-01T12:00:00Z",  # depois de event:B
            event_references=["event:B"],
        )
        report = validator.validate(fact)
        assert report.consistent is True

    def test_no_references_no_temporal_check(
        self, validator: MemoryConsistencyValidator
    ) -> None:
        fact = MemoryFact(
            entity_key="event:C", attribute="status", value="done",
            source="agent-a", timestamp_iso="2026-01-01T10:00:00Z",
        )
        report = validator.validate(fact)
        assert report.consistent is True


# ── TestSourceConflict — SIM-4: SOURCE_CONFLICT ───────────────────────────────

class TestSourceConflict:
    def test_detects_source_conflict(
        self, ledger: DurableLedger, validator: MemoryConsistencyValidator
    ) -> None:
        _seed_fact(ledger, "asset:001", "price", "100", source="oracle-a")
        fact = MemoryFact(
            entity_key="asset:001", attribute="price",
            value="200", source="oracle-b",
            timestamp_iso="2026-01-01T11:00:00Z",
        )
        report = validator.validate(fact)
        assert report.consistent is False
        assert report.inconsistency_type == InconsistencyType.SOURCE_CONFLICT
        assert report.flagged_for_review is True

    def test_same_source_same_value_no_conflict(
        self, ledger: DurableLedger, validator: MemoryConsistencyValidator
    ) -> None:
        _seed_fact(ledger, "asset:001", "price", "100", source="oracle-a")
        fact = MemoryFact(
            entity_key="asset:001", attribute="price",
            value="100", source="oracle-a",
            timestamp_iso="2026-01-01T11:00:00Z",
        )
        report = validator.validate(fact)
        assert report.consistent is True

    def test_different_sources_same_value_no_conflict(
        self, ledger: DurableLedger, validator: MemoryConsistencyValidator
    ) -> None:
        _seed_fact(ledger, "asset:001", "price", "100", source="oracle-a")
        fact = MemoryFact(
            entity_key="asset:001", attribute="price",
            value="100", source="oracle-b",  # fonte diferente, mesmo valor → sem conflito
            timestamp_iso="2026-01-01T11:00:00Z",
        )
        report = validator.validate(fact)
        assert report.consistent is True


# ── TestEntityDuplication — SIM-5: ENTITY_DUPLICATION ────────────────────────

class TestEntityDuplication:
    def test_detects_entity_duplication(
        self, ledger: DurableLedger, validator: MemoryConsistencyValidator
    ) -> None:
        _seed_fact(ledger, "user:001", "email", "a@b.com", source="idp-a")
        fact = MemoryFact(
            entity_key="user:002", attribute="email",
            value="a@b.com", source="idp-a",
            timestamp_iso="2026-01-01T11:00:00Z",
        )
        report = validator.validate(fact)
        assert report.consistent is False
        assert report.inconsistency_type == InconsistencyType.ENTITY_DUPLICATION
        assert report.flagged_for_review is True

    def test_different_sources_no_duplication(
        self, ledger: DurableLedger, validator: MemoryConsistencyValidator
    ) -> None:
        _seed_fact(ledger, "user:001", "email", "a@b.com", source="idp-a")
        fact = MemoryFact(
            entity_key="user:002", attribute="email",
            value="a@b.com", source="idp-b",  # fonte diferente → não é dupl. confirmada
            timestamp_iso="2026-01-01T11:00:00Z",
        )
        report = validator.validate(fact)
        assert report.consistent is True


# ── TestLedgerIntegrity — SIM-6: Ledger append-only preservado ───────────────

class TestLedgerIntegrity:
    def test_ledger_intact_after_conflict(
        self, ledger: DurableLedger, validator: MemoryConsistencyValidator
    ) -> None:
        """Conflito detectado não corrompe o ledger."""
        _seed_fact(ledger, "entity:x", "attr", "val-a")
        fact = MemoryFact(
            entity_key="entity:x", attribute="attr",
            value="val-b", source="source-a",
            timestamp_iso="2026-01-01T11:00:00Z",
        )
        validator.validate(fact)
        verification = ledger.verify()
        assert verification.valid is True

    def test_persist_if_consistent_writes_to_ledger(
        self, ledger: DurableLedger, validator: MemoryConsistencyValidator
    ) -> None:
        fact = MemoryFact(
            entity_key="entity:new", attribute="status",
            value="active", source="agent-a",
            timestamp_iso="2026-01-01T10:00:00Z",
        )
        before_count = len(ledger)
        report = validator.persist_if_consistent(
            fact,
            {"type": "memory_fact", "entity_key": "entity:new",
             "attribute": "status", "value": "active",
             "source": "agent-a", "timestamp_iso": "2026-01-01T10:00:00Z",
             "event_references": []},
        )
        assert report.consistent is True
        assert len(ledger) == before_count + 1

    def test_flagged_memory_stored_with_flag(
        self, ledger: DurableLedger, validator: MemoryConsistencyValidator
    ) -> None:
        """Memória inconsistente persiste marcada (flagged_for_review=True), não silenciada."""
        _seed_fact(ledger, "entity:y", "value", "100")
        fact = MemoryFact(
            entity_key="entity:y", attribute="value",
            value="200", source="source-a",
            timestamp_iso="2026-01-01T11:00:00Z",
        )
        report = validator.persist_if_consistent(
            fact,
            {"type": "memory_fact", "entity_key": "entity:y",
             "attribute": "value", "value": "200",
             "source": "source-a", "timestamp_iso": "2026-01-01T11:00:00Z",
             "event_references": []},
        )
        assert report.flagged_for_review is True
        # Verificar que a entrada foi persistida no ledger com o flag
        entries = ledger.entries()
        flagged = [
            e for e in entries
            if e.payload.get("flagged_for_review") is True
            and e.payload.get("entity_key") == "entity:y"
        ]
        assert len(flagged) >= 1


# ── TestResultInvariants — SIM-7: Invariantes de resultado ───────────────────

class TestResultInvariants:
    def test_result_is_frozen(self, validator: MemoryConsistencyValidator) -> None:
        fact = MemoryFact(
            entity_key="e", attribute="a", value="v",
            source="s", timestamp_iso="2026-01-01T10:00:00Z",
        )
        report = validator.validate(fact)
        with pytest.raises((AttributeError, TypeError)):
            report.consistent = False  # type: ignore[misc]

    def test_explain_always_present(self, validator: MemoryConsistencyValidator) -> None:
        fact = MemoryFact(
            entity_key="e", attribute="a", value="v",
            source="s", timestamp_iso="2026-01-01T10:00:00Z",
        )
        report = validator.validate(fact)
        assert report.explain_decision
        assert len(report.explain_decision) > 10

    def test_signature_is_hex_sha256(self, validator: MemoryConsistencyValidator) -> None:
        fact = MemoryFact(
            entity_key="e", attribute="a", value="v",
            source="s", timestamp_iso="2026-01-01T10:00:00Z",
        )
        report = validator.validate(fact)
        assert len(report.signature) == 64
