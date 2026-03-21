"""Tests for CommitRevealProtocol — Cenários 2, 5, 20."""
from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from buildtovalue.governance.commit_reveal import (
    CommitEntry,
    CommitRevealProtocol,
    CommitStatus,
    RevealResult,
    RevealStatus,
)
from buildtovalue.governance.durable_ledger import DurableLedger


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def ledger() -> DurableLedger:
    return DurableLedger(hmac_key=b"test-key-commit-reveal")


@pytest.fixture
def protocol(ledger: DurableLedger) -> CommitRevealProtocol:
    return CommitRevealProtocol(ledger=ledger, ttl_seconds=3600)


# ── TestCommit — SIM-1: Commit básico ─────────────────────────────────────────

class TestCommit:
    def test_commit_returns_entry(self, protocol: CommitRevealProtocol) -> None:
        entry = protocol.commit("agent-A", "intenção A", "salt-1")
        assert isinstance(entry, CommitEntry)
        assert entry.status == CommitStatus.PENDING

    def test_commit_hash_is_deterministic(self, protocol: CommitRevealProtocol) -> None:
        entry1 = protocol.commit("agent-A", "mesma intenção", "mesmo-salt")
        entry2 = protocol.commit("agent-A", "mesma intenção", "mesmo-salt")
        assert entry1.commit_hash == entry2.commit_hash

    def test_different_salts_produce_different_hashes(self, protocol: CommitRevealProtocol) -> None:
        entry1 = protocol.commit("agent-A", "intenção", "salt-1")
        entry2 = protocol.commit("agent-A", "intenção", "salt-2")
        assert entry1.commit_hash != entry2.commit_hash

    def test_commit_id_does_not_reveal_intention(self, protocol: CommitRevealProtocol) -> None:
        """commit_id (UUID) não deve conter a intenção nem o salt."""
        entry = protocol.commit("agent-A", "minha intenção secreta", "salt-x")
        assert "intenção" not in entry.commit_id
        assert "secreta" not in entry.commit_id
        assert "salt-x" not in entry.commit_id

    def test_commit_persisted_in_ledger(self, protocol: CommitRevealProtocol, ledger: DurableLedger) -> None:
        entry = protocol.commit("agent-A", "intenção A", "salt-1")
        entries = ledger.entries()
        commit_entries = [e for e in entries if e.payload.get("commit_id") == entry.commit_id]
        assert len(commit_entries) >= 1

    def test_explain_decision_present(self, protocol: CommitRevealProtocol) -> None:
        entry = protocol.commit("agent-A", "intenção A", "salt-1")
        assert entry.explain_decision
        assert len(entry.explain_decision) > 10

    def test_signature_present(self, protocol: CommitRevealProtocol) -> None:
        entry = protocol.commit("agent-A", "intenção A", "salt-1")
        assert entry.signature
        assert len(entry.signature) == 64


# ── TestRevealSuccess — SIM-2: Hash match → ALLOW ─────────────────────────────

class TestRevealSuccess:
    def test_correct_hash_returns_success(self, protocol: CommitRevealProtocol) -> None:
        entry = protocol.commit("agent-A", "intenção A", "salt-1")
        result = protocol.reveal(entry.commit_id, "intenção A", "salt-1")
        assert result.status == RevealStatus.SUCCESS
        assert result.allowed is True

    def test_successful_reveal_explain_present(self, protocol: CommitRevealProtocol) -> None:
        entry = protocol.commit("agent-A", "intenção A", "salt-1")
        result = protocol.reveal(entry.commit_id, "intenção A", "salt-1")
        assert result.explain_decision
        assert len(result.explain_decision) > 10

    def test_successful_reveal_persisted_in_ledger(
        self, protocol: CommitRevealProtocol, ledger: DurableLedger
    ) -> None:
        entry = protocol.commit("agent-A", "intenção A", "salt-1")
        protocol.reveal(entry.commit_id, "intenção A", "salt-1")
        entries = ledger.entries()
        reveal_entries = [
            e for e in entries
            if e.payload.get("type") == "commit_reveal_reveal"
            and e.payload.get("commit_id") == entry.commit_id
        ]
        assert len(reveal_entries) == 1


# ── TestRevealAbort — SIM-3: ABORT em falhas ──────────────────────────────────

class TestRevealAbort:
    def test_wrong_intention_aborts(self, protocol: CommitRevealProtocol) -> None:
        entry = protocol.commit("agent-A", "intenção A", "salt-1")
        result = protocol.reveal(entry.commit_id, "intenção DIFERENTE", "salt-1")
        assert result.status == RevealStatus.ABORT
        assert result.aborted is True

    def test_wrong_salt_aborts(self, protocol: CommitRevealProtocol) -> None:
        entry = protocol.commit("agent-A", "intenção A", "salt-1")
        result = protocol.reveal(entry.commit_id, "intenção A", "salt-ERRADO")
        assert result.status == RevealStatus.ABORT

    def test_unknown_commit_id_aborts(self, protocol: CommitRevealProtocol) -> None:
        result = protocol.reveal("commit-id-que-nao-existe", "intenção A", "salt-1")
        assert result.status == RevealStatus.ABORT

    def test_double_reveal_aborts(self, protocol: CommitRevealProtocol) -> None:
        """Segundo reveal do mesmo commit → ABORT (replay attack prevention)."""
        entry = protocol.commit("agent-A", "intenção A", "salt-1")
        result1 = protocol.reveal(entry.commit_id, "intenção A", "salt-1")
        assert result1.status == RevealStatus.SUCCESS

        result2 = protocol.reveal(entry.commit_id, "intenção A", "salt-1")
        assert result2.status == RevealStatus.ABORT

    def test_abort_persisted_in_ledger(
        self, protocol: CommitRevealProtocol, ledger: DurableLedger
    ) -> None:
        entry = protocol.commit("agent-A", "intenção A", "salt-1")
        protocol.reveal(entry.commit_id, "intenção ERRADA", "salt-1")
        entries = ledger.entries()
        abort_entries = [
            e for e in entries
            if e.payload.get("type") == "commit_reveal_abort"
            and e.payload.get("commit_id") == entry.commit_id
        ]
        assert len(abort_entries) == 1

    def test_abort_explain_present(self, protocol: CommitRevealProtocol) -> None:
        result = protocol.reveal("unknown-id", "intent", "salt")
        assert result.explain_decision
        assert len(result.explain_decision) > 10


# ── TestTTLExpiry — SIM-4: Timeout → ABORT ────────────────────────────────────

class TestTTLExpiry:
    def test_expired_ttl_aborts(self, ledger: DurableLedger) -> None:
        """TTL de 0 segundos → qualquer reveal é ABORT (tempo já expirado)."""
        protocol = CommitRevealProtocol(ledger=ledger, ttl_seconds=0)
        entry = protocol.commit("agent-A", "intenção A", "salt-1")
        result = protocol.reveal(entry.commit_id, "intenção A", "salt-1")
        assert result.status == RevealStatus.ABORT

    def test_valid_ttl_allows(self, ledger: DurableLedger) -> None:
        """TTL generoso → reveal funciona normalmente."""
        protocol = CommitRevealProtocol(ledger=ledger, ttl_seconds=3600)
        entry = protocol.commit("agent-A", "intenção A", "salt-1")
        result = protocol.reveal(entry.commit_id, "intenção A", "salt-1")
        assert result.status == RevealStatus.SUCCESS


# ── TestCrashRecovery — SIM-5: Crash + restart ────────────────────────────────

class TestCrashRecovery:
    def test_reveal_after_cache_cleared_uses_ledger(self, ledger: DurableLedger) -> None:
        """Após 'crash' (cache limpo), reveal deve reconstruir do ledger."""
        protocol = CommitRevealProtocol(ledger=ledger, ttl_seconds=3600)
        entry = protocol.commit("agent-A", "intenção A", "salt-1")

        # Simula crash limpando cache in-memory
        protocol._commits.clear()

        # Reveal deve reconstruir do ledger
        result = protocol.reveal(entry.commit_id, "intenção A", "salt-1")
        assert result.status == RevealStatus.SUCCESS

    def test_ledger_integrity_preserved(self, ledger: DurableLedger) -> None:
        """DurableLedger permanece íntegro após commit+reveal."""
        protocol = CommitRevealProtocol(ledger=ledger, ttl_seconds=3600)
        entry = protocol.commit("agent-A", "intenção A", "salt-1")
        protocol.reveal(entry.commit_id, "intenção A", "salt-1")

        verification = ledger.verify()
        assert verification.valid is True


# ── TestResultInvariants — SIM-6: Invariantes de resultado ───────────────────

class TestResultInvariants:
    def test_commit_entry_is_frozen(self, protocol: CommitRevealProtocol) -> None:
        entry = protocol.commit("agent-A", "intenção A", "salt-1")
        with pytest.raises((AttributeError, TypeError)):
            entry.status = CommitStatus.ABORTED  # type: ignore[misc]

    def test_reveal_result_is_frozen(self, protocol: CommitRevealProtocol) -> None:
        entry = protocol.commit("agent-A", "intenção A", "salt-1")
        result = protocol.reveal(entry.commit_id, "intenção A", "salt-1")
        with pytest.raises((AttributeError, TypeError)):
            result.status = RevealStatus.ABORT  # type: ignore[misc]

    def test_signatures_are_hex_sha256(self, protocol: CommitRevealProtocol) -> None:
        entry = protocol.commit("agent-A", "intenção A", "salt-1")
        result = protocol.reveal(entry.commit_id, "intenção A", "salt-1")
        assert len(entry.signature) == 64
        assert len(result.signature) == 64
