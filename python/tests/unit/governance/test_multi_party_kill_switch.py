"""Tests for MultiPartyKillSwitch — Cenários 10, 29, 30."""
from __future__ import annotations

import pytest

from buildtovalue.governance.durable_ledger import DurableLedger
from buildtovalue.governance.multi_party_kill_switch import (
    KillSwitchProposal,
    KillSwitchVoteRecord,
    MultiPartyKillSwitch,
    VoteResult,
)


# ── Fixtures ───────────────────────────────────────────────────────────────────

AUTHORIZED_VOTERS = {"operator", "delegate-1", "delegate-2"}


@pytest.fixture
def ledger() -> DurableLedger:
    return DurableLedger(hmac_key=b"test-key-kill-switch")


@pytest.fixture
def kill_switch(ledger: DurableLedger) -> MultiPartyKillSwitch:
    return MultiPartyKillSwitch(
        ledger=ledger,
        authorized_voters=AUTHORIZED_VOTERS,
        ttl_seconds=3600,
        threshold=2 / 3,
    )


# ── TestPropose — SIM-1: Proposta de isolamento ────────────────────────────────

class TestPropose:
    def test_authorized_proposer_creates_proposal(
        self, kill_switch: MultiPartyKillSwitch
    ) -> None:
        proposal = kill_switch.propose_isolation("agent-bad", "operator")
        assert isinstance(proposal, KillSwitchProposal)
        assert proposal.target_agent_id == "agent-bad"
        assert proposal.proposer_id == "operator"

    def test_unauthorized_proposer_returns_fail_secure(
        self, kill_switch: MultiPartyKillSwitch
    ) -> None:
        """Proposer não autorizado → proposta fail-secure com TTL=0 (inoperante)."""
        proposal = kill_switch.propose_isolation("agent-bad", "unknown-proposer")
        # Fail-secure: não levanta exceção, retorna proposta inoperante
        assert isinstance(proposal, KillSwitchProposal)
        assert proposal.ttl_seconds == 0  # inoperante

    def test_proposal_persisted_in_ledger(
        self, kill_switch: MultiPartyKillSwitch, ledger: DurableLedger
    ) -> None:
        proposal = kill_switch.propose_isolation("agent-bad", "operator")
        entries = ledger.entries()
        proposal_entries = [
            e for e in entries
            if e.payload.get("proposal_id") == proposal.proposal_id
        ]
        assert len(proposal_entries) >= 1

    def test_proposal_explain_present(self, kill_switch: MultiPartyKillSwitch) -> None:
        proposal = kill_switch.propose_isolation("agent-bad", "operator")
        assert proposal.explain_decision
        assert len(proposal.explain_decision) > 10

    def test_proposal_signature_present(self, kill_switch: MultiPartyKillSwitch) -> None:
        proposal = kill_switch.propose_isolation("agent-bad", "operator")
        assert proposal.signature
        assert len(proposal.signature) == 64


# ── TestVoting — SIM-2: Votação e quorum ──────────────────────────────────────

class TestVoting:
    def test_single_vote_pending(self, kill_switch: MultiPartyKillSwitch) -> None:
        proposal = kill_switch.propose_isolation("agent-bad", "operator")
        result = kill_switch.cast_vote(proposal.proposal_id, "delegate-1")
        assert result.result == VoteResult.PENDING

    def test_quorum_2_of_3_isolates(self, kill_switch: MultiPartyKillSwitch) -> None:
        """2/3 votos → ISOLATED (threshold 2/3)."""
        proposal = kill_switch.propose_isolation("agent-bad", "operator")
        kill_switch.cast_vote(proposal.proposal_id, "operator")
        result = kill_switch.cast_vote(proposal.proposal_id, "delegate-1")
        assert result.result == VoteResult.ISOLATED

    def test_isolation_recorded_in_ledger(
        self, kill_switch: MultiPartyKillSwitch, ledger: DurableLedger
    ) -> None:
        proposal = kill_switch.propose_isolation("agent-bad", "operator")
        kill_switch.cast_vote(proposal.proposal_id, "operator")
        kill_switch.cast_vote(proposal.proposal_id, "delegate-1")

        entries = ledger.entries()
        isolated_votes = [
            e for e in entries
            if e.payload.get("type") == "kill_switch_vote"
            and e.payload.get("result") == VoteResult.ISOLATED.value
        ]
        assert len(isolated_votes) >= 1

    def test_unauthorized_voter_rejected(self, kill_switch: MultiPartyKillSwitch) -> None:
        proposal = kill_switch.propose_isolation("agent-bad", "operator")
        result = kill_switch.cast_vote(proposal.proposal_id, "unknown-voter")
        assert result.result == VoteResult.REJECTED

    def test_double_vote_rejected(self, kill_switch: MultiPartyKillSwitch) -> None:
        """Mesmo votante não pode votar duas vezes."""
        proposal = kill_switch.propose_isolation("agent-bad", "operator")
        kill_switch.cast_vote(proposal.proposal_id, "delegate-1")
        result2 = kill_switch.cast_vote(proposal.proposal_id, "delegate-1")
        assert result2.result == VoteResult.REJECTED

    def test_double_vote_does_not_count(self, kill_switch: MultiPartyKillSwitch) -> None:
        """Duplo voto não contribui para o quorum."""
        proposal = kill_switch.propose_isolation("agent-bad", "operator")
        kill_switch.cast_vote(proposal.proposal_id, "delegate-1")
        kill_switch.cast_vote(proposal.proposal_id, "delegate-1")  # rejeitado
        # Apenas 1 voto válido — não deve isolar com threshold 2/3 (precisa de 2)
        status = kill_switch.check_status(proposal.proposal_id)
        assert status == VoteResult.PENDING


# ── TestExpiry — SIM-3: Expiração da janela ───────────────────────────────────

class TestExpiry:
    def test_expired_proposal_returns_expired(self, ledger: DurableLedger) -> None:
        """TTL=0 → janela imediatamente expirada."""
        ks = MultiPartyKillSwitch(
            ledger=ledger,
            authorized_voters=AUTHORIZED_VOTERS,
            ttl_seconds=0,
        )
        proposal = ks.propose_isolation("agent-bad", "operator")
        result = ks.cast_vote(proposal.proposal_id, "delegate-1")
        assert result.result == VoteResult.EXPIRED

    def test_expired_without_quorum_no_isolation(self, ledger: DurableLedger) -> None:
        """Janela expirada sem quorum → EXPIRED (sem ação, não ISOLATED)."""
        ks = MultiPartyKillSwitch(
            ledger=ledger,
            authorized_voters=AUTHORIZED_VOTERS,
            ttl_seconds=0,
        )
        proposal = ks.propose_isolation("agent-bad", "operator")
        # Votar depois de expirar
        result = ks.cast_vote(proposal.proposal_id, "operator")
        assert result.result == VoteResult.EXPIRED
        # Status deve ser EXPIRED, não ISOLATED
        status = ks.check_status(proposal.proposal_id)
        assert status in (VoteResult.EXPIRED, VoteResult.PENDING)


# ── TestCrashRecovery — SIM-4: Recuperação após crash ─────────────────────────

class TestCrashRecovery:
    def test_votes_survive_cache_clear(
        self, kill_switch: MultiPartyKillSwitch, ledger: DurableLedger
    ) -> None:
        """Após 'crash' (cache limpo), votos são reconstruídos do ledger."""
        proposal = kill_switch.propose_isolation("agent-bad", "operator")
        kill_switch.cast_vote(proposal.proposal_id, "operator")

        # Simula crash limpando cache
        kill_switch._proposals.clear()
        kill_switch._votes.clear()

        # Segundo voto deve recontar do ledger e atingir quorum
        result = kill_switch.cast_vote(proposal.proposal_id, "delegate-1")
        assert result.result == VoteResult.ISOLATED


# ── TestLedgerIntegrity — SIM-5: Integridade do ledger ────────────────────────

class TestLedgerIntegrity:
    def test_ledger_intact_after_full_flow(
        self, kill_switch: MultiPartyKillSwitch, ledger: DurableLedger
    ) -> None:
        """DurableLedger permanece íntegro após todo o fluxo."""
        proposal = kill_switch.propose_isolation("agent-bad", "operator")
        kill_switch.cast_vote(proposal.proposal_id, "operator")
        kill_switch.cast_vote(proposal.proposal_id, "delegate-1")
        kill_switch.cast_vote(proposal.proposal_id, "delegate-2")

        verification = ledger.verify()
        assert verification.valid is True

    def test_explain_always_present(self, kill_switch: MultiPartyKillSwitch) -> None:
        proposal = kill_switch.propose_isolation("agent-bad", "operator")
        result = kill_switch.cast_vote(proposal.proposal_id, "operator")
        assert result.explain_decision
        assert len(result.explain_decision) > 10

    def test_vote_record_is_frozen(self, kill_switch: MultiPartyKillSwitch) -> None:
        proposal = kill_switch.propose_isolation("agent-bad", "operator")
        result = kill_switch.cast_vote(proposal.proposal_id, "operator")
        with pytest.raises((AttributeError, TypeError)):
            result.result = VoteResult.ISOLATED  # type: ignore[misc]


# ── TestMinimumVoters ──────────────────────────────────────────────────────────

class TestMinimumVoters:
    def test_minimum_2_voters_required(self, ledger: DurableLedger) -> None:
        with pytest.raises(ValueError):
            MultiPartyKillSwitch(
                ledger=ledger,
                authorized_voters={"only-one"},
            )

    def test_exact_2_voters_works(self, ledger: DurableLedger) -> None:
        ks = MultiPartyKillSwitch(
            ledger=ledger,
            authorized_voters={"voter-1", "voter-2"},
            threshold=1.0,  # ambos devem votar
        )
        proposal = ks.propose_isolation("agent-bad", "voter-1")
        ks.cast_vote(proposal.proposal_id, "voter-1")
        result = ks.cast_vote(proposal.proposal_id, "voter-2")
        assert result.result == VoteResult.ISOLATED
