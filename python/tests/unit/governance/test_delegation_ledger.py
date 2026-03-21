"""Tests for DelegationLedger — Gap B, C12, C13."""
from __future__ import annotations

import time
from pathlib import Path

import pytest
import yaml

from buildtovalue.governance.delegation_ledger import (
    CustodyGapError,
    DelegationLedger,
    WorkContract,
)


@pytest.fixture
def policy_path(tmp_path: Path) -> Path:
    policy = {
        "max_chain_depth": 3,
        "scope_hierarchy": {"read_only": 0, "read_write": 1, "execute": 2},
    }
    p = tmp_path / "delegation_rules.yaml"
    p.write_text(yaml.dump(policy))
    return p


@pytest.fixture
def ledger(policy_path: Path) -> DelegationLedger:
    return DelegationLedger(policy_path=policy_path, hmac_key=b"test" * 8)


class TestRecordDelegation:
    def test_basic_delegation(self, ledger: DelegationLedger) -> None:
        rec = ledger.record_delegation("agent-a", "agent-b", "read_only")
        assert rec.parent_agent == "agent-a"
        assert rec.child_agent == "agent-b"
        assert len(rec.hmac_sha256) == 64

    def test_chain_depth_enforced(self, ledger: DelegationLedger) -> None:
        ledger.record_delegation("a", "b", "read_only")
        ledger.record_delegation("b", "c", "read_only")
        ledger.record_delegation("c", "d", "read_only")
        with pytest.raises(ValueError, match="exceeds max"):
            ledger.record_delegation("d", "e", "read_only")


class TestVerifyChain:
    def test_single_delegation(self, ledger: DelegationLedger) -> None:
        ledger.record_delegation("a", "b", "read_only")
        result = ledger.verify_chain("b")
        assert result.valid is True
        assert result.depth == 1

    def test_chain_of_three(self, ledger: DelegationLedger) -> None:
        ledger.record_delegation("a", "b", "read_only")
        ledger.record_delegation("b", "c", "read_only")
        result = ledger.verify_chain("c")
        assert result.depth == 2
        assert result.valid is True

    def test_no_chain(self, ledger: DelegationLedger) -> None:
        result = ledger.verify_chain("unknown")
        assert result.depth == 0
        assert result.valid is True


class TestRevocation:
    def test_revoke_delegation(self, ledger: DelegationLedger) -> None:
        rec = ledger.record_delegation("a", "b", "read_only")
        ledger.revoke_delegation(rec.record_id)
        result = ledger.verify_chain("b")
        assert result.depth == 0  # chain broken

    def test_revoke_unknown_raises(self, ledger: DelegationLedger) -> None:
        with pytest.raises(ValueError, match="Unknown record"):
            ledger.revoke_delegation("nonexistent")


class TestCycleDetection:
    def test_self_delegation_forbidden(self, ledger: DelegationLedger) -> None:
        with pytest.raises(ValueError, match="Self-delegation"):
            ledger.record_delegation("a", "a", "read_only")

    def test_cycle_detected(self, ledger: DelegationLedger) -> None:
        ledger.record_delegation("a", "b", "read_only")
        ledger.record_delegation("b", "c", "read_only")
        with pytest.raises(ValueError, match="Cycle detected"):
            ledger.record_delegation("c", "a", "read_only")


class TestNoPolicy:
    def test_default_ledger(self) -> None:
        dl = DelegationLedger(hmac_key=b"x" * 32)
        rec = dl.record_delegation("a", "b", "read_only")
        assert rec.parent_agent == "a"


# ── C12: WorkContract ─────────────────────────────────────────────────────────

class TestWorkContract:
    def test_record_work_contract_basic(self, ledger: DelegationLedger) -> None:
        wc = ledger.record_work_contract(
            contractor="freelancer-agent",
            scope_merkle=b"\xaa" * 32,
            model_hash=b"\xbb" * 32,
            acceptance_criteria={"min_accuracy": "0.95", "language": "pt"},
        )
        assert isinstance(wc, WorkContract)
        assert wc.contractor == "freelancer-agent"
        assert wc.scope_merkle == "aa" * 32
        assert wc.model_hash == "bb" * 32
        assert wc.sampling_seed is None  # not yet revealed
        assert wc.created_at > 0

    def test_work_contract_hmac_signed(self, ledger: DelegationLedger) -> None:
        wc = ledger.record_work_contract(
            contractor="agent-x",
            scope_merkle=b"\x01" * 32,
            model_hash=b"\x02" * 32,
            acceptance_criteria={"threshold": "0.9"},
        )
        assert len(wc.hmac_sha256) == 64
        assert all(c in "0123456789abcdef" for c in wc.hmac_sha256)

    def test_reveal_sampling_seed_after_delivery(self, ledger: DelegationLedger) -> None:
        wc = ledger.record_work_contract(
            contractor="agent-y",
            scope_merkle=b"\x03" * 32,
            model_hash=b"\x04" * 32,
            acceptance_criteria={},
        )
        assert wc.sampling_seed is None
        delivery_hash = b"\xde\xad\xbe\xef" * 8
        revealed = ledger.reveal_sampling_seed(wc.contract_id, delivery_hash)
        assert revealed.sampling_seed is not None
        assert len(revealed.sampling_seed) == 64  # BLAKE3 hex = 32 bytes = 64 chars

    def test_reveal_seed_unknown_contract_raises(self, ledger: DelegationLedger) -> None:
        with pytest.raises(ValueError, match="Unknown contract"):
            ledger.reveal_sampling_seed("nonexistent-id", b"\x00" * 32)

    def test_reveal_seed_deterministic(self, ledger: DelegationLedger) -> None:
        wc = ledger.record_work_contract(
            contractor="agent-z",
            scope_merkle=b"\x05" * 32,
            model_hash=b"\x06" * 32,
            acceptance_criteria={"k": "v"},
        )
        delivery = b"\xca\xfe" * 16
        r1 = ledger.reveal_sampling_seed(wc.contract_id, delivery)
        r2 = ledger.reveal_sampling_seed(wc.contract_id, delivery)
        assert r1.sampling_seed == r2.sampling_seed

    def test_reveal_seed_different_deliveries_differ(self, ledger: DelegationLedger) -> None:
        wc = ledger.record_work_contract(
            contractor="agent-w",
            scope_merkle=b"\x07" * 32,
            model_hash=b"\x08" * 32,
            acceptance_criteria={},
        )
        s1 = ledger.reveal_sampling_seed(wc.contract_id, b"\x00" * 32).sampling_seed
        s2 = ledger.reveal_sampling_seed(wc.contract_id, b"\xff" * 32).sampling_seed
        assert s1 != s2


# ── C13: ColdChain ────────────────────────────────────────────────────────────

class TestColdChainCustody:
    def test_transfer_within_gap_ok(self, ledger: DelegationLedger) -> None:
        # 5 seconds ago — well within 300s default
        recent = time.time() - 5
        rec = ledger.record_custody_transfer(
            sender="truck-a", receiver="port-b", scope="read_write",
            last_telemetry_at=recent,
        )
        assert rec.parent_agent == "truck-a"
        assert any("cold_chain_gap_s" in cap for cap in rec.capabilities)

    def test_transfer_gap_exceeded_blocks(self, ledger: DelegationLedger, tmp_path: Path) -> None:
        # 600 seconds ago — exceeds 300s max; block_on_gap=True
        policy = {"max_custody_gap_seconds": 300, "block_on_gap": True}
        p = tmp_path / "cold_chain.yaml"
        p.write_text(yaml.dump(policy))
        old = time.time() - 600
        with pytest.raises(CustodyGapError, match="600"):
            ledger.record_custody_transfer(
                sender="ship-x", receiver="truck-b", scope="read_write",
                last_telemetry_at=old, cold_chain_policy_path=p,
            )

    def test_transfer_gap_no_block_policy(self, ledger: DelegationLedger, tmp_path: Path) -> None:
        # 600 seconds ago but block_on_gap=False — should warn and allow
        policy = {"max_custody_gap_seconds": 300, "block_on_gap": False}
        p = tmp_path / "cold_chain.yaml"
        p.write_text(yaml.dump(policy))
        old = time.time() - 600
        rec = ledger.record_custody_transfer(
            sender="depot-a", receiver="depot-b", scope="read_only",
            last_telemetry_at=old, cold_chain_policy_path=p,
        )
        assert rec.parent_agent == "depot-a"

    def test_transfer_gap_recorded_in_capabilities(self, ledger: DelegationLedger) -> None:
        recent = time.time() - 10
        rec = ledger.record_custody_transfer(
            sender="a", receiver="b", scope="read_only",
            last_telemetry_at=recent,
        )
        gap_caps = [c for c in rec.capabilities if c.startswith("cold_chain_gap_s:")]
        assert len(gap_caps) == 1
