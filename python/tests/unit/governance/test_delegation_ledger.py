"""Tests for DelegationLedger — Gap B."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from buildtovalue.governance.delegation_ledger import (
    DelegationLedger,
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
    return DelegationLedger(policy_path=policy_path)


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


class TestNoPolicy:
    def test_default_ledger(self) -> None:
        dl = DelegationLedger()
        rec = dl.record_delegation("a", "b", "read_only")
        assert rec.parent_agent == "a"
