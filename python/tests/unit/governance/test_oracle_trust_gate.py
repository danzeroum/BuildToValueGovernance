"""Tests for OracleTrustGate — Scenario C34: P2P Contamination."""
from __future__ import annotations

import hashlib
import hmac as hmac_lib
import json
from datetime import datetime, timedelta, timezone

import pytest

from buildtovalue.governance.durable_ledger import DurableLedger
from buildtovalue.governance.oracle_trust_gate import (
    OracleEntry,
    OracleRegistry,
    OracleTrustGate,
    OracleVerdict,
)


# ------------------------------------------------------------------ #
# Helpers                                                             #
# ------------------------------------------------------------------ #

def _make_ledger() -> DurableLedger:
    return DurableLedger(hmac_key=b"test-key")


def _make_registry(oracle_id: str = "bacen_api_v1", key: bytes = b"secret") -> OracleRegistry:
    reg = OracleRegistry()
    reg.register(OracleEntry(
        oracle_id=oracle_id,
        hmac_key=key,
        valid_until=datetime.now(timezone.utc) + timedelta(days=365),
    ))
    return reg


def _sign_payload(payload: dict, key: bytes) -> dict:
    """Return payload dict with hmac_signature added."""
    canonical = json.dumps(payload, sort_keys=True).encode()
    sig = hmac_lib.new(key, canonical, hashlib.sha256).hexdigest()
    return {**payload, "hmac_signature": sig}


# ------------------------------------------------------------------ #
# TestOracleEntry                                                     #
# ------------------------------------------------------------------ #

class TestOracleEntry:
    def test_valid_entry_is_valid(self) -> None:
        entry = OracleEntry(
            oracle_id="test",
            hmac_key=b"key",
            valid_until=datetime.now(timezone.utc) + timedelta(days=30),
        )
        assert entry.is_valid()

    def test_revoked_entry_is_invalid(self) -> None:
        entry = OracleEntry(
            oracle_id="test",
            hmac_key=b"key",
            valid_until=datetime.now(timezone.utc) + timedelta(days=30),
            revoked=True,
        )
        assert not entry.is_valid()

    def test_expired_entry_is_invalid(self) -> None:
        entry = OracleEntry(
            oracle_id="test",
            hmac_key=b"key",
            valid_until=datetime.now(timezone.utc) - timedelta(days=1),
        )
        assert not entry.is_valid()


# ------------------------------------------------------------------ #
# TestOracleRegistry                                                  #
# ------------------------------------------------------------------ #

class TestOracleRegistry:
    def test_register_and_get(self) -> None:
        reg = _make_registry("oracle-1", b"key1")
        entry = reg.get("oracle-1")
        assert entry is not None
        assert entry.oracle_id == "oracle-1"

    def test_get_unknown_returns_none(self) -> None:
        reg = OracleRegistry()
        assert reg.get("nonexistent") is None

    def test_revoke_marks_as_revoked(self) -> None:
        reg = _make_registry("oracle-1", b"key1")
        ledger = _make_ledger()
        reg.revoke("oracle-1", ledger)
        entry = reg.get("oracle-1")
        assert entry is not None
        assert entry.revoked is True

    def test_revoke_unknown_is_idempotent(self) -> None:
        reg = OracleRegistry()
        ledger = _make_ledger()
        # Should not raise
        reg.revoke("nonexistent", ledger)

    def test_revoke_writes_to_ledger(self) -> None:
        reg = _make_registry("oracle-1", b"key1")
        ledger = _make_ledger()
        reg.revoke("oracle-1", ledger)
        entries = ledger.entries()
        revocation_entries = [
            e for e in entries
            if e.payload.get("type") == "oracle_revocation"
        ]
        assert len(revocation_entries) == 1
        assert revocation_entries[0].payload["oracle_id"] == "oracle-1"


# ------------------------------------------------------------------ #
# TestVerifyAndRecord — SIM-1 + SIM-2                                 #
# ------------------------------------------------------------------ #

class TestVerifyAndRecord:
    def test_valid_hmac_verified(self) -> None:
        key = b"bacen-secret-key"
        reg = _make_registry("bacen_api_v1", key)
        gate = OracleTrustGate(reg)
        ledger = _make_ledger()

        payload = {"solvente": True, "confidence": 0.99}
        response = _sign_payload(payload, key)

        verdict = gate.verify_and_record("banco_y", "bacen_api_v1", response, key, ledger)
        assert verdict.verified is True
        assert verdict.confidence == 0.99

    def test_invalid_hmac_unverified(self) -> None:
        key = b"bacen-secret-key"
        reg = _make_registry("bacen_api_v1", key)
        gate = OracleTrustGate(reg)
        ledger = _make_ledger()

        response = {"solvente": True, "confidence": 0.99, "hmac_signature": "bad_sig"}
        verdict = gate.verify_and_record("banco_y", "bacen_api_v1", response, key, ledger)
        assert verdict.verified is False

    def test_missing_hmac_unverified(self) -> None:
        key = b"bacen-secret-key"
        reg = _make_registry("bacen_api_v1", key)
        gate = OracleTrustGate(reg)
        ledger = _make_ledger()

        response = {"solvente": True, "confidence": 0.99}  # no hmac_signature
        verdict = gate.verify_and_record("banco_y", "bacen_api_v1", response, key, ledger)
        assert verdict.verified is False

    def test_revoked_oracle_unverified(self) -> None:
        key = b"bacen-key"
        reg = _make_registry("bacen_api_v1", key)
        ledger = _make_ledger()
        reg.revoke("bacen_api_v1", ledger)

        gate = OracleTrustGate(reg)
        payload = {"solvente": True, "confidence": 0.99}
        response = _sign_payload(payload, key)
        verdict = gate.verify_and_record("banco_y", "bacen_api_v1", response, key, ledger)
        assert verdict.verified is False

    def test_expired_oracle_unverified(self) -> None:
        reg = OracleRegistry()
        reg.register(OracleEntry(
            oracle_id="expired_oracle",
            hmac_key=b"key",
            valid_until=datetime.now(timezone.utc) - timedelta(days=1),
        ))
        gate = OracleTrustGate(reg)
        ledger = _make_ledger()

        payload = {"data": "test", "confidence": 0.5}
        response = _sign_payload(payload, b"key")
        verdict = gate.verify_and_record("claim", "expired_oracle", response, b"key", ledger)
        assert verdict.verified is False

    def test_unknown_oracle_unverified(self) -> None:
        reg = OracleRegistry()
        gate = OracleTrustGate(reg)
        ledger = _make_ledger()

        response = {"data": "test", "hmac_signature": "abc"}
        verdict = gate.verify_and_record("claim", "unknown_oracle", response, b"key", ledger)
        assert verdict.verified is False

    def test_verified_claim_written_to_ledger(self) -> None:
        key = b"bacen-key"
        reg = _make_registry("bacen_api_v1", key)
        gate = OracleTrustGate(reg)
        ledger = _make_ledger()

        payload = {"solvente": True, "confidence": 0.99}
        response = _sign_payload(payload, key)
        gate.verify_and_record("banco_y", "bacen_api_v1", response, key, ledger)

        verification_entries = [
            e for e in ledger.entries()
            if e.payload.get("type") == "oracle_verification"
        ]
        assert len(verification_entries) == 1
        assert verification_entries[0].payload["verified"] is True

    def test_unverified_claim_not_in_ledger(self) -> None:
        key = b"bacen-key"
        reg = _make_registry("bacen_api_v1", key)
        gate = OracleTrustGate(reg)
        ledger = _make_ledger()

        response = {"solvente": True, "confidence": 0.99, "hmac_signature": "bad"}
        gate.verify_and_record("banco_y", "bacen_api_v1", response, key, ledger)

        verification_entries = [
            e for e in ledger.entries()
            if e.payload.get("type") == "oracle_verification"
        ]
        assert len(verification_entries) == 0

    def test_fail_secure_on_exception(self) -> None:
        """Force error by passing invalid types — should not raise, return verified=False."""
        reg = _make_registry("oracle", b"key")
        gate = OracleTrustGate(reg)
        ledger = _make_ledger()

        # Pass None as response to force an error
        verdict = gate.verify_and_record("claim", "oracle", None, b"key", ledger)  # type: ignore[arg-type]
        assert verdict.verified is False


# ------------------------------------------------------------------ #
# TestIsActionBlocked — SIM-2 + SIM-4                                 #
# ------------------------------------------------------------------ #

class TestIsActionBlocked:
    def test_peer_agent_irreversible_no_oracle_blocked(self) -> None:
        gate = OracleTrustGate(OracleRegistry())
        blocked, reason = gate.is_action_blocked("peer_agent", "Irreversible", None)
        assert blocked is True

    def test_peer_agent_irreversible_unverified_oracle_blocked(self) -> None:
        gate = OracleTrustGate(OracleRegistry())
        verdict = OracleVerdict(
            claim="test", verified=False, oracle_id="test",
            confidence=0.0, hmac_signature="", explain_decision="unverified",
        )
        blocked, _ = gate.is_action_blocked("peer_agent", "Irreversible", verdict)
        assert blocked is True

    def test_peer_agent_irreversible_verified_oracle_allowed(self) -> None:
        gate = OracleTrustGate(OracleRegistry())
        verdict = OracleVerdict(
            claim="test", verified=True, oracle_id="test",
            confidence=0.99, hmac_signature="sig", explain_decision="verified",
        )
        blocked, _ = gate.is_action_blocked("peer_agent", "Irreversible", verdict)
        assert blocked is False

    def test_user_direct_irreversible_no_oracle_allowed(self) -> None:
        gate = OracleTrustGate(OracleRegistry())
        blocked, _ = gate.is_action_blocked("user_direct", "Irreversible", None)
        assert blocked is False

    def test_agent_broadcast_financial_transfer_blocked(self) -> None:
        gate = OracleTrustGate(OracleRegistry())
        blocked, _ = gate.is_action_blocked("agent_broadcast", "financial_transfer", None)
        assert blocked is True

    def test_social_consensus_financial_transfer_blocked(self) -> None:
        gate = OracleTrustGate(OracleRegistry())
        blocked, _ = gate.is_action_blocked("social_consensus", "financial_transfer", None)
        assert blocked is True

    def test_peer_agent_safe_action_allowed(self) -> None:
        gate = OracleTrustGate(OracleRegistry())
        blocked, _ = gate.is_action_blocked("peer_agent", "Safe", None)
        assert blocked is False


# ------------------------------------------------------------------ #
# TestOracleExplainDecision                                           #
# ------------------------------------------------------------------ #

class TestOracleExplainDecision:
    def test_verified_verdict_has_explain(self) -> None:
        key = b"key"
        reg = _make_registry("oracle", key)
        gate = OracleTrustGate(reg)
        ledger = _make_ledger()

        payload = {"data": "test", "confidence": 0.5}
        response = _sign_payload(payload, key)
        verdict = gate.verify_and_record("claim", "oracle", response, key, ledger)
        assert verdict.explain_decision

    def test_unverified_verdict_has_explain(self) -> None:
        reg = OracleRegistry()
        gate = OracleTrustGate(reg)
        ledger = _make_ledger()

        verdict = gate.verify_and_record("claim", "unknown", {}, b"key", ledger)
        assert verdict.explain_decision

    def test_error_verdict_has_explain(self) -> None:
        reg = _make_registry("oracle", b"key")
        gate = OracleTrustGate(reg)
        ledger = _make_ledger()

        verdict = gate.verify_and_record("claim", "oracle", None, b"key", ledger)  # type: ignore[arg-type]
        assert verdict.explain_decision
