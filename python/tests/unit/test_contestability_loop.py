"""Tests ADR-037: ContestabilityLoop — expire_overdue + adjust_trust"""
import time
import pytest
from buildtovalue.governance.contestability_loop import ContestabilityLoop, AppealStatus


@pytest.fixture
def loop(tmp_path):
    return ContestabilityLoop(sla_hours=0, db_path=str(tmp_path / "test.db"))


def submit(loop, user_id="u1") -> str:
    appeal = loop.submit_appeal(
        audit_trail_id=1,
        user_id=user_id,
        reason="test reason with enough characters",
    )
    # Forçar timestamp no passado para garantir overdue
    appeal.timestamp = int(time.time()) - 10
    loop.appeals[appeal.appeal_id] = appeal
    return appeal.appeal_id


def test_expire_overdue_expires_pending(loop):
    appeal_id = submit(loop)
    expired = loop.expire_overdue()
    assert expired >= 1
    assert loop.get_appeal(appeal_id).status == AppealStatus.EXPIRED


def test_expire_overdue_ignores_resolved(tmp_path):
    loop2 = ContestabilityLoop(sla_hours=24, db_path=str(tmp_path / "test2.db"))
    appeal_id = submit(loop2)
    loop2.resolve_appeal(appeal_id, "admin", "accepted", "fp confirmed")
    assert loop2.expire_overdue() == 0


def test_adjust_trust_accepted_appeal(loop):
    appeal_id = submit(loop)
    loop.resolve_appeal(appeal_id, "admin", "accepted", "fp confirmed")

    class FakeTrustStore:
        def __init__(self):
            self.calls = []
        def adjust(self, user_id, delta):
            self.calls.append((user_id, delta))

    ts = FakeTrustStore()
    assert loop.adjust_trust_after_appeal(appeal_id, ts) is True
    assert ts.calls[0] == ("u1", +0.1)


def test_adjust_trust_pending_noop(loop):
    appeal_id = submit(loop)

    class FakeTrustStore:
        def adjust(self, user_id, delta): pass

    assert loop.adjust_trust_after_appeal(appeal_id, FakeTrustStore()) is False
