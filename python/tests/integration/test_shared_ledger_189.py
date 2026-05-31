"""Integration test for #189 (ADR-0098 Opção C): shared in-process DurableLedger.

Locks in the behaviour wired by Steps 1-2:

- `app.state.durable_ledger` exists and is a `DurableLedger` (lifecycle readiness).
- The #182 seam is live: `CrossAgentCorrelator`'s degradation tracker writes to
  the SAME shared instance (regression guard — this seam was dead in main).
- A correlator degradation record is retrievable via `entries()` and the chain
  still passes `verify()`.
- Segregation (Opção C): `/v1/ledger/*` still serves the canonical Rust
  `decisions.jsonl`, NOT the in-process ledger — ledgers disjuntos, sem fusão.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import buildtovalue.api.app as app_module
from buildtovalue.governance.durable_ledger import DurableLedger

HEADERS = {"X-API-Key": "demo-key"}


@pytest.fixture()
def client():
    with TestClient(app_module.app) as c:
        yield c


def test_correlator_shares_in_process_ledger_and_is_verifiable(client) -> None:
    app = app_module.app

    dl = getattr(app.state, "durable_ledger", None)
    assert isinstance(dl, DurableLedger), "lifespan must create app.state.durable_ledger (#189 Step 1)"
    assert dl.verify().valid, "fresh shared ledger must verify clean"

    # #182 seam live: the correlator's degradation tracker holds the SAME instance.
    tracker = app.state.cross_agent._degradation_tracker
    assert tracker._ledger is dl, "correlator must share app.state.durable_ledger (#182 seam, #189 Step 2)"

    # A correlator degradation record lands in the shared ledger.
    before = len(dl)
    tracker.record_session(
        agent_id="agent-189",
        session_id="sess-1",
        is_collaborative=False,
        abort_reason="goal_drift",
        drift_score=0.91,
    )
    assert len(dl) == before + 1, "degradation record must append to the shared ledger"

    # Retrievable via entries() and the hash-chain still verifies.
    assert any(
        e.payload.get("event") == "alignment_degradation_tracker.record_session"
        and e.payload.get("agent_id") == "agent-189"
        for e in dl.entries()
    ), "degradation record must be retrievable via entries()"
    assert dl.verify().valid, "shared ledger must still verify after append"


def test_v1_ledger_reads_canonical_rust_ledger_not_in_process(client) -> None:
    """Opção C: /v1/ledger/* serves decisions.jsonl (Rust, canônico), não o
    DurableLedger in-process — disjuntos por design, ligação por hash, sem fusão."""
    r = client.get("/v1/ledger/stats", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["ledger_file"].endswith("decisions.jsonl"), r.json()
