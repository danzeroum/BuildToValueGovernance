"""
Tests for the iterative Arena demo engine (capture phase).

These tests are the smoke test that the same scenarios used by
test_arena_simulation.py also produce a clean step transcript and a
JSON-serialisable outcome that the CLI/Streamlit replay can consume.
"""
from __future__ import annotations

import json

import pytest

from buildtovalue.agentic.demo import (
    SCENARIOS,
    ScenarioOutcome,
    Step,
    outcome_to_jsonable,
    run_scenario_async,
)


# ─── Smoke: every registered scenario captures cleanly ───────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("scenario_id", list(SCENARIOS))
async def test_every_scenario_captures_outcome(scenario_id: str):
    outcome = await run_scenario_async(scenario_id)
    assert isinstance(outcome, ScenarioOutcome)
    assert outcome.scenario_id == scenario_id
    assert len(outcome.steps) >= 2  # at least intro + something
    # First step is always the narrator intro
    assert outcome.steps[0].kind == "intro"
    assert outcome.steps[0].actor == "NARRATOR"


# ─── Cooperative: high security expected ─────────────────────────────────────

@pytest.mark.asyncio
async def test_cooperative_scenario_high_security():
    outcome = await run_scenario_async("cooperative")
    assert outcome.arena_report is not None
    assert outcome.arena_report.security_score == 1.0
    assert outcome.arena_report.utility_score == 1.0
    # At least one channel transcript step + protocol_select + arena_report
    kinds = {s.kind for s in outcome.steps}
    assert "proposal" in kinds
    assert "protocol_select" in kinds
    assert "arena_report" in kinds


# ─── Red team: guard MUST emit a BLOCK verdict before the abort ──────────────

@pytest.mark.asyncio
async def test_red_team_scenario_emits_guard_block_before_abort():
    outcome = await run_scenario_async("red_team")
    block_steps = [
        s for s in outcome.steps
        if s.kind == "guard_verdict" and s.payload.get("allowed") is False
    ]
    assert len(block_steps) >= 1, "Guard must emit at least one BLOCK verdict"

    # The BLOCK must precede the engine's final abort step in the transcript.
    abort_steps = [s for s in outcome.steps if s.kind == "abort"]
    if abort_steps:
        first_block_idx = outcome.steps.index(block_steps[0])
        first_abort_idx = outcome.steps.index(abort_steps[0])
        assert first_block_idx < first_abort_idx

    # Arena report reflects the failure: utility=0, security<1.
    assert outcome.arena_report is not None
    assert outcome.arena_report.utility_score == 0.0
    assert outcome.arena_report.security_score < 1.0


# ─── Drift: sentinel must emit a Critical/High drift_check ───────────────────

@pytest.mark.asyncio
async def test_drift_scenario_emits_critical_drift_check():
    outcome = await run_scenario_async("drift")
    drift_steps = [s for s in outcome.steps if s.kind == "drift_check"]
    assert len(drift_steps) >= 1
    # At least one drift check at High or Critical level
    severities = {s.payload.get("drift_level") for s in drift_steps}
    assert severities & {"High", "Critical"}, severities


# ─── Generalisation: all three domains run in one outcome ────────────────────

@pytest.mark.asyncio
async def test_generalisation_runs_three_domains():
    outcome = await run_scenario_async("generalisation")
    domain_intros = [
        s for s in outcome.steps
        if s.kind == "intro" and "domain" in s.payload
    ]
    domains_seen = {s.payload["domain"] for s in domain_intros}
    assert domains_seen == {"healthcare", "finance", "security"}


# ─── Leaderboard: cooperative ranks first ────────────────────────────────────

@pytest.mark.asyncio
async def test_leaderboard_ranks_cooperative_first():
    outcome = await run_scenario_async("leaderboard")
    final = [s for s in outcome.steps if s.kind == "leaderboard"]
    assert len(final) == 1
    ranked = final[0].payload["ranked"]
    assert len(ranked) == 3
    assert ranked[0]["scenario_id"] == "cooperative"


# ─── Outcome is JSON serialisable (CLI --json + Streamlit download) ──────────

@pytest.mark.asyncio
async def test_outcome_is_json_serialisable():
    outcome = await run_scenario_async("cooperative")
    payload = outcome_to_jsonable(outcome)
    # Round-trip through json — must not raise
    text = json.dumps(payload)
    decoded = json.loads(text)
    assert decoded["scenario_id"] == "cooperative"
    assert isinstance(decoded["steps"], list)
    assert decoded["steps"][0]["kind"] == "intro"
