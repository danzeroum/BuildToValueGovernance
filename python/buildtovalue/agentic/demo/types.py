"""
Demo types — shared dataclasses for the iterative Arena demonstration.

A `Step` is one atomic, narratable event that the user advances through (in
Streamlit by clicking "Next", in CLI by pressing Enter). A `ScenarioOutcome`
is the full ordered transcript of a scenario plus its final ArenaReport.

Both dataclasses are frozen and use only JSON-serialisable primitives in
`payload`, so the entire outcome can be exported via `dataclasses.asdict()`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Optional

from buildtovalue.agentic.arena_reporter import ArenaReport


StepKind = Literal[
    "intro",            # scenario header / Arena property being exercised
    "proposal",         # NegotiationMessage type=propose
    "counter",          # NegotiationMessage type=counter
    "accept",           # NegotiationMessage type=accept|confirm
    "abort",            # NegotiationMessage type=abort or engine abort
    "guard_verdict",    # NegotiationGuard.sanitize result
    "drift_check",      # GoalDriftSentinel report
    "protocol_select",  # ProtocolDesigner.select result
    "arena_report",     # ArenaReporter.generate_report result
    "leaderboard",      # final ranking across multiple matches
]


@dataclass(frozen=True)
class Step:
    """One narratable event in a scenario walkthrough."""
    kind: StepKind
    actor: str               # AGENT_A | AGENT_B | RED_TEAM | GUARD | SENTINEL | DESIGNER | REPORTER | NARRATOR
    title: str               # short headline
    narration: str           # didactic explanation of what just happened
    payload: dict[str, Any]  # JSON-serialisable structured data
    arena_property: str      # which ARIA Arena requirement this step exercises


@dataclass(frozen=True)
class ScenarioOutcome:
    """Capture of one scenario run — replayed by the UI at the user's pace."""
    scenario_id: str
    scenario_title: str
    steps: tuple[Step, ...]
    arena_report: Optional[ArenaReport]  # None for aggregate scenarios (leaderboard)
