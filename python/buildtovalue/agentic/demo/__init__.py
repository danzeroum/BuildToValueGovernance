"""Iterative Arena demonstration — capture-then-replay engine.

Public surface:
    Step                   — one narratable event
    ScenarioOutcome        — full ordered transcript + ArenaReport
    SCENARIOS              — registry: id → {title, runner}
    run_scenario(id)       — sync wrapper, returns ScenarioOutcome
    run_scenario_async(id) — async version
    outcome_to_jsonable    — ScenarioOutcome → JSON-serialisable dict
"""
from .runner import outcome_to_jsonable, run_scenario, run_scenario_async
from .scenarios import SCENARIOS
from .types import ScenarioOutcome, Step

__all__ = [
    "Step",
    "ScenarioOutcome",
    "SCENARIOS",
    "run_scenario",
    "run_scenario_async",
    "outcome_to_jsonable",
]
