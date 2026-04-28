"""
Runner — single async entry point used by the CLI and Streamlit demos.

Each call captures one scenario into a `ScenarioOutcome` (deterministic,
serialisable). The UI then replays the outcome at the user's pace.
"""
from __future__ import annotations

import asyncio
from dataclasses import asdict
from typing import Any

from .scenarios import SCENARIOS
from .types import ScenarioOutcome


async def run_scenario_async(scenario_id: str) -> ScenarioOutcome:
    if scenario_id not in SCENARIOS:
        raise KeyError(
            f"Unknown scenario '{scenario_id}'. "
            f"Known: {sorted(SCENARIOS)}."
        )
    return await SCENARIOS[scenario_id]["runner"]()


def run_scenario(scenario_id: str) -> ScenarioOutcome:
    """Synchronous wrapper — convenient for Streamlit and CLI."""
    return asyncio.run(run_scenario_async(scenario_id))


def outcome_to_jsonable(outcome: ScenarioOutcome) -> dict[str, Any]:
    """Convert ScenarioOutcome to a fully JSON-serialisable dict.

    `dataclasses.asdict` already flattens our frozen dataclasses; we just need
    to coerce the leaf `evidence_chain` tuple and any tuple/frozenset payloads
    into lists.
    """
    def _coerce(value: Any) -> Any:
        if isinstance(value, (tuple, frozenset, set)):
            return [_coerce(v) for v in value]
        if isinstance(value, dict):
            return {k: _coerce(v) for k, v in value.items()}
        if isinstance(value, list):
            return [_coerce(v) for v in value]
        return value

    raw = asdict(outcome)
    return _coerce(raw)
