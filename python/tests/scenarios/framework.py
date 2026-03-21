"""Scenario Simulation Framework — 5-dimension attack testing.

Each scenario tests a governance module through 5 simulation dimensions:
  SIM-1: Legitimate use (happy path)
  SIM-2: Direct attack
  SIM-3: Obfuscated / evasion attack
  SIM-4: Edge case / boundary
  SIM-5: Cascade failure / fail-secure
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass(frozen=True)
class ScenarioSim:
    """A single simulation within a scenario."""
    sim_id: str              # e.g. "C32-SIM-1"
    scenario: str            # e.g. "C32"
    dimension: str           # "legitimate" | "direct_attack" | "obfuscated" | "edge_case" | "cascade"
    input_data: Dict[str, Any]
    expected_verdict: str    # "ALLOW" | "BLOCK" | "PENDING_APPROVAL"
    description: str


@dataclass
class ScenarioResult:
    """Result of running a single simulation."""
    sim_id: str
    passed: bool
    actual_verdict: str
    expected_verdict: str
    explain: str
    latency_ms: float


SIM_DIMENSIONS = [
    "legitimate",
    "direct_attack",
    "obfuscated",
    "edge_case",
    "cascade",
]


def build_5_sims(
    scenario_id: str,
    sim_configs: List[Dict[str, Any]],
) -> List[ScenarioSim]:
    """Factory that creates 5 ScenarioSim instances from config dicts.

    Each config dict should have keys: dimension, input_data, expected_verdict, description.
    """
    sims = []
    for i, config in enumerate(sim_configs, start=1):
        sims.append(ScenarioSim(
            sim_id=f"{scenario_id}-SIM-{i}",
            scenario=scenario_id,
            dimension=config["dimension"],
            input_data=config["input_data"],
            expected_verdict=config["expected_verdict"],
            description=config["description"],
        ))
    return sims


def run_scenario(
    sim: ScenarioSim,
    gate_func: Callable[[Dict[str, Any]], str],
) -> ScenarioResult:
    """Execute a gate function and compare to expected verdict."""
    start = time.monotonic()
    try:
        actual = gate_func(sim.input_data)
    except Exception as exc:
        actual = "ERROR"
        explain = str(exc)
        elapsed = (time.monotonic() - start) * 1000
        return ScenarioResult(
            sim_id=sim.sim_id,
            passed=False,
            actual_verdict=actual,
            expected_verdict=sim.expected_verdict,
            explain=explain,
            latency_ms=elapsed,
        )

    elapsed = (time.monotonic() - start) * 1000
    passed = actual == sim.expected_verdict
    return ScenarioResult(
        sim_id=sim.sim_id,
        passed=passed,
        actual_verdict=actual,
        expected_verdict=sim.expected_verdict,
        explain=f"{'PASS' if passed else 'FAIL'}: expected={sim.expected_verdict}, got={actual}",
        latency_ms=elapsed,
    )
