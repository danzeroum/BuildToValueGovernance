# Negotiation Engine Benchmark Dataset

30 structured YAML scenarios for evaluating `NegotiationEngine` correctness,
adversarial robustness, and edge-case handling.

**ARIA Track 3.4 — Artefacto 2**

---

## Structure

```
benchmarks/negotiation/
├── README.md                      # This file
├── expected_outcomes.yaml         # Ground truth for all 30 scenarios
└── scenarios/
    ├── compatible/                # SC-001–008: should converge (confirmed)
    ├── conflicting/               # SC-009–016: should abort (incompatible_policy)
    ├── adversarial/               # SC-017–024: should abort (jailbreak/goal_drift)
    └── edge_cases/                # SC-025–030: boundary conditions
```

## Scenario Categories

| Category    | IDs        | Count | Expected Outcome       |
|-------------|------------|-------|------------------------|
| compatible  | SC-001–008 | 8     | `confirmed`            |
| conflicting | SC-009–016 | 8     | `aborted` (incompatible_policy) |
| adversarial | SC-017–024 | 8     | `aborted` (jailbreak_blocked or goal_drift) |
| edge_cases  | SC-025–030 | 6     | mixed                  |

## Scenario Schema

```yaml
id: SC-NNN
name: snake_case_name
category: compatible | conflicting | adversarial | edge_cases
description: >
  Human-readable description.

agent_a_policy:
  key: value

agent_b_policy:
  key: value

# Only present for adversarial scenarios:
adversarial_injection:
  target_field: reason | policy.<key>
  vector: base64_obfuscation | yaml_injection | ...
  payload_preview: "..."

# Optional engine config overrides:
engine_config:
  max_rounds: 1          # default: 10
  timeout_seconds: 0.001 # default: 300.0

expected:
  outcome: confirmed | aborted
  max_rounds: N          # upper bound (for confirmed) or max allowed (for aborted)
  shared_policy_must_contain: {...} | null
  abort_reason: null | incompatible_policy | jailbreak_blocked | goal_drift |
                timeout | max_rounds

adversarial_vector: null | base64_obfuscation | yaml_injection | ...
```

## Using as pytest Fixtures

```python
import pytest
import yaml
from pathlib import Path

SCENARIO_DIR = Path(__file__).parent.parent / "benchmarks/negotiation/scenarios"
OUTCOMES_FILE = Path(__file__).parent.parent / "benchmarks/negotiation/expected_outcomes.yaml"

def load_scenarios():
    outcomes = yaml.safe_load(OUTCOMES_FILE.read_text())["outcomes"]
    for yaml_file in sorted(SCENARIO_DIR.rglob("*.yaml")):
        scenario = yaml.safe_load(yaml_file.read_text())
        scenario_id = scenario["id"]
        expected = outcomes[scenario_id]
        yield pytest.param(scenario, expected, id=scenario_id)

@pytest.mark.parametrize("scenario,expected", load_scenarios())
@pytest.mark.asyncio
async def test_scenario(scenario, expected, sentinel, guard, ledger_a, ledger_b):
    engine_cfg = scenario.get("engine_config", {})
    engine_a = NegotiationEngine(
        own_policy=scenario["agent_a_policy"],
        goal_sentinel=sentinel,
        negotiation_guard=guard,
        ledger=ledger_a,
        max_rounds=engine_cfg.get("max_rounds", 10),
        timeout_seconds=engine_cfg.get("timeout_seconds", 5.0),
    )
    engine_b = NegotiationEngine(
        own_policy=scenario["agent_b_policy"],
        goal_sentinel=sentinel,
        negotiation_guard=guard,
        ledger=ledger_b,
        max_rounds=engine_cfg.get("max_rounds", 10),
        timeout_seconds=engine_cfg.get("timeout_seconds", 5.0),
    )
    ch_a, ch_b = make_in_process_pair()
    result_a, result_b = await asyncio.gather(
        engine_a.propose(ch_a),
        engine_b.respond(ch_b),
    )
    assert result_a.status == expected["outcome"]
    if expected["abort_reason"]:
        assert expected["abort_reason"] in (result_a.abort_reason or "")
```

## Adversarial Vectors Covered

| Vector                    | Scenarios       | Guard Layer                      |
|---------------------------|-----------------|----------------------------------|
| `base64_obfuscation`      | SC-017, SC-020  | FFI deobfuscation (Rust kernel)  |
| `yaml_injection`          | SC-018, SC-022  | NegotiationGuard YAML check      |
| `social_engineering`      | SC-019          | PersuasionGuard (regex patterns) |
| `unicode_obfuscation`     | SC-021          | FFI Unicode normalisation        |
| `leetspeak_obfuscation`   | SC-023          | FFI Rust kernel                  |
| `goal_drift_attack`       | SC-024          | GoalDriftSentinel                |

## References

- ADR-056: NegotiationEngine Protocol
- ADR-053: AlignmentDegradationTracker
- ADR-058: ArenaReporter
- ARIA Track 3.4 proposal (2026-Q1)
