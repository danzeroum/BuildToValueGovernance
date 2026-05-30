"""Liveness ratchet for governance controls (#185).

This meta-test enforces the governance invariant that every *control* under
`buildtovalue/governance/` is either:

  * PROVEN — has a passing liveness guard in `test_control_activation.py`
    that asserts the control's positive "fired" signal, or
  * ALLOWLISTED — explicitly tolerated, with a reason and a tracking note,
    pending a guard.

A control-bearing module that is in NEITHER set turns CI red on introduction.
This is precisely the failure mode behind #181 Bug 2 (collusion_detected
hardwired False) and #180 (tracker wired to a defunct API): code that
type-checks and passes ordinary tests yet never fires. A liveness guard would
have caught both at PR time.

The ratchet only moves forward: once a control is PROVEN it may not also sit on
the allowlist (so coverage cannot silently regress), and every PROVEN id must
map to a real guard (no stale bookkeeping).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Set

from tests.governance.test_control_activation import (
    FIXTURE_GUARD_IDS,
    GUARDS,
)

# Module stems (file name without .py) under buildtovalue/governance/ that
# define a governance control with a passing liveness guard. Each maps to one
# or more guards in test_control_activation.py.
PROVEN_CONTROLS: Set[str] = {
    "cross_agent_correlator",
    "tool_sanitizer",
    "goal_drift_sentinel",
    "abliteration_detector",
    "bot_detector",
    "chatbot_gates",
    "agent_pdp",
    "agent_budget",
    "contestability",  # contestability/_loop.py — ContestabilityLoop
}

# Controls whose detection logic exists but lacks a positive liveness proof
# today. Tolerated by the ratchet, tracked for burn-down (Sprint 5 follow-ups).
# Removing an entry here REQUIRES adding a guard (the ratchet enforces no
# overlap with PROVEN, so you cannot have both).
ALLOWLIST: Dict[str, str] = {
    "capability_enforcer": "Tier B — guard pending (#185 burn-down)",
    "consensus_validator": "Tier C — timeout/divergent firing not yet proven",
    "content_provenance": "Tier B — guard pending",
    "context_sanitizer": "Tier C — REJECTED level not yet proven",
    "feedback_provenance": "Tier B — guard pending",
    "manifest_hash_verifier": "Tier B — crypto verifier, guard pending",
    "memory_consistency": "Tier B — guard pending",
    "model_integrity_verifier": "Tier B — guard pending",
    "multi_party_kill_switch": "Tier B — guard pending",
    "oracle_trust_gate": "Tier C — recently added, guard pending",
    "output_leakage_detector": "Tier B — guard pending",
    "output_validator": "Tier B — guard pending",
    "persuasion_guard": "Tier B — guard pending",
    "privacy_budget": "Tier B — guard pending",
    "rag_contradiction_detector": "Tier C — new module, guard pending",
    "rag_integrity_verifier": "Tier B — guard pending",
    "safe_expression_evaluator": "Tier B — guard pending",
    "sensitivity_accumulator": "Tier B — guard pending",
    "skill_behavior_monitor": "Tier B — guard pending",
    "tool_call_guard": "Tier B — guard pending",
    "visual_input_firewall": "Tier B — guard pending",
    "visual_reasoning_guard": "Tier B — guard pending",
    "alignment_manifest": "Tier B — crypto verifier, guard pending",
    "policy_hygiene": "Tier B — guard pending",
    "timing_protection": "Tier B — side-channel control, guard pending",
    "liveness_monitor": "Not a detector — agent autonomy heartbeat (excluded)",
}

# Class-name suffixes that mark a module as a governance *control* (detects /
# blocks / flags). Used to DISCOVER controls so new ones cannot be added
# without either a guard or an allowlist entry.
_CONTROL_CLASS_RE = re.compile(
    r"^class \w*("
    r"Detector|Guard|Validator|Gate|Sentinel|Enforcer|Firewall|Monitor|"
    r"Verifier|Sanitizer|Correlator|Accumulator|KillSwitch|Limiter"
    r")\b",
    re.MULTILINE,
)

_GOVERNANCE_DIR = (
    Path(__file__).resolve().parents[2]
    / "buildtovalue"
    / "governance"
)


def _discover_control_modules() -> Set[str]:
    """Return governance module stems that define a control-bearing class."""
    found: Set[str] = set()
    for path in _GOVERNANCE_DIR.glob("*.py"):
        if path.name.startswith("_") or path.name == "__init__.py":
            continue
        text = path.read_text(encoding="utf-8")
        if _CONTROL_CLASS_RE.search(text):
            found.add(path.stem)
    return found


def test_proven_controls_have_guards() -> None:
    """Every PROVEN control id must map to a real guard (no stale entries)."""
    guard_modules = {g.control_id for g in GUARDS} | FIXTURE_GUARD_IDS
    # Map guard ids back to module stems (drop the scan suffix variant).
    covered_stems = {
        gid.replace("_scan", "") for gid in guard_modules
    }
    # contestability_loop guard -> contestability package stem
    covered_stems = {
        "contestability" if s == "contestability_loop" else s
        for s in covered_stems
    }
    missing = PROVEN_CONTROLS - covered_stems
    assert not missing, (
        f"PROVEN_CONTROLS without a passing guard: {sorted(missing)}. "
        "Add a guard in test_control_activation.py or remove from PROVEN_CONTROLS."
    )


def test_proven_and_allowlist_are_disjoint() -> None:
    """A control cannot be both proven and tolerated — ratchet moves forward."""
    overlap = PROVEN_CONTROLS & set(ALLOWLIST)
    assert not overlap, (
        f"Controls both PROVEN and ALLOWLISTED: {sorted(overlap)}. "
        "Once a control has a liveness guard, remove it from the allowlist."
    )


def test_no_unaccounted_control_module() -> None:
    """Every discovered control module must be PROVEN or ALLOWLISTED.

    This is the tripwire: a newly added governance control with no liveness
    guard (and not deliberately allowlisted) fails CI here — the #181 Bug 2
    class of defect cannot land silently.
    """
    inventory = PROVEN_CONTROLS | set(ALLOWLIST)
    discovered = _discover_control_modules()
    unaccounted = discovered - inventory
    assert not unaccounted, (
        "Governance control module(s) with no liveness proof and not "
        f"allowlisted: {sorted(unaccounted)}. Add a guard in "
        "test_control_activation.py (preferred) or, if intentionally "
        "deferred, add an ALLOWLIST entry with a tracking reason."
    )


def test_allowlist_entries_are_real_modules() -> None:
    """Allowlist must not rot: every entry must still exist on disk."""
    stems = {p.stem for p in _GOVERNANCE_DIR.glob("*.py")}
    stems |= {
        d.name for d in _GOVERNANCE_DIR.iterdir() if d.is_dir()
    }
    stale = set(ALLOWLIST) - stems - PROVEN_CONTROLS
    assert not stale, (
        f"ALLOWLIST references non-existent modules: {sorted(stale)}. "
        "Remove stale entries."
    )
