"""
Scaling Trust Arena — Iterative Demonstration (Streamlit)
=========================================================

Step-by-step walkthrough of the BuildToValue Track 2 components, exactly as
the ARIA Scaling Trust Arena would evaluate them. Pick a scenario in the
sidebar, click "Capture", then advance through every NegotiationMessage,
guard verdict, and drift check one click at a time.

Run with:
    streamlit run playground/arena_demo.py

No gateway needed — this app uses the real Track 2 components in-process.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from typing import Any

import streamlit as st

from buildtovalue.agentic.demo import (
    SCENARIOS,
    ScenarioOutcome,
    outcome_to_jsonable,
    run_scenario_async,
)
from buildtovalue.agentic.demo.types import Step


# ─── Page config ─────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="BTV Arena — Track 2 Demo",
    page_icon="🏟️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Session state ───────────────────────────────────────────────────────────

if "outcome" not in st.session_state:
    st.session_state.outcome = None  # type: ScenarioOutcome | None
if "cursor" not in st.session_state:
    st.session_state.cursor = 0


# ─── Sidebar — scenario picker ───────────────────────────────────────────────

with st.sidebar:
    st.title("🏟️ Arena demo")
    st.caption("ARIA Scaling Trust — Track 2")
    scenario_id = st.selectbox(
        "Choose a scenario",
        options=list(SCENARIOS),
        format_func=lambda sid: f"{sid}  —  {SCENARIOS[sid]['title']}",
    )
    st.markdown("---")
    if st.button("▶  Capture scenario", type="primary", use_container_width=True):
        with st.spinner("Running negotiation, guard, drift sentinel…"):
            outcome = asyncio.run(run_scenario_async(scenario_id))
        st.session_state.outcome = outcome
        st.session_state.cursor = 0
        st.rerun()

    if st.session_state.outcome:
        st.markdown("---")
        st.caption(f"Captured **{len(st.session_state.outcome.steps)}** steps.")
        if st.button("🗑  Reset", use_container_width=True):
            st.session_state.outcome = None
            st.session_state.cursor = 0
            st.rerun()

        # Download captured outcome as JSON
        payload = json.dumps(
            outcome_to_jsonable(st.session_state.outcome),
            indent=2, default=str,
        )
        st.download_button(
            "⬇  Download outcome (JSON)",
            data=payload,
            file_name=f"arena-{st.session_state.outcome.scenario_id}.json",
            mime="application/json",
            use_container_width=True,
        )


# ─── Helpers — render one step ───────────────────────────────────────────────

_ACTOR_EMOJI: dict[str, str] = {
    "NARRATOR":  "📖",
    "AGENT_A":   "🅰",
    "AGENT_B":   "🅱",
    "DEFENDER":  "🛡",
    "RED_TEAM":  "🦹",
    "PRESSURE":  "🦹",
    "GUARD":     "🛡",
    "SENTINEL":  "🌡",
    "DESIGNER":  "🔐",
    "REPORTER":  "🏁",
}

_KIND_LABEL: dict[str, str] = {
    "intro":           "intro",
    "proposal":        "proposal",
    "counter":         "counter-offer",
    "accept":          "accept / confirm",
    "abort":           "abort",
    "guard_verdict":   "guard verdict",
    "drift_check":     "drift check",
    "protocol_select": "protocol selection",
    "arena_report":    "arena report",
    "leaderboard":     "leaderboard",
}


def _render_step(step: Step) -> None:
    actor_emoji = _ACTOR_EMOJI.get(step.actor, "•")
    st.markdown(
        f"### {actor_emoji} **{step.actor}** — {step.title}"
    )
    st.caption(f"Step kind: `{_KIND_LABEL.get(step.kind, step.kind)}`  ·  "
               f"Arena property: _{step.arena_property}_")
    if step.narration:
        st.markdown(step.narration)

    # Specialised rendering per kind for highest-impact widgets
    if step.kind == "guard_verdict":
        allowed = step.payload.get("allowed")
        if allowed is False:
            st.error(f"🛡  BLOCKED — {step.payload.get('reason', 'no reason')}")
        else:
            st.success("🛡  Allowed")
        with st.expander("Guard explanation"):
            st.code(step.payload.get("explain_decision", ""))
    elif step.kind == "drift_check":
        cols = st.columns(3)
        cols[0].metric("Drift level", step.payload.get("drift_level", "?"))
        cols[1].metric("Action",      step.payload.get("drift_action", "?"))
        cols[2].metric("Round",       step.payload.get("session_id", ""))
    elif step.kind in ("proposal", "counter", "accept", "abort"):
        with st.expander("Negotiation message", expanded=True):
            st.json(step.payload)
    elif step.kind == "protocol_select":
        cols = st.columns(2)
        with cols[0]:
            st.markdown("**Selected protocols**")
            for name in step.payload.get("selected", []):
                st.markdown(f"- ✅  `{name}`")
        with cols[1]:
            st.markdown("**Roadmap (unavailable)**")
            for name in step.payload.get("unavailable", []):
                st.markdown(f"- 🛣  `{name}`")
        if step.payload.get("rationale"):
            st.caption("Requirement → protocol mapping")
            st.json(step.payload["rationale"])
    elif step.kind == "arena_report":
        cols = st.columns(3)
        utility = step.payload.get("utility_score")
        cols[0].metric(
            "Utility", f"{utility:.2f}" if isinstance(utility, (int, float)) else "N/A",
        )
        cols[1].metric("Security",       f"{step.payload['security_score']:.2f}")
        cols[2].metric("Cost (events/s)", f"{step.payload['cost_efficiency']:.1f}")
        st.caption(f"Violations: {step.payload['violations_count']}  ·  "
                   f"Evidence chain length: {step.payload['evidence_chain_length']}")
        with st.expander("Signature & explanation"):
            st.code(step.payload.get("signature", ""))
            st.write(step.payload.get("explanation", ""))
    elif step.kind == "leaderboard":
        rows = step.payload.get("ranked", [])
        if rows:
            st.markdown("**Quarterly snapshot — ranked**")
            st.dataframe(
                [{"#": i + 1, **r} for i, r in enumerate(rows)],
                hide_index=True,
                use_container_width=True,
            )
    elif step.payload:
        with st.expander("Payload"):
            st.json(step.payload)


# ─── Main pane ───────────────────────────────────────────────────────────────

st.title("🏟️  Scaling Trust Arena — Track 2 demo")
st.markdown(
    "Each scenario runs the **real** BTV Track 2 components "
    "(`NegotiationEngine`, `NegotiationGuard`, `GoalDriftSentinel`, "
    "`ProtocolDesigner`, `ArenaReporter`) over an in-process A2A channel. "
    "The capture is deterministic and fully signed."
)

if st.session_state.outcome is None:
    st.info(
        "👈  Pick a scenario in the sidebar and click **Capture**. "
        "Each scenario maps to one ARIA Arena property: cooperative baseline, "
        "red-team adversary, goal-drift pressure, multi-domain generalisation, "
        "or quarterly leaderboard."
    )
    st.markdown("---")
    st.markdown("### Available scenarios")
    for sid, meta in SCENARIOS.items():
        st.markdown(f"- **`{sid}`** — {meta['title']}")
    st.stop()

outcome: ScenarioOutcome = st.session_state.outcome
total = len(outcome.steps)
cursor = max(0, min(st.session_state.cursor, total - 1))

st.markdown(f"## {outcome.scenario_title}")
st.progress((cursor + 1) / total, text=f"Step {cursor + 1} / {total}")

# Navigation buttons
nav_a, nav_b, nav_c, nav_d = st.columns([1, 1, 1, 4])
if nav_a.button("⏮  First", disabled=cursor == 0):
    st.session_state.cursor = 0
    st.rerun()
if nav_b.button("◀  Prev", disabled=cursor == 0):
    st.session_state.cursor = cursor - 1
    st.rerun()
if nav_c.button("Next  ▶", disabled=cursor >= total - 1, type="primary"):
    st.session_state.cursor = cursor + 1
    st.rerun()
nav_d.caption(
    f"Use the buttons to walk one step at a time. "
    f"Total steps captured: {total}."
)

st.markdown("---")
_render_step(outcome.steps[cursor])

# Compact transcript at the bottom for orientation
with st.expander(f"Full transcript ({total} steps)", expanded=False):
    for i, step in enumerate(outcome.steps):
        marker = "👉" if i == cursor else "  "
        st.markdown(
            f"{marker} `{i + 1:>2}.` "
            f"**{step.actor}** · {_KIND_LABEL.get(step.kind, step.kind)} · {step.title}"
        )
