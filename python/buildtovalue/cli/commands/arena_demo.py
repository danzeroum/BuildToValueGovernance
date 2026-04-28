"""
CLI: btv arena-demo — iterative walkthrough of the Scaling Trust Arena.

Each scenario walks through every NegotiationMessage, guard verdict, and
drift check one step at a time. Press Enter to advance, or pass --auto to
run without pauses (useful in CI).

Examples:
    btv arena-demo --scenario cooperative
    btv arena-demo --scenario red_team --json /tmp/arena.json
    btv arena-demo --scenario all --auto
"""
from __future__ import annotations

import json
from pathlib import Path

import click

from buildtovalue.agentic.demo import (
    SCENARIOS,
    outcome_to_jsonable,
    run_scenario,
)
from buildtovalue.agentic.demo.types import Step


# Color per actor — keeps the transcript scannable in a terminal.
_ACTOR_COLORS: dict[str, str] = {
    "NARRATOR":  "cyan",
    "AGENT_A":   "green",
    "AGENT_B":   "blue",
    "DEFENDER":  "green",
    "RED_TEAM":  "red",
    "PRESSURE":  "red",
    "GUARD":     "yellow",
    "SENTINEL":  "magenta",
    "DESIGNER":  "white",
    "REPORTER":  "bright_white",
}

_KIND_BADGES: dict[str, str] = {
    "intro":           "📖",
    "proposal":        "📨",
    "counter":         "🔁",
    "accept":          "✅",
    "abort":           "⛔",
    "guard_verdict":   "🛡️ ",
    "drift_check":     "🌡️ ",
    "protocol_select": "🔐",
    "arena_report":    "🏁",
    "leaderboard":     "🏆",
}


def _render_step(step: Step, idx: int, total: int, use_color: bool) -> None:
    color = _ACTOR_COLORS.get(step.actor, "white")
    badge = _KIND_BADGES.get(step.kind, "•")
    header = f"[{idx + 1}/{total}] {badge}  {step.actor}  ·  {step.title}"
    click.echo()
    click.echo(click.style(header, fg=color, bold=True) if use_color else header)
    click.echo("─" * min(len(header), 78))
    if step.narration:
        click.echo(step.narration)
    if step.arena_property:
        line = f"  ↳ Arena property: {step.arena_property}"
        click.echo(click.style(line, fg="bright_black") if use_color else line)
    # Render payload compactly — full dict is in --json export.
    if step.payload:
        compact = {
            k: v for k, v in step.payload.items()
            if k not in ("explanation",) and v is not None
        }
        if compact:
            click.echo("  payload:")
            for k, v in compact.items():
                click.echo(f"    {k}: {v}")


def _walk_outcome(outcome, auto: bool, use_color: bool) -> None:
    total = len(outcome.steps)
    click.echo()
    click.secho(
        f"═══ {outcome.scenario_title} ═══",
        fg="bright_cyan", bold=True,
    ) if use_color else click.echo(f"=== {outcome.scenario_title} ===")
    for idx, step in enumerate(outcome.steps):
        _render_step(step, idx, total, use_color)
        if not auto and idx < total - 1:
            click.pause(info="\n  ↵ Press Enter for next step…")


@click.command("arena-demo")
@click.option(
    "--scenario", "-s",
    type=click.Choice(list(SCENARIOS) + ["all"]),
    default="cooperative", show_default=True,
    help="Scenario to walk through (or 'all' for the full suite).",
)
@click.option(
    "--auto", is_flag=True,
    help="Do not pause between steps (CI / smoke-test mode).",
)
@click.option(
    "--json", "json_path", type=click.Path(),
    help="Export the full ScenarioOutcome to this path as JSON.",
)
@click.option(
    "--no-color", is_flag=True,
    help="Disable ANSI colors (useful for log capture).",
)
def arena_demo_cmd(scenario: str, auto: bool, json_path: str | None, no_color: bool) -> None:
    """Iterative walkthrough of the Scaling Trust Arena (Track 2)."""
    use_color = not no_color
    scenarios_to_run = list(SCENARIOS) if scenario == "all" else [scenario]
    all_outcomes = []

    for sid in scenarios_to_run:
        outcome = run_scenario(sid)
        all_outcomes.append(outcome)
        _walk_outcome(outcome, auto=auto, use_color=use_color)

    if json_path:
        path = Path(json_path)
        payload = (
            outcome_to_jsonable(all_outcomes[0])
            if len(all_outcomes) == 1
            else [outcome_to_jsonable(o) for o in all_outcomes]
        )
        path.write_text(json.dumps(payload, indent=2, default=str))
        click.echo()
        click.secho(f"📝 Outcome written to {path}", fg="green") \
            if use_color else click.echo(f"Outcome written to {path}")
