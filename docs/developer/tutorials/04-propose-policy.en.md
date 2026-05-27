---
title: "Tutorial 04 — Propose a Policy (Legislator / Judge)"
---

# Tutorial 04 — Propose a Policy

Tracks: **Legislator** (proposes ADRs and YAML policies) and **Judge**
(calibrates ethical thresholds, rules on contestations).

## As a Legislator

1. Read the [CAP Protocol](../cap-protocol.md).
2. Copy the template:

   ```bash
   cp docs/adr/0000-adr-index.md docs/adr/NNNN-kebab-case-title.md
   ```

3. Fill in the required sections: Context, Decision, Consequences, Invariants
   to verify.
4. Open a PR against `main`. CI runs `scripts/validate_invariants.py` and
   `mkdocs build --strict`.

## As a Judge

1. Identify an ethical threshold in the YAML configuration
   ([ADR-0038](../../adr/0038-ethical-context-engine-v4.md) documents the
   engine).
2. Submit the calibration proposal via PR, **accompanied** by:
   - Ledger evidence that justifies the change.
   - Impact analysis on existing flows
     ([sizing-guide](../compliance/sizing-guide.md)).
3. Contestation cases are evaluated via the `ContestabilityLoop`
   ([concept](../concepts/contestability-loop.md)).

## Golden rule

Every amendment to the constitution (ADR change or threshold) **must**
reference the evidence that motivated it. No trail, no change.
