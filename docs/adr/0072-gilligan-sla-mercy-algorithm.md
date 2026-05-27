# ADR-072 — Gilligan SLA Mercy Algorithm (S1–S6)

**Status:** Accepted
**Date:** 2026-05-27
**Supersedes:** none
**Related:** ADR-003 (Mercy Algorithm), ADR-017 (ContestabilityLoop), ADR-047 (Structured Mediation Protocol)

## Context

The Compliance Dashboard (Painel 2 of the Governance Console) must surface
appeals approaching their 24h SLA deadline. A plain countdown is insufficient
— the Ethics of Care (Gilligan) requires that the urgency signal *itself* be
graded by remaining capacity for human response and by the nature of the
underlying violation.

Without this ADR, the Dashboard would implement an ad-hoc threshold table
inside JavaScript, drifting silently from the canonical ADR-003 mercy
philosophy. R14 of the Developer Portal risk register tracks this exact
gap.

## Decision

Each `appeal_pending` is classified into one of six scenarios **S1–S6**
based on remaining time to the SLA deadline and (optionally) appeal
severity. The mapping is canonical:

| Scenario | Remaining time | UI signal | System action |
| --- | --- | --- | --- |
| **S1** | > 18h | Green | None (informational only) |
| **S2** | 12h – 18h | Yellow | Passive notification to reviewer queue |
| **S3** | 6h – 12h | Orange | Active alert on Dashboard |
| **S4** | 2h – 6h | Red | Intervention recommended; pager on-call |
| **S5** | < 2h | Critical red | Auto-escalation per `data/policies/webhooks.yaml` |
| **S6** | Expired (≤ 0h) | Block | SLA-breach evidence recorded in ledger; appeal status → `expired` |

The scenarios derive from Gilligan's principle that **rigidity without
mercy is cruelty**: as the window closes, the system invests progressively
more attention — not because the rules changed, but because the available
care narrows.

### Algorithm (canonical)

```python
def gilligan_sla_scenario(deadline_utc, now_utc):
    remaining = (deadline_utc - now_utc).total_seconds() / 3600.0
    if remaining <= 0: return "S6"
    if remaining < 2:  return "S5"
    if remaining < 6:  return "S4"
    if remaining < 12: return "S3"
    if remaining < 18: return "S2"
    return "S1"
```

Severity (`appeal.severity`) may **shift the scenario up by one level**
(e.g. an S3 appeal touching `hard_blocked=True` becomes S4) but never
**down** — mercy never relaxes urgency, only adds it.

### Invariants

1. **S6 is terminal.** Once an appeal hits S6, the ledger entry is
   immutable; the system never re-opens it without a fresh evidence
   record citing this S6 entry as cause.
2. **Auto-escalation in S5 must go through `ContestabilityLoop`**
   (ADR-017 + ADR-047). The webhook fan-out is a notification side
   effect — it does not constitute a decision.
3. **Bias declaration required.** Operators tuning these thresholds
   via Governance Console must declare bias under the YAML schema
   (`policy.schema.json`).

## Consequences

- The Compliance Dashboard (`demo/dpo-ciso/panels/compliance-dashboard.js`)
  imports `gilliganScenario(deadlineISO)` and renders S1–S6 badges directly,
  with no policy of its own.
- Webhook integration (`data/policies/webhooks.yaml`) is the only path that
  can fire S5 escalation — bypassing it is a constitutional violation
  (caught by `policy-blind-test.yml` + `alignment_regression.yml`).
- Future tuning (e.g. shifting S5 from 2h to 3h) goes through CAP — Protocol
  of Constitutional Amendment.

## Verification

- `python/tests/unit/governance/test_gilligan_scenarios.py` (to be added)
  asserts that the 6 scenario boundaries are exact and that severity can
  only shift upward.
- Governance Console smoke test: feed 36 synthetic appeals (one per
  scenario × 6 severity levels) and assert that the Dashboard renders the
  correct badge for each.

## References

- ADR-003 — Mercy Algorithm (philosophical foundation)
- ADR-017 — ContestabilityLoop (the 24h SLA itself)
- ADR-047 — Contestability Structured Mediation Protocol
- `python/buildtovalue/governance/contestability_loop.py`
- `data/policies/webhooks.yaml` (notification fan-out)
