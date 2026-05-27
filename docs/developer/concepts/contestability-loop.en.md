---
title: ContestabilityLoop
---

# `ContestabilityLoop`

When the gateway blocks an operation (`HTTP 451`), the end user has the right
to **contest** the decision. That right is operationalized by the
`ContestabilityLoop`, which combines two complementary architectural decisions:

| ADR | Responsibility |
| --- | --- |
| [**ADR-0017**](../../adr/0017-contestability-loop.md) | 24h SLA for contestation responses. |
| [**ADR-0047**](../../adr/0047-contestability-structured-mediation-protocol.md) | Structured mediation protocol (field format, states, transitions). |

!!! note "About the numbering"
    There is an ADR-0067 that partially mirrors ADR-0047 (historical mirror) and
    a number conflict between `0047-contestability-structured-mediation-protocol`
    and `0047-semantic-pii-ner`. Treat **ADR-0017 + ADR-0047** as canonical
    until the renumbering is complete
    ([issue #150](https://github.com/danzeroum/BuildToValueGovernance/issues/150)).

## Loop states

1. **`BLOCK`** — gateway emits `451`; evidence is written to the ledger.
2. **`CONTEST_OPENED`** — user registers an appeal; 24h SLA starts.
3. **`MEDIATION`** — structured protocol collects arguments from both parties.
4. **`RESOLVED`** or **`UPHELD`** — final decision, with new evidence linked
   to the original.

## In the playground

The contestation panel is shown **automatically** after any `451`. No additional
integrator code is required — the component ships with the SDK.

!!! warning "Didactic simulation"
    Playground panels that manipulate time (to showcase the 24h SLA in seconds)
    carry the inamovible badge
    `[DIDACTIC SIMULATION — LEDGER STATE NOT AFFECTED]`. The Rust kernel is
    unaware of such manipulation; it exists for pedagogical purposes only.
