---
title: ADR Trail
---

# ADR Trail

This is a **curated index** of the Architecture Decision Records — not a
parallel physical directory. The canonical ADRs live in
[`docs/adr/`](https://github.com/danzeroum/BuildToValueGovernance/tree/main/docs/adr).

## Where to start

| Question | Start with |
| --- | --- |
| What is BTV? | [ADR-0001 — Hybrid Architecture](../../adr/0001-hybrid-architecture.md) |
| How is evidence protected? | [ADR-0004 — Immutable Ledger](../../adr/0004-immutable-ledger.md) |
| Why two evidence sizes? | [ADR-0063 — TechnicalEvidence Size Invariant](../../adr/0063-technical-evidence-size-invariant.md) |
| How do I contest a decision? | [ADR-0017](../../adr/0017-contestability-loop.md) + [ADR-0047](../../adr/0047-contestability-structured-mediation-protocol.md) |
| How does the ethics engine work? | [ADR-0038 — Ethical Context Engine v4](../../adr/0038-ethical-context-engine-v4.md) |
| Mercy algorithm? | [ADR-0003 — Mercy Algorithm](../../adr/0003-mercy-algorithm.md) |

## Full index

[ADR-0000 — ADR Index](../../adr/0000-adr-index.md) (maintainers: keep this in
sync after every new ADR).

## Cleanup notes

- The legacy `docs/adrs/` directory was consolidated into `docs/adr/` in
  Phase 0 of the Developer Portal.
- `ADR-0047` numbering conflict (`semantic-pii-ner` vs
  `contestability-structured-mediation-protocol`) and mirror `ADR-0067` are
  tracked in [issue #150](https://github.com/danzeroum/BuildToValueGovernance/issues/150).
