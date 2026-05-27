---
title: Economic Sizing Guide
---

# Economic Sizing Guide

When is adopting BuildToValue worth it? This page is honest about costs,
benefits, and **active technical debt**.

## When BTV is justifiable

- Flows with **regulatory exposure** (LGPD, HIPAA, GDPR) where a single
  violation costs more than the evidence overhead.
- Domains where **AI decision traceability** is required (financial, health,
  HR).
- Operations where **end-user contestation** needs a guaranteed SLA.

## When it is not (yet) justifiable

- Purely cosmetic flows (e.g. emoji suggestion).
- Workloads where the ledger latency is prohibitive and there is no
  regulatory exposure.

## Active Technical Debt

!!! danger "Radical transparency"
    We list known failures **before** you decide to adopt. A developer sizing
    their integration based on benchmarks must know about unexpected behaviors
    in the flows below.

| ID | Area | Status | Impact |
| --- | --- | --- | --- |
| **DT-004** | Mercy and Compliance flows | 4 active E2E failures | Edge cases in `MercyAlgorithm` ([ADR-0003](../../adr/0003-mercy-algorithm.md)) and in the compliance pipeline may return `INDETERMINATE` when `ALLOW`/`BLOCK` is expected. No loss of auditability; loss of determinism. |
| **#150** | ADRs | Numbering conflict | `ADR-0047` points to two distinct documents; mirror `ADR-0067` awaits a decision. Canonical mapping: see [contestability-loop](../concepts/contestability-loop.md). |

## Reference metrics

Metric collection lives in
[`benchmarks/`](https://github.com/danzeroum/BuildToValueGovernance/tree/main/benchmarks).
To reproduce: `make benchmark`.

## Regulatory map

See [`regulatory-map.md`](regulatory-map.md).
