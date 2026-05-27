---
title: Developer Portal
---

# Developer Portal

Welcome to the BuildToValue **Trust OS**. This portal is organized into
**three pedagogical tracks** that mirror the branches of the Algorithmic
Republic ([ADR-001](../adr/0001-hybrid-architecture.md)). Pick your track:

<div class="grid cards" markdown>

-   :material-cog: **Integrator Track**

    You **consume** the gateway over HTTP/SDK. Learn how to interpret evidence,
    handle `HTTP 451` blocks, and verify cryptographic proofs.

    [Start →](tutorials/01-handle-failure.md)

-   :material-gavel: **Legislator Track**

    You **propose** new ADRs and YAML policies. Learn the Constitutional
    Amendment Protocol (CAP) and the ADR trail.

    [Start →](cap-protocol.md)

-   :material-scale-balance: **Judge Track**

    You **calibrate** ethical thresholds and rule on appeals via the
    `ContestabilityLoop` ([ADR-0017](../adr/0017-contestability-loop.md) +
    [ADR-0047](../adr/0047-contestability-structured-mediation-protocol.md)).

    [Start →](tutorials/04-propose-policy.md)

</div>

!!! tip "Language"
    Switch between **Português (BR)** and **English** using the language selector
    in the top bar.

## Principles of this portal

1. **Orchestration, not duplication.** Canonical content lives in `docs/adr/`,
   `rust/` and `demo/`. The portal **references**, never copies.
2. **Automated source of truth.** Invariants (byte sizes, hashes, ADR IDs) are
   extracted from the Rust code at build time by
   [`scripts/autogen_reference.py`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/scripts/autogen_reference.py).
3. **Fail-secure first.** The [first tutorial](tutorials/01-handle-failure.md)
   teaches the block — trust is truly tested in the `BLOCK`, not in the happy path.
4. **Radical transparency.** [Active technical debt](compliance/sizing-guide.md)
   is visible before the adoption decision.

## Portal map

- [Concepts](concepts/evidence-anatomy.md) — evidence anatomy, fail-secure, contestability.
- [Tutorials](tutorials/01-handle-failure.md) — step-by-step paths.
- [Technical reference](reference/index.md) — **generated** from the Rust kernel.
- [Compliance & sizing](compliance/sizing-guide.md) — when BTV is economically justifiable.
- [ADR trail](adr-trail/README.md) — curated index of the 70+ canonical ADRs.
- [CAP protocol](cap-protocol.md) — how to amend the system constitution.
- [Interactive playground](https://github.com/danzeroum/BuildToValueGovernance/tree/main/demo/playground) — run scenarios in your browser.
