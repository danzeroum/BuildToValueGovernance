---
title: Evidence Anatomy
---

# Anatomy of `TechnicalEvidence`

`TechnicalEvidence` is the immutable record BuildToValue produces for every
gateway decision. It is simultaneously **proof** (auditable outside the system)
and **operational artifact** (consumed by internal components).

## Two sizes, one decision

The struct exists in **two canonical forms**, each serving a distinct
architectural purpose. This is not a bug — it is a deliberate decision recorded
in [ADR-063](../../adr/0063-technical-evidence-size-invariant.md) and explained
in depth in [`CHANGELOG_PHILOSOPHICAL.md`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/CHANGELOG_PHILOSOPHICAL.md).

**The exact sizes are extracted from the Rust source and displayed in the
[generated technical reference](../reference/index.md).** Do not type the
numbers manually anywhere — the `scripts/validate_invariants.py` check in CI
will fail if you do.

### Operational form (Kernel)

- Defined in [`rust/kernel/src/core/types.rs`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/rust/kernel/src/core/types.rs).
- Includes reserved fields for hardware attestation (C8) and capability metadata
  (Prop-031).
- Validated at compile time via `const_assert_eq!`.

### Constitutional form (Wire)

- Defined in [`rust/btv-types/src/lib.rs`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/rust/btv-types/src/lib.rs).
- Produced by `Verdict::to_technical_evidence()`.
- This is the format transmitted between components — **this** is what you
  consume if you integrate with the gateway.

## How to decide which one to use

| You are... | Use the... form |
| --- | --- |
| Integrating with the gateway over HTTP/SDK | **Constitutional** (wire) |
| Verifying a proof out-of-browser with `btv-cli` | **Constitutional** (wire) |
| Contributing to the Rust kernel | **Operational** (kernel) |
| Reading documentation that says "the size" without qualifier | **Stop** — ask for the qualifier |

## Anti-pattern: the bare number

Every reference to the evidence size **must** carry a qualifier
(operational/constitutional, kernel/wire). Unqualified citations must be treated
as **incomplete** — that is exactly the anti-pattern that motivated the existence
of `CHANGELOG_PHILOSOPHICAL.md`.
