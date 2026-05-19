# ADR-061 — Decision::Block + NegotiationDeadlockReason

**Status:** Accepted  
**Date:** 2026-05-19

## Context

The kernel's `Action` enum (`Allow / Log / Block / Redact`) conflated
"policy rejected this request" with "active threat detected". When the
negotiation engine in `negotiation_engine.py` reached a deadlock, it
raised an unstructured Python exception with no Ledger record.

## Decision

Two types are added to `kernel/src/core/types.rs`:

### `Decision` enum

```rust
pub enum Decision {
    Allow = 0, Log = 1, Deny = 2, Block = 3, Redact = 4, Report = 5,
}
```

- `Deny` = policy rejected (calibrated risk). Triggers 24h contestation SLA.
- `Block` = active threat. Triggers Trust Score penalty + security alert.
  The distinction prevents misclassifying security blocks as routine denials.

`Action` is retained for the scanner pipeline (Module trait). `Decision` is
the output type of the Executive pipeline (Ledger records, FFI responses).

### `DeadlockResolutionError`

Fixed-size struct (no heap allocation) recording negotiation deadlocks.
`explanation` field is required — `DeadlockResolutionError::new()` returns
`Err` if explanation is empty, so a deadlock without explanation cannot
reach the Ledger.

### `NegotiationDeadlockReason`

Four-variant enum covering: `MaxRoundsExceeded`, `TimeoutExpired`,
`ConflictingPolicy`, `AgentUnreachable`.

## Consequences

- Negotiation deadlocks produce structured Ledger records instead of
  untrapped Python exceptions.
- `Deny` vs `Block` distinction enables correct SLA routing and Trust Score
  updates without special-casing action strings.
- `btv-types::Decision` (Allow/Deny/Block) is a subset of the kernel's
  `Decision`; the two crates remain independent (kernel does not depend on
  btv-types).
