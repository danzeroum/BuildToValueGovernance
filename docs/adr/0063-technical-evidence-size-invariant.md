# ADR-063 — TechnicalEvidence Size Invariant

**Status:** Active — both BiasDeclaration and TechnicalEvidence invariants enforced at compile time  
**Date:** 2026-05-19

## Context

`EVIDENCE_SIZE = 9632` was declared as a constant, but no compile-time check
bound the struct to that number. A developer adding a `String` field would
silently change the size, invalidating persisted records.

`btv-types` has a separate `TechnicalEvidence` (9596 bytes) with a compile-time
`const assert`. The kernel's `TechnicalEvidence` is 9632 bytes (operational
scanner type) and contains `Vec<u8>` fields — `size_of` is meaningful only
for fully fixed-size types.

## Decision

### Active: BiasDeclaration size invariant

```rust
const _: () = assert!(
    std::mem::size_of::<BiasDeclaration>() == 512,
    "ADR-063 VIOLATION: BiasDeclaration size invariant broken."
);
```

`BiasDeclaration` is fully fixed-size (`repr(C, align(8))`), so this assert is
meaningful and catches layout regressions at compile time.

### Active: TechnicalEvidence size invariant (ADR-063 phase 2)

All `Vec<u8>` fields have been replaced with fixed-size `[u8; N]` equivalents
(notably `_reserved_metadata: [u8; 7072]`). The struct is fully `#[repr(C, align(8))]`.

The assert is active in both `core/types.rs` and `evidence/technical.rs` (via
`static_assertions::const_assert_eq!`). The confirmed canonical size is **9632 bytes**.

`from_bytes` was updated to validate the `version` field (must be 1–3) before
returning, preventing zero-filled or truncated buffers from propagating as live
evidence. See S-05 in the Sprint 0 security ledger.

The kernel's `TechnicalEvidence` and `btv-types::TechnicalEvidence` remain distinct
types serving different purposes (scanner operational record vs. constitutional wire
format).

## Consequences

- `BiasDeclaration` layout is now compiler-enforced: any change to its fields
  fails the build before it can corrupt persisted records.
- Adding a field to `BiasDeclaration` requires updating `EVIDENCE_SIZE` and
  incrementing the ADR version — the failing assert makes this requirement
  impossible to miss.
