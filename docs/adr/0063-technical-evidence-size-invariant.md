# ADR-063 — TechnicalEvidence Size Invariant

**Status:** Partially active — BiasDeclaration assert active, TechnicalEvidence deferred  
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

### Deferred: TechnicalEvidence size invariant

The `TechnicalEvidence` assert is commented out in `core/types.rs`. Activation
requires:

1. Replace `Vec<u8>` fields in `TechnicalEvidence` with fixed-size `[u8; N]`
   equivalents.
2. Update `EVIDENCE_SIZE` to match the new struct layout.
3. Uncomment the `const assert`.

This is tracked as Phase 2 of ADR-063. The kernel's `TechnicalEvidence` and
`btv-types::TechnicalEvidence` are distinct types serving different purposes
(scanner operational record vs. constitutional wire format).

## Consequences

- `BiasDeclaration` layout is now compiler-enforced: any change to its fields
  fails the build before it can corrupt persisted records.
- Adding a field to `BiasDeclaration` requires updating `EVIDENCE_SIZE` and
  incrementing the ADR version — the failing assert makes this requirement
  impossible to miss.
