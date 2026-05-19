# ADR-060 — BiasDeclaration Validated Constructor

**Status:** Accepted  
**Date:** 2026-05-19  
**Replaces:** ADR-010 (additive — extends mandate, does not revoke it)

## Context

`BiasDeclaration::new()` in `kernel/src/core/types.rs` previously returned
`Self` unconditionally, accepting `calibration_date = 0` and
`test_dataset_size = 0` without error. This meant a zero-value declaration
(indistinguishable from "not set") could propagate silently into
`TechnicalEvidence.bias`, invalidating the ADR-010 mandate that every
decision carries a valid bias declaration.

`impl Default for BiasDeclaration` was public, providing a second silent
path to a zeroed declaration.

## Decision

1. `BiasDeclaration::new()` now returns `Result<Self, BiasDeclarationError>`.
   - `calibration_date == 0` → `Err(MissingCalibrationDate)`
   - `test_dataset_size == 0` → `Err(MissingDatasetSize)`

2. `impl Default for BiasDeclaration` is gated with `#[cfg(test)]`.
   Production code that calls `BiasDeclaration::default()` will not compile.

3. A new `BiasDeclaration::aggregate()` constructor is provided for the
   gatekeeper's worst-case aggregation, which may legitimately produce
   `calibration_date = 0` when no modules reported calibration data. The
   resulting declaration triggers a `log::warn!` via `is_calibration_valid()`.

4. All ~30 call sites in static `bias_declaration()` trait implementations
   use `.expect("static bias values are valid")` — the hardcoded values are
   structurally valid (non-zero date, non-zero size), so the `.expect()` is
   infallible in practice and self-documenting.

## Consequences

- **Positive:** A zeroed `BiasDeclaration` cannot reach the Ledger without an
  explicit `.aggregate()` call and a logged warning.
- **Positive:** `BiasDeclarationError` is a typed, structured error that can be
  caught by callers who need to handle the invalid-declaration case.
- **Trade-off:** Trait implementations that previously returned
  `BiasDeclaration::new(...)` directly now require `.expect()`. This is
  intentional — it makes the "this is infallible because the values are
  constants" assumption explicit and visible to reviewers.
