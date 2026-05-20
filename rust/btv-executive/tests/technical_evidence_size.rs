//! C13 — TechnicalEvidence constitutional = 9596 bytes (ADR-063).
//!
//! This test makes the CI job "C13 — TechnicalEvidence = 9596 bytes" non-vacuous.
//! The compile-time `const assert` in btv-types is the primary enforcement;
//! this runtime test makes the CI filter `technical_evidence_size` resolve to a real test.
use std::mem::size_of;
use buildtovalue_kernel::TechnicalEvidence;

#[test]
fn technical_evidence_size() {
    assert_eq!(
        size_of::<TechnicalEvidence>(),
        9596,
        "ADR-063: TechnicalEvidence must be exactly 9596 bytes. \
         See docs/adr/0063-technical-evidence-size-invariant.md"
    );
}
