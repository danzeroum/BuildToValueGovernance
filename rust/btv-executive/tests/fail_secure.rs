//! Fail-secure invariant tests.
//!
//! Every `DecisionError` variant must be unreachable from a partial result.
//! This file documents that the error enum has NO variant containing a `Verdict`,
//! `InclusionReceipt`, or `DeliveryToken` — enforcing atomicity.
#[cfg(test)]
mod fail_secure {
    use btv_executive::DecisionError;

    /// Compile-time: DecisionError variants contain only Strings (error messages),
    /// never btv-core linear resource types.
    /// If this function compiles, the invariant holds.
    fn assert_no_partial_result(e: DecisionError) -> String {
        match e {
            DecisionError::GatekeeperFailed(s)    => s,
            DecisionError::ComplianceUnavailable(s) => s,
            DecisionError::LogUnavailable(s)       => s,
            DecisionError::IntegrityFailure        => "integrity".into(),
            DecisionError::InputViolation(s)       => s,
            // If a future variant adds a Verdict/Receipt/DeliveryToken,
            // this match becomes non-exhaustive AND the type-checker will
            // require handling the linear resource — the oversight is visible.
        }
    }

    #[test]
    fn decision_error_is_exhaustive_no_partial_result() {
        let _ = assert_no_partial_result;
        // No assertion needed: the function existing and compiling IS the test.
    }
}
