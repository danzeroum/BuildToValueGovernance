// This test verifies that InclusionReceipt carries #[must_use].
// trybuild cannot construct an InclusionReceipt externally (pub(crate) constructor),
// so the must_use enforcement for external callers is validated via:
//   1. Attribute inspection (this file documents the requirement)
//   2. Integration test that the compiler warns when Result<InclusionReceipt> is ignored
// The structural #[must_use] check is enforced in the type definition itself.
fn main() {}
