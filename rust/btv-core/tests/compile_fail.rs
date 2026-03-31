/// Compile-fail test harness for the 7 cases of the Constitutional Enclosure Theorem.
///
/// Each test in `tests/ui/` must produce a compile error — passing would indicate
/// a violation of Paper 1's guarantees.
#[test]
fn compile_fail_tests() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
