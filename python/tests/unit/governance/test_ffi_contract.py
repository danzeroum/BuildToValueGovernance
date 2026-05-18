"""FFI contract tests — verify Python TypedDict fields match Rust struct expectations."""
from buildtovalue.governance.ffi_types import FindingWire, BiasWire


def test_finding_wire_required_fields():
    required = {"title", "description", "severity", "confidence"}
    assert required.issubset(set(FindingWire.__annotations__))


def test_bias_wire_has_all_fields():
    expected = {
        "false_positive_rate", "false_negative_rate",
        "calibration_date", "test_dataset_size", "is_valid",
    }
    assert expected == set(BiasWire.__annotations__)
