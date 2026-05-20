from typing import TypedDict
try:
    from typing import Required  # Python 3.11+
except ImportError:
    from typing_extensions import Required  # Python 3.10


class FindingWire(TypedDict, total=False):
    title: Required[str]
    description: Required[str]
    severity: Required[float]
    confidence: Required[float]
    category: str  # optional — Rust may not send on older kernels


class BiasWire(TypedDict):
    false_positive_rate: float
    false_negative_rate: float
    calibration_date: int
    test_dataset_size: int
    is_valid: bool
