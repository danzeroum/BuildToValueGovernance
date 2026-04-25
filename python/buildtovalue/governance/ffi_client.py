"""
FFI data types — shared wire format between Rust kernel and Python governance.

v2.3.1: Removed FFIClient (broken FFI bridge with mock _deserialize_evidence).
  The ctypes-based FFIClient used a placeholder _deserialize_evidence that returned
  zeroed data, making every scan result look clean. The real bridge is the HTTP API
  (Rust gateway → Python governance via /v1/decide).

  This file is kept ONLY for the TechnicalEvidence and Finding dataclasses that
  ethical_context_engine.py uses as type annotations. No FFI machinery remains.
"""
from dataclasses import dataclass
from typing import Any, Dict, List


class FFIError(Exception):
    """Kept for any code that catches FFIError — no longer raised by this module."""


class BufferOverflowError(FFIError):
    pass


class IntegrityError(FFIError):
    pass


class StaleDataError(FFIError):
    pass


@dataclass
class Finding:
    """Security finding produced by the Rust kernel scan."""
    title: str
    description: str
    severity: float
    confidence: float
    location: str
    evidence: str
    category: str


@dataclass
class TechnicalEvidence:
    """Technical evidence payload from the Rust kernel."""
    finding_count: int
    critical_count: int
    composite_risk: float
    findings: List[Finding]
    critical: List[Finding]
    stats: Dict[str, Any]
    hash: str
    timestamp: int
    ffi_validation_time_ms: float = 0.0
    ffi_buffer_size: int = 0
