"""
FFI Client v3.0 — Rust <-> Python bridge (Phase 3).

Bridge priority:
  1. PyO3 (buildtovalue_governance.scan_for_evidence_batch) — preferred
  2. ctypes C ABI (libbuildtovalue_governance.so) — fallback

Fail-strict: any error → raise, never return mock/empty data.

Phase 3 changes from stripped v2.x:
  - FFIClient class restored with real kernel integration
  - _scan_pyo3 uses scan_for_evidence_batch (single-item call)
  - _deserialize_evidence_ctypes parses JSON from real kernel
  - DeserializationError raised on any parse failure, never silently suppressed
"""
from __future__ import annotations

import json
import logging
import ctypes
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional, List, Dict

logger = logging.getLogger(__name__)

RUST_LIB_PATH = os.environ.get(
    "BUILDTOVALUE_RUST_LIB",
    "target/release/libbuildtovalue_governance.so",
)
MAX_BUFFER_SIZE = 10 * 1024 * 1024  # 10 MB


# ── Exceptions ────────────────────────────────────────────────────────────────

class FFIError(Exception):
    pass

class BufferOverflowError(FFIError):
    pass

class DeserializationError(FFIError):
    pass

class BridgeNotAvailableError(FFIError):
    pass


# ── Wire types (FFI-layer, richer than governance/types.py) ───────────────────

@dataclass
class BiasDeclaration:
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0
    calibration_date: int = 0
    test_dataset_size: int = 0
    is_valid: bool = False


@dataclass
class Finding:
    title: str = ""
    description: str = ""
    severity: float = 0.5
    confidence: float = 0.5
    location: str = ""
    evidence: str = ""
    category: str = ""


@dataclass
class TechnicalEvidence:
    """FFI wire-format evidence returned by the real Rust kernel."""
    version: int = 0
    timestamp: int = 0
    audit_trail_id: str = ""
    composite_risk: float = 0.0
    risk_level: str = "Unknown"
    finding_count: int = 0
    critical_count: int = 0
    entropy: float = 0.0
    input_size: int = 0
    executed_modules: int = 0
    processing_time_us: int = 0
    hash: str = ""
    max_severity: str = "Unknown"
    bias: Optional[BiasDeclaration] = None
    findings: List[Finding] = field(default_factory=list)
    critical: List[Finding] = field(default_factory=list)
    stats: Dict[str, float] = field(default_factory=dict)
    ffi_validation_time_ms: float = 0.0
    ffi_buffer_size: int = 0


# ── FFI Client ────────────────────────────────────────────────────────────────

class FFIClient:
    """
    Rust kernel FFI client v3.0.

    Uses PyO3 (buildtovalue_governance module) if available;
    falls back to ctypes C ABI. Raises on any error — never returns mock data.
    """

    def __init__(self, lib_path: Optional[str] = None) -> None:
        self._lib_path = lib_path or RUST_LIB_PATH
        self._ctypes_lib: Optional[ctypes.CDLL] = None
        self.bridge_mode: str = "none"
        self._metrics: Dict[str, int] = {
            "calls_total": 0,
            "buffer_overflows": 0,
            "deserialization_errors": 0,
        }
        self._init_bridge()

    def _init_bridge(self) -> None:
        try:
            import buildtovalue_governance  # noqa: F401 — just verify import
            self.bridge_mode = "pyo3"
            logger.info("FFI bridge: PyO3 (buildtovalue_governance)")
            return
        except ImportError:
            logger.debug("PyO3 bridge unavailable, trying ctypes")

        try:
            lib = ctypes.CDLL(self._lib_path)
            lib.btv_scan_for_evidence.argtypes = [
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_size_t,
                ctypes.c_void_p,
            ]
            lib.btv_scan_for_evidence.restype = ctypes.c_int
            self._ctypes_lib = lib
            self.bridge_mode = "ctypes"
            logger.info("FFI bridge: ctypes C ABI (%s)", self._lib_path)
            return
        except OSError as exc:
            logger.error("ctypes bridge unavailable: %s", exc)

        raise BridgeNotAvailableError(
            "No Rust bridge found. Run `maturin develop` or `cargo build --release`."
        )

    def scan(self, input_text: str) -> TechnicalEvidence:
        """
        Scan text with the real Rust kernel.

        Raises:
            BufferOverflowError: input exceeds 10 MB
            DeserializationError: kernel response cannot be parsed
            FFIError: kernel call failed
        """
        start = time.perf_counter()
        self._metrics["calls_total"] += 1

        raw = input_text.encode("utf-8")
        if len(raw) > MAX_BUFFER_SIZE:
            self._metrics["buffer_overflows"] += 1
            raise BufferOverflowError(f"Input {len(raw)} bytes exceeds {MAX_BUFFER_SIZE}")

        try:
            if self.bridge_mode == "pyo3":
                ev = self._scan_pyo3(input_text)
            elif self.bridge_mode == "ctypes":
                ev = self._scan_ctypes(input_text)
            else:
                raise BridgeNotAvailableError("No bridge configured")
        except (BufferOverflowError, DeserializationError, BridgeNotAvailableError):
            raise
        except Exception as exc:
            raise FFIError(f"Rust scan failed: {exc}") from exc

        ev.ffi_validation_time_ms = (time.perf_counter() - start) * 1000
        ev.ffi_buffer_size = len(raw)
        return ev

    def _scan_pyo3(self, input_text: str) -> TechnicalEvidence:
        import buildtovalue_governance as btv

        trail_id = uuid.uuid4().int
        try:
            result_bytes = btv.scan_for_evidence_batch([input_text], [trail_id])
        except Exception as exc:
            raise FFIError(f"PyO3 scan_for_evidence_batch failed: {exc}") from exc

        try:
            data_list = json.loads(result_bytes)
            data = data_list[0]
        except (json.JSONDecodeError, IndexError, TypeError) as exc:
            self._metrics["deserialization_errors"] += 1
            raise DeserializationError(f"Failed to parse PyO3 response: {exc}") from exc

        return self._parse_evidence_dict(data)

    def _scan_ctypes(self, input_text: str) -> TechnicalEvidence:
        assert self._ctypes_lib is not None
        raw = input_text.encode("utf-8")
        buf = (ctypes.c_uint8 * len(raw))(*raw)
        out_buf = ctypes.create_string_buffer(65536)
        rc = self._ctypes_lib.btv_scan_for_evidence(buf, len(raw), out_buf)
        if rc != 0:
            raise FFIError(f"btv_scan_for_evidence returned {rc}")
        try:
            data = json.loads(out_buf.value.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            self._metrics["deserialization_errors"] += 1
            raise DeserializationError(f"Invalid JSON from C ABI: {exc}") from exc
        return self._parse_evidence_dict(data)

    def _parse_evidence_dict(self, data: dict) -> TechnicalEvidence:
        required = ["composite_risk", "risk_level", "finding_count",
                    "critical_count", "hash", "processing_time_us"]
        missing = [k for k in required if k not in data]
        if missing:
            self._metrics["deserialization_errors"] += 1
            raise DeserializationError(f"Missing required fields: {missing}")

        bias = None
        bias_fpr = data.get("bias_fpr")
        bias_fnr = data.get("bias_fnr")
        if bias_fpr is not None and bias_fnr is not None:
            bias = BiasDeclaration(
                false_positive_rate=float(bias_fpr),
                false_negative_rate=float(bias_fnr),
                calibration_date=int(data.get("bias_calibration_date", 0)),
            )

        return TechnicalEvidence(
            version=int(data.get("version", 0)),
            timestamp=int(data.get("timestamp", 0)),
            audit_trail_id=str(data.get("audit_trail_id", "")),
            composite_risk=float(data["composite_risk"]),
            risk_level=str(data["risk_level"]),
            finding_count=int(data["finding_count"]),
            critical_count=int(data["critical_count"]),
            entropy=float(data.get("entropy", 0.0)),
            input_size=int(data.get("input_size", 0)),
            executed_modules=int(data.get("executed_modules", 0)),
            processing_time_us=int(data["processing_time_us"]),
            hash=str(data["hash"]),
            max_severity=str(data.get("max_severity", "Unknown")),
            bias=bias,
        )

    def get_metrics(self) -> dict:
        total = max(self._metrics["calls_total"], 1)
        return {
            **self._metrics,
            "buffer_overflow_rate": self._metrics["buffer_overflows"] / total,
            "deserialization_error_rate": self._metrics["deserialization_errors"] / total,
            "bridge_mode": self.bridge_mode,
        }


_ffi_client: Optional[FFIClient] = None

def get_ffi_client() -> FFIClient:
    global _ffi_client
    if _ffi_client is None:
        _ffi_client = FFIClient()
    return _ffi_client
