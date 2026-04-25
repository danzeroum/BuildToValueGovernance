"""
BuildToValue v3.0 — Rust Validators FFI Bridge (Python Side)

Python bindings para validators Rust via ctypes.

Architecture: Python -> ctypes -> C ABI -> Rust

Phase 4 Updates:
- Fixed library path candidates (libbuildtovalue_kernel.so, not libbuildtovalue.so)
- Removed `Any` from typing imports (analyst constraint)
- Added BUILDTOVALUE_KERNEL_LIB env var override

Author: BuildToValue Architecture Team
License: Apache 2.0
"""

import ctypes
import json
import logging
import os
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# FFI STRUCTURES (must match Rust)
# ═══════════════════════════════════════════════════════════════════════════

class FFIFinding(ctypes.Structure):
    """C-compatible Finding structure."""
    _fields_ = [
        ("rule_id", ctypes.c_char_p),
        ("title", ctypes.c_char_p),
        ("description", ctypes.c_char_p),
        ("severity", ctypes.c_uint8),
        ("confidence", ctypes.c_uint8),
        ("validator_module", ctypes.c_char_p),
        ("metadata", ctypes.c_char_p),
    ]


class FFIValidationResult(ctypes.Structure):
    """C-compatible validation result."""
    _fields_ = [
        ("findings", ctypes.POINTER(FFIFinding)),
        ("findings_count", ctypes.c_size_t),
        ("error_message", ctypes.c_char_p),
    ]


# ═══════════════════════════════════════════════════════════════════════════
# PYTHON DATACLASSES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    """Python-friendly Finding."""
    rule_id: str
    title: str
    description: str
    severity: int
    confidence: int
    validator_module: str
    metadata: Optional[str] = None

    def to_dict(self) -> Dict[str, Optional[str]]:
        return {
            'rule_id': self.rule_id,
            'title': self.title,
            'description': self.description,
            'severity': str(self.severity),
            'confidence': str(self.confidence),
            'validator': self.validator_module,
            'metadata': self.metadata,
        }


# ═══════════════════════════════════════════════════════════════════════════
# RUST LIBRARY LOADER
# ═══════════════════════════════════════════════════════════════════════════

class RustValidatorsFFI:
    """
    FFI bridge para validators Rust.

    Carrega libbuildtovalue_kernel.so/.dll/.dylib e expoe funcoes.
    Phase 4: Fixed library name (was libbuildtovalue, now libbuildtovalue_kernel).
    """

    def __init__(self, lib_path: Optional[Path] = None):
        if lib_path is None:
            lib_path = self._find_library()

        self.lib = ctypes.CDLL(str(lib_path))
        self._setup_functions()

        logger.info(f"Loaded Rust validators library: {lib_path}")

    def _find_library(self) -> Path:
        """Auto-detect Rust library path.

        Phase 4: Searches for libbuildtovalue_kernel (correct crate name).
        The crate is `buildtovalue-kernel` in Cargo.toml, which produces
        `libbuildtovalue_kernel.so` (hyphens become underscores in .so names).
        """
        # Environment override (highest priority)
        env_path = os.environ.get('BUILDTOVALUE_KERNEL_LIB')
        if env_path:
            p = Path(env_path)
            if p.exists():
                return p
            logger.warning(f"BUILDTOVALUE_KERNEL_LIB={env_path} not found, trying defaults")

        candidates = [
            Path("../rust/target/release/libbuildtovalue_kernel.so"),        # Linux
            Path("../rust/target/release/libbuildtovalue_kernel.dylib"),     # macOS
            Path("../rust/target/release/buildtovalue_kernel.dll"),          # Windows
            Path(__file__).parent.parent.parent.parent
                / "rust" / "target" / "release" / "libbuildtovalue_kernel.so",
            # maturin-built PyO3 library
            Path(__file__).parent.parent.parent.parent
                / "rust" / "target" / "release" / "libbuildtovalue_governance.so",
        ]

        for path in candidates:
            if path.exists():
                return path

        raise FileNotFoundError(
            "Rust kernel library not found. Run: cd rust && cargo build --release\n"
            "Or set BUILDTOVALUE_KERNEL_LIB env var to the correct path.\n"
            "Searched:\n" + "\n".join(f"  - {p}" for p in candidates)
        )

    def _setup_functions(self) -> None:
        """Setup ctypes function signatures."""

        self.lib.validate_consent.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        self.lib.validate_consent.restype = FFIValidationResult

        self.lib.validate_consent_revocation.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        self.lib.validate_consent_revocation.restype = FFIValidationResult

        self.lib.validate_sensitive_data.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        self.lib.validate_sensitive_data.restype = FFIValidationResult

        self.lib.validate_batch.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_char_p),
            ctypes.c_size_t,
            ctypes.c_char_p,
        ]
        self.lib.validate_batch.restype = FFIValidationResult

        self.lib.free_validation_result.argtypes = [FFIValidationResult]
        self.lib.free_validation_result.restype = None

    # ═══════════════════════════════════════════════════════════════════════
    # HIGH-LEVEL API
    # ═══════════════════════════════════════════════════════════════════════

    def validate_consent(
            self,
            input_text: str,
            metadata: Optional[Dict[str, str]] = None
    ) -> List[Finding]:
        """Validate consent (LGPD Art. 7, I)."""
        return self._call_validator("validate_consent", input_text, metadata)

    def validate_consent_revocation(
            self,
            input_text: str,
            metadata: Optional[Dict[str, str]] = None
    ) -> List[Finding]:
        """Validate consent revocation (LGPD Art. 8, 5)."""
        return self._call_validator("validate_consent_revocation", input_text, metadata)

    def validate_sensitive_data(
            self,
            input_text: str,
            metadata: Optional[Dict[str, str]] = None
    ) -> List[Finding]:
        """Validate sensitive data (LGPD Art. 11)."""
        return self._call_validator("validate_sensitive_data", input_text, metadata)

    def validate_batch(
            self,
            validator_names: List[str],
            inputs: List[str],
            metadata: Optional[Dict[str, str]] = None
    ) -> List[Finding]:
        """Batch validation (performance optimization)."""
        validators_str = ",".join(validator_names).encode('utf-8')

        input_ptrs = (ctypes.c_char_p * len(inputs))()
        for i, inp in enumerate(inputs):
            input_ptrs[i] = inp.encode('utf-8')

        metadata_json = json.dumps(metadata).encode('utf-8') if metadata else None

        result = self.lib.validate_batch(
            validators_str,
            input_ptrs,
            len(inputs),
            metadata_json
        )

        findings = self._extract_findings(result)
        self.lib.free_validation_result(result)

        return findings

    # ═══════════════════════════════════════════════════════════════════════
    # INTERNAL HELPERS
    # ═══════════════════════════════════════════════════════════════════════

    def _call_validator(
            self,
            func_name: str,
            input_text: str,
            metadata: Optional[Dict[str, str]]
    ) -> List[Finding]:
        """Generic validator caller."""
        func = getattr(self.lib, func_name)

        input_bytes = input_text.encode('utf-8')
        metadata_json = json.dumps(metadata).encode('utf-8') if metadata else None

        result = func(input_bytes, metadata_json)

        if result.error_message:
            error = result.error_message.decode('utf-8')
            self.lib.free_validation_result(result)
            raise RuntimeError(f"Rust validator error: {error}")

        findings = self._extract_findings(result)
        self.lib.free_validation_result(result)

        return findings

    def _extract_findings(self, result: FFIValidationResult) -> List[Finding]:
        """Extract findings from FFI result."""
        if result.findings_count == 0:
            return []

        findings: List[Finding] = []
        for i in range(result.findings_count):
            ffi_finding = result.findings[i]

            finding = Finding(
                rule_id=ffi_finding.rule_id.decode('utf-8') if ffi_finding.rule_id else "",
                title=ffi_finding.title.decode('utf-8') if ffi_finding.title else "",
                description=ffi_finding.description.decode('utf-8') if ffi_finding.description else "",
                severity=ffi_finding.severity,
                confidence=ffi_finding.confidence,
                validator_module=ffi_finding.validator_module.decode('utf-8') if ffi_finding.validator_module else "",
                metadata=ffi_finding.metadata.decode('utf-8') if ffi_finding.metadata else None,
            )
            findings.append(finding)

        return findings


# ═══════════════════════════════════════════════════════════════════════════
# SINGLETON INSTANCE
# ═══════════════════════════════════════════════════════════════════════════

_rust_validators: Optional[RustValidatorsFFI] = None


def get_rust_validators() -> RustValidatorsFFI:
    """Get singleton RustValidatorsFFI instance."""
    global _rust_validators

    if _rust_validators is None:
        _rust_validators = RustValidatorsFFI()

    return _rust_validators
