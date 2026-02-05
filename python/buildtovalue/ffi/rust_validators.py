"""
BuildToValue v2.0 - Rust Validators FFI Bridge (Python Side)

Python bindings para validators Rust via ctypes.

Architecture: Python → ctypes → C ABI → Rust

Author: BuildToValue Architecture Team
License: Apache 2.0
"""

import ctypes
import json
import logging
from pathlib import Path
from typing import List, Dict, Optional, Any
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

    def to_dict(self) -> Dict[str, Any]:
        return {
            'rule_id': self.rule_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'confidence': self.confidence,
            'validator': self.validator_module,
            'metadata': self.metadata,
        }


# ═══════════════════════════════════════════════════════════════════════════
# RUST LIBRARY LOADER
# ═══════════════════════════════════════════════════════════════════════════

class RustValidatorsFFI:
    """
    FFI bridge para validators Rust.

    Carrega librust_validators.so/.dll/.dylib e expõe funções.
    """

    def __init__(self, lib_path: Optional[Path] = None):
        """
        Args:
            lib_path: Caminho para librust_validators (auto-detect se None)
        """
        if lib_path is None:
            lib_path = self._find_library()

        self.lib = ctypes.CDLL(str(lib_path))
        self._setup_functions()

        logger.info(f"✅ Loaded Rust validators library: {lib_path}")

    def _find_library(self) -> Path:
        """Auto-detect Rust library path."""
        # Try common locations
        candidates = [
            Path("../rust/target/release/libbuildtovalue.so"),  # Linux
            Path("../rust/target/release/libbuildtovalue.dylib"),  # macOS
            Path("../rust/target/release/buildtovalue.dll"),  # Windows
            Path(__file__).parent.parent.parent.parent / "rust" / "target" / "release" / "libbuildtovalue.so",
        ]

        for path in candidates:
            if path.exists():
                return path

        raise FileNotFoundError(
            "Rust library not found. Run: cd rust && cargo build --release"
        )

    def _setup_functions(self):
        """Setup ctypes function signatures."""

        # validate_consent
        self.lib.validate_consent.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        self.lib.validate_consent.restype = FFIValidationResult

        # validate_consent_revocation
        self.lib.validate_consent_revocation.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        self.lib.validate_consent_revocation.restype = FFIValidationResult

        # validate_sensitive_data
        self.lib.validate_sensitive_data.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        self.lib.validate_sensitive_data.restype = FFIValidationResult

        # validate_batch
        self.lib.validate_batch.argtypes = [
            ctypes.c_char_p,  # validator_names
            ctypes.POINTER(ctypes.c_char_p),  # inputs
            ctypes.c_size_t,  # inputs_count
            ctypes.c_char_p,  # metadata_json
        ]
        self.lib.validate_batch.restype = FFIValidationResult

        # free_validation_result
        self.lib.free_validation_result.argtypes = [FFIValidationResult]
        self.lib.free_validation_result.restype = None

    # ═══════════════════════════════════════════════════════════════════════
    # HIGH-LEVEL API
    # ═══════════════════════════════════════════════════════════════════════

    def validate_consent(
            self,
            input_text: str,
            metadata: Optional[Dict[str, Any]] = None
    ) -> List[Finding]:
        """
        Validate consent (LGPD Art. 7º, I).

        Args:
            input_text: Input to validate
            metadata: Context metadata (user.has_consent, processing.requires_consent, etc.)

        Returns:
            List of findings
        """
        return self._call_validator("validate_consent", input_text, metadata)

    def validate_consent_revocation(
            self,
            input_text: str,
            metadata: Optional[Dict[str, Any]] = None
    ) -> List[Finding]:
        """
        Validate consent revocation (LGPD Art. 8º, § 5º).

        Args:
            input_text: Input to validate
            metadata: Context metadata (user.consent_revoked, processing.continues)

        Returns:
            List of findings
        """
        return self._call_validator("validate_consent_revocation", input_text, metadata)

    def validate_sensitive_data(
            self,
            input_text: str,
            metadata: Optional[Dict[str, Any]] = None
    ) -> List[Finding]:
        """
        Validate sensitive data (LGPD Art. 11).

        Args:
            input_text: Input to validate
            metadata: Context metadata (consent.is_specific_for_sensitive)

        Returns:
            List of findings
        """
        return self._call_validator("validate_sensitive_data", input_text, metadata)

    def validate_batch(
            self,
            validator_names: List[str],
            inputs: List[str],
            metadata: Optional[Dict[str, Any]] = None
    ) -> List[Finding]:
        """
        Batch validation (performance optimization).

        Args:
            validator_names: List of validators ("consent", "sensitive_data", "cpf", etc.)
            inputs: List of inputs to validate
            metadata: Single metadata dict for all inputs

        Returns:
            List of findings (all validators combined)
        """
        validators_str = ",".join(validator_names).encode('utf-8')

        # Convert inputs to C array
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
            metadata: Optional[Dict[str, Any]]
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

        findings = []
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
