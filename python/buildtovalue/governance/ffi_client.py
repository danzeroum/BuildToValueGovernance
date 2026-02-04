"""
FFI Client para comunicação com Rust Kernel.
Implementa bridge Python ↔ Rust via ctypes.
"""
import ctypes
from dataclasses import dataclass
from typing import List, Optional
from pathlib import Path


# ═══════════════════════════════════════════════════════════════════════════
# TIPOS DE DADOS (Espelhados do Rust)
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    """Finding individual detectado pelo Rust."""
    module: str
    severity: str
    rule_id: str
    title: str
    description: str
    confidence: float
    position_start: int
    position_end: int


@dataclass
class InputStatistics:
    """Estatísticas calculadas pelo Rust."""
    entropy: float
    zscore: float
    char_ratio_digits: float
    char_ratio_alpha: float
    char_ratio_special: float
    length: int
    has_pii: bool
    has_sensitive_data: bool


@dataclass
class TechnicalEvidence:
    """
    Evidência técnica completa do Rust (9.4KB).
    Estrutura DEVE ser compatível com Rust (repr(C)).
    """
    protocol_version: int
    audit_trail_id: int
    evidence_hash: int
    composite_risk: int
    finding_count: int
    critical_count: int
    findings: List[Finding]
    critical: List[Finding]
    stats: InputStatistics
    input_size: int
    processing_time_us: int
    original_request_hash: int


# ═══════════════════════════════════════════════════════════════════════════
# FFI CLIENT
# ═══════════════════════════════════════════════════════════════════════════

class FFIClient:
    """
    Cliente FFI para chamar funções Rust.
    Carrega biblioteca .so e expõe métodos Python.
    """

    def __init__(self, lib_path: Optional[str] = None):
        """
        Inicializa cliente FFI.

        Args:
            lib_path: Caminho para libbuildtovalue_kernel.so
                     Se None, tenta localizar automaticamente
        """
        if lib_path is None:
            lib_path = self._find_library()

        self.lib = ctypes.CDLL(lib_path)
        self._setup_functions()

    def _find_library(self) -> str:
        """Localiza biblioteca Rust automaticamente."""
        possible_paths = [
            "/app/lib/libbuildtovalue_kernel.so",
            "./target/release/libbuildtovalue_kernel.so",
            "./libbuildtovalue_kernel.so",
        ]

        for path in possible_paths:
            if Path(path).exists():
                return path

        raise FileNotFoundError(
            "libbuildtovalue_kernel.so não encontrado. "
            "Compile o projeto Rust primeiro."
        )

    def _setup_functions(self):
        """Configura assinaturas das funções FFI."""
        # scan_for_evidence (função principal)
        self.lib.scan_for_evidence.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),  # input_ptr
            ctypes.c_size_t,  # input_len
            ctypes.POINTER(ctypes.c_void_p),  # output_ptr (TechnicalEvidence)
        ]
        self.lib.scan_for_evidence.restype = ctypes.c_int32

    def scan_for_evidence(self, input_text: str) -> TechnicalEvidence:
        """
        Escaneia texto e retorna evidências técnicas.

        Args:
            input_text: Texto a ser analisado

        Returns:
            TechnicalEvidence com findings detectados

        Raises:
            RuntimeError: Se Rust retornar erro
        """
        # Converte string para bytes
        input_bytes = input_text.encode('utf-8')
        input_ptr = (ctypes.c_uint8 * len(input_bytes))(*input_bytes)

        # Aloca buffer de saída (TechnicalEvidence)
        output_ptr = ctypes.c_void_p()

        # Chama Rust
        result = self.lib.scan_for_evidence(
            input_ptr,
            len(input_bytes),
            ctypes.byref(output_ptr)
        )

        if result != 0:
            raise RuntimeError(f"Rust scan_for_evidence falhou: código {result}")

        # Parse resultado (TODO: Implementar deserialização Protobuf)
        # Por ora, retorna mock para desenvolvimento
        return self._parse_evidence(output_ptr)

    def _parse_evidence(self, ptr: ctypes.c_void_p) -> TechnicalEvidence:
        """
        Parse TechnicalEvidence do ponteiro Rust.

        TODO: Implementar deserialização Protobuf real
        """
        # Mock para desenvolvimento (substituir por Protobuf)
        return TechnicalEvidence(
            protocol_version=2,
            audit_trail_id=0,
            evidence_hash=0,
            composite_risk=0,
            finding_count=0,
            critical_count=0,
            findings=[],
            critical=[],
            stats=InputStatistics(
                entropy=0.0,
                zscore=0.0,
                char_ratio_digits=0.0,
                char_ratio_alpha=0.0,
                char_ratio_special=0.0,
                length=len(input_text) if 'input_text' in locals() else 0,
                has_pii=False,
                has_sensitive_data=False
            ),
            input_size=0,
            processing_time_us=0,
            original_request_hash=0
        )
