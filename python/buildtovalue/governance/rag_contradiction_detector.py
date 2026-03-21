"""RagContradictionDetector — Cenário 31: Gaslighting Digital / RAG Poisoning.

Detecta contradições semânticas entre um chunk novo e a memória estabelecida.
Algoritmo determinístico (sem LLM no hot path): regex para extração de entidades
e comparação com valores previamente verificados no DurableLedger.

Entidades monitoradas: credential, password, network_name, secret, api_key.

Design: módulo injetado no construtor de RagIntegrityVerifier.
verify_chunk() original preservado para retrocompatibilidade.

Invariantes:
  - Fail-secure: erro → retorna ContradictionFinding de segurança
  - Algoritmo determinístico — sem dependência de LLM
  - explain_decision obrigatório em ContradictionFinding
  - Funções ≤ 50 linhas
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, List, Optional, Tuple

if TYPE_CHECKING:
    from .rag_integrity_verifier import MemoryProvenanceRecord

logger = logging.getLogger("btv.governance.rag_contradiction_detector")

# ---------------------------------------------------------------------------
# Padrões de extração de entidades sensíveis
# ---------------------------------------------------------------------------

# senha / password / secret
_RE_PASSWORD = re.compile(
    r"(?:senha|password|secret|segredo|token|api[_\s-]?key)[:\s=]+['\"]?([^\s'\"]{4,})['\"]?",
    re.IGNORECASE,
)
# rede / SSID / VPN
_RE_NETWORK = re.compile(
    r"(?:rede|ssid|wifi|wi-fi|vpn|network)[:\s=]+['\"]?([^\s'\"]{3,})['\"]?",
    re.IGNORECASE,
)
# credencial genérica: user:pass, login: ...
_RE_CREDENTIAL = re.compile(
    r"(?:user(?:name)?|login|acesso)[:\s=]+['\"]?([^\s'\"]{3,})['\"]?",
    re.IGNORECASE,
)

# Mapa de nome → regex para iteração
_ENTITY_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("password",    _RE_PASSWORD),
    ("network",     _RE_NETWORK),
    ("credential",  _RE_CREDENTIAL),
]


@dataclass(frozen=True)
class ContradictionFinding:
    """Contradição detectada entre chunk novo e memória estabelecida."""
    entity: str            # tipo: "password", "network", "credential"
    existing_value: str    # valor no chunk verificado anterior
    new_value: str         # valor no chunk novo (suspeito)
    existing_source: str   # canal de origem do chunk anterior
    explain_decision: str  # obrigatório (Levinas)


class RagContradictionDetector:
    """Detecta contradições entre chunk novo e chunks com proveniência verificada.

    Algoritmo:
      1. Extrai entidades nomeadas do chunk novo via regex determinístico.
      2. Para cada entidade, verifica se há valor diferente em established_chunks.
      3. Emite ContradictionFinding se valor divergir.
    """

    def check(
        self,
        new_chunk: str,
        established_chunks: List[Tuple[str, "MemoryProvenanceRecord"]],
    ) -> Optional[ContradictionFinding]:
        """Verifica contradições entre `new_chunk` e `established_chunks`.

        Retorna `ContradictionFinding` na primeira contradição encontrada.
        Retorna `None` se nenhuma contradição for detectada.

        Fail-secure: erro interno → retorna ContradictionFinding de segurança.
        """
        try:
            return self._check_inner(new_chunk, established_chunks)
        except Exception as exc:  # noqa: BLE001
            logger.error("Erro no detector de contradição: %s", exc)
            return ContradictionFinding(
                entity="INTERNAL_ERROR",
                existing_value="",
                new_value="",
                existing_source="",
                explain_decision=(
                    f"Erro interno no RagContradictionDetector: {exc}. "
                    "BLOCK por fail-secure."
                ),
            )

    def _check_inner(
        self,
        new_chunk: str,
        established_chunks: List[Tuple[str, "MemoryProvenanceRecord"]],
    ) -> Optional[ContradictionFinding]:
        """Lógica central de detecção de contradição."""
        new_entities = _extract_entities(new_chunk)
        if not new_entities:
            return None

        for entity_type, new_value in new_entities.items():
            for existing_text, provenance in established_chunks:
                existing_entities = _extract_entities(existing_text)
                if entity_type not in existing_entities:
                    continue
                existing_value = existing_entities[entity_type]
                if _values_differ(existing_value, new_value):
                    return ContradictionFinding(
                        entity=entity_type,
                        existing_value=existing_value,
                        new_value=new_value,
                        existing_source=provenance.source_channel,
                        explain_decision=(
                            f"Contradição detectada em '{entity_type}': "
                            f"valor estabelecido='{existing_value[:20]}…' "
                            f"(canal: {provenance.source_channel}) "
                            f"difere do novo valor='{new_value[:20]}…'. "
                            "Possível ataque de RAG Poisoning / Gaslighting Digital."
                        ),
                    )
        return None


def _extract_entities(text: str) -> dict[str, str]:
    """Extrai entidades nomeadas do texto via regex.

    Retorna dict: entity_type → valor (primeiro match).
    """
    result: dict[str, str] = {}
    for entity_type, pattern in _ENTITY_PATTERNS:
        m = pattern.search(text)
        if m:
            result[entity_type] = m.group(1).strip()
    return result


def _values_differ(a: str, b: str) -> bool:
    """Retorna True se os valores diferem (case-insensitive, sem espaços extras)."""
    return a.strip().lower() != b.strip().lower()


# ---------------------------------------------------------------------------
# Testes unitários
# ---------------------------------------------------------------------------

class TestRagContradictionDetector:
    """pytest: pytest -k RagContradictionDetector"""

    def _make_provenance(self, channel: str = "user_direct"):
        from unittest.mock import MagicMock
        p = MagicMock()
        p.source_channel = channel
        return p

    def test_detects_password_contradiction(self) -> None:
        detector = RagContradictionDetector()
        existing = "senha: MinhaSenh@Segura"
        prov     = self._make_provenance("user_direct")
        new_chunk = "senha: Hacker123"
        result = detector.check(new_chunk, [(existing, prov)])
        assert result is not None
        assert result.entity == "password"
        assert "Hacker123" in result.new_value
        assert "user_direct" in result.existing_source

    def test_no_contradiction_same_value(self) -> None:
        detector = RagContradictionDetector()
        existing = "senha: MinhaSenh@"
        prov     = self._make_provenance("user_direct")
        new_chunk = "senha: MinhaSenh@"
        assert detector.check(new_chunk, [(existing, prov)]) is None

    def test_no_contradiction_unrelated_text(self) -> None:
        detector = RagContradictionDetector()
        existing = "O tempo está bom hoje"
        prov     = self._make_provenance("user_direct")
        new_chunk = "A reunião é às 15h"
        assert detector.check(new_chunk, [(existing, prov)]) is None

    def test_network_contradiction(self) -> None:
        detector = RagContradictionDetector()
        existing = "rede: MinhaRedeCasa"
        prov     = self._make_provenance("user_direct")
        new_chunk = "rede: RedeHacker"
        result = detector.check(new_chunk, [(existing, prov)])
        assert result is not None
        assert result.entity == "network"

    def test_empty_established_chunks_no_contradiction(self) -> None:
        detector = RagContradictionDetector()
        assert detector.check("senha: qualquer", []) is None
