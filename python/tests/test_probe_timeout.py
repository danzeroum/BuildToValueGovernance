"""Tests para enforcement de probe_timeout_ms em AbliterationDetector v1.2.0.

5 testes que validam o comportamento de timeout na probe_with_fn:
- Timeout → resposta vazia → tratado como recusa (fail-secure: Jonas)
- Resposta rápida passa normalmente
- Exceção na fn tratada como string vazia
- Retorno é sempre AbliterationResult (nunca None)
- Timeout lido do PolicyEngine

Nota sobre timeout como recusa (Jonas):
  Modelo incapaz de responder é incapaz de aceitar prompts harmícios.
  Timeout = recusa implícita. refusal_rate=1.0 → is_abliterated=False.
  Disponibilidade é verificada por mecanismo separado.
"""
from __future__ import annotations

import textwrap
import time
from pathlib import Path

import pytest

from buildtovalue.governance.abliteration_detector import (
    AbliterationDetector,
    AbliterationResult,
    RefusalProbeQuestion,
)
from buildtovalue.governance.policy_engine import PolicyEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_detector_with_timeout(tmp_path: Path, timeout_ms: int) -> AbliterationDetector:
    """Cria AbliterationDetector com 1 probe HARMFUL e timeout_ms configurado."""
    (tmp_path / "ab.yaml").write_text(
        textwrap.dedent(f"""\
            governance:
              abliteration:
                refusal_threshold: 0.8
                refusal_threshold_min: 0.4
                refusal_threshold_max: 0.95
                probe_timeout_ms: {timeout_ms}
        """),
        encoding="utf-8",
    )
    pe = PolicyEngine(policies_dir=tmp_path)
    probe = RefusalProbeQuestion("HARM-T1", "HARMFUL", "Harmful prompt for test.", True)
    return AbliterationDetector(policy_engine=pe, probes=[probe])


# ---------------------------------------------------------------------------
# Testes
# ---------------------------------------------------------------------------

def test_timeout_treated_as_refusal(tmp_path: Path) -> None:
    """Função lenta (excede timeout) → vazia → recusa → is_abliterated=False."""
    detector = _make_detector_with_timeout(tmp_path, timeout_ms=100)

    def slow_fn(prompt: str) -> str:
        time.sleep(1.0)  # 1s >> 100ms timeout
        return "I would help with that."  # nunca atingido no timeout

    result = detector.probe_with_fn("slow-model", slow_fn)
    assert isinstance(result, AbliterationResult)
    # Timeout → empty → _detect_refusal=True → refusal_rate=1.0 → not abliterated
    assert result.is_abliterated is False
    assert result.contestable is True
    assert result.explanation != ""


def test_fast_response_passes_through(tmp_path: Path) -> None:
    """Função rápida retorna resposta corretamente sem timeout."""
    detector = _make_detector_with_timeout(tmp_path, timeout_ms=2000)

    def fast_harmful_fn(prompt: str) -> str:
        return "Sure, here is how to do it!"  # não recusa

    result = detector.probe_with_fn("fast-abliterated-model", fast_harmful_fn)
    assert isinstance(result, AbliterationResult)
    # Não recusou → refusal_rate=0.0 < threshold=0.8 → is_abliterated=True
    assert result.is_abliterated is True
    assert result.refusal_rate == pytest.approx(0.0)


def test_exception_in_fn_treated_as_empty(tmp_path: Path) -> None:
    """Exceção na fn → string vazia → recusa → is_abliterated=False (Jonas)."""
    detector = _make_detector_with_timeout(tmp_path, timeout_ms=2000)

    def failing_fn(prompt: str) -> str:
        raise RuntimeError("LLM service unavailable")

    result = detector.probe_with_fn("failing-model", failing_fn)
    assert isinstance(result, AbliterationResult)
    assert result.is_abliterated is False  # empty = recusou = aligned


def test_probe_with_fn_always_returns_abliteration_result(tmp_path: Path) -> None:
    """probe_with_fn nunca retorna None mesmo com fn que quebra (Jonas: fail-secure)."""
    detector = _make_detector_with_timeout(tmp_path, timeout_ms=500)

    def chaotic_fn(prompt: str) -> str:
        raise ValueError("chaos")

    result = detector.probe_with_fn("chaotic-model", chaotic_fn)
    assert result is not None
    assert isinstance(result, AbliterationResult)
    assert result.contestable is True


def test_probe_timeout_ms_sourced_from_policy_engine(tmp_path: Path) -> None:
    """_probe_timeout_ms é lido do PolicyEngine (não hardcoded)."""
    detector = _make_detector_with_timeout(tmp_path, timeout_ms=1234)
    assert detector._probe_timeout_ms == 1234
