"""Testes de integração: PolicyEngine v1.1.0 → AbliterationDetector + IntegrityVerifier.

8 testes que cobrem a leitura do threshold tipado via accessor ADR-042
em ambos os módulos que consomem PolicyEngine, sem mocks externos.

Filosofia:
  Rawls: cada teste é uma afirmação contestável sobre o contrato de integração.
  Jonas: fail-secure preservado — sem PolicyEngine, defaults conservadores.
"""
from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

from buildtovalue.governance.policy_engine import PolicyEngine
from buildtovalue.governance.abliteration_detector import AbliterationDetector
from buildtovalue.governance.model_integrity_verifier import (
    AbliterationDetector as InternalAbliterationDetector,
    IntegrityVerifier,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def policy_engine_with_abliteration(tmp_path: Path) -> PolicyEngine:
    """PolicyEngine com abliteration threshold=0.65 no YAML."""
    (tmp_path / "ab.yaml").write_text(
        textwrap.dedent("""\
            governance:
              abliteration:
                refusal_threshold: 0.65
                refusal_threshold_min: 0.4
                refusal_threshold_max: 0.9
                probe_timeout_ms: 3000
              model_integrity:
                verification_enabled: true
                block_on_failure: true
                models:
                  test-model-v1:
                    manifest_path: "data/manifests/test-model-v1.json"
                    expected_hash_env: "BTV_TEST_MODEL_HASH"
        """),
        encoding="utf-8",
    )
    return PolicyEngine(policies_dir=tmp_path)


@pytest.fixture
def empty_policy_engine(tmp_path: Path) -> PolicyEngine:
    """PolicyEngine sem YAMLs — defaults fail-secure."""
    return PolicyEngine(policies_dir=tmp_path)


# ---------------------------------------------------------------------------
# AbliterationDetector (abliteration_detector.py) + PolicyEngine
# ---------------------------------------------------------------------------

def test_abliteration_detector_reads_threshold_from_policy_engine(
    policy_engine_with_abliteration: PolicyEngine,
) -> None:
    """AbliterationDetector lê refusal_threshold via policy_engine.abliteration_threshold."""
    detector = AbliterationDetector(policy_engine=policy_engine_with_abliteration)
    assert detector._refusal_threshold == pytest.approx(0.65)


def test_abliteration_detector_reads_probe_timeout_from_policy_engine(
    policy_engine_with_abliteration: PolicyEngine,
) -> None:
    """AbliterationDetector lê probe_timeout_ms via policy_engine.abliteration.probe_timeout_ms."""
    detector = AbliterationDetector(policy_engine=policy_engine_with_abliteration)
    assert detector._probe_timeout_ms == 3000


def test_abliteration_detector_fallback_without_policy_engine() -> None:
    """Sem PolicyEngine: defaults conservadores (_DEFAULT_REFUSAL_THRESHOLD, 5000ms)."""
    detector = AbliterationDetector()
    assert detector._refusal_threshold == pytest.approx(0.80)
    assert detector._probe_timeout_ms == 5000


def test_abliteration_detector_explicit_threshold_overridden_by_policy(
    policy_engine_with_abliteration: PolicyEngine,
) -> None:
    """Threshold explícito no construtor é substituído pelo PolicyEngine (contrato ADR-042)."""
    detector = AbliterationDetector(
        policy_engine=policy_engine_with_abliteration,
        refusal_threshold=0.99,  # ignorado quando PolicyEngine fornecido
    )
    assert detector._refusal_threshold == pytest.approx(0.65)


# ---------------------------------------------------------------------------
# AbliterationDetector interno (model_integrity_verifier.py) + PolicyEngine
# ---------------------------------------------------------------------------

def test_internal_abliteration_detector_reads_threshold_from_policy(
    policy_engine_with_abliteration: PolicyEngine,
) -> None:
    """Detector interno usa policy_engine.abliteration_threshold — sem _governance_config direto."""
    detector = InternalAbliterationDetector(policy_engine=policy_engine_with_abliteration)
    assert detector._refusal_threshold == pytest.approx(0.65)


def test_internal_abliteration_detector_fallback_without_policy(
    empty_policy_engine: PolicyEngine,
) -> None:
    """Sem PolicyEngine: threshold padrão da constante canônica do módulo."""
    from buildtovalue.governance.abliteration_detector import (
        _DEFAULT_REFUSAL_THRESHOLD,
    )

    detector = InternalAbliterationDetector()
    assert detector._refusal_threshold == pytest.approx(_DEFAULT_REFUSAL_THRESHOLD)


# ---------------------------------------------------------------------------
# IntegrityVerifier + manifest_path_for
# ---------------------------------------------------------------------------

def test_integrity_verifier_calls_manifest_path_for_in_verify(
    policy_engine_with_abliteration: PolicyEngine,
) -> None:
    """IntegrityVerifier.verify() chama manifest_path_for para audit trail."""
    verifier = IntegrityVerifier(policy_engine=policy_engine_with_abliteration)
    # model desconhecido → fail-secure (False), mas manifest_path_for não deve lançar
    result = verifier.verify("test-model-v1")
    assert result is False  # não está em LEGITIMATE_MODELS → fail-secure


def test_integrity_verifier_without_policy_engine_no_crash() -> None:
    """IntegrityVerifier sem PolicyEngine não lança exceção (regressão)."""
    verifier = IntegrityVerifier(policy_engine=None)
    result = verifier.verify("qualquer-modelo-xyz")
    assert result is False  # modelo desconhecido → fail-secure
