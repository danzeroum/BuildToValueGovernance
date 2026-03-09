"""Tests for PolicyEngine v1.1.0 — ADR-042: ModelIntegrityConfig + AbliterationConfig.

14 testes isolados que cobrem os novos accessors tipados sem tocar
AbliterationDetector nem ModelIntegrityVerifier (integracao no proximo ciclo).

Filosofia: cada teste e uma afirmacao contestavel sobre o contrato
da Republica Algoritmica (Rawls: equidade verificavel).
Fail-secure (Jonas): defaults conservadores sao assercoes de primeiro nivel.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from buildtovalue.governance.policy_engine import (
    AbliterationConfig,
    ModelConfig,
    ModelIntegrityConfig,
    PolicyAction,
    PolicyEngine,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def empty_engine(tmp_path: Path) -> PolicyEngine:
    """PolicyEngine sem YAMLs — governance_config vazio, defaults fail-secure."""
    return PolicyEngine(policies_dir=tmp_path)


@pytest.fixture
def engine_with_model_integrity(tmp_path: Path) -> PolicyEngine:
    """PolicyEngine com model_integrity.yaml em subdiretorio security/ (rglob)."""
    sec_dir = tmp_path / "security"
    sec_dir.mkdir()
    (sec_dir / "model_integrity.yaml").write_text(
        textwrap.dedent("""\
            governance:
              model_integrity:
                verification_enabled: true
                block_on_failure: true
                models:
                  phi-3-mini-v1:
                    manifest_path: "data/manifests/phi-3-mini-v1.json"
                    expected_hash_env: "BTV_PHI3_MANIFEST_HASH"
              abliteration:
                refusal_threshold: 0.6
                refusal_threshold_min: 0.4
                refusal_threshold_max: 0.9
                probe_timeout_ms: 5000
            rules:
              - rule_id: MODEL_INTEGRITY_HASH_MISMATCH
                description: "Hash mismatch"
                action: BLOCK
                severity: critical
                condition_field: model_hash_mismatch
                condition_operator: eq
                condition_value: "true"
                adr_refs: ["ADR-042"]
              - rule_id: MODEL_ABLITERATION_DETECTED
                description: "Abliteration detected"
                action: BLOCK
                severity: critical
                condition_field: abliteration_detected
                condition_operator: eq
                condition_value: "true"
                adr_refs: ["ADR-042"]
        """),
        encoding="utf-8",
    )
    return PolicyEngine(policies_dir=tmp_path)


# ---------------------------------------------------------------------------
# ModelIntegrityConfig — defaults fail-secure (Jonas)
# ---------------------------------------------------------------------------

def test_model_integrity_defaults_verification_enabled(empty_engine: PolicyEngine) -> None:
    """Sem YAML: verification_enabled=True por default (Jonas: fail-secure)."""
    cfg = empty_engine.model_integrity
    assert cfg.verification_enabled is True


def test_model_integrity_defaults_block_on_failure(empty_engine: PolicyEngine) -> None:
    """Sem YAML: block_on_failure=True por default (Jonas: fail-secure)."""
    cfg = empty_engine.model_integrity
    assert cfg.block_on_failure is True


def test_model_integrity_defaults_empty_models(empty_engine: PolicyEngine) -> None:
    """Sem YAML: models dict vazio — sem modelos conhecidos."""
    cfg = empty_engine.model_integrity
    assert isinstance(cfg.models, dict)
    assert len(cfg.models) == 0


def test_model_integrity_returns_frozen_dataclass(empty_engine: PolicyEngine) -> None:
    """ModelIntegrityConfig e frozen — imutavel apos construcao (Rawls: contrato)."""
    cfg = empty_engine.model_integrity
    assert isinstance(cfg, ModelIntegrityConfig)
    with pytest.raises(Exception):
        cfg.verification_enabled = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# ModelIntegrityConfig — carregamento de YAML via rglob
# ---------------------------------------------------------------------------

def test_model_integrity_loads_from_subdir_yaml(
    engine_with_model_integrity: PolicyEngine,
) -> None:
    """rglob carrega YAML de subdiretorio security/; accessors tipados populados."""
    cfg = engine_with_model_integrity.model_integrity
    assert cfg.verification_enabled is True
    assert cfg.block_on_failure is True
    assert "phi-3-mini-v1" in cfg.models


def test_model_config_parsed_manifest_path(
    engine_with_model_integrity: PolicyEngine,
) -> None:
    """ModelConfig.manifest_path lido corretamente do YAML."""
    model = engine_with_model_integrity.model_integrity.models["phi-3-mini-v1"]
    assert isinstance(model, ModelConfig)
    assert model.manifest_path == "data/manifests/phi-3-mini-v1.json"


def test_model_config_parsed_expected_hash_env(
    engine_with_model_integrity: PolicyEngine,
) -> None:
    """ModelConfig.expected_hash_env lido corretamente do YAML."""
    model = engine_with_model_integrity.model_integrity.models["phi-3-mini-v1"]
    assert model.expected_hash_env == "BTV_PHI3_MANIFEST_HASH"


def test_manifest_path_for_known_model(engine_with_model_integrity: PolicyEngine) -> None:
    """manifest_path_for retorna caminho correto para modelo conhecido."""
    path = engine_with_model_integrity.manifest_path_for("phi-3-mini-v1")
    assert path == "data/manifests/phi-3-mini-v1.json"


def test_manifest_path_for_unknown_model(engine_with_model_integrity: PolicyEngine) -> None:
    """manifest_path_for retorna None para modelo desconhecido — sem excecao."""
    path = engine_with_model_integrity.manifest_path_for("modelo-inexistente-xyz")
    assert path is None


def test_manifest_path_for_empty_engine(empty_engine: PolicyEngine) -> None:
    """manifest_path_for retorna None quando nenhum modelo configurado."""
    assert empty_engine.manifest_path_for("phi-3-mini-v1") is None


# ---------------------------------------------------------------------------
# AbliterationConfig — clamping e defaults
# ---------------------------------------------------------------------------

def test_abliteration_defaults(empty_engine: PolicyEngine) -> None:
    """Sem YAML: AbliterationConfig com defaults conservadores."""
    cfg = empty_engine.abliteration
    assert isinstance(cfg, AbliterationConfig)
    assert cfg.refusal_threshold == pytest.approx(0.6)
    assert cfg.refusal_threshold_min == pytest.approx(0.4)
    assert cfg.refusal_threshold_max == pytest.approx(0.9)
    assert cfg.probe_timeout_ms == 5000


def test_abliteration_threshold_clamped_above(tmp_path: Path) -> None:
    """refusal_threshold > max e clamped para max — configuracao insegura bloqueada."""
    (tmp_path / "ab.yaml").write_text(
        textwrap.dedent("""\
            governance:
              abliteration:
                refusal_threshold: 0.99
                refusal_threshold_min: 0.4
                refusal_threshold_max: 0.9
        """),
        encoding="utf-8",
    )
    engine = PolicyEngine(policies_dir=tmp_path)
    assert engine.abliteration_threshold == pytest.approx(0.9)


def test_abliteration_threshold_clamped_below(tmp_path: Path) -> None:
    """refusal_threshold < min e clamped para min — configuracao permissiva bloqueada."""
    (tmp_path / "ab.yaml").write_text(
        textwrap.dedent("""\
            governance:
              abliteration:
                refusal_threshold: 0.1
                refusal_threshold_min: 0.4
                refusal_threshold_max: 0.9
        """),
        encoding="utf-8",
    )
    engine = PolicyEngine(policies_dir=tmp_path)
    assert engine.abliteration_threshold == pytest.approx(0.4)


def test_abliteration_threshold_shortcut_consistency(
    engine_with_model_integrity: PolicyEngine,
) -> None:
    """abliteration_threshold e atalho consistente com abliteration.refusal_threshold."""
    engine = engine_with_model_integrity
    assert engine.abliteration_threshold == pytest.approx(
        engine.abliteration.refusal_threshold
    )


# ---------------------------------------------------------------------------
# Avaliacao de regras — contexto com model integrity
# ---------------------------------------------------------------------------

def test_model_hash_mismatch_triggers_block(
    engine_with_model_integrity: PolicyEngine,
) -> None:
    """Regra MODEL_INTEGRITY_HASH_MISMATCH dispara BLOCK; resultado contestavel."""
    result = engine_with_model_integrity.evaluate(
        composite_risk=0.0,
        context={"model_hash_mismatch": "true"},
    )
    assert result.action == PolicyAction.BLOCK
    assert "MODEL_INTEGRITY_HASH_MISMATCH" in result.triggered_rules
    assert result.contestable is True
    assert result.explain_decision() != ""
    assert result.hmac_tag != ""


def test_abliteration_detected_triggers_block(
    engine_with_model_integrity: PolicyEngine,
) -> None:
    """Regra MODEL_ABLITERATION_DETECTED dispara BLOCK; HMAC presente."""
    result = engine_with_model_integrity.evaluate(
        composite_risk=0.0,
        context={"abliteration_detected": "true"},
    )
    assert result.action == PolicyAction.BLOCK
    assert "MODEL_ABLITERATION_DETECTED" in result.triggered_rules
    assert result.hmac_tag != ""
    assert result.explain_decision() != ""
