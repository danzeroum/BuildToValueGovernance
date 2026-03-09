"""Tests para ManifestHashVerifier v1.0.0 — ADR-042 Fase 2.

11 testes cobrindo todos os 6 caminhos de verify() + imutabilidade
e explain_decision() obrigatório (Levinas).

Filosofia:
  Rawls: cada teste é uma afirmação contestável sobre o contrato de hash.
  Jonas: defaults conservadores validados (block_on_failure=True → fail).
"""
from __future__ import annotations

import hashlib
import textwrap
from pathlib import Path

import pytest

from buildtovalue.governance.manifest_hash_verifier import (
    ManifestHashVerifier,
    ManifestVerificationResult,
)
from buildtovalue.governance.policy_engine import PolicyEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def manifest_content() -> bytes:
    return b'{"model": "test-model-v1", "version": "1.0", "weights_sha256": "abc123"}'


@pytest.fixture
def manifest_file(tmp_path: Path, manifest_content: bytes) -> Path:
    """Cria arquivo de manifesto real em tmp_path."""
    p = tmp_path / "test-model-v1.json"
    p.write_bytes(manifest_content)
    return p


@pytest.fixture
def correct_hash(manifest_content: bytes) -> str:
    return hashlib.sha256(manifest_content).hexdigest().lower()


def _make_engine(
    tmp_path: Path,
    manifest_path: str,
    env_var: str = "BTV_TEST_MODEL_HASH",
    verification_enabled: bool = True,
    block_on_failure: bool = True,
) -> PolicyEngine:
    """Factory: cria PolicyEngine com YAML de model_integrity apontando para manifest_path."""
    policies_dir = tmp_path / "policies"
    policies_dir.mkdir(exist_ok=True)
    (policies_dir / "mi.yaml").write_text(
        textwrap.dedent(f"""\
            governance:
              model_integrity:
                verification_enabled: {str(verification_enabled).lower()}
                block_on_failure: {str(block_on_failure).lower()}
                models:
                  test-model-v1:
                    manifest_path: "{manifest_path}"
                    expected_hash_env: "{env_var}"
        """),
        encoding="utf-8",
    )
    return PolicyEngine(policies_dir=policies_dir)


# ---------------------------------------------------------------------------
# Caminho 1: verification_enabled=False → skip
# ---------------------------------------------------------------------------

def test_verification_disabled_returns_is_valid_true(tmp_path: Path) -> None:
    """verification_enabled=False → is_valid=True sem verificar arquivo."""
    pe = _make_engine(tmp_path, "/nonexistent/path.json", verification_enabled=False)
    result = ManifestHashVerifier().verify("test-model-v1", pe)
    assert result.is_valid is True
    assert "verification_enabled=False" in result.explain_decision()


# ---------------------------------------------------------------------------
# Caminho 2: manifest_path não configurado
# ---------------------------------------------------------------------------

def test_manifest_path_not_configured_block_true(tmp_path: Path) -> None:
    """Model não em policy + block_on_failure=True → is_valid=False."""
    policies_dir = tmp_path / "policies"
    policies_dir.mkdir()
    (policies_dir / "empty.yaml").write_text(
        "governance:\n  model_integrity:\n    verification_enabled: true\n    block_on_failure: true\n    models: {}\n",
        encoding="utf-8",
    )
    pe = PolicyEngine(policies_dir=policies_dir)
    result = ManifestHashVerifier().verify("test-model-v1", pe)
    assert result.is_valid is False
    assert "MANIFEST FAIL-SECURE" in result.explain_decision()


# ---------------------------------------------------------------------------
# Caminho 3: env var ausente
# ---------------------------------------------------------------------------

def test_missing_env_var_block_on_failure_true(
    tmp_path: Path, manifest_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Env var não definida + block_on_failure=True → is_valid=False."""
    monkeypatch.delenv("BTV_TEST_MODEL_HASH", raising=False)
    pe = _make_engine(tmp_path, manifest_file.as_posix())
    result = ManifestHashVerifier().verify("test-model-v1", pe)
    assert result.is_valid is False
    assert "BTV_TEST_MODEL_HASH" in result.explain_decision()


def test_missing_env_var_block_on_failure_false(
    tmp_path: Path, manifest_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Env var não definida + block_on_failure=False → is_valid=True (warn)."""
    monkeypatch.delenv("BTV_TEST_MODEL_HASH", raising=False)
    pe = _make_engine(tmp_path, manifest_file.as_posix(), block_on_failure=False)
    result = ManifestHashVerifier().verify("test-model-v1", pe)
    assert result.is_valid is True
    assert "block_on_failure=False" in result.explain_decision()


# ---------------------------------------------------------------------------
# Caminho 4: arquivo não encontrado
# ---------------------------------------------------------------------------

def test_manifest_file_not_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Arquivo configurado mas ausente → is_valid=False."""
    monkeypatch.setenv("BTV_TEST_MODEL_HASH", "abc123")
    pe = _make_engine(tmp_path, "/nonexistent/path/model.json")
    result = ManifestHashVerifier().verify("test-model-v1", pe)
    assert result.is_valid is False
    assert "não encontrado" in result.explain_decision()


# ---------------------------------------------------------------------------
# Caminho 5: hash match → is_valid=True
# ---------------------------------------------------------------------------

def test_valid_hash_returns_is_valid_true(
    tmp_path: Path,
    manifest_file: Path,
    correct_hash: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hash correto → is_valid=True com explain_decision() não vazio."""
    monkeypatch.setenv("BTV_TEST_MODEL_HASH", correct_hash)
    pe = _make_engine(tmp_path, manifest_file.as_posix())
    result = ManifestHashVerifier().verify("test-model-v1", pe)
    assert result.is_valid is True
    assert "ntegro" in result.explain_decision()  # "íntegro"
    assert result.contestable is True


# ---------------------------------------------------------------------------
# Caminho 6: hash mismatch → is_valid=False
# ---------------------------------------------------------------------------

def test_wrong_hash_returns_is_valid_false(
    tmp_path: Path,
    manifest_file: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hash errado → is_valid=False com MODEL_INTEGRITY_HASH_MISMATCH auditado."""
    monkeypatch.setenv("BTV_TEST_MODEL_HASH", "0" * 64)  # hash inválido
    pe = _make_engine(tmp_path, manifest_file.as_posix())
    result = ManifestHashVerifier().verify("test-model-v1", pe)
    assert result.is_valid is False
    assert "mismatch" in result.explain_decision()
    assert "MANIFEST FAIL-SECURE" in result.explain_decision()


def test_hash_comparison_is_case_insensitive(
    tmp_path: Path,
    manifest_file: Path,
    correct_hash: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hash em uppercase no env var é aceito (normalizado lowercase)."""
    monkeypatch.setenv("BTV_TEST_MODEL_HASH", correct_hash.upper())
    pe = _make_engine(tmp_path, manifest_file.as_posix())
    result = ManifestHashVerifier().verify("test-model-v1", pe)
    assert result.is_valid is True


# ---------------------------------------------------------------------------
# Contrato de tipo (Rawls: imutabilidade)
# ---------------------------------------------------------------------------

def test_result_is_frozen_dataclass(
    tmp_path: Path,
    manifest_file: Path,
    correct_hash: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ManifestVerificationResult é frozen — imutável após construção."""
    monkeypatch.setenv("BTV_TEST_MODEL_HASH", correct_hash)
    pe = _make_engine(tmp_path, manifest_file.as_posix())
    result = ManifestHashVerifier().verify("test-model-v1", pe)
    assert isinstance(result, ManifestVerificationResult)
    with pytest.raises(Exception):
        result.is_valid = False  # type: ignore[misc]


def test_explain_decision_non_empty_on_failure(
    tmp_path: Path,
    manifest_file: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """explain_decision() não vazio em resultado de falha (Levinas obrigatório)."""
    monkeypatch.setenv("BTV_TEST_MODEL_HASH", "0" * 64)
    pe = _make_engine(tmp_path, manifest_file.as_posix())
    result = ManifestHashVerifier().verify("test-model-v1", pe)
    assert result.explain_decision() != ""
    assert len(result.explain_decision()) > 20
