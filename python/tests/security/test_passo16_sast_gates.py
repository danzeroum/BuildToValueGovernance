"""
Passo 16 — SAST gate structural and functional verification.

RED: Tests fail until lint-guards.yml, .pre-commit-config.yaml, and
     pyproject.toml carry all required SAST gate configurations.
"""
import os
import subprocess
import pytest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]

def _read(rel: str) -> str:
    return (REPO_ROOT / rel).read_text()

# ── lint-guards.yml structural ─────────────────────────────────────────────

def test_lint_guards_has_bandit_high_check():
    """lint-guards.yml must contain a bandit -lll (HIGH only) step."""
    text = _read(".github/workflows/lint-guards.yml")
    assert "bandit" in text, "lint-guards.yml: missing bandit step"
    assert "-lll" in text, "lint-guards.yml: bandit must use -lll (HIGH only)"

def test_lint_guards_has_cargo_audit():
    """lint-guards.yml must contain a cargo audit step for Rust deps."""
    text = _read(".github/workflows/lint-guards.yml")
    assert "cargo audit" in text or "cargo-audit" in text, \
        "lint-guards.yml: missing cargo audit step"

def test_lint_guards_has_coverage_step():
    """lint-guards.yml must contain a pytest --cov coverage step."""
    text = _read(".github/workflows/lint-guards.yml")
    assert "--cov" in text, "lint-guards.yml: missing --cov coverage step"

def test_lint_guards_has_trufflehog():
    """lint-guards.yml must contain a TruffleHog secrets scan step."""
    text = _read(".github/workflows/lint-guards.yml")
    assert "trufflehog" in text.lower(), "lint-guards.yml: missing trufflehog step"

# ── .pre-commit-config.yaml structural ────────────────────────────────────

def test_pre_commit_has_bandit_hook():
    """.pre-commit-config.yaml must include a bandit hook."""
    text = _read(".pre-commit-config.yaml")
    assert "bandit" in text.lower(), \
        ".pre-commit-config.yaml: missing bandit hook"

def test_pre_commit_has_trufflehog_hook():
    """.pre-commit-config.yaml must include a trufflehog hook."""
    text = _read(".pre-commit-config.yaml")
    assert "trufflehog" in text.lower(), \
        ".pre-commit-config.yaml: missing trufflehog hook"

# ── pyproject.toml structural ──────────────────────────────────────────────

def test_pyproject_has_bandit_section():
    """python/pyproject.toml must have [tool.bandit] config."""
    text = _read("python/pyproject.toml")
    assert "[tool.bandit]" in text, \
        "python/pyproject.toml: missing [tool.bandit] section"

def test_pyproject_has_coverage_report_section():
    """python/pyproject.toml must have [tool.coverage.report] with fail_under."""
    text = _read("python/pyproject.toml")
    assert "[tool.coverage.report]" in text, \
        "python/pyproject.toml: missing [tool.coverage.report] section"
    assert "fail_under" in text, \
        "python/pyproject.toml: [tool.coverage.report] must set fail_under"

# ── functional: bandit 0 HIGH ──────────────────────────────────────────────

_BANDIT_AVAILABLE = subprocess.run(
    ["python", "-m", "bandit", "--version"],
    capture_output=True,
    cwd=str(REPO_ROOT / "python"),
).returncode == 0


@pytest.mark.skipif(not _BANDIT_AVAILABLE, reason="bandit not installed")
def test_bandit_zero_high_findings():
    """Codebase must have 0 HIGH severity bandit findings."""
    result = subprocess.run(
        ["python", "-m", "bandit", "-r", "buildtovalue/", "-lll", "-q"],
        capture_output=True, text=True,
        cwd=str(REPO_ROOT / "python"),
    )
    assert result.returncode == 0, (
        f"Bandit HIGH findings:\n{result.stdout}\n{result.stderr}"
    )

# ── functional: auth.py production guard (covers auth.py:29) ──────────────

def test_auth_production_guard_raises_without_api_keys():
    """init_auth() raises RuntimeError when BTV_ENV=production + no BTV_API_KEYS.

    This test covers auth.py:29 and brings auth.py to 100 % branch coverage.
    """
    from buildtovalue.api import auth as auth_module

    saved_env = os.environ.get("BTV_ENV")
    saved_keys = os.environ.get("BTV_API_KEYS")
    saved_enabled = auth_module._auth_enabled
    saved_valid_keys = auth_module._valid_keys
    try:
        os.environ["BTV_ENV"] = "production"
        os.environ.pop("BTV_API_KEYS", None)
        auth_module._auth_enabled = False
        auth_module._valid_keys = None

        with pytest.raises(RuntimeError, match="BTV_API_KEYS must be set in production"):
            auth_module.init_auth()
    finally:
        if saved_env is None:
            os.environ.pop("BTV_ENV", None)
        else:
            os.environ["BTV_ENV"] = saved_env
        if saved_keys is None:
            os.environ.pop("BTV_API_KEYS", None)
        else:
            os.environ["BTV_API_KEYS"] = saved_keys
        auth_module._auth_enabled = saved_enabled
        auth_module._valid_keys = saved_valid_keys
