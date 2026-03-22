"""
Tests: PolicyHygieneValidator v1.0.0 — PREFPO-inspired
pytest python/tests/governance/test_policy_hygiene.py -v
"""
import hashlib
import hmac as _hmac
import json
import tempfile
from pathlib import Path

import pytest

from buildtovalue.governance.policy_hygiene import (
    HygieneReport,
    PolicyHygieneValidator,
    BASELINE_LENGTH_CHARS,
    MAX_TRIGRAM_REPETITION,
    GRADE_MAX,
)

VALIDATOR = PolicyHygieneValidator()

HEALTHY_POLICY = """\
rules:
  - rule_id: GOV-001
    description: Bloquear alta sensibilidade de risco composto
    action: BLOCK
    severity: critical
    condition_field: composite_risk
    condition_operator: gte
    condition_value: 0.85
    adr_refs: ["ADR-011"]

  - rule_id: GOV-002
    description: Educar risco médio com tags PII
    action: EDUCATE
    severity: medium
    condition_field: composite_risk
    condition_operator: gte
    condition_value: 0.55
    adr_refs: ["ADR-011", "ADR-016"]
"""

REPETITIVE_POLICY = " ".join(["block allow block allow block allow"] * 50)

VERY_SHORT_POLICY = "rules: []"

VERY_LONG_POLICY = "# " + ("a " * 5000)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _write_tmp(content: str) -> Path:
    """Escreve conteúdo em arquivo temporário e retorna Path."""
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8"
    )
    f.write(content)
    f.flush()
    return Path(f.name)


def _verify_signature(report: HygieneReport) -> bool:
    """Verifica HMAC-SHA256 do relatório."""
    payload = json.dumps(
        {
            "evaluated_at": report.evaluated_at_iso,
            "grade": report.hygiene_grade,
            "path": report.policy_path,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    expected = _hmac.new(
        PolicyHygieneValidator._HMAC_KEY, payload, hashlib.sha256
    ).hexdigest()
    return report.signature == expected


# ─── HygieneReport ────────────────────────────────────────────────────────────

class TestHygieneReport:
    def test_is_frozen(self):
        """HygieneReport é imutável (frozen=True)."""
        path = _write_tmp(HEALTHY_POLICY)
        r = VALIDATOR.validate(path)
        with pytest.raises((AttributeError, TypeError)):
            r.hygiene_grade = 0  # type: ignore

    def test_to_dict_contains_all_fields(self):
        """to_dict() expõe todos os campos esperados."""
        path = _write_tmp(HEALTHY_POLICY)
        r = VALIDATOR.validate(path)
        d = r.to_dict()
        for k in (
            "policy_path", "length_ratio", "trigram_repetition",
            "hygiene_grade", "issues", "explain_decision",
            "evaluated_at_iso", "signature", "is_healthy",
        ):
            assert k in d, f"Campo ausente: {k}"

    def test_to_dict_issues_is_list(self):
        """to_dict() converte tuple de issues para list."""
        path = _write_tmp(HEALTHY_POLICY)
        r = VALIDATOR.validate(path)
        assert isinstance(r.to_dict()["issues"], list)


# ─── Política saudável ────────────────────────────────────────────────────────

class TestHealthyPolicy:
    def test_healthy_policy_grade_high(self):
        """Política bem formada deve ter grade >= 4."""
        path = _write_tmp(HEALTHY_POLICY)
        r = VALIDATOR.validate(path)
        assert r.hygiene_grade >= 4

    def test_healthy_policy_is_healthy_true(self):
        """is_healthy=True quando grade >= 4."""
        path = _write_tmp(HEALTHY_POLICY)
        r = VALIDATOR.validate(path)
        assert r.is_healthy is True

    def test_healthy_no_issues(self):
        """Política saudável não deve ter issues."""
        path = _write_tmp(HEALTHY_POLICY)
        r = VALIDATOR.validate(path)
        assert len(r.issues) == 0

    def test_healthy_signature_valid(self):
        """Assinatura HMAC-SHA256 deve ser verificável."""
        path = _write_tmp(HEALTHY_POLICY)
        r = VALIDATOR.validate(path)
        assert _verify_signature(r)

    def test_healthy_explain_present(self):
        """explain_decision não vazio (Levinas)."""
        path = _write_tmp(HEALTHY_POLICY)
        r = VALIDATOR.validate(path)
        assert r.explain_decision
        assert "PolicyHygieneValidator" in r.explain_decision

    def test_healthy_explain_mentions_saudavel(self):
        """explain_decision menciona status SAUDÁVEL."""
        path = _write_tmp(HEALTHY_POLICY)
        r = VALIDATOR.validate(path)
        assert "SAUDÁVEL" in r.explain_decision


# ─── Política vazia/curta ─────────────────────────────────────────────────────

class TestEmptyOrShortPolicy:
    def test_empty_policy_grade_critical(self):
        """Política vazia deve ter grade crítico (<= 2)."""
        path = _write_tmp("")
        r = VALIDATOR.validate(path)
        assert r.hygiene_grade <= 2

    def test_empty_policy_is_healthy_false(self):
        """Política vazia não é saudável."""
        path = _write_tmp("")
        r = VALIDATOR.validate(path)
        assert r.is_healthy is False

    def test_very_short_policy_penalized(self):
        """Política muito curta (< 0.3 baseline) recebe penalidade."""
        path = _write_tmp(VERY_SHORT_POLICY)
        r = VALIDATOR.validate(path)
        # VERY_SHORT_POLICY tem ~10 chars, baseline=500 → ratio~0.02 → critico
        assert r.hygiene_grade <= 2

    def test_very_short_has_issue(self):
        """Política curta deve ter issue descritivo."""
        path = _write_tmp(VERY_SHORT_POLICY)
        r = VALIDATOR.validate(path)
        assert len(r.issues) > 0
        assert any("curta" in iss.lower() or "vazia" in iss.lower() for iss in r.issues)

    def test_short_policy_signature_still_valid(self):
        """Assinatura deve ser válida mesmo para política ruim."""
        path = _write_tmp(VERY_SHORT_POLICY)
        r = VALIDATOR.validate(path)
        assert _verify_signature(r)


# ─── Política excessivamente longa ────────────────────────────────────────────

class TestLongPolicy:
    def test_very_long_policy_penalized(self):
        """Política muito longa (> 5x baseline) recebe penalidade."""
        path = _write_tmp(VERY_LONG_POLICY)
        r = VALIDATOR.validate(path)
        # VERY_LONG_POLICY tem ~10k chars, baseline=500 → ratio~20 → penalidade
        assert r.hygiene_grade <= 4

    def test_very_long_has_issue(self):
        """Política inflada deve ter issue descritivo."""
        path = _write_tmp(VERY_LONG_POLICY)
        r = VALIDATOR.validate(path)
        assert any("longa" in iss.lower() or "inflado" in iss.lower() for iss in r.issues)


# ─── Política repetitiva ──────────────────────────────────────────────────────

class TestRepetitivePolicy:
    def test_repetitive_policy_penalized(self):
        """Política com alta repetição de trigrams recebe penalidade."""
        path = _write_tmp(REPETITIVE_POLICY)
        r = VALIDATOR.validate(path)
        # Trigram repetition deve ser alta
        assert r.trigram_repetition > MAX_TRIGRAM_REPETITION
        assert r.hygiene_grade <= 4

    def test_repetitive_has_issue(self):
        """Política repetitiva deve ter issue sobre trigrams."""
        path = _write_tmp(REPETITIVE_POLICY)
        r = VALIDATOR.validate(path)
        assert any("trigram" in iss.lower() or "repetição" in iss.lower() for iss in r.issues)


# ─── Limites de grade ─────────────────────────────────────────────────────────

class TestGradeBoundaries:
    def test_is_healthy_true_when_grade_gte_4(self):
        """is_healthy=True para grade >= 4."""
        path = _write_tmp(HEALTHY_POLICY)
        r = VALIDATOR.validate(path)
        if r.hygiene_grade >= 4:
            assert r.is_healthy is True

    def test_is_healthy_false_when_grade_lt_4(self):
        """is_healthy=False para grade < 4."""
        path = _write_tmp(VERY_SHORT_POLICY)
        r = VALIDATOR.validate(path)
        if r.hygiene_grade < 4:
            assert r.is_healthy is False

    def test_grade_never_negative(self):
        """Grade nunca negativo mesmo com múltiplas penalidades."""
        path = _write_tmp(VERY_SHORT_POLICY)
        r = VALIDATOR.validate(path)
        assert r.hygiene_grade >= 0

    def test_grade_never_above_max(self):
        """Grade nunca acima de GRADE_MAX."""
        path = _write_tmp(HEALTHY_POLICY)
        r = VALIDATOR.validate(path)
        assert r.hygiene_grade <= GRADE_MAX


# ─── Métricas individuais ─────────────────────────────────────────────────────

class TestMetrics:
    def test_length_ratio_near_one_for_baseline_sized(self):
        """Política com tamanho próximo ao baseline tem ratio ~1.0."""
        content = "a " * (BASELINE_LENGTH_CHARS // 2)  # ~500 chars
        path = _write_tmp(content)
        r = VALIDATOR.validate(path)
        assert 0.5 <= r.length_ratio <= 2.0

    def test_trigram_repetition_zero_for_unique_content(self):
        """Conteúdo sem repetições tem trigram_repetition=0.0."""
        unique_content = " ".join(f"word{i}" for i in range(50))
        path = _write_tmp(unique_content)
        r = VALIDATOR.validate(path)
        assert r.trigram_repetition == 0.0

    def test_trigram_repetition_range(self):
        """trigram_repetition sempre em [0.0, 1.0]."""
        for content in [HEALTHY_POLICY, REPETITIVE_POLICY, VERY_SHORT_POLICY]:
            path = _write_tmp(content)
            r = VALIDATOR.validate(path)
            assert 0.0 <= r.trigram_repetition <= 1.0


# ─── Fail-secure ──────────────────────────────────────────────────────────────

class TestFailSecure:
    def test_fail_secure_on_missing_file(self):
        """Arquivo inexistente → HygieneReport com grade=0 (fail-secure)."""
        r = VALIDATOR.validate(Path("/nonexistent/policy.yaml"))
        assert r.hygiene_grade == 0
        assert r.is_healthy is False
        assert "FAIL-SECURE" in r.explain_decision

    def test_fail_secure_signature_valid(self):
        """Fail-secure ainda gera assinatura válida."""
        r = VALIDATOR.validate(Path("/nonexistent/policy.yaml"))
        assert _verify_signature(r)

    def test_fail_secure_explain_decision_present(self):
        """Fail-secure inclui explain_decision (Levinas)."""
        r = VALIDATOR.validate(Path("/nonexistent/policy.yaml"))
        assert r.explain_decision
        assert len(r.explain_decision) > 30

    def test_fail_secure_has_issue(self):
        """Fail-secure inclui issue descritivo."""
        r = VALIDATOR.validate(Path("/nonexistent/policy.yaml"))
        assert len(r.issues) > 0

    def test_fail_secure_length_ratio_zero(self):
        """Fail-secure reporta length_ratio=0.0."""
        r = VALIDATOR.validate(Path("/nonexistent/policy.yaml"))
        assert r.length_ratio == 0.0


# ─── Thread-safety ────────────────────────────────────────────────────────────

class TestThreadSafety:
    def test_stateless_validator_can_be_shared(self):
        """Mesma instância pode validar múltiplos arquivos sem conflito."""
        path1 = _write_tmp(HEALTHY_POLICY)
        path2 = _write_tmp(VERY_SHORT_POLICY)
        r1 = VALIDATOR.validate(path1)
        r2 = VALIDATOR.validate(path2)
        # Resultados independentes
        assert r1.hygiene_grade != r2.hygiene_grade

    def test_multiple_validations_consistent(self):
        """Mesma política validada duas vezes retorna mesmo grade."""
        path = _write_tmp(HEALTHY_POLICY)
        r1 = VALIDATOR.validate(path)
        r2 = VALIDATOR.validate(path)
        assert r1.hygiene_grade == r2.hygiene_grade
        assert r1.length_ratio == r2.length_ratio
        assert r1.trigram_repetition == r2.trigram_repetition
