"""
Testes Sprint 1 — Gaps 6 e 7
SessionSensitivityAccumulator v1.1.0
"""
import pytest
from buildtovalue.governance.sensitivity_accumulator import (
    SessionSensitivityAccumulator,
    _frequency_boost,
    FREQ_HIGH_RISK_TAGS,
    COMBINATION_RISK_BOOST,
    FREQ_WEIGHT_PER_REPEAT,
    FREQ_MAX_COUNT,
)

acc = lambda: SessionSensitivityAccumulator()

# findings que ativam TODAS as 6 DANGEROUS_COMBINATIONS
ALL_DANGEROUS_FINDINGS = ["cpf", "credit_card", "email", "prompt_injection", "ssn", "nhs"]
# findings que ativam 2 combos com 3 tags (caso parcial documentado)
PARTIAL_FINDINGS = ["cpf", "credit_card", "email"]


# ── Gap 6: _frequency_boost unit ──────────────────────────────────────────

def test_gap6_single_occurrence_no_freq_boost():
    """Uma única ocorrência não gera boost — pode ser request legítimo."""
    a = acc()
    state = a.accumulate("s1", ["cpf"])
    assert state.cumulative_risk == 0.0


def test_gap6_repeated_tag_adds_freq_boost():
    """CPF aparece 5x → freq_boost > 0 mesmo sem combinação ativa."""
    a = acc()
    for _ in range(5):
        state = a.accumulate("s1", ["cpf"])
    # 4 repeats × 0.02 = 0.08
    assert state.cumulative_risk == pytest.approx(0.08, abs=1e-9)


def test_gap6_combination_plus_freq_boost():
    """CPF + cartão (combinação ativa) + repetição = risco combinado."""
    a = acc()
    for _ in range(3):
        a.accumulate("s1", ["cpf", "credit_card"])
    state = a.accumulate("s1", ["cpf"])
    assert state.cumulative_risk > COMBINATION_RISK_BOOST


def test_gap6_max_risk_3tags_is_084():
    """
    Documenta o máximo alcançável com 3 findings (cpf+credit_card+email):
      combination_boost = 2 combos × 0.15 = 0.30
      freq_boost = 3 tags × min(99, 9) × 0.02 = 3 × 0.18 = 0.54
      total = 0.84 — correto, não é bug.
    Para saturar em 1.0 é necessário ativar todas as 6 combinações.
    """
    a = acc()
    for _ in range(100):
        state = a.accumulate("s1", PARTIAL_FINDINGS)
    assert state.cumulative_risk == pytest.approx(0.84, abs=1e-9)


def test_gap6_saturates_at_1_all_combos():
    """
    Todas as 6 DANGEROUS_COMBINATIONS ativas + frequência alta → satura em 1.0.
      combination_boost = 6 × 0.15 = 0.90
      freq_boost = 6 tags × 9 × 0.02 = 1.08
      min(1.0, 1.98) = 1.0
    """
    a = acc()
    for _ in range(100):
        state = a.accumulate("s1", ALL_DANGEROUS_FINDINGS)
    assert state.cumulative_risk == pytest.approx(1.0)


def test_gap6_benign_tag_no_boost():
    """Tag fora de FREQ_HIGH_RISK_TAGS (PII_EU_FISCAL) não gera freq_boost."""
    a = acc()
    for _ in range(10):
        state = a.accumulate("s1", ["vat"])
    assert "PII_EU_FISCAL" not in FREQ_HIGH_RISK_TAGS
    assert state.cumulative_risk == 0.0


# ── Gap 7: metrics corretos ──────────────────────────────────────────────

def test_gap7_metrics_not_inflated():
    """Gap 7: combinations_detected conta apenas novas descobertas, não re-counts."""
    a = acc()
    a.accumulate("s1", ["cpf", "credit_card"])  # combo 1: nova
    assert a.metrics["combinations_detected"] == 1
    a.accumulate("s1", ["cpf"])                  # combo já ativa: não incrementa
    a.accumulate("s1", ["credit_card"])          # idem
    assert a.metrics["combinations_detected"] == 1


def test_gap7_new_combo_increments():
    """Segunda combinação distinta incrementa o contador corretamente."""
    a = acc()
    a.accumulate("s1", ["cpf", "credit_card"])   # combo 1
    a.accumulate("s1", ["cpf", "email"])         # combo 2: PII_CONTACT+PII_BRAZILIAN
    assert a.metrics["combinations_detected"] == 2


def test_gap7_all_6_combos_count_once():
    """Todas as 6 combinações ativadas em um único request: metrics=6."""
    a = acc()
    a.accumulate("s1", ALL_DANGEROUS_FINDINGS)
    assert a.metrics["combinations_detected"] == 6
    # Segunda chamada: nenhuma nova combo
    a.accumulate("s1", ALL_DANGEROUS_FINDINGS)
    assert a.metrics["combinations_detected"] == 6
