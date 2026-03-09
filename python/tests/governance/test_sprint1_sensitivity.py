"""
Testes Sprint 1 + Sprint 4 — Gaps 6 e 7
SessionSensitivityAccumulator v1.3.0

Historico:
  Sprint 1: 6 DANGEROUS_COMBINATIONS originais.
  Sprint 4 (Gaps 8/18): +6 novas combinacoes.
    PII_EU_FISCAL agora esta em FREQ_HIGH_RISK_TAGS.
    ALL_DANGEROUS_FINDINGS ativa 8 das 12 combinacoes.
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

# findings que ativam 8 combinacoes com as 12 do Sprint 4
ALL_DANGEROUS_FINDINGS = ["cpf", "credit_card", "email", "prompt_injection", "ssn", "nhs"]
# findings que ativam 2 combos com 3 tags (caso parcial documentado)
PARTIAL_FINDINGS = ["cpf", "credit_card", "email"]


# ── Gap 6: _frequency_boost unit ──────────────────────────────────────────

def test_gap6_single_occurrence_no_freq_boost():
    """Uma unica ocorrencia nao gera boost."""
    a = acc()
    state = a.accumulate("s1", ["cpf"])
    assert state.cumulative_risk == 0.0


def test_gap6_repeated_tag_adds_freq_boost():
    """CPF aparece 5x -> freq_boost > 0 mesmo sem combinacao ativa."""
    a = acc()
    for _ in range(5):
        state = a.accumulate("s1", ["cpf"])
    assert state.cumulative_risk == pytest.approx(0.08, abs=1e-9)


def test_gap6_combination_plus_freq_boost():
    """CPF + cartao (combinacao ativa) + repeticao = risco combinado."""
    a = acc()
    for _ in range(3):
        a.accumulate("s1", ["cpf", "credit_card"])
    state = a.accumulate("s1", ["cpf"])
    assert state.cumulative_risk > COMBINATION_RISK_BOOST


def test_gap6_max_risk_3tags_is_084():
    """
    Maximo alcancavel com 3 findings (cpf+credit_card+email):
      combination_boost = 2 combos x 0.15 = 0.30
      freq_boost = 3 tags x 9 x 0.02 = 0.54
      total = 0.84
    """
    a = acc()
    for _ in range(100):
        state = a.accumulate("s1", PARTIAL_FINDINGS)
    assert state.cumulative_risk == pytest.approx(0.84, abs=1e-9)


def test_gap6_saturates_at_1_all_combos():
    """
    Todas as combinacoes ativas + frequencia alta -> satura em 1.0.
    """
    a = acc()
    for _ in range(100):
        state = a.accumulate("s1", ALL_DANGEROUS_FINDINGS)
    assert state.cumulative_risk == pytest.approx(1.0)


def test_gap6_benign_tag_no_boost():
    """
    Tag genuinamente benigna (sem sensitivity mapping) nao gera freq_boost.

    Nota Sprint 4: PII_EU_FISCAL foi adicionado a DANGEROUS_COMBINATIONS
    (combo VAT+IBAN para jurisdicao EU) e agora ESTA em FREQ_HIGH_RISK_TAGS.
    Teste atualizado: verifica invariante com tag sem mapeamento de sensitivity.
    """
    # Sprint 4: PII_EU_FISCAL e agora um risk tag
    assert "PII_EU_FISCAL" in FREQ_HIGH_RISK_TAGS
    # Tag sem mapeamento de sensitivity nao gera boost mesmo com repeticoes
    a = acc()
    for _ in range(10):
        state = a.accumulate("s1", ["unknown_benign_tag_xyz"])
    assert state.cumulative_risk == 0.0


# ── Gap 7: metrics corretos ──────────────────────────────────────────────

def test_gap7_metrics_not_inflated():
    """Gap 7: combinations_detected conta apenas novas descobertas."""
    a = acc()
    a.accumulate("s1", ["cpf", "credit_card"])
    assert a.metrics["combinations_detected"] == 1
    a.accumulate("s1", ["cpf"])
    a.accumulate("s1", ["credit_card"])
    assert a.metrics["combinations_detected"] == 1


def test_gap7_new_combo_increments():
    """Segunda combinacao distinta incrementa o contador corretamente."""
    a = acc()
    a.accumulate("s1", ["cpf", "credit_card"])
    a.accumulate("s1", ["cpf", "email"])
    assert a.metrics["combinations_detected"] == 2


def test_gap7_all_combos_count_once():
    """
    Sprint 1 original: 6 DANGEROUS_COMBINATIONS.
    Sprint 4 (Gaps 8/18): +2 novas ativadas por ALL_DANGEROUS_FINDINGS:
      - SECURITY_INJECTION + PII_US_GOV  (prompt_injection + ssn)
      - SECURITY_INJECTION + PII_UK_HEALTH (prompt_injection + nhs)
    Total ativado por ALL_DANGEROUS_FINDINGS: 8 combinacoes.
    Cada combinacao e contada uma unica vez (idempotente).
    """
    a = acc()
    a.accumulate("s1", ALL_DANGEROUS_FINDINGS)
    assert a.metrics["combinations_detected"] == 8
    # Segunda chamada: nenhuma nova combo — idempotente
    a.accumulate("s1", ALL_DANGEROUS_FINDINGS)
    assert a.metrics["combinations_detected"] == 8
