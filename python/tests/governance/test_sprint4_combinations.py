"""
Testes Sprint 4 — Gaps 8, 18
SessionSensitivityAccumulator v1.2.0: 6 novas DANGEROUS_COMBINATIONS
"""
import pytest
from buildtovalue.governance.sensitivity_accumulator import (
    SessionSensitivityAccumulator, DANGEROUS_COMBINATIONS, FREQ_HIGH_RISK_TAGS,
)

acc = lambda: SessionSensitivityAccumulator()


# ── Gap 8: Corporativas ──────────────────────────────────────────────────────

def test_gap8_cnpj_credit_card_detected():
    """CNPJ + cartão = fraude corporativa — era bypass silencioso."""
    a = acc()
    state = a.accumulate("s1", ["cnpj", "credit_card"])
    assert state.cumulative_risk > 0.0
    assert a.metrics["combinations_detected"] == 1

def test_gap8_cnpj_cpf_detected():
    """CNPJ + CPF = sócio + empresa — dossier corporativo completo."""
    a = acc()
    state = a.accumulate("s1", ["cnpj", "cpf"])
    assert state.cumulative_risk > 0.0
    assert a.metrics["combinations_detected"] == 1

def test_gap8_cnpj_alone_not_risky():
    """CNPJ isolado: sem combinação ativa = risco 0."""
    a = acc()
    state = a.accumulate("s1", ["cnpj"])
    assert state.cumulative_risk == 0.0
    assert a.metrics["combinations_detected"] == 0


# ── Gap 8: Cross-jurisdicionais ──────────────────────────────────────────────

def test_gap8_vat_iban_detected():
    """VAT + IBAN = fraude fiscal europeia — era bypass silencioso."""
    a = acc()
    state = a.accumulate("s1", ["vat", "iban"])
    assert state.cumulative_risk > 0.0
    assert a.metrics["combinations_detected"] == 1

def test_gap8_vat_alone_not_risky():
    """VAT isolado: PII_EU_FISCAL sem combinação = risco 0."""
    a = acc()
    state = a.accumulate("s1", ["vat"])
    assert state.cumulative_risk == 0.0


# ── Gap 18: Injection expandido ──────────────────────────────────────────────

def test_gap18_injection_ssn_detected():
    """Injection + SSN = exfiltração gov EUA — era bypass silencioso."""
    a = acc()
    state = a.accumulate("s1", ["prompt_injection", "ssn"])
    assert state.cumulative_risk > 0.0
    assert a.metrics["combinations_detected"] == 1

def test_gap18_injection_nhs_detected():
    """Injection + NHS = exfiltração saúde UK."""
    a = acc()
    state = a.accumulate("s1", ["prompt_injection", "nhs"])
    assert state.cumulative_risk > 0.0
    assert a.metrics["combinations_detected"] == 1

def test_gap18_injection_vat_detected():
    """Injection + VAT = exfiltração fiscal EU."""
    a = acc()
    state = a.accumulate("s1", ["prompt_injection", "vat"])
    assert state.cumulative_risk > 0.0
    assert a.metrics["combinations_detected"] == 1


# ── Contagem total ────────────────────────────────────────────────────────────

def test_total_combinations_count():
    """v1.2.0 deve ter exatamente 12 DANGEROUS_COMBINATIONS."""
    assert len(DANGEROUS_COMBINATIONS) == 12

def test_freq_high_risk_tags_covers_new_combos():
    """FREQ_HIGH_RISK_TAGS cobre as novas tags automaticamente."""
    assert "PII_BRAZILIAN_CORPORATE" in FREQ_HIGH_RISK_TAGS
    assert "PII_EU_FISCAL"           in FREQ_HIGH_RISK_TAGS
    assert "FINANCIAL_EU"            in FREQ_HIGH_RISK_TAGS
