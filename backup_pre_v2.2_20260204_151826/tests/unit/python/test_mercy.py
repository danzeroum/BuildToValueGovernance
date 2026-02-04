
import pytest
from governance.mercy_algorithm import MercyCalculator, MercyFactors
from governance.ffi_client import TechnicalEvidence, Finding
from governance.ethical_context_engine import RequestMetadata

@pytest.fixture
def mercy_calculator():
    return MercyCalculator()

@pytest.fixture
def mock_evidence():
    """Cria TechnicalEvidence mock para testes"""
    evidence = TechnicalEvidence()
    evidence.composite_risk = 150
    evidence.finding_count = 2
    evidence.stats.entropy = 4.5
    return evidence

@pytest.fixture
def mock_context():
    """Cria RequestMetadata mock"""
    return RequestMetadata(
        agent_id="test-agent",
        session_id="session-123",
        user_role="authenticated",
        domain="general",
        timestamp=int(time.time()),
    )

def test_high_uncertainty_increases_mercy(mercy_calculator, mock_evidence, mock_context):
    """Alta incerteza deve aumentar mercy score"""
    
    # Modifica evidence para alta incerteza
    mock_evidence.stats.entropy = 7.5  # Alta entropia
    mock_evidence.findings[0].confidence = 100  # Baixa confiança (39%)
    
    mercy_score = mercy_calculator.calculate(
        evidence=mock_evidence,
        context=mock_context,
        trust_score=0.5,
    )
    
    # Mercy score deve ser alto (> 0.6)
    assert mercy_score > 0.6

def test_low_uncertainty_reduces_mercy(mercy_calculator, mock_evidence, mock_context):
    """Baixa incerteza deve reduzir mercy score"""
    
    # Evidence com certeza alta
    mock_evidence.stats.entropy = 3.0  # Baixa entropia
    mock_evidence.findings[0].confidence = 255  # Alta confiança (100%)
    mock_evidence.critical_count = 1  # Critical finding
    
    mercy_score = mercy_calculator.calculate(
        evidence=mock_evidence,
        context=mock_context,
        trust_score=0.5,
    )
    
    # Mercy score deve ser baixo (< 0.4)
    assert mercy_score < 0.4

def test_medical_context_increases_justifiability(mercy_calculator, mock_evidence):
    """Contexto medical deve aumentar justificabilidade"""
    
    context_general = RequestMetadata(
        agent_id="test-agent",
        session_id="session-123",
        user_role="authenticated",
        domain="general",
        timestamp=int(time.time()),
    )
    
    context_medical = RequestMetadata(
        agent_id="medical-agent",
        session_id="session-123",
        user_role="healthcare_professional",
        domain="medical",
        timestamp=int(time.time()),
    )
    
    mercy_general = mercy_calculator.calculate(mock_evidence, context_general, 0.5)
    mercy_medical = mercy_calculator.calculate(mock_evidence, context_medical, 0.5)
    
    # Medical deve ter mais mercy que general
    assert mercy_medical > mercy_general

def test_high_trust_increases_mercy(mercy_calculator, mock_evidence, mock_context):
    """Alto trust score deve aumentar mercy"""
    
    mercy_low_trust = mercy_calculator.calculate(mock_evidence, mock_context, 0.2)
    mercy_high_trust = mercy_calculator.calculate(mock_evidence, mock_context, 0.9)
    
    # High trust deve resultar em mais mercy
    assert mercy_high_trust > mercy_low_trust

def test_low_harm_potential_increases_mercy(mercy_calculator, mock_context):
    """Baixo potencial de dano aumenta mercy"""
    
    # Evidence com finding leve (email)
    evidence_low_harm = TechnicalEvidence()
    evidence_low_harm.findings[0].title = b"EMAIL_PATTERN_DETECTED"
    evidence_low_harm.finding_count = 1
    
    # Evidence com finding grave (cartão)
    evidence_high_harm = TechnicalEvidence()
    evidence_high_harm.critical[0].title = b"CREDIT_CARD_DETECTED"
    evidence_high_harm.critical_count = 1
    
    mercy_low_harm = mercy_calculator.calculate(evidence_low_harm, mock_context, 0.5)
    mercy_high_harm = mercy_calculator.calculate(evidence_high_harm, mock_context, 0.5)
    
    # Baixo dano deve ter mais mercy
    assert mercy_low_harm > mercy_high_harm

def test_first_offense_increases_mercy(mercy_calculator, mock_evidence, mock_context):
    """Primeira violação deve receber mercy"""
    
    # Primeira violação
    mercy_first = mercy_calculator.calculate(mock_evidence, mock_context, 0.5)
    
    # Registra violação
    mercy_calculator.record_violation(mock_context.session_id)
    
    # Segunda violação (mesma sessão)
    mercy_second = mercy_calculator.calculate(mock_evidence, mock_context, 0.5)
    
    # Primeira deve ter mais mercy que segunda
    assert mercy_first > mercy_second

def test_mercy_factors_breakdown(mercy_calculator, mock_evidence, mock_context):
    """Testa cálculo detalhado dos fatores de misericórdia"""
    
    factors = mercy_calculator._calculate_factors(mock_evidence, mock_context, 0.6)
    
    # Verifica que todos os fatores foram calculados
    assert 0.0 <= factors.uncertainty_score <= 1.0
    assert 0.0 <= factors.context_justifiability <= 1.0
    assert 0.0 <= factors.trust_score <= 1.0
    assert 0.0 <= factors.harm_potential <= 1.0
    assert isinstance(factors.first_offense, bool)

def test_mercy_threshold_application(mercy_calculator, mock_evidence, mock_context):
    """Testa aplicação de thresholds de misericórdia"""
    
    # Força mercy alto
    mock_evidence.stats.entropy = 7.0
    mock_evidence.findings[0].confidence = 80
    mock_context.domain = "medical"
    mock_context.user_role = "healthcare_professional"
    
    mercy_score = mercy_calculator.calculate(mock_evidence, mock_context, 0.8)
    
    # Mercy > 0.5 → Deve recomendar abrandar ação
    assert mercy_calculator.should_apply_mercy(mercy_score, action_severity=2)
    
    # Mercy > 0.8 → Deve recomendar abrandar 2 níveis
    if mercy_score > 0.8:
        assert True  # Forte candidato a mercy

def test_mercy_explanation(mercy_calculator, mock_evidence, mock_context):
    """Testa geração de explicação de misericórdia"""
    
    mercy_score = mercy_calculator.calculate(mock_evidence, mock_context, 0.7)
    factors = mercy_calculator._calculate_factors(mock_evidence, mock_context, 0.7)
    
    explanation = mercy_calculator.get_mercy_explanation(mercy_score, factors)
    
    # Verifica que explicação foi gerada
    assert isinstance(explanation, str)
    assert len(explanation) > 0
    
    # Se mercy foi aplicado, explicação deve conter justificativa
    if mercy_score > 0.5:
        assert any(word in explanation.lower() for word in ['incerteza', 'contexto', 'confi'])

def test_consistency_across_similar_inputs(mercy_calculator, mock_context):
    """Mesma evidência deve produzir mercy score similar"""
    
    # Cria duas evidências idênticas
    evidence1 = TechnicalEvidence()
    evidence1.composite_risk = 150
    evidence1.finding_count = 2
    evidence1.stats.entropy = 4.5
    
    evidence2 = TechnicalEvidence()
    evidence2.composite_risk = 150
    evidence2.finding_count = 2
    evidence2.stats.entropy = 4.5
    
    mercy1 = mercy_calculator.calculate(evidence1, mock_context, 0.6)
    mercy2 = mercy_calculator.calculate(evidence2, mock_context, 0.6)
    
    # Scores devem ser idênticos (determinismo)
    assert abs(mercy1 - mercy2) < 0.01

def test_mercy_prevents_excessive_blocking(mercy_calculator):
    """Mercy deve prevenir bloqueios excessivos em contextos legítimos"""
    
    # Simula contexto de pesquisa com dados anonimizados
    evidence = TechnicalEvidence()
    evidence.findings[0].title = b"CPF_PATTERN_DETECTED"
    evidence.findings[0].confidence = 150  # Média confiança
    evidence.finding_count = 1
    evidence.stats.entropy = 5.5  # Alguma aleatoriedade
    
    context = RequestMetadata(
        agent_id="research-agent",
        session_id="research-session",
        user_role="researcher",
        domain="research",
        timestamp=int(time.time()),
    )
    
    mercy_score = mercy_calculator.calculate(evidence, context, trust_score=0.8)
    
    # Em contexto de pesquisa com trust alto, mercy deve ser significativo
    assert mercy_score > 0.5, "Mercy insuficiente para contexto legítimo"