
import pytest
from governance.mercy_algorithm import MercyCalculator
from governance.ethical_context_engine import EthicalContextEngine, ActionType

def test_context_over_rule():
    """
    Testa que contexto pode sobrepor regra.
    
    Princípio (Gilligan): Contexto importa mais que regras abstratas.
    """
    
    ffi_client = FFIClient()
    engine = create_governance_engine()
    
    cpf_input = "Discussão sobre CPF 123.456.789-09"
    evidence = ffi_client.scan_for_evidence(cpf_input)
    
    # Contexto 1: General → BLOCK (regra)
    context_general = RequestMetadata(
        agent_id="general-agent",
        session_id="session-001",
        user_role="authenticated",
        domain="general",
        timestamp=int(time.time()),
    )
    
    verdict_general = engine.decide(evidence, context_general)
    assert verdict_general.action == ActionType.BLOCK
    
    # Contexto 2: Medical → EDUCATE (contexto sobrepõe regra)
    context_medical = RequestMetadata(
        agent_id="medical-agent",
        session_id="session-001",
        user_role="healthcare_professional",
        domain="medical",
        timestamp=int(time.time()),
    )
    
    verdict_medical = engine.decide(evidence, context_medical)
    
    # Contexto médico deve abrandar ação (EDUCATE ou LOG, não BLOCK)
    assert verdict_medical.action in [ActionType.EDUCATE, ActionType.LOG], \
        "Contexto não sobrepôs regra (Gilligan violado)"

def test_mercy_in_uncertainty():
    """
    Testa que sistema aplica misericórdia em casos de incerteza.
    
    Princípio (Gilligan): Quando não temos certeza, devemos errar para o lado do cuidado.
    """
    
    mercy_calc = MercyCalculator()
    
    # Evidence com alta incerteza
    evidence_uncertain = create_mock_evidence(
        entropy=7.5,  # Alta entropia
        confidence=120,  # Baixa confiança (47%)
        finding_count=1,
    )
    
    context = RequestMetadata(
        agent_id="test-agent",
        session_id="session-001",
        user_role="authenticated",
        domain="general",
        timestamp=int(time.time()),
    )
    
    mercy_score = mercy_calc.calculate(evidence_uncertain, context, trust_score=0.5)
    
    # Alta incerteza deve resultar em mercy score alto
    assert mercy_score > 0.6, \
        f"Mercy score baixo ({mercy_score:.2f}) para alta incerteza (Gilligan violado)"

def test_relationship_based_decision():
    """
    Testa que histórico do usuário influencia decisão.
    
    Princípio (Gilligan): Decisões devem considerar relacionamento/histórico.
    """
    
    engine = create_governance_engine()
    ffi_client = FFIClient()
    
    cpf_input = "CPF: 123.456.789-09"
    evidence = ffi_client.scan_for_evidence(cpf_input)
    
    # Usuário novo (sem histórico)
    context_new = RequestMetadata(
        agent_id="test-agent",
        session_id="session-new",
        user_role="authenticated",
        domain="general",
        timestamp=int(time.time()),
    )
    
    verdict_new = engine.decide(evidence, context_new)
    
    # Usuário com bom histórico
    session_good = "session-good"
    
    # Registra 100 atividades permitidas
    for i in range(100):
        engine.trust_calculator.record_activity(UserActivity(
            session_id=session_good,
            timestamp=int(time.time()) - 1000 + i,
            action='request',
            result='allowed',
        ))
    
    context_good = RequestMetadata(
        agent_id="test-agent",
        session_id=session_good,
        user_role="authenticated",
        domain="general",
        timestamp=int(time.time()),
    )
    
    verdict_good = engine.decide(evidence, context_good)
    
    # Usuário com bom histórico deve ter decisão mais permissiva
    # (ou mesma ação mas com mercy_score maior)
    
    if verdict_good.action == verdict_new.action:
        # Mesma ação, mas mercy_score deve ser maior
        assert verdict_good.mercy_score > verdict_new.mercy_score, \
            "Histórico não influenciou mercy (Gilligan violado)"
    else:
        # Ação mais permissiva
        action_severity = {
            ActionType.ALLOW: 0,
            ActionType.LOG: 1,
            ActionType.EDUCATE: 2,
            ActionType.REDACT: 3,
            ActionType.BLOCK: 4,
        }
        assert action_severity[verdict_good.action] < action_severity[verdict_new.action], \
            "Histórico não abrandou ação (Gilligan violado)"

def test_care_in_feedback_loop():
    """
    Testa que sistema aprende com erros (apelações).
    
    Princípio (Gilligan): Cuidado implica aprender e melhorar com feedback.
    """
    
    engine = create_governance_engine()
    session_id = "session-feedback"
    
    # Usuário bloqueado
    for i in range(5):
        engine.trust_calculator.record_activity(UserActivity(
            session_id=session_id,
            timestamp=int(time.time()) - 100 + i,
            action='request',
            result='blocked',
        ))
    
    trust_before = engine.trust_calculator.calculate(session_id, 'authenticated')
    
    # Apelações bem-sucedidas (sistema errou)
    for i in range(3):
        engine.trust_calculator.record_activity(UserActivity(
            session_id=session_id,
            timestamp=int(time.time()) - 50 + i,
            action='appeal',
            result='appealed_success',
        ))
    
    trust_after = engine.trust_calculator.calculate(session_id, 'authenticated')
    
    # Trust deve ter aumentado (sistema reconheceu erro)
    assert trust_after > trust_before, \
        "Sistema não aprendeu com feedback (Gilligan violado)"
    
    print(f"\nFeedback Loop:")
    print(f"Trust antes: {trust_before:.2f}")
    print(f"Trust após apelações: {trust_after:.2f}")
    print(f"Aumento: {((trust_after - trust_before) / trust_before) * 100:.1f}%")