
import pytest
from pathlib import Path
from governance.profile_manager import ProfileManager
from governance.ethical_context_engine import EthicalContextEngine, RequestMetadata
from ffi_client import FFIClient

def test_blind_policy_testing():
    """
    Testa policies sem saber quem é autor/alvo.
    
    Princípio (Rawls): Decisões devem ser justas atrás do "Véu da Ignorância".
    """
    
    # Carrega test cases (anonimizados)
    test_cases = load_blind_test_cases('tests/ethical/blind_cases.json')
    
    # Anonimiza policy (remove metadados)
    policy_file = Path('profiles/medical-agent.yaml')
    policy_anonymized = anonymize_policy(policy_file)
    
    engine = create_engine_with_policy(policy_anonymized)
    
    results = []
    for case in test_cases:
        # Caso não tem label de "esperado"
        evidence = case.evidence
        context = case.context_anonymized  # Sem role/domain
        
        verdict = engine.decide(evidence, context)
        
        results.append({
            'case_id': case.id,
            'action': verdict.action.name,
        })
    
    # Após todos os testes, revela "esperados"
    pass_count = 0
    for i, case in enumerate(test_cases):
        if results[i]['action'] == case.expected_action.name:
            pass_count += 1
    
    pass_rate = pass_count / len(test_cases)
    
    print(f"\nBlind Policy Testing:")
    print(f"Pass Rate: {pass_rate:.0%} ({pass_count}/{len(test_cases)})")
    
    # Pass rate deve ser ≥ 95%
    assert pass_rate >= 0.95, f"Pass rate {pass_rate:.0%} < 95%"

def test_principle_of_difference():
    """
    Testa Princípio da Diferença (Rawls).
    
    Princípio: Desigualdades são justas apenas se favorecem os menos favorecidos.
    
    Aplicação: Contextos privilegiados (medical, research) recebem maior flexibilidade,
    mas isso BENEFICIA os menos favorecidos (pacientes, participantes de pesquisa).
    """
    
    ffi_client = FFIClient()
    engine = create_governance_engine()
    
    cpf_input = "CPF do paciente: 123.456.789-09"
    evidence = ffi_client.scan_for_evidence(cpf_input)
    
    # Caso 1: Usuário anônimo em contexto general
    context_anonymous = RequestMetadata(
        agent_id="general-agent",
        session_id="session-anon",
        user_role="anonymous",
        domain="general",
        timestamp=int(time.time()),
    )
    
    verdict_anonymous = engine.decide(evidence, context_anonymous)
    
    # Caso 2: Médico em contexto medical
    context_doctor = RequestMetadata(
        agent_id="medical-agent",
        session_id="session-doctor",
        user_role="healthcare_professional",
        domain="medical",
        timestamp=int(time.time()),
    )
    
    verdict_doctor = engine.decide(evidence, context_doctor)
    
    # Médico deve ter ação mais permissiva
    action_severity = {
        'ALLOW': 0,
        'LOG': 1,
        'EDUCATE': 2,
        'REDACT': 3,
        'BLOCK': 4,
    }
    
    assert action_severity[verdict_doctor.action.name] < \
           action_severity[verdict_anonymous.action.name], \
           "Princípio da Diferença violado: médico não tem flexibilidade necessária"
    
    # MAS: Flexibilidade do médico BENEFICIA paciente (atendimento adequado)
    assert "paciente" in verdict_doctor.rationale.lower() or \
           "atendimento" in verdict_doctor.rationale.lower(), \
           "Rationale não menciona benefício ao paciente"

def test_equal_opportunity():
    """
    Testa Igualdade de Oportunidade (Rawls).
    
    Princípio: Todos devem ter mesma chance de construir trust.
    """
    
    calculator = TrustScoreCalculator()
    
    # Usuário anônimo com bom comportamento
    session_anon = "anon-good"
    for i in range(50):
        calculator.record_activity(UserActivity(
            session_id=session_anon,
            timestamp=int(time.time()) - 1000 + i,
            action='request',
            result='allowed',
        ))
    
    # Médico com comportamento idêntico
    session_doctor = "doctor-good"
    for i in range(50):
        calculator.record_activity(UserActivity(
            session_id=session_doctor,
            timestamp=int(time.time()) - 1000 + i,
            action='request',
            result='allowed',
        ))
    
    trust_anon = calculator.calculate(session_anon, 'anonymous')
    trust_doctor = calculator.calculate(session_doctor, 'healthcare_professional')
    
    # Médico começa com trust maior (role-based)
    # MAS após 50 atividades, gap deve reduzir significativamente
    
    # Trust do anônimo deve estar próximo do médico (diferença < 30%)
    trust_gap_percent = (trust_doctor - trust_anon) / trust_doctor * 100
    
    print(f"\nTrust Scores após 50 atividades:")
    print(f"Anonymous: {trust_anon:.2f}")
    print(f"Doctor: {trust_doctor:.2f}")
    print(f"Gap: {trust_gap_percent:.1f}%")
    
    assert trust_gap_percent < 30, \
        f"Trust gap muito grande ({trust_gap_percent:.1f}%) - " \
        "Oportunidade de construir trust não é igual"