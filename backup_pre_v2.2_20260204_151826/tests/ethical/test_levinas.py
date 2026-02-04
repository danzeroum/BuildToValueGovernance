
import pytest
from governance.ethical_context_engine import EthicalContextEngine, ActionType

def test_educate_before_punish():
    """
    Testa que sistema educa antes de punir.
    
    Princípio (Levinas): Responsabilidade pelo Outro → educar, não apenas bloquear.
    """
    
    engine = create_governance_engine()
    ffi_client = FFIClient()
    
    # Input com CNPJ (menos grave que CPF)
    cnpj_input = "CNPJ da empresa: 12.345.678/0001-90"
    evidence = ffi_client.scan_for_evidence(cnpj_input)
    
    context = RequestMetadata(
        agent_id="general-agent",
        session_id="session-001",
        user_role="authenticated",
        domain="general",
        timestamp=int(time.time()),
    )
    
    verdict = engine.decide(evidence, context)
    
    # CNPJ em contexto geral deve ser EDUCATE (não BLOCK)
    assert verdict.action in [ActionType.EDUCATE, ActionType.LOG], \
        "Sistema não educa antes de punir (Levinas violado)"
    
    # Rationale deve conter mensagem educativa
    assert "contexto" in verdict.rationale.lower() or \
           "legítim" in verdict.rationale.lower() or \
           "apropriado" in verdict.rationale.lower(), \
           "Rationale não contém orientação educativa"

def test_contestability_guaranteed():
    """
    Testa que sistema garante direito de contestação.
    
    Princípio (Levinas): Responsabilidade pelo Outro → permitir recurso.
    """
    
    engine = create_governance_engine()
    ffi_client = FFIClient()
    
    cpf_input = "CPF: 123.456.789-09"
    evidence = ffi_client.scan_for_evidence(cpf_input)
    
    context = RequestMetadata(
        agent_id="general-agent",
        session_id="session-001",
        user_role="authenticated",
        domain="general",
        timestamp=int(time.time()),
    )
    
    verdict = engine.decide(evidence, context)
    
    # Se bloqueado, rationale deve mencionar recurso
    if verdict.action == ActionType.BLOCK:
        assert "contestar" in verdict.rationale.lower() or \
               "recurso" in verdict.rationale.lower() or \
               "apelar" in verdict.rationale.lower(), \
               "Decisão bloqueada não menciona direito de recurso (Levinas violado)"

def test_fail_secure_not_fail_open():
    """
    Testa que sistema falha de forma segura (protege usuário).
    
    Princípio (Levinas): Dever de cuidado → em dúvida, proteger.
    """
    
    engine = create_governance_engine()
    
    # Simula erro no Rust Kernel (evidence inválido)
    evidence_corrupted = create_corrupted_evidence()
    
    context = RequestMetadata(
        agent_id="test-agent",
        session_id="session-001",
        user_role="authenticated",
        domain="general",
        timestamp=int(time.time()),
    )
    
    # Sistema deve bloquear (não permitir) em caso de erro
    with pytest.raises(Exception) as exc_info:
        verdict = engine.decide(evidence_corrupted, context)
    
    # OU, se não crashar, deve retornar BLOCK
    # (nunca ALLOW em caso de erro)
    # assert verdict.action == ActionType.BLOCK

def test_explanation_completeness():
    """
    Testa que explicações são completas e acessíveis.
    
    Princípio (Levinas): Responsabilidade → transparência total.
    """
    
    engine = create_governance_engine()
    ffi_client = FFIClient()
    
    cpf_input = "CPF: 123.456.789-09"
    evidence = ffi_client.scan_for_evidence(cpf_input)
    
    context = RequestMetadata(
        agent_id="general-agent",
        session_id="session-001",
        user_role="authenticated",
        domain="general",
        timestamp=int(time.time()),
    )
    
    verdict = engine.decide(evidence, context)
    
    # Rationale deve ter tamanho mínimo (não genérico demais)
    assert len(verdict.rationale) > 50, \
        "Rationale muito curto (falta transparência)"
    
    # Deve mencionar:
    # - O que foi detectado
    # - Por que foi bloqueado/permitido
    # - Como proceder
    
    assert any(word in verdict.rationale.lower() for word in ['cpf', 'detectad', 'encontrad'])
    assert any(word in verdict.rationale.lower() for word in ['porque', 'devido', 'razão', 'política'])
    
    # Se bloqueado, deve ter instruções
    if verdict.action in [ActionType.BLOCK, ActionType.EDUCATE]:
        assert any(word in verdict.rationale.lower() for word in 
                  ['contexto', 'utiliz', 'apropriado', 'legítim', 'contestar'])