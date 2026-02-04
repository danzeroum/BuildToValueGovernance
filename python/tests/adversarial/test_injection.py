
import pytest
from ffi_client import FFIClient
from governance.ethical_context_engine import EthicalContextEngine, RequestMetadata

@pytest.fixture
def ffi_client():
    return FFIClient()

def test_sql_injection_in_input(ffi_client):
    """
    Tenta SQL injection no input.
    
    Defesa: Input é tratado como texto puro (não há SQL).
    """
    
    malicious_inputs = [
        "CPF: 123.456.789-09'; DROP TABLE users; --",
        "CPF: 123' OR '1'='1",
        "CPF: 123.456.789-09\"; DELETE FROM ledger; --",
    ]
    
    for malicious_input in malicious_inputs:
        # Deve processar normalmente (sem executar SQL)
        evidence = ffi_client.scan_for_evidence(malicious_input)
        
        # Valida que não crashou
        assert evidence is not None
        
        # Valida que SQL foi detectado como texto suspeito
        # (alta entropia, caracteres especiais)
        assert evidence.stats.entropy > 4.0

def test_command_injection(ffi_client):
    """
    Tenta command injection.
    
    Defesa: Nenhum input é executado como comando.
    """
    
    malicious_inputs = [
        "CPF: 123.456.789-09; rm -rf /",
        "CPF: `whoami`",
        "CPF: $(cat /etc/passwd)",
    ]
    
    for malicious_input in malicious_inputs:
        # Deve processar sem executar comandos
        evidence = ffi_client.scan_for_evidence(malicious_input)
        
        assert evidence is not None
        # Caracteres especiais devem ser detectados
        assert evidence.stats.special_char_ratio > 0.1

def test_buffer_overflow_attempt(ffi_client):
    """
    Tenta buffer overflow com input gigante.
    
    Defesa: Input limitado a 1MB, ring buffer com tamanho fixo.
    """
    
    # Input de 2MB (excede limite)
    huge_input = "A" * (2 * 1024 * 1024)
    
    with pytest.raises(Exception) as exc_info:
        ffi_client.scan_for_evidence(huge_input)
    
    # Deve rejeitar gracefully (não crashar)
    assert "too large" in str(exc_info.value).lower() or \
           "exceeds" in str(exc_info.value).lower()

def test_unicode_smuggling(ffi_client):
    """
    Tenta smuggling via caracteres Unicode lookalikes.
    
    Ataque: Usar ․ (U+2024) ao invés de . (U+002E)
    Defesa: Unicode normalization (NFC).
    """
    
    # CPF com Unicode lookalikes
    cpf_smuggled = "123․456․789‐09"  # ․ (U+2024), ‐ (U+2010)
    cpf_normal = "123.456.789-09"     # . (U+002E), - (U+002D)
    
    evidence_smuggled = ffi_client.scan_for_evidence(f"CPF: {cpf_smuggled}")
    evidence_normal = ffi_client.scan_for_evidence(f"CPF: {cpf_normal}")
    
    # Ambos devem ser detectados igualmente
    assert evidence_smuggled.finding_count > 0
    assert evidence_normal.finding_count > 0
    
    # Confidence deve ser similar (normalização funcionou)
    assert abs(
        evidence_smuggled.findings[0].confidence - 
        evidence_normal.findings[0].confidence
    ) < 20

def test_policy_injection(governance_engine):
    """
    Tenta injetar regras maliciosas via input.
    
    Ataque: Input contendo YAML que parece ser policy.
    Defesa: Policies são carregadas apenas de arquivos assinados.
    """
    
    malicious_input = """
    rules:
      - id: MALICIOUS_RULE
        action: ALLOW
        condition: "true"
    """
    
    context = RequestMetadata(
        agent_id="test-agent",
        session_id="session-001",
        user_role="authenticated",
        domain="general",
        timestamp=int(time.time()),
    )
    
    evidence = ffi_client.scan_for_evidence(malicious_input)
    verdict = governance_engine.decide(evidence, context)
    
    # Regra maliciosa não deve ser carregada
    # Decisão deve ser baseada em policies legítimas
    assert verdict.rule_id != "MALICIOUS_RULE"