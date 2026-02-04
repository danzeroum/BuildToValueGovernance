
import pytest
from ffi_client import FFIClient

@pytest.fixture
def ffi_client():
    return FFIClient()

def test_base64_encoding_evasion(ffi_client):
    """
    Tenta evadir detecção com Base64.
    
    Ataque: Codificar CPF em Base64.
    Defesa: Deobfuscator detecta e decodifica Base64.
    """
    
    import base64
    
    cpf = "123.456.789-09"
    cpf_b64 = base64.b64encode(cpf.encode()).decode()
    
    input_text = f"Dados codificados: {cpf_b64}"
    
    evidence = ffi_client.scan_for_evidence(input_text)
    
    # Deobfuscator deve ter detectado Base64 e decodificado
    # Portanto, CPF deve ser encontrado
    assert evidence.finding_count > 0
    
    # Verifica que Base64 foi identificado
    findings = evidence.get_all_findings()
    titles = [f.title.decode('utf-8').strip('\x00') for f in findings]
    assert any("BASE64" in title or "CPF" in title for title in titles)

def test_hex_encoding_evasion(ffi_client):
    """
    Tenta evadir com encoding hexadecimal.
    
    Defesa: Deobfuscator detecta padrões Hex.
    """
    
    cpf = "123.456.789-09"
    cpf_hex = cpf.encode().hex()
    
    input_text = f"Hex: {cpf_hex}"
    
    evidence = ffi_client.scan_for_evidence(input_text)
    
    # Deve detectar Hex e possivelmente CPF após decode
    assert evidence.finding_count > 0

def test_leetspeak_evasion(ffi_client):
    """
    Tenta evadir com leetspeak.
    
    Ataque: 1 → I, 3 → E, 4 → A, 5 → S, 7 → T, 8 → B, 0 → O
    Defesa: Deobfuscator normaliza leetspeak.
    """
    
    # CPF em leetspeak: 123.456.789-09
    cpf_leet = "1Z3.4S6.7B9-09"  # Z→2, S→5, B→8
    
    input_text = f"CPF: {cpf_leet}"
    
    evidence = ffi_client.scan_for_evidence(input_text)
    
    # Após normalização, deve detectar CPF
    # (pode ter confiança levemente menor)
    assert evidence.finding_count > 0

def test_whitespace_insertion_evasion(ffi_client):
    """
    Tenta evadir inserindo espaços.
    
    Ataque: "1 2 3 . 4 5 6 . 7 8 9 - 0 9"
    Defesa: Normalização remove espaços.
    """
    
    cpf_spaced = "1 2 3 . 4 5 6 . 7 8 9 - 0 9"
    
    input_text = f"CPF: {cpf_spaced}"
    
    evidence = ffi_client.scan_for_evidence(input_text)
    
    # Deve detectar CPF após remover espaços
    assert evidence.finding_count > 0

def test_mixed_case_evasion(ffi_client):
    """
    Tenta evadir com case mixing (menos relevante para CPF).
    
    Mais aplicável a emails/URLs.
    """
    
    email_mixed = "TeSt@ExAmPlE.CoM"
    
    input_text = f"Email: {email_mixed}"
    
    evidence = ffi_client.scan_for_evidence(input_text)
    
    # Deve detectar email independente de case
    findings = evidence.get_all_findings()
    titles = [f.title.decode('utf-8').strip('\x00') for f in findings]
    assert any("EMAIL" in title for title in titles)

def test_url_encoding_evasion(ffi_client):
    """
    Tenta evadir com URL encoding (%XX).
    
    Ataque: "123%2E456%2E789%2D09" (%2E = ., %2D = -)
    Defesa: Deobfuscator decodifica URL encoding.
    """
    
    cpf_url_encoded = "123%2E456%2E789%2D09"
    
    input_text = f"CPF: {cpf_url_encoded}"
    
    evidence = ffi_client.scan_for_evidence(input_text)
    
    # Deve detectar após URL decode
    assert evidence.finding_count > 0

def test_unicode_normalization_evasion(ffi_client):
    """
    Tenta evadir com formas Unicode diferentes (NFD vs NFC).
    
    Defesa: Unicode normalization para NFC.
    """
    
    import unicodedata
    
    # CPF com caracteres decompostos (NFD)
    cpf_nfd = "123.456.789-09"
    cpf_nfd_decomposed = unicodedata.normalize('NFD', cpf_nfd)
    
    # CPF com caracteres compostos (NFC)
    cpf_nfc = unicodedata.normalize('NFC', cpf_nfd)
    
    evidence_nfd = ffi_client.scan_for_evidence(f"CPF: {cpf_nfd_decomposed}")
    evidence_nfc = ffi_client.scan_for_evidence(f"CPF: {cpf_nfc}")
    
    # Ambos devem ser detectados igualmente
    assert evidence_nfd.finding_count > 0
    assert evidence_nfc.finding_count > 0

def test_zero_width_character_evasion(ffi_client):
    """
    Tenta evadir com caracteres zero-width.
    
    Ataque: "123​.456​.789​-09" (U+200B zero-width space)
    Defesa: Remoção de caracteres zero-width na normalização.
    """
    
    # CPF com zero-width spaces
    cpf_zw = "123\u200b.456\u200b.789\u200b-09"
    
    input_text = f"CPF: {cpf_zw}"
    
    evidence = ffi_client.scan_for_evidence(input_text)
    
    # Deve detectar CPF após remover zero-width chars
    assert evidence.finding_count > 0