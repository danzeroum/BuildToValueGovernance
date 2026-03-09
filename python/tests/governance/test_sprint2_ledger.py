"""
Testes Sprint 2 — Gap 8
DurableLedger v1.1.0: prev_hash agora é verificado na cadeia.
"""
import copy
import pytest
from buildtovalue.governance.durable_ledger import DurableLedger

KEY  = b"test-key-sprint2"
PAY  = lambda n: {"explain_decision": f"decisao-{n}", "seq": n}


def test_happy_path_verify():
    """Ledger limpo com 5 entradas: verify() deve ser válido."""
    L = DurableLedger(KEY)
    for i in range(1, 6):
        L.append(PAY(i))
    r = L.verify()
    assert r.valid is True
    assert r.entries_checked == 5


def test_gap8_tampered_prev_hash_detected():
    """
    PROVA DO BUG: em v1.0.0 adulteração de prev_hash passava silenciosamente.
    Em v1.1.0 verify() deve retornar valid=False com reason sobre prev_hash.
    """
    L = DurableLedger(KEY)
    L.append(PAY(1))
    L.append(PAY(2))

    # Adulterar prev_hash da entrada 2 diretamente (object.__setattr__ burla frozen)
    entry2 = L._entries[1]
    object.__setattr__(entry2, "prev_hash", "a" * 64)

    r = L.verify()
    assert r.valid is False
    assert r.first_invalid_sequence == 2
    assert "prev_hash" in r.reason


def test_gap8_tampered_payload_detected():
    """Adulteração de payload detectada via chain hash."""
    L = DurableLedger(KEY)
    L.append(PAY(1))
    L.append(PAY(2))

    entry1 = L._entries[0]
    original = entry1.payload.copy()
    original["injected"] = "malicious"
    object.__setattr__(entry1, "payload", original)

    r = L.verify()
    assert r.valid is False
    assert r.first_invalid_sequence == 1
    assert "chain hash" in r.reason


def test_gap8_tampered_hmac_detected():
    """Adulteração de HMAC detectada."""
    L = DurableLedger(KEY)
    L.append(PAY(1))

    entry1 = L._entries[0]
    object.__setattr__(entry1, "hmac_sha256", "b" * 64)

    r = L.verify()
    assert r.valid is False
    assert r.first_invalid_sequence == 1
    assert "HMAC" in r.reason


def test_gap8_first_invalid_sequence_correct():
    """Adulteração na entrada 3 de 5: entries_checked deve ser 2."""
    L = DurableLedger(KEY)
    for i in range(1, 6):
        L.append(PAY(i))

    entry3 = L._entries[2]
    object.__setattr__(entry3, "prev_hash", "c" * 64)

    r = L.verify()
    assert r.valid is False
    assert r.first_invalid_sequence == 3
    assert r.entries_checked == 2


def test_empty_ledger_valid():
    """Ledger vazio é válido por definição."""
    L = DurableLedger(KEY)
    r = L.verify()
    assert r.valid is True
    assert r.entries_checked == 0


def test_explain_decision_required():
    """append() sem explain_decision deve levantar ValueError."""
    L = DurableLedger(KEY)
    with pytest.raises(ValueError, match="explain_decision"):
        L.append({"data": "sem explicação"})
