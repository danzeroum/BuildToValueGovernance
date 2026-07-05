"""Testes dos aliases compatíveis com o gateway Rust (gateway_compat.py).

Garantem que /v1/validate e /v1/sanitize existem na API Python e devolvem a
mesma superfície de resposta que o gateway Rust — o contrato que os SDKs
Python/JS consomem.
"""
import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    os.environ.pop("BTV_API_KEYS", None)
    os.environ["BTV_ENV"] = "development"
    from buildtovalue.api.app import app
    with TestClient(app) as c:
        yield c


# Campos exigidos pelo ValidateVerdict do SDK (sdk/python/buildtovalue/models.py)
_SDK_VALIDATE_REQUIRED = {
    "verdict_id", "action", "original_action", "mercy_applied",
    "finding_count", "critical_count", "composite_risk", "hard_blocked",
    "contestable", "appeal_deadline_hours", "message", "matched_policies",
    "signature",
}


class TestValidateAlias:

    def test_validate_returns_sdk_compatible_shape(self, client):
        resp = client.post("/v1/validate", json={"input": "hello world"})
        assert resp.status_code == 200
        data = resp.json()
        missing = _SDK_VALIDATE_REQUIRED - set(data)
        assert not missing, f"campos exigidos pelo SDK ausentes: {missing}"

    def test_validate_blocks_attack_input(self, client):
        resp = client.post(
            "/v1/validate",
            json={"input": "<script>alert(1)</script> drop table users"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["action"] == "BLOCK"
        assert data["hard_blocked"] is True

    def test_validate_allows_benign_input(self, client):
        resp = client.post("/v1/validate", json={"input": "bom dia, tudo bem?"})
        assert resp.status_code == 200
        assert resp.json()["action"] in ("ALLOW", "LOG")


class TestSanitizeAlias:

    def test_sanitize_masks_cpf(self, client):
        resp = client.post(
            "/v1/sanitize", json={"text": "CPF do cliente: 123.456.789-09"}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "123.456.789" not in data["sanitized_text"]
        assert "cpf" in data["masked_types"]
        assert data["masked_count"] >= 1

    def test_sanitize_masks_email(self, client):
        resp = client.post(
            "/v1/sanitize", json={"text": "contato: fulano@example.com"}
        )
        data = resp.json()
        assert "fulano@example.com" not in data["sanitized_text"]
        assert "email" in data["masked_types"]

    def test_sanitize_clean_text_untouched(self, client):
        resp = client.post("/v1/sanitize", json={"text": "texto sem dados pessoais"})
        data = resp.json()
        assert data["sanitized_text"] == "texto sem dados pessoais"
        assert data["masked_count"] == 0
        assert data["original_length"] == len("texto sem dados pessoais")

    def test_sanitize_response_matches_rust_contract(self, client):
        resp = client.post("/v1/sanitize", json={"text": "x"})
        data = resp.json()
        assert set(data) == {
            "original_length", "sanitized_text", "masked_count",
            "masked_types", "latency_ms",
        }
