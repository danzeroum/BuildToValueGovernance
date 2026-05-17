"""
E2E: Proxy HTTP Transparente — Fluxo Agente → Gateway → Governance.

Testa o caminho crítico: agente aponta OPENAI_BASE_URL para o gateway,
gateway intercepta, governance valida, resultado retorna ao agente.

Pré-requisitos:
    docker compose -f ops/docker-compose.quickstart.yml up -d
    pytest tests/e2e/test_proxy_flow.py -v

Variáveis de ambiente:
    BTV_GATEWAY_URL   (padrão: http://localhost:8080)
    BTV_API_KEY       (padrão: vazio — dev mode sem auth)
    BTV_UPSTREAM_MOCK (padrão: http://localhost:8082)
"""
import json
import os
import urllib.error
import urllib.request

import pytest

GATEWAY = os.environ.get("BTV_GATEWAY_URL", "http://localhost:8080")
API_KEY = os.environ.get("BTV_API_KEY", "")
UPSTREAM_MOCK = os.environ.get("BTV_UPSTREAM_MOCK", "http://localhost:8082")


def _headers() -> dict:
    h = {"Content-Type": "application/json"}
    if API_KEY:
        h["x-api-key"] = API_KEY
    return h


def _post(path: str, payload: dict) -> tuple[int, dict]:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{GATEWAY}{path}",
        data=body,
        headers=_headers(),
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def _get(path: str) -> tuple[int, str]:
    req = urllib.request.Request(f"{GATEWAY}{path}", headers=_headers())
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.status, r.read().decode()


# ── Pré-condição ────────────────────────────────────────────────────────────

def test_gateway_healthy():
    """Gateway deve responder /health antes de qualquer teste de proxy."""
    req = urllib.request.Request(f"{GATEWAY}/health")
    with urllib.request.urlopen(req, timeout=5) as r:
        assert r.status == 200
        data = json.loads(r.read())
    assert data.get("status") == "ok", f"status inesperado: {data}"


def test_proxy_metrics_present_at_boot():
    """btv_proxy_* devem aparecer em /metrics desde o boot (lazy_static::initialize)."""
    _, text = _get("/metrics")
    assert "btv_proxy_requests_total" in text
    assert "btv_proxy_blocked_total" in text
    assert "btv_proxy_forward_latency_ms" in text


# ── Bloqueio (fail-secure) ───────────────────────────────────────────────────

def test_proxy_blocks_gdpr_violation():
    """
    Agente violador (decisão de crédito automatizada + CPF) deve ser bloqueado
    com HTTP 451 e body JSON contendo 'blocked: true' e 'appeal_url'.
    """
    status, body = _post(
        "/v1/proxy/v1/chat/completions",
        {
            "messages": [
                {
                    "role": "user",
                    "content": (
                        "Decisão de crédito: CPF 123.456.789-00, score 420, "
                        "NEGAR sem revisão humana nem notificação ao titular."
                    ),
                }
            ],
            "model": "gpt-4o",
            "session_id": "e2e-block-gdpr",
        },
    )
    assert status == 451, f"Esperava 451, recebeu {status}: {body}"
    assert body.get("blocked") is True
    assert "appeal_url" in body


def test_proxy_blocks_phi_transmission():
    """Transmissão de PHI sem base legal deve ser bloqueada."""
    status, body = _post(
        "/v1/proxy/v1/chat/completions",
        {
            "messages": [
                {
                    "role": "user",
                    "content": "Paciente João Silva, prontuário #4521, HIV positivo — enviar ao convênio.",
                }
            ],
            "model": "gpt-4o",
            "session_id": "e2e-block-phi",
        },
    )
    assert status == 451, f"Esperava 451, recebeu {status}: {body}"
    assert body.get("blocked") is True


# ── Encaminhamento (conforme) ────────────────────────────────────────────────

@pytest.mark.skipif(
    not os.environ.get("BTV_UPSTREAM_MOCK"),
    reason="Requer upstream-mock (BTV_UPSTREAM_MOCK). Suba com o compose: "
           "docker compose -f ops/docker-compose.quickstart.yml up -d",
)
def test_proxy_forwards_compliant_request():
    """
    Agente conforme → gateway encaminha ao upstream-mock (httpbin /anything).
    O mock devolve 200 com echo do body recebido.
    """
    status, body = _post(
        "/v1/proxy/anything",
        {
            "messages": [{"role": "user", "content": "Consulta de saldo — autenticado, sem dados sensíveis."}],
            "model": "gpt-4o",
            "session_id": "e2e-allow-conforme",
        },
    )
    assert status == 200, f"Esperava 200, recebeu {status}: {body}"
    # httpbin /anything ecoa o body em data.json ou json
    assert "json" in body or "data" in body


# ── Contadores pós-teste ─────────────────────────────────────────────────────

def test_proxy_blocked_counter_incremented():
    """Após os testes de bloqueio, btv_proxy_blocked_total deve ser > 0."""
    _, text = _get("/metrics")
    for line in text.splitlines():
        if line.startswith("btv_proxy_blocked_total") and not line.startswith("#"):
            count = float(line.split()[-1])
            assert count > 0, "Esperava btv_proxy_blocked_total > 0"
            return
    pytest.fail("Métrica btv_proxy_blocked_total não encontrada")
