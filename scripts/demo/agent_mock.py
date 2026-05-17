#!/usr/bin/env python3
"""
Mock de agente para demo do BTV Trust OS.

Envia dois requests ao gateway — um violador (BLOCK) e um conforme (ALLOW) —
e exibe o resultado colorido no terminal.

Sem dependências externas: usa apenas stdlib.

Uso:
    python scripts/demo/agent_mock.py
    BTV_GATEWAY_URL=http://localhost:8080 python scripts/demo/agent_mock.py
"""
import urllib.request
import json
import sys
import os
import time

GATEWAY = os.environ.get("BTV_GATEWAY_URL", "http://localhost:8080")
ENDPOINT = f"{GATEWAY}/v1/decide"

CASES = [
    (
        "VIOLADOR — GDPR Art. 22",
        {
            "input": (
                "Decisão de crédito: CPF 123.456.789-00, score 420, "
                "NEGAR sem revisão humana, sem notificação ao titular."
            ),
            "session_id": "demo-violador-001",
        },
    ),
    (
        "CONFORME",
        {
            "input": (
                "Consulta de saldo: cliente autenticado via duplo fator, "
                "operação aprovada por supervisor humano, sem dados sensíveis."
            ),
            "session_id": "demo-conforme-001",
        },
    ),
]

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"

SEPARATOR = "─" * 60


def post_decide(payload: dict) -> dict:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        ENDPOINT,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def wait_for_gateway(max_attempts: int = 10) -> bool:
    health_url = f"{GATEWAY}/health"
    for i in range(max_attempts):
        try:
            urllib.request.urlopen(health_url, timeout=3)
            return True
        except Exception:
            if i < max_attempts - 1:
                time.sleep(2)
    return False


def main() -> int:
    print(f"\n{BOLD}BTV Trust OS — Demo de Bloqueio em Tempo Real{RESET}")
    print(f"Gateway: {GATEWAY}")
    print(SEPARATOR)

    print("Aguardando gateway...", end=" ", flush=True)
    if not wait_for_gateway():
        print(f"{RED}offline{RESET}")
        print("Execute: docker compose -f ops/docker-compose.quickstart.yml up -d")
        return 1
    print(f"{GREEN}online{RESET}\n")

    for label, payload in CASES:
        print(f"Enviando: {BOLD}{label}{RESET}")
        try:
            result = post_decide(payload)
        except Exception as e:
            print(f"  {RED}ERRO: {e}{RESET}\n")
            return 1

        verdict = result.get("verdict", result.get("action", "?"))
        explain = result.get("explain_decision", result.get("explain", ""))
        latency = result.get("latency_ms", "?")

        color = RED if verdict in ("BLOCK", "DENY") else GREEN
        print(f"  verdict   : {color}{BOLD}{verdict}{RESET}")
        print(f"  latência  : {latency}ms")
        if explain:
            print(f"  explicação: {explain[:100]}")
        print()

    print(SEPARATOR)
    print(f"{GREEN}Demo completo.{RESET} Abra o dashboard: http://localhost:8501")
    return 0


if __name__ == "__main__":
    sys.exit(main())
