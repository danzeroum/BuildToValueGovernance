---
title: "Tutorial 02 — Primeira Integração"
---

# Tutorial 02 — Primeira Integração

Você já sabe [tratar o bloqueio](01-handle-failure.md). Agora vamos chamar o
gateway no caminho feliz.

## Passo 1 — Decisão

```bash
curl -X POST http://localhost:8080/v1/decide \
  -H 'Content-Type: application/json' \
  -d '{
    "agent_id": "demo-agent",
    "action": "summarize",
    "context": {"user_consent": true}
  }'
```

Resposta:

```json
{
  "decision": "ALLOW",
  "evidence_url": "/v1/evidence/<hash>",
  "verdict_id": "<ulid>"
}
```

## Passo 2 — Consumir a evidência

A evidência vem no formato **constitucional** (wire). Para inspecionar a
estrutura, consulte a [referência técnica gerada](../reference/index.md).

## Passo 3 — SDKs

- [Python SDK](../../integrations/python-sdk.md)
- [TypeScript SDK](../../integrations/typescript-sdk.md)

## Próximo

[Tutorial 03 — Verificação criptográfica fora do navegador](03-verify-evidence-cli.md).
