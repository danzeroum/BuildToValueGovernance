[Docs](../README.md) · [Engenheiro](../for-engineers.md) · [Integrações](./index.md) › **Example Agent**

![Engenheiro](https://img.shields.io/badge/Trilha-Engenheiro-1f6feb)

<!-- audience: engineer -->

---

# Example BTV-Compatible Agent — Perfil de Integração (ADR-029)

## Identificação

| Campo | Valor |
|---|---|
| `agent_id` | `BLAKE3(agent_config_canonical)` — estável entre reinicializações |
| `profile_id` | `default` |
| `sector_id` | `general` |
| ADR de referência | ADR-029 (contrato canônico) |

## Mapeamento de Ações → ActionImpact

| Ação do agente | `impact` | Requer gate BTV |
|---|---|---|
| Ler arquivo | `Safe` | Não (logar localmente) |
| Escrever arquivo | `Destructive` | Sim |
| Enviar e-mail | `Irreversible` | Sim |
| Chamar API externa | `Irreversible` | Sim |
| Consultar banco de dados | `Safe` | Não |
| Deletar registro | `Irreversible` | Sim |

## Fluxo de Integração
```
1. GET /v1/trust/{session_id}          → session_trust_score (TTL 60s)
2. POST /v1/validate                   → AgentDecisionRequest
3. Verificar HMAC da resposta          → constant-time (ADR-008)
4. Executar ação se ALLOW/EDUCATE      → registrar evidence_id no log local
5. Se BLOCK → apresentar explain_decision ao operador + POST /v1/appeals
```

## Exemplo de Request
```json
{
  "schema_version": "1.0",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "agent_id": "a3b4c5d6e7f8a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a1b2c3d4e5f6a7b8",
  "session_id": "sess-abc123",
  "action": {
    "name": "send_email",
    "impact": "Irreversible",
    "capabilities": ["external_data_transfer", "email"]
  },
  "parameters_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "parameters_preview": {},
  "context": {
    "profile_id": "default",
    "sector_id": "general",
    "session_trust_score": 0.75,
    "agent_metadata": { "agent_version": "1.0.0" }
  },
  "timestamp_utc": "2026-03-07T12:00:00Z"
}
```

## Protocolo de Resiliência

| Cenário | Comportamento obrigatório |
|---|---|
| Timeout (> 5s) | BLOCK local + log `btv.timeout` |
| HTTP 5xx | 1 retry (100ms) → BLOCK |
| HMAC inválido | BLOCK + alerta `btv.hmac_mismatch` |
| Circuit aberto (≥3 falhas/30s) | BLOCK todas Destructive/Irreversible |

## Invariantes (ADR-029 §9)

- Sem veredicto verificado → sem execução
- Fail-secure: qualquer erro → BLOCK
- Cache proibido para `Irreversible`
- `evidence_id` registrado em todo ALLOW/EDUCATE
- API key exclusiva por agente

---

### Próximos passos / Relacionados

- [Integrações — visão geral](./index.md)
- [API Reference](../api-reference.md)
- [Conceitos](../concepts.md)

---

<sub>[↑ Hub](../README.md) · [Trilha Engenheiro](../for-engineers.md) · [Trilha DPO/CISO](../for-dpo-ciso.md) · [Links de Referência](../reference-links.md)</sub>
