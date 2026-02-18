# ADR-025: Webhook Notifications for Critical Decisions

**Status:** ✅ Ativo
**Data:** Fevereiro 2026
**Versão:** v2.1
**Grupo:** D — API & Observability

## Contexto

Quando o BTV emite BLOCK ou HARD_BLOCK, a equipe de segurança do cliente não
é notificada em tempo real. O Ledger Query (ADR-024) permite consulta posterior,
mas operações de segurança exigem alertas imediatos.

## Decisão

Implementar `WebhookDispatcher` que envia POST para URLs configuradas quando
decisões críticas ocorrem. Integra-se com o Python governance layer (app.py).

### Configuração (YAML)
```yaml
# data/policies/webhooks.yaml
webhooks:
  - url: "https://cliente.com/btv-alerts"
    actions: ["BLOCK", "HARD_BLOCK"]
    enabled: true
    timeout_seconds: 5
    retry_max: 2
```

### Invariantes

1. **Fire-and-forget:** Webhook failure NEVER blocks the verdict pipeline
2. **Timeout:** 5s max per attempt (não atrasar o response ao cliente)
3. **Retry:** Max 2 retries com backoff (1s, 2s)
4. **No secrets in payload:** Nunca enviar input original, apenas metadata
5. **Ledger first:** Webhook só dispara APÓS decisão gravada no ledger

## Fundamento Filosófico

**Jonas (1984):** Responsabilidade exige comunicação proporcional ao risco.
Uma decisão BLOCK sem notificação é ação sem accountability.

## Referências

- ADR-024 (Ledger Query)
- ADR-015 (Ledger Imutável)