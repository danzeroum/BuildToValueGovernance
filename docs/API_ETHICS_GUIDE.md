# API Ethics Guide — BuildToValue Governance

> Guia de contrato para todos que integram (ou estendem) o BTV via HTTP/gRPC.
> Status: v1.0 — referência normativa.

## 1. O Princípio Fundante: "Difícil de Usar Incorretamente"

Uma API de governança ética tem responsabilidade dupla: **guiar o código correto** e **comunicar o motivo regulatório** de cada restrição. Mensagens de erro genéricas ("400 Bad Request") falham nas duas dimensões. Toda resposta de erro do BTV deve permitir que o desenvolvedor saiba (a) o que está errado, (b) por qual ADR/regulação a restrição existe, (c) como remediar, e (d) como contestar se discordar.

## 2. Recursos REST de Primeira Classe

Substantivos no plural, sempre versionados:

```
GET    /api/v1/decisions/{id}            ← evidência imutável
POST   /api/v1/decisions                 ← submete payload para governança
GET    /api/v1/appeals                   ← coleção de contestações
POST   /api/v1/appeals                   ← cria nova contestação (SLA 24h, ADR-0017)
GET    /api/v1/appeals/{id}              ← estado da contestação
GET    /api/v1/tenants/{id}/metrics      ← saúde do tenant (agregado)
```

## 3. Error-as-a-Resource (RFC 7807)

Todas as respostas `4xx` e `5xx` usam **`Content-Type: application/problem+json`** (RFC 7807). Campos raiz padrão; campos BTV em `extensions`.

```json
{
  "type": "https://docs.buildtovalue.org/errors/E120",
  "title": "BiasDeclaration ausente",
  "status": 400,
  "detail": "A requisição não inclui BiasDeclaration assinada exigida pelo ADR-0010.",
  "instance": "/api/v1/decisions",
  "extensions": {
    "error_code": "E120",
    "ethical_ground": "BiasDeclaration ausente ou inválida",
    "adr_reference": "https://docs.buildtovalue.org/adrs/0010-bias-declaration-mandate",
    "verdict_id": null,
    "audit_log_id": "01927c4f-7e23-7a1b-9c4f-1f8e4c8a9d12",
    "appeal_url": "/api/v1/appeals",
    "contestable_until": null
  }
}
```

- `audit_log_id` é UUID v7 (ordenável por tempo) que aponta para a entrada imutável no ledger forense (ADR-0052). Sem ele, o DPO não consegue instruir contestação.
- `contestable_until` é `null` quando o erro for de contrato (ex: schema inválido); preenchido com ISO-8601 quando for decisão de política (E130).

## 4. Versionamento e Deprecação

Definido normativamente no **ADR-0082**. Resumo:

- Mudanças não-breaking adicionam campos como `Option<T>` (Rust) / `@JsonProperty(required = false)` (Java).
- Mudanças breaking exigem novo prefixo (`/v2/`) e ciclo de **mínimo 90 dias** com headers `Deprecation` + `Sunset`.
- `ExplainDecision` e `BiasDeclaration` **nunca** perdem campos.
- Notificações de deprecação via webhook `POST /tenant/webhooks/deprecation`.

## 5. Headers Obrigatórios

### 5.1 Em toda resposta de decisão (ALLOW ou BLOCK)

| Header | Valor | Propósito |
|---|---|---|
| `X-BTV-Decision-Id` | UUID v7 | Liga resposta HTTP à entrada do ledger forense |
| `X-BTV-Verdict-Signature` | `hmac-sha256=<hex>` | Autenticidade contra proxies reversos (primitiva `security::signing`) |
| `X-BTV-Sampling-Mode` | `full` \| `integrity` | Modo do Speed Layer aplicado (Lambda Governance) |

### 5.2 Em respostas sujeitas a rate limit

| Header | Valor |
|---|---|
| `X-RateLimit-Limit` | inteiro |
| `X-RateLimit-Remaining` | inteiro |
| `X-RateLimit-Reset` | epoch seconds |
| `X-BTV-Throttle-Reason` | `z_score_exceeded` (quando throttled) |

### 5.3 Em respostas com endpoint deprecated

| Header | Valor |
|---|---|
| `Deprecation` | `date="YYYY-MM-DD"` |
| `Sunset` | `date="YYYY-MM-DD"` (≥ 90 dias após Deprecation) |

## 6. Referências

- ADR-0010 — BiasDeclaration Mandate
- ADR-0017 — Contestability Loop (SLA 24h)
- ADR-0052 — Forensic Audit Storage
- ADR-0082 — API Evolution & Deprecation Policy
- RFC 7807 — Problem Details for HTTP APIs
- RFC 8594 — The `Sunset` HTTP Header Field
