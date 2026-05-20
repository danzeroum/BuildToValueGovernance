[Docs](./README.md) · [Engenheiro](./for-engineers.md) › **API Reference**

![Engenheiro](https://img.shields.io/badge/Trilha-Engenheiro-1f6feb)

<!-- audience: engineer -->

---

# Referência da API

A spec completa está em [`spec/openapi.yaml`](https://github.com/buildtovalue/buildtovalue/blob/main/spec/openapi.yaml) (OpenAPI 3.0.3).

**Base URL:** `http://localhost:8080` (dev) · `https://gateway.buildtovalue.io` (prod)

**Autenticação:** header `X-API-Key: <sua-chave>` em todos os endpoints exceto `/health`.

---

## POST /v1/decide

Pipeline ético completo (Rust + Python judiciary). Use para decisões que importam.

**Request:**
```json
{
  "input": "Meu CPF é 123.456.789-09",
  "session_id": "sess-user-001",
  "profile": "healthcare",
  "agent_id": "agent-xyz"
}
```

| Campo | Tipo | Obrigatório | Descrição |
|---|---|---|---|
| `input` | string | ✅ | Texto a avaliar |
| `session_id` | string | — | ID opaco da sessão (para trust score) |
| `profile` | string | — | Perfil setorial |
| `agent_id` | string | — | ID do agente chamador (auditoria) |

**Header opcional:** `X-BTV-Jurisdiction: BR,EU` — bitmask de jurisdições

**Response 200:**
```json
{
  "verdict_id": "VRD-01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "action": "EDUCATE",
  "original_action": "BLOCK",
  "mercy_applied": true,
  "finding_count": 2,
  "critical_count": 1,
  "composite_risk": 0.71,
  "hard_blocked": false,
  "contestable": true,
  "appeal_deadline_hours": 24,
  "signature": "hmac-sha256:abc123...",
  "rationale": "CPF detectado. Primeira infração — resposta educativa.",
  "jurisdiction_bitmask": 1,
  "latency_ms": 34.2,
  "explain": {
    "summary": "PII sensível detectado. Misericórdia aplicada.",
    "rawls_rationale": "Violação de política LGPD Art. 6.",
    "levinas_rationale": "Usuário merece explicação, não só bloqueio.",
    "jonas_rationale": "Risco contido; sem dano irreversível.",
    "gilligan_rationale": "Primeira infração + trust > 0.6 → EDUCATE.",
    "trust_score": 0.72,
    "mercy_score": 0.83,
    "pipeline_stages": ["rawls", "levinas", "jonas", "gilligan"]
  }
}
```

---

## POST /v1/validate

Scan Rust-only (sem pipeline ético). Mais rápido, menos raciocínio. Use para validação rápida.

**Request:** igual ao `/v1/decide` (sem `agent_id`).

**Response 200:** igual ao `/v1/decide` mas sem campo `explain`, e com campos extras:
```json
{
  "message": "SQL injection detectado.",
  "matched_policies": ["sql_injection_hard_block"],
  "hard_block_term": "DROP TABLE",
  "max_finding_confidence": 0.99,
  "entropy": 3.2,
  "blake3_hash": "deadbeef..."
}
```

---

## POST /v1/sanitize

Mascara PII e neutraliza injection patterns no texto.

**Request:**
```json
{ "text": "Contate João em joao@example.com ou 011-99999-9999" }
```

**Response 200:**
```json
{
  "sanitized": "Contate João em [EMAIL] ou [PHONE]",
  "redactions": 2,
  "latency_ms": 3.1
}
```

---

## POST /v1/appeals

Contesta um verdict (LGPD Art. 20 / EU AI Act Art. 14).

**Request:**
```json
{
  "verdict_id": "VRD-01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "user_id": "user-anon-001",
  "reason": "Este CPF é de um dataset de teste ABNT, não é dado real.",
  "grounds": ["technical_error", "false_positive"],
  "evidence": "Referência: ABNT NBR ISO/IEC 27001 Anexo A"
}
```

| Campo | Tipo | Obrigatório | Descrição |
|---|---|---|---|
| `verdict_id` | string | ✅ | ID do verdict a contestar |
| `user_id` | string | ✅ | Identificador opaco do apelante |
| `reason` | string (≥20 chars) | ✅ | Motivo articulado (princípio Levinas) |
| `grounds` | string[] | — | Grounds filosóficos/legais |
| `evidence` | string | — | Evidência adicional |

**Response 201:**
```json
{
  "appeal_id": "APL-01ARZ3NDEK...",
  "status": "pending",
  "sla_deadline": "2026-03-21T12:00:00Z",
  "mediator_recommendation": null
}
```

---

## GET /v1/appeals/{appeal_id}

Consulta o status de um appeal.

**Response 200:** objeto `Appeal` com `status`, `resolution`, `mediator_recommendation`.

**Status possíveis:** `pending` → `under_review` → `accepted` | `rejected` | `expired`

---

## GET /v1/trust/{session_id}

Trust score atual da sessão.

**Response 200:**
```json
{
  "session_id": "sess-user-001",
  "trust_score": 0.82,
  "total_requests": 47,
  "offenses": 1,
  "calculated_at": "2026-03-20T12:00:00Z"
}
```

---

## GET /health

Health check público (sem autenticação).

```json
{ "status": "ok", "uptime_seconds": 3600.5, "version": "2.0.0" }
```

---

## Códigos de erro

| Código | Significado |
|---|---|
| `401` | API key ausente ou inválida |
| `400` / `422` | Request malformado (ex: `reason` < 20 chars) |
| `404` | Recurso não encontrado (appeal_id inexistente) |
| `429` | Rate limit atingido — header `Retry-After` indica quando tentar novamente |
| `503` | Governança Python indisponível — kernel Rust opera em modo fail-secure |

---

## SDKs

Os SDKs tratam erros automaticamente com retry e backoff:

```python
from buildtovalue.exceptions import (
    BTVAuthError,      # 401
    BTVBlockedError,   # verdict.action == BLOCK (com raise_on_block=True)
    BTVRateLimitError, # 429, com .retry_after em segundos
    BTVGatewayError,   # 5xx
    BTVValidationError # 4xx
)
```

---

### Próximos passos / Relacionados

- [Quickstart](./quickstart.md)
- [Conceitos](./concepts.md)
- [Integrações](./integrations/index.md)
- [Changelog](./changelog.md)

---

<sub>[↑ Hub](./README.md) · [Trilha Engenheiro](./for-engineers.md) · [Trilha DPO/CISO](./for-dpo-ciso.md) · [Links de Referência](./reference-links.md)</sub>
