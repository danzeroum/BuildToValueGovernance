# API Ethics Guide — BuildToValue Governance

> **Fonte de verdade** para qualquer desenvolvedor que integre, estenda ou mantenha a interface pública do BTV.  
> Princípio central (Prof. Lachi, FIA): *"Uma API bem projetada é difícil de usar indevidamente."*

---

## 1. Princípio Fundante

O BTV é um **Trust OS**. Sua API não é apenas uma interface técnica — é um contrato ético.  
Isso impõe dois requisitos simultâneos:

1. **Guiar o código correto**: o desenvolvedor do Tenant deve conseguir integrar sem ler o kernel.
2. **Comunicar o motivo regulatório**: cada restrição deve ser rastreável a um ADR específico.

> **Anti-pattern proibido**: retornar `403 Forbidden` sem corpo.  
> **Padrão obrigatório**: todo `4xx` deve conter `error_code`, `adr_reference` e `appeal_url`.

---

## 2. Recursos de Primeira Classe (Substantivos REST)

O BTV expõe **recursos**, não operações. URLs são substantivos no plural.

```
# Decisões de governança
POST   /api/v1/decisions                   ← submete payload para governança
GET    /api/v1/decisions/{decision_id}     ← recupera evidência imutável

# Contestações (Appeals) — recurso de primeira classe
POST   /api/v1/appeals                     ← cria nova contestação
GET    /api/v1/appeals                     ← lista contestações do tenant
GET    /api/v1/appeals/{appeal_id}         ← estado: created|reviewing|resolved

# Métricas de saúde do Tenant
GET    /api/v1/tenants/{tenant_id}/metrics?window=1h|24h|7d

# Políticas ativas
GET    /api/v1/policies                    ← lista policies do tenant
GET    /api/v1/policies/{policy_id}        ← versão e hash BLAKE3
```

### Regras de URL
- Sempre plural para coleções: `/decisions`, `/appeals`, `/policies`
- Nunca verbos na URL: ~~`/blockDecision`~~ → `POST /decisions` com body
- Versionamento obrigatório no prefixo: `/api/v1/`, `/api/v2/`
- Parâmetros de filtro via query string: `?window=24h`, `?status=blocked`

---

## 3. Error-as-a-Resource (Feedback Ético Informativo)

Todo erro `4xx` retorna um objeto estruturado que **guia a resolução**.

### Estrutura Canônica

```json
{
  "error_code": "E120",
  "ethical_ground": "BiasDeclaration ausente ou inválida",
  "adr_reference": "https://docs.buildtovalue.org/adrs/0010-bias-declaration-mandate",
  "remediation": "https://docs.buildtovalue.org/guides/bias-fix",
  "appeal_url": "/api/v1/appeals",
  "verdict_id": "blake3:a3f8c2...",
  "contestable_until": "2026-05-29T02:35:00Z"
}
```

### Campo `verdict_id`

O `verdict_id` é o hash BLAKE3 da `TechnicalEvidence` original (9596 bytes fixos).  
Ele é **obrigatório** em todo erro contestável — garante que o humano revisor tenha a **mesma visão exata** que o algoritmo teve no momento da decisão.  
Sem `verdict_id`, a contestação não pode ser instruída e o SLA de 24h não pode ser auditado.

```
Contestation Flow:
  BLOCK → response.verdict_id → POST /api/v1/appeals { verdict_id }
         → reviewer busca GET /api/v1/decisions/{verdict_id}
         → evidência imutável + BiasDeclaration + plugin_id + version
```

### Catálogo de Códigos de Erro

| Código | HTTP | Motivo Ético | Contestável |
|--------|------|--------------|-------------|
| E120 | 403 | BiasDeclaration ausente | Não (erro de contrato) |
| E130 | 403 | Violação de política ativa | Sim (24h SLA) |
| E140 | 403 | DIR abaixo do threshold | Sim (24h SLA) |
| E150 | 400 | Schema inválido (EarlyGuard) | Não |
| E160 | 400 | Assinatura HMAC inválida (Tampering) | Não |
| E429 | 429 | Z-Score de frequência excedido | Não |
| E500 | 500 | Plugin ético falhou (fail-secure BLOCK) | Sim (24h SLA) |

> **Regra de segurança**: nunca expor stack trace, detalhes internos ou path de arquivo  
> em respostas de erro. O `error_code` + `adr_reference` é suficiente para diagnóstico.

---

## 4. HATEOAS Ético — Respostas Autoexplicativas

As respostas do BTV devem conter **links para as próximas ações possíveis**,  
tornando o sistema navegável sem consultar documentação externa.

### Exemplo: decisão bloqueada

```json
{
  "decision": "BLOCK",
  "verdict_id": "blake3:a3f8c2...",
  "timestamp": "2026-05-28T02:35:00Z",
  "ethical_ground": "dir_threshold_violation",
  "_links": {
    "self": { "href": "/api/v1/decisions/blake3:a3f8c2..." },
    "appeal": { "href": "/api/v1/appeals", "method": "POST" },
    "policy": { "href": "/api/v1/policies/policy-v2.3.1" },
    "adr": { "href": "https://docs.buildtovalue.org/adrs/0008-dir-threshold" },
    "guide": { "href": "https://docs.buildtovalue.org/guides/dir-remediation" }
  }
}
```

### Exemplo: decisão permitida

```json
{
  "decision": "ALLOW",
  "verdict_id": "blake3:d9e1f4...",
  "sampling_mode": "full",
  "explain_decision": { "href": "/api/v1/decisions/blake3:d9e1f4..." },
  "_links": {
    "self": { "href": "/api/v1/decisions/blake3:d9e1f4..." },
    "metrics": { "href": "/api/v1/tenants/{tenant_id}/metrics" }
  }
}
```

---

## 5. Rate Limiting Transparente — Headers Obrigatórios

O BTV deve expor seus limites para que o cliente **nunca seja surpreendido** pelo throttle.

```http
HTTP/1.1 200 OK
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 847
X-RateLimit-Reset: 1748390400
X-BTV-Sampling-Mode: full
X-BTV-Governance-Version: v1
```

Quando throttled (Z-Score excedido):

```http
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1748390460
X-BTV-Throttle-Reason: z_score_exceeded
Retry-After: 60
```

---

## 6. Versionamento de API

Detalhado no **ADR-052**. Resumo operacional:

- Toda breaking change cria `/api/v2/` — `/api/v1/` não é removido antes do Sunset
- Campos de auditabilidade (`explain_decision`, `verdict_id`, `BiasDeclaration`) **nunca são removidos**
- `ExplainDecision` evolui apenas com campos **opcionais** adicionados
- Deprecação mínima de 90 dias com headers `Deprecation` e `Sunset`

---

## 7. Regras para Contribuidores

Se você está adicionando um novo endpoint ao BTV, verifique:

- [ ] URL usa substantivo plural e prefixo `/api/v1/`
- [ ] Todo `4xx` retorna estrutura `EthicalError` com `adr_reference`
- [ ] Resposta de BLOCK inclui `verdict_id` (hash BLAKE3 da evidência)
- [ ] Resposta inclui `_links` com `appeal` quando contestável
- [ ] Headers `X-RateLimit-*` presentes em toda resposta
- [ ] Breaking change gera novo ADR + bump de versão URL
- [ ] `explain_decision` obrigatório em toda decisão da Governance Layer

---

*Documento mantido pela Arquiteta (Opus). Revisões via PR com aprovação obrigatória do Reviewer (Opus).*  
*Versão: 1.0.0 — 2026-05-28*
