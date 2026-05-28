# ADR-052: API Evolution & Deprecation Policy

**Status:** Accepted  
**Data:** 2026-05-28  
**Decisores:** Arquiteta (Opus), Dev Rust (Sonnet), Reviewer (Opus)  
**Referências:** API_ETHICS_GUIDE.md, ADR-018 (Axum Gateway), ADR-010 (BiasDeclaration)

---

## Contexto

O BTV expõe contratos de API consumidos por integrações críticas em produção (bancário, saúde, RH).  
Uma mudança silenciosa em `ExplainDecision`, na estrutura de `TechnicalEvidence` (9596 bytes)  
ou no formato de `BiasDeclaration` pode:

1. Derrubar integrações regulatórias ativas
2. Invalidar evidências já auditadas
3. Quebrar o fluxo de `ContestabilitySLA` de 24h
4. Gerar violações de LGPD/EU AI Act por perda de rastreabilidade

---

## Decisão

### Classificação de Mudanças

| Tipo | Exemplo | Ação Requerida |
|------|---------|----------------|
| **Non-breaking** | Novo campo opcional na resposta | Adicionar em `/v1/` sem novo ADR |
| **Non-breaking** | Novo endpoint na mesma versão | Adicionar em `/v1/` + atualizar api-reference |
| **Breaking** | Remoção de campo obrigatório | Novo `/v2/` + ADR + deprecation 90 dias |
| **Breaking** | Mudança de tipo de dado | Novo `/v2/` + ADR + deprecation 90 dias |
| **Breaking** | Renomear campo de auditabilidade | **Proibido** — ver Invariante abaixo |
| **Emergency** | Patch de segurança crítico (CVSS ≥ 7.0) | Imediato + postmortem em 48h |

### Ciclo de Deprecação (mínimo 90 dias)

```
Dia 0:    Anúncio + headers Deprecation/Sunset adicionados ao /v1/
Dia 1-89: /v1/ opera normalmente com headers de aviso
Dia 30:   Webhook notificação aos tenants afetados
Dia 60:   Segunda notificação + documentação de migração publicada
Dia 90:   Sunset — /v1/ endpoint desativado (retorna 410 Gone)
```

### Headers de Deprecação Obrigatórios

```http
# Adicionados no Dia 0 a todos os endpoints deprecados
Deprecation: date="2026-06-27"
Sunset: date="2026-08-26"
Link: <https://docs.buildtovalue.org/migration/v1-to-v2>; rel="deprecation"
```

### Notificação via Webhook

POST para `tenant.webhook_url` configurado:

```json
{
  "event": "api.deprecation.notice",
  "affected_endpoints": ["/api/v1/decisions"],
  "sunset_date": "2026-08-26",
  "migration_guide": "https://docs.buildtovalue.org/migration/v1-to-v2",
  "days_remaining": 90
}
```

---

## Invariante de Auditabilidade (Linha Vermelha)

Os seguintes campos são **irremoviveis** de qualquer versão da API.  
Podem ser evoluídos (novos campos opcionais), nunca removidos ou renomeados:

- `explain_decision` — obrigação de Transparency Radical
- `verdict_id` — hash BLAKE3 da TechnicalEvidence (âncora de contestação)
- `BiasDeclaration` — prova estatística de equidade
- `contestable_until` — prazo do SLA de 24h
- `adr_reference` — rastreabilidade regulatória

> **Qualquer PR que remova ou renomeie estes campos será automaticamente rejeitado.**  
> A CI deve incluir um contrato de schema (JSON Schema ou Serde) que falha o build  
> se estes campos não estiverem presentes.

---

## Versionamento na URL (escolha definitiva)

Adotamos **URI versioning** (`/api/v1/`, `/api/v2/`) porque:

1. Visível para logs, gateways e firewalls sem inspecionar headers
2. Permite routing diferenciado no API Gateway
3. Compatível com `X-BTV-Governance-Version` header (redundância auditável)
4. Conforme ao ensinamento do Prof. Lachi: *"deixa claro para o cliente qual versão está sendo usada"*

**Rejeitado:** header versioning (`Accept: application/vnd.btv.v2+json`) — invisível em logs.

---

## Consequências

**Positivas:**
- Integrações bancárias e de saúde nunca quebram por surpresa
- Ledger permanece consultável em qualquer versão (evidências são imutáveis)
- ContestabilitySLA 24h preservado entre versões
- Developers sabem exatamente quando e como migrar

**Negativas:**
- Overhead de manter múltiplas versões simultaneamente (máx. 2 versões ativas)
- Necessidade de CI com contrato de schema para os campos invariantes

---

## Implementação

- **Sprint atual:** Adicionar headers `Deprecation`/`Sunset` ao middleware Axum
- **Sprint +1:** Implementar webhook de notificação de deprecação
- **Sprint +2:** CI com JSON Schema contract test para campos invariantes
- **Fase 7:** Aplicar política ao Plugin Runtime (ADR futuro sobre ABI Wasm)

---

*ADR criado pela Arquiteta (Opus). Aprovação: Reviewer (Opus).*
