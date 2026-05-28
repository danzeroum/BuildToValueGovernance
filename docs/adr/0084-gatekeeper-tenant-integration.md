# ADR-0084: Gatekeeper Tenant Integration

**Status**: 🆕 PROPOSTO
**Data**: 28 de maio de 2026
**Autores**: IA Arquiteta (validado por revisões consolidadas)
**Impacto**: `rust/gateway/src/middleware/`, `rust/gateway/src/state.rs`,
             `rust/gateway/src/main.rs`

---

## Contexto

O ADR-0083 implementou `TenantStorageRouter` e `TenantKeyDeriver` no kernel.
O próximo bloqueante é integrar esses componentes ao pipeline do gateway Axum
de forma que:

1. Toda requisição carregue um `tenant_id` validado antes de tocar qualquer
   dado do ledger.
2. O `Gatekeeper` permaneça **síncrono e livre de I/O** — sua responsabilidade
   é varredura, não armazenamento.
3. A escrita no ledger físico por tenant ocorra no **handler**, após a
   varredura, com a TEK derivada para o tenant da requisição.

---

## Decisão: Middleware Axum extrai `tenant_id`

O `tenant_id` é extraído do Bearer JWT no middleware antes de o handler
executar. O handler recebe o `tenant_id` como extensão tipada de request —
nunca vê o JWT raw.

**Rejeitado: extração dentro do Gatekeeper.**
O Gatekeeper é síncrono por invariante arquitetural (ADR-0082 §5, ADR-0083 §D1).
Introduzir parsing de JWT no Gatekeeper violaria a separação de camadas
e exigiria torná-lo async, quebrando o SLA de `<30ms p99`.

---

## Sequência de Execução

```
Request HTTP
  │
  ▼
[ApiKeyLayer]           ← autenticação (auth.rs, Gap #6)
  │
  ▼
[TenantExtractor]       ← extrai tenant_id do JWT → TenantId extension (ADR-0084)
  │
  ├─ JWT sem tenant_id  → TenantId("default")         retro-compat ADR-0083
  ├─ JWT tenant inválido → E131 (403) imediato         fail-secure
  │
  ▼
Handler(State<AppState>, Extension<TenantId>, ...)
  │
  ├─ Gatekeeper::scan_for_evidence(input)           ← síncrono, sem tenant
  ├─ AppState.router.route(tenant_id).await         ← ledger do tenant
  ├─ AppState.deriver.derive(tenant_id) → TEK       ← chave do tenant
  └─ ledger.append(entry, &tek)                     ← escrita isolada
```

---

## O que este ADR implementa

1. **`TenantId` newtype**: extensão de request tipada para carregar o
   `tenant_id` validado sem `String` avulsa em `Extensions`.

2. **`TenantExtractor` Layer**: middleware Tower/Axum que:
   - Lê o header `Authorization: Bearer <token>`.
   - Decodifica os claims JWT com `BTV_JWT_SECRET` (via `jsonwebtoken`).
   - Extrai `claims.tenant_id`; se ausente → `"default"` (retro-compat).
   - Valida `tenant_id` via `validate_tenant_id` (formato `[a-z0-9-]`).
   - Insere `TenantId(tenant_id)` como extensão tipada de request.
   - Em dev sem `BTV_JWT_SECRET`: decodifica sem verificação de assinatura
     (apenas `dangerous_insecure_decode`) com aviso de log.

3. **`AppState` additions**: `TenantStorageRouter` e `TenantKeyDeriver`
   injetados no estado compartilhado do Axum.

## O que este ADR NÃO implementa (próximo passo)

A chamada `ledger.append(entry, &tek)` nos handlers existentes fica para
o próximo sprint. Este ADR entrega a **infra-estrutura** (extração,
validação, estado compartilhado). O handler pode começar a usar
`Extension<TenantId>` imediatamente após este commit.

---

## Invariantes

1. O handler nunca acessa o JWT raw — apenas `Extension<TenantId>`.
2. O Gatekeeper não sabe o que é `tenant_id` — recebe apenas `input: &str`.
3. `"default"` é sempre válido (retro-compatibilidade com APIs pré-JWT).
4. `tenant_id` inválido retorna E131 antes de qualquer leitura de estado.

---

## Breaking Changes (consumidores externos do JSONL)

⚠️ O caminho do ledger JSONL muda de:

```
data/ledger/decisions.jsonl
```

para:

```
data/ledger/{tenant_id}/decisions.jsonl
```

Clientes que leem o JSONL diretamente (scripts de auditoria, testes de
integração externos, dashboards customizados) **devem ser atualizados
antes do merge** para `main`. Para retro-compatibilidade durante
migração, basta varrer `data/ledger/*/decisions.jsonl` em ordem de
modificação. O tenant `default` agrega o tráfego pré-ADR-0083.

O ledger binário (`DurableLedger`) também migra para
`{BTV_TENANT_DATA_DIR}/{tenant_id}/ledger.db` (padrão `/data/tenants`).

## Referências

- ADR-0083 — Multi-Tenancy Isolation (TenantStorageRouter + TenantKeyDeriver)
- ADR-0082 — API Evolution & Deprecation Policy (§5: sync invariant)
- `docs/API_ETHICS_GUIDE.md` §5.1 (X-BTV-Decision-Id, separação de chaves)
- RFC 7519 — JSON Web Token (JWT)
