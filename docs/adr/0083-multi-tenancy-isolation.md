# ADR-0083: Multi-Tenancy Isolation

**Status**: 🆕 PROPOSTO
**Data**: 28 de maio de 2026
**Autores**: IA Arquiteta (validado por revisões consolidadas)
**Impacto**: `rust/kernel/src/ledger/`, `rust/kernel/src/security/`,
             `rust/kernel/src/api/error_as_resource.rs`, gateway `main.rs`

---

## Contexto

O BTV opera hoje com um único `DurableLedger` singleton. Todos os tenants
compartilham o mesmo arquivo de ledger em disco, a mesma chave HMAC e o
mesmo canal de auditoria. Isso cria três violações críticas antes da
evolução para produção multi-tenant:

1. **Contaminação de dados**: eventos de um tenant vazam para o escopo de
   auditoria de outro. LGPD Art. 37 exige registros separados por controlador.

2. **Ausência de cripto-shredding por tenant**: destruir o acesso aos dados de
   um tenant (ex: direito ao esquecimento LGPD Art. 18, IV) requer destruir a
   chave de criptografia do tenant sem afetar os demais. Impossível com chave
   única.

3. **Escalada de privilégio via path traversal**: sem validação do `tenant_id`
   extraído do JWT, um atacante com JWT manipulado pode rotear sua requisição
   para o ledger de outro tenant.

Este ADR decide a arquitetura de isolamento que habilita Rawls/Jonas
por janela por tenant (Fase 5–6), `TenantCacheMoat` (Fase 7) e
cripto-shredding (Fase 11).

---

## Decisão

### D1 — Estratégia de Migração: Tenant Default (sem downtime)

O SQLite atual torna-se o tenant `"default"`. Novos tenants recebem
arquivo isolado em:

```
/data/tenants/{tenant_id}/ledger.db
/data/tenants/{tenant_id}/ledger.wal
```

A validação do `tenant_id` proíbe qualquer caractere fora de
`[a-z0-9\-]` (máximo 64 chars) para prevenir path traversal.
O tenant `"default"` sempre existe como fallback para chamadas
sem `tenant_id` no JWT (retro-compatibilidade com clientes existentes).

### D2 — Derivação de Chave: TEK via HKDF

```
TEK = HKDF-SHA256(ikm=MKK, salt=[], info="btv-tek-v1:{tenant_id}", len=32)
```

- **MKK** (Master Key for Key-derivation): carregada em RAM via
  `keys::init_kernel_mac_key()`, derivada de `BTV_HMAC_KEY`.
  Nunca gravada em disco.
- **TEK** (Tenant Encryption Key): derivada deterministicamente, mantida
  em `Zeroizing<[u8; 32]>`. Destruída ao sair do escopo.
- **Cripto-shredding**: basta destruir o material de TEK do tenant no KMS
  externo. O BLAKE3 hash-chain permanece verificável por hash; o conteúdo
  decifrado torna-se inacessível.

Esta abordagem não é HKDF para criptografia de dados em repouso nesta fase
— é a base para que Fase 11 possa derivar chaves de criptografia por tenant
a partir da MKK. O `TenantKeyDeriver` exposto aqui deriva bytes de chave;
o uso deles para cifrar o ledger fica em ADR futuro.

### D3 — Validação de Fronteira no Gatekeeper

O `tenant_id` extraído do JWT deve ser comparado com o `tenant_id` de
roteamento **antes** de qualquer acesso ao ledger. Falha → **E131**
(Tenant Isolation Boundary Violation, HTTP 403), sem fallback.

```
JWT.claims.tenant_id == routing.tenant_id  →  OK
JWT.claims.tenant_id != routing.tenant_id  →  E131 imediato
JWT sem claims.tenant_id                   →  rota para "default"
```

O `TenantStorageRouter` valida o `tenant_id` antes de criar ou retornar
o ledger, garantindo que path traversal seja impossível em nível de kernel.

---

## Invariantes

1. **Jamais dois tenants compartilham ledger**: `TenantStorageRouter` é a
   única factory de `DurableLedger`. Instâncias diretas fora do router são
   proibidas em contexto multi-tenant.
2. **TEK zero-on-drop**: `TenantKeyDeriver::derive` retorna `Zeroizing<[u8; 32]>`.
   A chave é apagada da memória quando sai do escopo — o chamador nunca
   deve copiar para `Vec<u8>` ou `String`.
3. **Sem acesso ao ledger antes da validação JWT**: o Gatekeeper valida
   `tenant_id` antes de chamar `router.route()`.
4. **`tenant_id` alfanumérico**: qualquer caractere fora de `[a-z0-9\-]`
   (máx 64 chars) produz E131 imediato — nunca toca o filesystem.

---

## Consequências

**Positivas:**
- Habilita Rawls/Jonas com janela deslizante por tenant (Fases 5–6).
- Base para cripto-shredding sem reestruturar o hash-chain (Fase 11).
- Auditoria forense por tenant satisfaz LGPD Art. 37 (registros por controlador).
- Path traversal eliminado em nível de kernel, não de handler.

**Negativas / Trade-offs:**
- `DurableLedger::new()` é async; o router precisa de `tokio::sync::RwLock`.
  Em contêineres com muitos tenants simultâneos, o primeiro acesso de cada
  tenant tem latência adicional de abertura de arquivo.
- Cada tenant consome um file descriptor; em produção, configurar
  `ulimit -n` adequadamente.

**Fora de escopo desta fase:**
- Criptografia em repouso do ledger (Fase 11 — ADR futuro).
- `TenantCacheMoat` — usa `TenantKeyDeriver` mas é implementado no
  módulo de cache (Fase 7).
- Integração do `TenantStorageRouter` no Gatekeeper existente — requer
  ADR de integração após validação do router em staging.

---

## Referências

- ADR-0010 — BiasDeclaration Mandate
- ADR-0017 — Contestability Loop (SLA 24h)
- ADR-0052 — Forensic Audit Storage
- ADR-0082 — API Evolution & Deprecation Policy
- LGPD Art. 18 (Direito ao esquecimento) e Art. 37 (Registros)
- RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
