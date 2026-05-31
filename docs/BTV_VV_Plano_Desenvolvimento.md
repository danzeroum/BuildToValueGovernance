# BTV Governance — Análise, Validação e Plano de Desenvolvimento

> **Contexto.** Este documento responde à missão de 4 etapas a partir da auditoria
> `BTV_Plano_Desenvolvimento_Completo.docx` (v2.0). O objetivo desta fase é **planejar e
> escrever testes (RED)**, **não** escrever código de produção. Cada um dos pontos da
> auditoria foi validado contra o estado atual do repositório
> (`danzeroum/BuildToValueGovernance`, branch de trabalho `claude/pensive-babbage-nPjkr`).
>
> **Decisões do usuário que moldam este plano:**
> 1. **Escopo:** vulnerabilidades **+ capítulos de arquitetura** (versionamento, paginação,
>    RFC 7807, observabilidade, plugins).
> 2. **CRITICO-07:** validar JWT no próprio `auth.rs` (defesa em profundidade), documentando
>    a divergência de que **não é um bypass total** (o `tenant_extractor` já valida em prod).
> 3. **CRITICO-05:** apenas **remover** o `schemas.py` órfão (é código morto; `_models.py` já
>    é a fonte canônica).
>
> **Ajustes pós-revisão (validados no código):** quatro apontamentos do analista foram
> confirmados contra `state.rs` e incorporados — (1) `session_tracker` tem intenção ADR-044,
> a migração para `RwLock` é condicional (Passo 8); (2) testes que constroem `AppState` devem
> ser `#[tokio::test]` pois `new()` faz `tokio::spawn` (Passo 0); (3) os `#[allow(clippy::
> unwrap_used)]` dos registros Prometheus em `lazy_static!` são exceções documentadas que o
> gate clippy deve respeitar (Passo 16); (4) Prometheus/tracing já existem no gateway Rust →
> escopo de observabilidade reduzido para OTel + observabilidade Python (Passo 13).
>
> **Nota de contagem:** a tabela de validação cruzada do doc lista **14** itens. A seção de
> diagnóstico inclui um **15º** (MED-R05) que **não** está na tabela. Tratamos MED-R05 como
> item adicional `[DOC-EXTRA]`. Itens descobertos por nós fora do doc são marcados `[NOVO]`.

---

## ETAPA 1 — Resumo de Entendimento

### 1.1 Interpretação dos problemas (em minhas palavras)

| ID | Minha leitura do problema |
|----|---------------------------|
| **CRITICO-01** | Senhas são "hasheadas" com SHA-256 puro. SHA-256 é rápido e sem sal: dois usuários com a mesma senha geram o mesmo hash (vulnerável a rainbow tables) e brute-force é barato. Precisa de KDF lento com sal (bcrypt/argon2). |
| **CRITICO-02** | Se `BTV_ADMIN_PASSWORD` não estiver setada, o seed do admin cai para a string `"admin"`. Credencial padrão conhecida → comprometimento trivial em deploys mal configurados. |
| **CRITICO-03** | Endpoints de `appeals`, `ledger`, `webhooks` (e outros) não exigem nenhuma identidade. Qualquer cliente HTTP lê/escreve recursos de governança. Webhooks externos sem verificação de origem são vetor de entrada. |
| **CRITICO-04** | Existe um `SecurityHeadersMiddleware`, mas ele está pendurado num `FastAPI()` isolado que nunca é montado no app real. Resultado: nenhum header de segurança nas respostas de produção. É código morto. |
| **CRITICO-05** | `schemas.py` duplica modelos que vivem em `_models.py`, com campos divergentes. Risco de duas fontes de verdade. (Na validação descobri que `schemas.py` é **órfão** — ninguém importa.) |
| **CRITICO-06** | `_init_users_db()` roda no início de **cada** login (cria tabela + seed). Overhead em hot-path e risco teórico de corrida concorrente. Deveria rodar uma vez no startup. |
| **CRITICO-07** | No middleware Rust, um header `Authorization: Bearer <qualquer-coisa>` faz o request seguir direto (`inner.call`) **sem validar** o token nesse ponto. O doc chama de "bypass total". |
| **CRITICO-09** | O `Gatekeeper` é guardado por `std::sync::Mutex` dentro do runtime Tokio. Lock síncrono bloqueia a thread do executor → serializa requisições, mata a concorrência async. |
| **CRITICO-10** | `warm_policies()` existe para pré-carregar políticas no startup, mas nunca é chamada. Políticas acabam carregadas sob demanda na 1ª requisição (latência/comportamento imprevisível). |
| **HIGH-01** | A API Python não tem rate limiting. Aberta a brute-force de login e DoS por saturação. |
| **HIGH-03** | `input_text` é `str` sem `max_length`. Payload arbitrário (MB/GB) → consumo de memória / DoS. |
| **HIGH-04** | `_resolve_role()` é um stub que sempre devolve `"anonymous"`. Toda autorização baseada em role é inerte. |
| **MED-R02** | Header `X-RateLimit-Remaining` é fixo em `"59"`. Engana clientes que fazem backoff adaptativo. |
| **MED-R03** | O rate limiter Rust usa `HashMap` sem evicção/TTL → cresce indefinidamente → memory leak/OOM. |
| **MED-R05** `[DOC-EXTRA]` | Quando o decode do JWT falha, cai para tenant `"default"` em vez de rejeitar (fail-soft). Risco de cross-tenant. |

### 1.2 Dependências entre as correções

- **HIGH-04 (`_resolve_role`) ⟸ CRITICO-03 (auth nos endpoints).** Adicionar autenticação sem
  consertar a resolução de role cria "ilusão de segurança": usuários autenticados continuam
  tratados como anônimos. **HIGH-04 deve vir junto ou antes** das checagens de role.
- **CRITICO-02 (remover senha padrão) ⟺ CRITICO-01 (bcrypt).** Mesmo arquivo, mesma função de
  seed; devem ser um único commit para não deixar estado intermediário inseguro.
- **CRITICO-06 (init no startup) ⟸ existência do `lifespan`.** O repo já tem `_lifespan.py`
  com `init_auth()`; a correção **reusa** esse lifespan (não cria `@app.on_event`, que é
  deprecado).
- **CRITICO-07 (validar JWT no auth.rs)** compartilha lógica de decode com **MED-R05**
  (`tenant_extractor`). Devem usar a **mesma** função de validação (DRY) → planejados em
  sequência, mesmo módulo conceitual.
- **MED-R02 ⟺ MED-R03** vivem no mesmo arquivo (`rate_limit.rs`); um commit.
- **CRITICO-04 (headers) ⟺ HIGH-01 (rate limit) ⟺ versionamento/paginação** todos tocam
  `app.py` → agrupar para minimizar conflitos de merge.

### 1.3 Impacto esperado de cada correção (o que muda para o cliente da API)

| Correção | Mudança observável |
|----------|--------------------|
| 01/02 | **Breaking no startup:** sem `BTV_ADMIN_PASSWORD` (≥12 chars) o app **recusa** subir. Hashes SHA-256 antigos param de validar → precisa re-seed/migração de senhas. |
| 03 | Endpoints antes públicos passam a exigir API key / JWT / HMAC. **Clientes sem credencial recebem 401.** |
| 04 | Toda resposta passa a incluir HSTS, CSP, X-Frame-Options, etc. Transparente para clientes bem-comportados. |
| 05 | Nenhum impacto runtime (remoção de código morto). |
| 06 | Sem mudança funcional; login mais rápido; startup faz o seed. |
| 07 | `Bearer` inválido no gateway passa a receber **401** (antes passava). |
| 09 | Sem mudança de contrato; **throughput** sob concorrência sobe. |
| 10 | 1ª requisição após restart deixa de ter latência de cold-load; se políticas falharem, o gateway **não sobe** (fail-fast). |
| HIGH-01 | Excesso de requisições → **429** com headers de rate limit. |
| HIGH-03 | `input_text` > 50 000 chars → **422** (validação Pydantic). |
| HIGH-04 | Decisões/headers passam a refletir o role real do chamador. |
| R02 | `X-RateLimit-Remaining` passa a refletir o valor real. |
| R03 | Sem mudança de contrato; memória do gateway estabiliza. |
| R05 | JWT inválido → **401** em vez de roteado para `default`. |

### 1.4 Dúvidas / divergências com o diagnóstico (validadas na Etapa 2)

1. **CRITICO-07 não é "bypass total".** O `tenant_extractor.rs` **valida** assinatura+exp em
   produção (com `BTV_JWT_SECRET`). O bypass real existe no **caminho Bearer do `auth.rs`**
   (que pula a checagem de API key). Severidade alta permanece, mas a narrativa "qualquer
   string acessa qualquer endpoint protegido" é imprecisa em prod. → Decisão: validar no
   `auth.rs` mesmo assim (defesa em profundidade).
2. **CRITICO-05 — `schemas.py` é órfão.** O doc sugere criar um novo `models.py` consolidado;
   na realidade `_models.py` **já é** a fonte canônica e mais completa. A solução correta é
   **deletar `schemas.py`**, não criar módulo novo.
3. **CRITICO-06 — corrida é improvável.** Usa `CREATE TABLE IF NOT EXISTS`; o impacto real é
   overhead, não corrupção. Severidade "médio" é mais justa. Correção (mover p/ startup)
   continua válida.
4. **CRITICO-09 — o doc esqueceu o `session_tracker`.** Há **dois** `std::sync::Mutex`
   (`gatekeeper` linha 183 e `session_tracker` linha 186). Ambos devem migrar.
5. **CRITICO-10 — `warm_policies()` está em `policy_loader.rs`**, não em `main.rs`. A correção
   (chamar no `main`) é a mesma; a localização da definição diverge do doc.
6. **HIGH-04 — assinatura divergente.** A função real é `_resolve_role(session_id: str)`, não
   `_resolve_role(request, user=None)`. O "código depois" do doc **não compila** contra a
   assinatura atual; a correção precisa do contexto de request/claims, exigindo mudar a
   assinatura **e** os call-sites.
7. **Versionamento `/api/v1` — conflito.** As rotas já carregam `/v1/...` no próprio path
   (`@router.post("/v1/appeals")`). Aplicar o prefixo `/api/v1` do doc geraria `/api/v1/v1/...`
   (duplo prefixo). → O passo de versionamento **normaliza** isso, não soma cego.
8. **`add_security_headers` é classe, não função.** O `response_sanitizer.py` define um
   `SecurityHeadersMiddleware(BaseHTTPMiddleware)`. Registrar via
   `app.add_middleware(SecurityHeadersMiddleware)` é mais simples que a conversão p/ função
   do doc. Reusa `ResponseSanitizer.get_safe_headers()`.
9. **Imports são absolutos** (`from buildtovalue.api...`). Os exemplos do doc usam imports
   relativos (`from routes.auth import ...`) — não aplicáveis aqui.

---

## ETAPA 2 — Relatório de Validação (estado atual do repo)

Legenda: **✅ Confirmado** · **⚠️ Divergente** (existe, mas diferente do doc) · **❌ Não encontrado**

| ID | Arquivo:linha real | Status | Observação de validação |
|----|--------------------|--------|--------------------------|
| CRITICO-01 | `python/buildtovalue/api/routes/auth.py:94,113` | ✅ | `hashlib.sha256(...).hexdigest()`. bcrypt/argon2/passlib **ausentes** no projeto. |
| CRITICO-02 | `…/routes/auth.py:93` | ✅ | `os.environ.get("BTV_ADMIN_PASSWORD", "admin")`; só usado no seed de tabela vazia, com `logger.warning`. |
| CRITICO-03 | `routes/appeals.py` (5), `ledger.py` (2), `webhooks.py` (3) + `fleet/health/intelligence/metrics` | ✅ | Helpers **já existem**: `require_api_key` em `api/auth.py:39-50`; `require_jwt` em `routes/auth.py:140-147`. Endpoints só dependem de providers de estado, não de auth. |
| CRITICO-04 | `api/response_sanitizer.py:98-112` | ⚠️ | Confirmado morto, **mas** é classe `SecurityHeadersMiddleware(BaseHTTPMiddleware)` + `app=FastAPI()` isolado, não a função `@app.middleware` do doc. `app.py` só registra `CORSMiddleware` (linha 70). |
| CRITICO-05 | `api/schemas.py` (69 ln) vs `api/_models.py` (223 ln) | ⚠️ | Confirmado duplicação e campos a mais em `_models.py` (`evidence_hash`, `grounds`, `mediator_recommendation`). **Divergência:** `schemas.py` tem **zero imports** → código morto; `_models.py` é canônico. |
| CRITICO-06 | `routes/auth.py:154` (`login()` chama `_init_users_db()`) | ✅ | Confirmado per-request. Já existe `_lifespan.py` (lifespan ativo, `init_auth()` na linha 203) para ancorar o fix. |
| CRITICO-07 | `rust/gateway/src/middleware/auth.rs:99-110` | ⚠️ | Caminho `Bearer` faz `inner.call(req)` sem validar (TODO explícito). **Divergência:** `tenant_extractor.rs:196-207` **valida** assinatura+exp em prod. Não é bypass total; é bypass da camada API-key. |
| CRITICO-09 | `rust/gateway/src/state.rs:183` **e :186** | ⚠️ | `std::sync::Mutex<Gatekeeper>` confirmado. **Divergência:** há também `Mutex<SessionTracker>` (:186) não citado pelo doc. Sem `tokio::sync` no Cargo de uso. |
| CRITICO-10 | def em `rust/gateway/src/policy_loader.rs:235`; **sem** call em `main.rs` | ⚠️ | Confirmado nunca chamada. **Divergência:** doc diz `main.rs` p/ a definição; ela está em `policy_loader.rs`. |
| HIGH-01 | `python/buildtovalue/api/app.py` | ✅ | Sem rate limiting; `slowapi` ausente. (Há `test_rate_limit_per_tenant.py`, porém testando lógica mockada, não middleware real.) |
| HIGH-03 | `python/buildtovalue/api/_models.py:17` | ✅ | `input_text: str = ""` em `DecideRequest`, sem `Field(max_length=…)`. |
| HIGH-04 | `python/buildtovalue/api/_decide_helpers.py:93-95` | ⚠️ | `_resolve_role(session_id: str) -> "anonymous"`. **Divergência de assinatura** vs doc (`request, user=None`). |
| MED-R02 | `rust/gateway/src/middleware/rate_limit.rs:142` | ✅ | `from_static("59")` hardcoded. |
| MED-R03 | `rate_limit.rs:60` | ✅ | `Arc<Mutex<HashMap<String,(u32,Instant)>>>` sem evicção; `moka` ausente no Cargo. |
| MED-R05 `[DOC-EXTRA]` | `rust/gateway/src/middleware/tenant_extractor.rs:158-163` | ⚠️ | Fallback p/ `DEFAULT_TENANT_ID` no erro de decode. **Contexto:** só em dev (sem secret); em prod o `decode()` já rejeita. Não consta na tabela de validação cruzada do doc. |

**Achados `[NOVO]` durante a validação:**
- `[NOVO-01]` **`session_tracker: Mutex<SessionTracker>`** (`state.rs:186`) usa o mesmo
  `std::sync::Mutex` síncrono. **Porém** o campo tem comentário ADR-044 (`// stateful, por
  sessao`) e `ip_classifier`/`jurisdiction_mapper` (`:184-185`) são **stateless** (sem lock).
  Migrar `session_tracker` para `RwLock` pode **não** trazer ganho (mutações frequentes →
  `RwLock` degenera para lock exclusivo). **Confirmar a intenção no ADR-044 antes de migrar**
  (ver Passo 8): `gatekeeper` é read-heavy → `RwLock`; `session_tracker` pode permanecer
  `Mutex` (trocando só `std::sync` → `tokio::sync::Mutex` para não bloquear o executor).
- `[NOVO-02]` **Endpoints sem auth além dos citados:** `fleet`, `health`, `intelligence`
  (`/sync`, `/status`), `metrics`. A contagem real de "11" do doc só fecha somando estes.
  Decidir explicitamente quais são públicos por design (ex.: `/health`, `/metrics` para o
  Prometheus scraper) vs protegidos.
- `[NOVO-03]` **Conflito de prefixo `/v1`** já documentado (item 7 da §1.4).

**Testes existentes que precisarão ser atualizados:**
- `python/tests/unit/api/test_appeals_api.py` (fixture remove `BTV_API_KEYS` para simular
  ausência de auth — quebrará quando appeals exigir auth; precisa enviar credenciais).
- `python/tests/integration/test_auth.py` (já cobre `X-API-Key`; estender p/ JWT/roles).
- `python/tests/integration/test_rate_limit_per_tenant.py` (alinhar com o novo middleware).
- `python/tests/conftest.py` (já injeta `BTV_JWT_SECRET`; adicionar `BTV_ADMIN_PASSWORD` ≥12).
- Rust: `tests/api_tests.rs`, módulos `#[cfg(test)]` em `state.rs`, `policy_loader.rs`,
  `tenant_extractor.rs`, e `rate_limit.rs`.

---

## ETAPA 3 — Estratégia de Verificação & Validação (V&V)

### 3.1 Princípio: Verificação ≠ Validação (aplicado a cada nível)

- **Verificação ("está correto?"):** o código cumpre a especificação do doc e os contratos
  de interface (assinaturas, status codes, schemas Pydantic, traits Rust)? Critérios de
  aceitação satisfeitos?
- **Validação ("é o que deveria fazer?"):** o comportamento resolve o risco real (segurança/
  negócio)? Ex.: não basta `bcrypt.checkpw` retornar `True` (verificação) — o sistema deve
  **rejeitar** credenciais erradas e **não vazar** timing/hash (validação).

### 3.2 Cobertura por nível de teste

**Nível 1 — Unitário** (pytest+pytest-cov / cargo test+tarpaulin)
- Limites: senha vazia, 11 chars (deve falhar ≥12), unicode/emoji, payload 50 000 vs 50 001.
- Risco: `bcrypt` hash/verify, `validate_jwt` (token expirado, assinatura errada, alg trocado,
  claim ausente) → **100% de branches** nos módulos de auth.
- Complexidade: funções com ciclomática > 5 (ex.: middleware de auth Rust) → teste por branch.

**Nível 2 — Integração** (pytest+httpx async / `#[tokio::test]`)
- Contratos: TestClient ↔ SQLite (users/appeals), gateway Rust ↔ API Python, cadeia de
  middleware completa.
- Fail-secure: JWT secret ausente, DB indisponível, política não carrega.
- Concorrência: **≥50 tasks** simultâneas em `_init_users_db` (idempotência), `RwLock`
  (leituras concorrentes), rate limiter (contagem correta sob paralelismo).

**Nível 3 — Sistema** (pytest + docker-compose; k6/locust p/ carga). Fluxos obrigatórios:
1. login → JWT → endpoint protegido → 200
2. login senha errada → 401 → após N tentativas → 429
3. submit appeal sem API key → 401
4. submit appeal com API key → 201 → get → resolve
5. Bearer inválido no gateway Rust → 401
6. `input_text` > 50KB → 422
7. restart do gateway → políticas carregadas antes da 1ª requisição

**Nível 4 — Aceitação** (OWASP ZAP DAST + checklist)
- OWASP Top 10 2021 mapeado: A01 (HIGH-04, CRITICO-03), A02 (CRITICO-01), A05 (CRITICO-04),
  A07 (CRITICO-02/07/R05), A04/A06 (rate limit, deps).
- Headers (HSTS/CSP/X-Frame/X-Content-Type) em **todas** as respostas.
- Audit trail imutável (decisões não deletáveis); SLA de contestabilidade dentro do prazo.

### 3.3 Cenários BDD (escritos ANTES do código — RED primeiro)

```gherkin
# CRITICO-01 — bcrypt hashing
Feature: Hashing de senha com bcrypt
  Scenario: Senha é armazenada com bcrypt, não SHA-256
    Given um usuário criado com a senha "S3nh@-Forte-2026"
    When inspeciono o hash persistido
    Then o hash começa com "$2b$" (ou "$2a$")
    And o mesmo texto gera hashes diferentes (sal aleatório)
  Scenario: Verificação aceita a senha correta e rejeita a errada
    Given um usuário com senha "S3nh@-Forte-2026"
    When tento autenticar com "senha-errada"
    Then a autenticação falha
    When tento autenticar com "S3nh@-Forte-2026"
    Then a autenticação tem sucesso

# CRITICO-02 — sem senha padrão
  Scenario: App recusa subir sem BTV_ADMIN_PASSWORD
    Given a variável BTV_ADMIN_PASSWORD não definida
    When o startup executa o seed do admin
    Then um RuntimeError é levantado e o processo não inicia
  Scenario: App recusa senha admin curta
    Given BTV_ADMIN_PASSWORD = "curta"  # <12
    Then o startup falha com mensagem instrucional

# CRITICO-03 — endpoints protegidos
Feature: Autenticação nos endpoints de governança
  Scenario: submit appeal sem credencial é rejeitado
    Given o app com BTV_API_KEYS configurado
    When envio POST /v1/appeals sem X-API-Key nem Bearer
    Then a resposta é 401
  Scenario: submit appeal com JWT válido é aceito
    Given um JWT válido assinado com BTV_JWT_SECRET
    When envio POST /v1/appeals com esse Bearer
    Then a resposta é 201

# CRITICO-06 — init no startup
Feature: Inicialização única do users DB
  Scenario: _init_users_db roda no startup, não por requisição
    Given a app inicializada
    When faço 100 logins consecutivos
    Then _init_users_db foi invocada exatamente 1 vez (no lifespan)

# CRITICO-07 — gateway Rust valida JWT
Feature: Autenticação no Gateway Rust
  Scenario: Bearer inválido é rejeitado
    Given o gateway rodando com BTV_JWT_SECRET configurado
    When chega "Authorization: Bearer token_invalido"
    Then a resposta é 401
    And nenhum handler interno é invocado
  Scenario: Bearer válido é aceito
    Given um JWT válido assinado com BTV_JWT_SECRET
    When chega com esse token
    Then a resposta é 200
    And as claims ficam disponíveis em request.extensions

# CRITICO-09 — RwLock concorrência
Feature: Acesso concorrente ao Gatekeeper
  Scenario: 50 leituras concorrentes não serializam
    Given o AppState com gatekeeper em RwLock
    When 50 tasks tokio leem políticas simultaneamente
    Then todas completam sem deadlock
    And nenhuma thread do executor fica bloqueada

# HIGH-01 — rate limiting
Feature: Rate limiting na API Python
  Scenario: Excesso de requisições retorna 429
    Given o limite de 10/min no /v1/auth/login
    When envio 11 requisições em 1 minuto do mesmo IP
    Then a 11ª resposta é 429

# HIGH-03 — input_text max_length
Feature: Limite de tamanho do input_text
  Scenario: payload acima do limite é rejeitado
    Given DecideRequest com max_length=50000
    When envio input_text com 50001 caracteres
    Then a resposta é 422
```

### 3.4 Análise estática / SAST (critérios de bloqueio — PR não abre se falhar)
- **Python:** `bandit -r python/ -ll` sem HIGH/MEDIUM · `radon cc` sem função >10 ·
  `vulture` (confirma remoção de `schemas.py`) · `pytest --cov` ≥80% geral, **100% em auth**.
- **Rust:** `cargo clippy --all-targets -- -D warnings -D clippy::unwrap_used
  -D clippy::expect_used -D clippy::panic` · `cargo tarpaulin --fail-under 75` ·
  `cargo audit` sem CVSS≥7.0.
- **Pipeline:** `trufflehog` (sem secret verificado), OWASP Dependency-Check,
  checklist de headers via `curl -I`.
- **Integração com o repo:** estender `.github/workflows/lint-guards.yml` e
  `.pre-commit-config.yaml` (já existentes) com bandit/clippy/cov; **não** introduzir CI novo do zero.

### 3.5 Mapa de cobertura (resumo)

| ID | Unit | Integração | Sistema | Aceitação |
|----|:---:|:---:|:---:|:---:|
| 01/02 | bcrypt hash/verify, limites senha | login→token | fluxo 1,2 | A02, A07 |
| 03 | deps de auth por rota | 401/201 por credencial | fluxo 3,4 | A01 |
| 04 | headers gerados | middleware na cadeia | header em todas resp | A05 |
| 05 | — (remoção) | imports não quebram | smoke | — |
| 06 | idempotência seed | 50 logins → 1 init | restart | — |
| 07 | validate_jwt branches | gateway 401/200 | fluxo 5 | A07 |
| 09 | — | 50 leituras RwLock | carga k6 | — |
| 10 | warm_policies ok/erro | startup ordem | fluxo 7 | — |
| H01 | limiter contagem | 429 | fluxo 2 | A04 |
| H03 | 50000/50001 | 422 | fluxo 6 | — |
| H04 | role por claims | autorização real | fluxo 1 | A01 |
| R02 | remaining real | header dinâmico | carga | — |
| R03 | evicção TTL | 50 clientes | soak test | — |
| R05 | decode falha→erro | gateway 401 | fluxo 5 | A07 |

---

## ETAPA 4 — Plano de Desenvolvimento Sequencial

Ordenação por: (1) dependência técnica, (2) menor superfície de quebra, (3) agrupamento por
arquivo, (4) testabilidade incremental. **Não** por criticidade (deploy único). Cada passo =
1 commit atômico. Para código novo, os testes BDD/TDD entram **antes** (RED).

> **Convenção de cada passo:** Arquivos · Problemas · Pré-req · O que fazer · Verificação ·
> Validação · Como confirmar · Risco de regressão.

---

### Passo 0 — Andaime de testes (RED) e harness de SAST
**Arquivos:** `python/tests/...` (novos), `rust/gateway/tests/...` (novos),
`.pre-commit-config.yaml`, `.github/workflows/lint-guards.yml`, `python/pyproject.toml`
(deps de teste: bcrypt, slowapi; já tem PyJWT/prometheus/pytest-cov).
**Problemas:** infra para todos. **Pré-req:** nenhum.
**O que fazer:** escrever todos os testes dos cenários BDD §3.3 como falhando (RED); adicionar
fixtures (`BTV_ADMIN_PASSWORD`, JWT helper) ao `conftest.py`; ligar bandit/clippy/cov nos hooks
e CI **sem** ainda exigir bloqueio (modo report).
**⚠️ Restrição Rust (revisão):** `AppState::new()` chama `spawn_drainer(sink)` → `tokio::spawn`
(`state.rs:283`, comentado em `:446`), exigindo runtime ativo. Todo teste que constrói
`AppState` **deve** ser `#[tokio::test]` (não `#[test]`) ou usar os construtores de teste já
existentes `AppState::with_policies_dir()` / `with_audit_dir()` (`state.rs:330,340`).
**Verificação:** os testes existem e falham pelas razões certas (código ausente, não erro de import).
**Validação:** os cenários cobrem o comportamento de segurança esperado.
**Como confirmar:** `pytest -k "novo"` → todos RED; `cargo test` → novos testes RED.
**Risco:** Baixo. **O que pode quebrar:** nada de produção.

---

### Passo 1 — auth.py: bcrypt + remover senha padrão + init no startup
**Arquivos:** `python/buildtovalue/api/routes/auth.py`, `python/buildtovalue/api/_lifespan.py`.
**Problemas:** CRITICO-01, CRITICO-02, CRITICO-06. **Pré-req:** Passo 0.
**O que fazer:** trocar `hashlib.sha256` por `bcrypt.hashpw/checkpw` (rounds=12); remover o
fallback `"admin"` e exigir `BTV_ADMIN_PASSWORD` ≥12 (senão `RuntimeError`); remover
`_init_users_db()` do `login()` e chamá-la uma vez no `lifespan` existente (perto do
`init_auth()`).
**Verificação:** hash começa com `$2b$`; `checkpw` aceita/rejeita; login não chama init.
**Validação (BDD):** CRITICO-01, 02, 06 verdes; senha errada → 401; sem env → app não sobe.
**Como confirmar:** `pytest tests -k "bcrypt or admin_pw or init_db"`; cobertura `auth.py` 100%;
`curl` login com senha certa/errada.
**Risco:** **Alto.** **O que pode quebrar:** hashes SHA-256 existentes invalidam (precisa
re-seed); fixtures sem `BTV_ADMIN_PASSWORD` falham (tratado no Passo 0).

---

### Passo 2 — _decide_helpers.py: implementar _resolve_role
**Arquivos:** `python/buildtovalue/api/_decide_helpers.py` + call-sites de `_resolve_role`.
**Problemas:** HIGH-04. **Pré-req:** Passo 1 (segredo/decode JWT já garantido).
**O que fazer:** mudar a assinatura para receber request/claims; extrair role do JWT validado
(reusar `SECRET_KEY`/PyJWT); fallback `"anonymous"` só quando realmente sem auth. Atualizar
todos os call-sites (a assinatura muda — ver §1.4 item 6).
**Verificação:** role real retornado p/ token válido; `"anonymous"` sem token.
**Validação:** autorização passa a refletir o chamador (A01).
**Como confirmar:** `pytest -k resolve_role`; teste de autorização por role.
**Risco:** **Médio.** **O que pode quebrar:** call-sites com a assinatura antiga.

---

### Passo 3 — Endpoints: aplicar autenticação diferenciada
**Arquivos:** `routes/appeals.py`, `routes/ledger.py`, `routes/webhooks.py` (+ decidir
`fleet/intelligence/metrics`; deixar `/health`, `/metrics` públicos por design — `[NOVO-02]`).
**Problemas:** CRITICO-03. **Pré-req:** Passos 1-2.
**O que fazer:** aplicar `Depends(require_api_key)` em leitura, `Depends(require_jwt)` em
escrita (reusar helpers de `api/auth.py` e `routes/auth.py`), e HMAC-SHA256 nos webhooks.
**Verificação:** cada rota tem a dependência correta; OpenAPI reflete os security schemes.
**Validação (BDD):** CRITICO-03 verde — 401 sem credencial, 201/200 com.
**Como confirmar:** `pytest tests/unit/api/test_appeals_api.py` (atualizado), `test_auth.py`.
**Risco:** **Alto.** **O que pode quebrar:** todo cliente sem credencial; testes que assumiam
endpoints abertos (atualizar fixtures — Etapa 2).

---

### Passo 4 — app.py: security headers + rate limiting (Python)
**Arquivos:** `python/buildtovalue/api/app.py`, `api/response_sanitizer.py`.
**Problemas:** CRITICO-04, HIGH-01. **Pré-req:** Passo 0.
**O que fazer:** registrar `SecurityHeadersMiddleware` via `app.add_middleware(...)` (reusar
`ResponseSanitizer.get_safe_headers()`, adicionando CSP/HSTS/Referrer/Permissions); integrar
`slowapi` (`Limiter`, handler de `RateLimitExceeded`) com limites por endpoint
(login 10/min, escrita 5/min, leitura 100/h).
**Verificação:** headers presentes em toda resposta; 11ª req → 429.
**Validação (BDD):** HIGH-01 verde; checklist de headers (A05).
**Como confirmar:** `curl -I /health | grep -E "Strict-Transport|Content-Security|X-Frame"`;
`pytest -k "headers or rate_limit"`.
**Risco:** **Médio.** **O que pode quebrar:** CSP estrito quebra dashboards/HTML embutido;
limites baixos afetam testes/integração.

---

### Passo 5 — _models.py: max_length em input_text + remover schemas.py
**Arquivos:** `python/buildtovalue/api/_models.py`, **deletar** `python/buildtovalue/api/schemas.py`.
**Problemas:** HIGH-03, CRITICO-05. **Pré-req:** nenhum (isolado).
**O que fazer:** `input_text: str = Field(default="", max_length=50000)`; confirmar com
`grep`/`vulture` que `schemas.py` tem zero imports e removê-lo (decisão do usuário: só remover).
**Verificação:** 50001 chars → 422; build/import sem `schemas.py`.
**Validação (BDD):** HIGH-03 verde; vulture limpo.
**Como confirmar:** `pytest -k input_text`; `python -c "import buildtovalue.api.app"`.
**Risco:** **Baixo.**

---

### Passo 6 — Rust auth.rs: validar JWT no caminho Bearer (defesa em profundidade)
**Arquivos:** `rust/gateway/src/middleware/auth.rs` (+ helper de validação compartilhado).
**Problemas:** CRITICO-07. **Pré-req:** Passo 0.
**O que fazer:** no ramo `Bearer`, decodificar/validar (HS256, exp, claims) com
`jsonwebtoken` reusando a lógica de `tenant_extractor::decode_tenant_claims`; em falha →
`401`; em sucesso → injetar claims em `req.extensions`. Documentar no código a divergência
(não era bypass total). **Sem** dev-bypass quando `BTV_JWT_SECRET` setado.
**Verificação:** branches de validate_jwt 100%; handler não é invocado em token inválido.
**Validação (BDD):** CRITICO-07 verde.
**Como confirmar:** `cargo test auth_middleware`; teste de integração 401/200.
**Risco:** **Médio.** **O que pode quebrar:** clientes que mandavam Bearer "decorativo".

---

### Passo 7 — Rust tenant_extractor.rs: fail-fast em decode inválido
**Arquivos:** `rust/gateway/src/middleware/tenant_extractor.rs`.
**Problemas:** MED-R05. **Pré-req:** Passo 6 (compartilham validação).
**O que fazer:** no `Err(())` do decode, retornar `401` em vez de `DEFAULT_TENANT_ID`. Manter
default apenas quando **não há** Bearer (anônimo legítimo, se aplicável).
**Verificação:** decode falho → erro propagado.
**Validação (BDD):** JWT inválido → 401 (A07).
**Como confirmar:** `cargo test tenant_extractor`.
**Risco:** **Médio.** **O que pode quebrar:** fluxos dev que dependiam do fallback.

---

### Passo 8 — Rust state.rs: substituir std::sync::Mutex por locks async
**Arquivos:** `rust/gateway/src/state.rs` + todos os call-sites de `.lock()`.
**Problemas:** CRITICO-09 + `[NOVO-01]`. **Pré-req:** Passo 0.
**O que fazer:** `gatekeeper` (read-heavy) → `tokio::sync::RwLock` (`.read().await` na maioria,
`.write().await` ao mutar). **`session_tracker`:** **primeiro confirmar o ADR-044** — se as
mutações forem dominantes (provável, dado o comentário "stateful, por sessao"), **manter
semântica de Mutex** trocando apenas `std::sync::Mutex` → `tokio::sync::Mutex` (o ganho real é
não bloquear o executor; `RwLock` aqui não ajudaria). `ip_classifier`/`jurisdiction_mapper`
são stateless → **não tocar**. Adicionar `tokio` feature `sync` se faltar.
**Verificação:** compila; 50 leituras concorrentes do `gatekeeper` sem deadlock; lock do
`session_tracker` não bloqueia a thread do executor.
**Validação (BDD):** CRITICO-09 verde; benchmark mostra menos serialização no gatekeeper.
**Como confirmar:** `cargo test --test api_tests`; `#[tokio::test]` concorrente.
**Risco:** **Alto** (toca muitos call-sites async). **O que pode quebrar:** qualquer
`.lock()` síncrono remanescente; ordem de locks (deadlock); decisão errada de RwLock vs Mutex
no `session_tracker` se o ADR-044 não for consultado.

---

### Passo 9 — Rust main.rs: chamar warm_policies() no startup
**Arquivos:** `rust/gateway/src/main.rs`.
**Problemas:** CRITICO-10. **Pré-req:** Passo 8 (estado estável).
**O que fazer:** após `GatewayConfig::load()` e antes do `axum::serve`, chamar
`policy_loader::warm_policies(...).await` com fail-fast (`?`/`expect` → não sobe sem políticas).
**Verificação:** log "Policies warmed"; falha de carga aborta startup.
**Validação (BDD):** fluxo 7 — políticas prontas antes da 1ª requisição.
**Como confirmar:** `cargo test`; restart manual + 1ª requisição sem cold-load.
**Risco:** **Baixo/Médio.** **O que pode quebrar:** se warm falhar em ambientes sem fonte de
políticas, o gateway deixa de subir (intencional).

---

### Passo 10 — Rust rate_limit.rs: moka + X-RateLimit-Remaining real
**Arquivos:** `rust/gateway/src/middleware/rate_limit.rs`, `rust/gateway/Cargo.toml` (add `moka`).
**Problemas:** MED-R02, MED-R03. **Pré-req:** Passo 0.
**O que fazer:** trocar `HashMap` por `moka::future::Cache` com TTL 60s e `max_capacity`;
calcular `remaining = limit - count` e setar headers dinâmicos (`Remaining`, `Limit`, `Reset`).
**Verificação:** header reflete contagem; entradas expiram (sem leak).
**Validação (BDD):** R02/R03 verdes; soak test estabiliza memória.
**Como confirmar:** `cargo test rate_limit`; `cargo audit` ok.
**Risco:** **Médio.** **O que pode quebrar:** semântica de janela difere de moka TTL (ajustar).

---

### Passo 11 `[ARQUITETURA]` — Versionamento de API + RFC 7807
**Arquivos:** `python/buildtovalue/api/app.py`, routers, handler de exceção global.
**O que fazer:** **normalizar** o prefixo (resolver o conflito `/v1` vs `/api/v1` — §1.4 item
7; escolher um padrão e redirecionar 301 do antigo por 90 dias); adotar Problem Details
(RFC 7807) em todas as respostas 4xx/5xx.
**Verificação:** rotas respondem no path canônico; erros seguem schema RFC 7807.
**Validação:** clientes recebem erros padronizados; sem duplo-prefixo.
**Risco:** **Alto** (transversal a todas as rotas e clientes).

---

### Passo 12 `[ARQUITETURA]` — Paginação + filtros nos endpoints de listagem
**Arquivos:** `routes/appeals.py`, `routes/ledger.py`, modelos de resposta.
**O que fazer:** `?page=&limit=` (default 1/20) + envelope `{data, pagination:{page,limit,total,pages}}`;
filtros/ordenação via query params.
**Verificação:** metadados corretos; limites respeitados.
**Validação:** datasets grandes navegáveis. **Risco:** **Médio.**

---

### Passo 13 `[ARQUITETURA]` — Observabilidade (escopo reduzido — só o que falta)
**Estado atual (revisão):** o gateway Rust **já tem** endpoint Prometheus `/metrics`
(`routes/metrics.rs`, montado em `mod.rs:77`), registros Prometheus (`state.rs` via
`lazy_static`) e `tracing`/`tracing-subscriber`. **Não recriar isso.** Lacunas reais:
**(a)** OTel/distributed tracing (sem dep `opentelemetry` no `Cargo.toml`); **(b)** Python:
logging estruturado com `request_id`, endpoint Prometheus cru e counters de segurança.
**Arquivos:** `app.py` (middleware logging/request_id + `/metrics`), `Cargo.toml` (+OTel),
init de OTel em ambos.
**O que fazer:** middleware structlog com `X-Request-ID`; counters
`btv_auth_failures_total`, `btv_rate_limit_exceeded_total` + histograma de latência (Python);
exporter OTLP + spans nas operações críticas (validate JWT, resolve role, policy lookup) nos
dois serviços, propagando W3C traceparent Rust→Python.
**Verificação:** `/metrics` Python expõe counters; logs JSON com correlation id; spans cruzam
gateway→API.
**Validação:** incidentes de auth/rate-limit observáveis ponta-a-ponta. **Risco:** **Médio.**

---

### Passo 14 `[ARQUITETURA]` — Contrato e registry de plugins
**Arquivos:** novo módulo de plugins (Python `PluginBase`/`PluginRegistry`; Rust trait `Plugin`),
hooks (`pre_auth`, `post_auth`, `on_audit_event`, …).
**O que fazer:** implementar contrato, ciclo de vida (register→validate→init→bind→execute→
shutdown) e registry thread-safe com isolamento de falhas, conforme cap. 7 do doc.
**Verificação:** registro idempotente; falha de plugin não derruba o app.
**Validação:** extensibilidade sem tocar o núcleo. **Risco:** **Médio** (código novo, TDD/RED first).

---

### Passo 15 — Smoke test end-to-end (login → decide → appeal → audit trail)
**Arquivos:** `ops/e2e-tests.sh`, `ops/docker-compose.e2e.yml`, novo teste de sistema.
**O que fazer:** subir gateway Rust + API Python via docker-compose e exercer os 7 fluxos
obrigatórios da §3.2, incluindo verificação de **audit trail imutável**.
**Verificação:** todos os fluxos retornam os status esperados.
**Validação:** comportamento de negócio/segurança ponta-a-ponta. **Risco:** **Baixo** (só testa).

---

### Passo 16 — SAST completo + gates de bloqueio (pré-deploy)
**Arquivos:** `.github/workflows/lint-guards.yml`, `.pre-commit-config.yaml`.
**O que fazer:** ativar como **bloqueantes** os critérios da §3.4 (bandit, clippy `-D warnings`,
cov ≥80%/auth 100% e ≥75% Rust, cargo audit, trufflehog, ZAP/dependency-check). Gerar relatórios.
**⚠️ Exceção clippy (revisão):** `state.rs` já contém ~18 `#[allow(clippy::unwrap_used)]`
documentados nos `unwrap()` dos registros Prometheus dentro de `lazy_static!` (com nota de que
o `#[allow]` não pode ficar no site da macro). O gate `-D clippy::unwrap_used` **deve respeitar
esses `#[allow]` explícitos como exceções documentadas** — não removê-los nem tratá-los como
violação. Validar que `cargo clippy` passa **com** esses allows presentes.
**Verificação:** pipeline falha em qualquer bloqueador real, mas passa com os `#[allow]` legítimos.
**Validação:** nenhum HIGH/MEDIUM, nenhum secret, cobertura mínima atingida. **Risco:** **Baixo.**

---

## 5. Estimativa de Tempo (1 desenvolvedor)

| Etapa | Conteúdo | Estimativa |
|-------|----------|-----------:|
| **Análise** | Etapas 1-2 (leitura, validação no repo) — já executada nesta entrega | ~1 dia |
| **Testes (RED)** | Passo 0 + BDD/TDD de todos os passos | ~3-4 dias |
| **Implementação** | Passos 1-10 (vulnerabilidades) | ~6-8 dias |
| | Passos 11-14 (arquitetura) — Passo 13 reduzido (Prometheus/tracing já existem em Rust; só falta OTel + observabilidade Python) | ~6-8 dias |
| **Validação final** | Passos 15-16 (E2E + SAST/gates) | ~2-3 dias |
| **Total** | | **~18-24 dias úteis** |

> Sem os capítulos de arquitetura (só vulnerabilidades), o total cairia para ~9-13 dias úteis.

---

## Verificação deste plano (como confirmar que está pronto antes de implementar)
1. Cada um dos 15 itens (14 do quadro + MED-R05) e os `[NOVO]` têm um passo associado. ✔
2. Os passos respeitam a ordem de dependência (HIGH-04 antes/junto de CRITICO-03; bcrypt+senha
   no mesmo commit; auth.rs antes de tenant_extractor). ✔
3. Cada passo é atômico (1 arquivo/módulo, 1 commit) e tem testes RED antes do código. ✔
4. Há smoke E2E (Passo 15) e gate SAST (Passo 16) finais. ✔
