# RIPD — Relatório de Impacto à Proteção de Dados Pessoais

**Sistema:** BuildToValue (BTV) — Governança de Agentes de IA
**Commit avaliado:** `ac6ac79`
**Data de emissão:** 2026-07-29
**Fundamento:** Lei 13.709/2018, **Art. 5º, XVII** (definição) e **Art. 38** (requisição pela ANPD)
**Documento correlato:** [Relatório Técnico LGPD](RELATORIO_TECNICO_LGPD.md) — 48 achados com evidência em código

---

> ## ⚠️ Estado deste RIPD
>
> Este é um RIPD de **diagnóstico**, não de conformidade. Ele documenta o estado real do sistema
> na data de emissão, incluindo dez riscos classificados como P0 e **não mitigados**.
>
> Um RIPD só sustenta uma decisão de tratamento quando os riscos residuais são aceitáveis. Os
> riscos residuais aqui **não são aceitáveis para tratamento de dados pessoais reais** — em
> especial dados sensíveis do Art. 11. A seção 7 traz o plano de ação por risco.
>
> Este documento não foi aprovado por encarregado (DPO). A seção 8 está deliberadamente em branco.

---

## 1. Executive summary

### 1.1 O que é o sistema

O BTV é um plano de controle que se interpõe entre agentes de IA e provedores de LLM. Toda
requisição é escaneada por um kernel Rust (detecção de PII, injeção de prompt, dados sensíveis),
avaliada contra políticas declarativas, submetida a um pipeline de decisão ética em Python, e
registrada em um ledger com encadeamento criptográfico. Vereditos em violação retornam HTTP 451
com evidência linkada; vereditos conformes são encaminhados ao provedor upstream.

Três superfícies de integração: biblioteca Rust nativa, gateway HTTP/sidecar (Axum, porta 8080) e
serviço de governança (FastAPI, porta 8000), além de dashboards (Streamlit e HTML estático) e um
SDK Python/TypeScript com servidor MCP.

### 1.2 Papéis e finalidades

O BTV ocupa **dois papéis simultâneos** sob a LGPD, e a documentação existente reconhece apenas o primeiro:

| Papel | Contexto | Dados |
|---|---|---|
| **Operador** (Art. 5º, VII) | Tratamento por conta do controlador-cliente que instala o BTV | Todo prompt interceptado — conteúdo livre, potencialmente com CPF, dados de saúde, biometria |
| **Controlador** (Art. 5º, VI) | Site público próprio (`demo.buildtovalue.cloud`, `docs.buildtovalue.io`) | IP e User-Agent de visitantes (Google Fonts/Analytics), `session_id`, histórico de vereditos em `localStorage` |

**Finalidades de tratamento identificadas:**

| # | Finalidade | Superfície |
|---|---|---|
| F1 | Validação de segurança e detecção de PII em inputs de IA | `/v1/validate`, `/v1/scan`, kernel |
| F2 | Decisão automatizada de permitir/bloquear/educar/redigir | `/v1/decide`, `/v1/proxy` |
| F3 | Registro de evidência para auditoria e contestação | Ledger binário, WAL, `decisions.jsonl`, Σ |
| F4 | Contestação de decisão automatizada (Art. 20) | `/v1/appeals` |
| F5 | Cálculo de score de confiança por sessão | `/v1/trust/{session_id}`, `trust.db` |
| F6 | Encaminhamento a provedor de LLM externo | `/v1/proxy` → OpenAI/DeepSeek/Anthropic |
| F7 | Operação do site público e da documentação | `demo/`, MkDocs |
| F8 | Treinamento de modelo de detecção (SLM) | `intelligence/training/` |

### 1.3 Principais riscos e status de mitigação

| # | Risco | Severidade | Mitigação |
|---|---|---|---|
| R-001 | Dado sensível do Art. 11 gravado em claro no WAL append-only, sem possibilidade de exclusão | P0 | ❌ nenhuma |
| R-002 | Ausência total de criptografia em repouso; sem DEK/KEK/KMS | P0 | ❌ nenhuma |
| R-003 | Nenhum job de expurgo em execução; retenção declarada não enforçada | P0 | ❌ nenhuma |
| R-004 | Nenhum endpoint de direito do titular (Art. 18, I a IX) | P0 | ❌ nenhuma |
| R-005 | Nenhum controle de finalidade em toda a superfície | P0 | ❌ nenhuma |
| R-006 | Bypass de autenticação por sufixo de arquivo no gateway | P0 | ❌ nenhuma |
| R-007 | `/demo-login` emite JWT de `admin` para qualquer origem sob CORS `*` | P0 | ⚠️ parcial — fail-secure se `BTV_DEMO_PASSWORD` não for provisionada |
| R-008 | Nenhuma checagem de posse; enumeração de titulares com API key | P0 | ❌ nenhuma |
| R-009 | Transferência internacional sem mecanismo do Art. 33 | P0 | ⚠️ parcial — `BTV_PROXY_UPSTREAM_URL` **pode** apontar para modelo local, mas o default não |
| R-010 | ROPA gerado é factualmente falso e usa base legal inválida para dado sensível | P0 | ❌ nenhuma |

17 riscos P1 e 21 riscos P2 adicionais estão detalhados no relatório técnico. **Nenhum dos 48
achados foi corrigido nesta entrega** — esta é uma auditoria, não uma remediação.

### 1.4 Achado transversal

O padrão que atravessa a maior parte dos achados é a **assimetria entre a norma que o BTV aplica
e a que o BTV cumpre**. O arquivo `data/policies/frameworks/lgpd_base.yaml:199` define, como
violação a ser detectada nos sistemas dos clientes, a condição
`(data.at_rest == true and storage.encrypted == false)` — e as próprias bases SQLite do BTV,
incluindo `explanations.full_data` (com `ip_address`) e `appeal_records.explanation_text`, estão
em texto claro no disco.

O mesmo se repete na base legal (exige base válida para dado sensível; declara legítimo interesse
para dado do Art. 11 no próprio ROPA), na detecção de PII (exige mascaramento antes do
processamento; grava o input bruto no ledger) e na governança de LLM (existe para governar
chamadas a LLM; não governa as suas próprias).

Isso importa mais que qualquer risco isolado, porque o produto é vendido como instrumento de
conformidade. Uma falha aqui não fica contida: propaga-se a todo controlador que o adota.

---

## 2. Inventário de dados

### 2.1 Categorias de dados tratados

| Categoria | Exemplo | Classificação | Onde |
|---|---|---|---|
| Conteúdo livre de prompt | texto submetido pelo usuário final do agente | **Pessoal ou sensível — indeterminado a priori** | `/v1/validate`, `/v1/decide`, `/v1/proxy` |
| Trecho casado por validador (`matched_text`) | CPF mascarado, CNPJ, e-mail, **input bruto no caso do Art. 11** | **Sensível** (R-001) | `Finding` → `WalEntry.evidence_snapshot` |
| Identificador de sessão | `session_id` opaco (pseudônimo) | Pessoal (pseudonimizado) | `trust.db`, ledger, `decisions.jsonl` |
| Identificador de titular em contestação | `user_id` | Pessoal | `appeals` |
| Narrativa de contestação | `reason` (texto livre, mín. 20 caracteres), `evidence`, `reviewer_notes` | **Pessoal, potencialmente sensível** | `appeals`, `appeal_records.explanation_text` |
| Endereço IP | `RequestMetadata.ip_address` | Pessoal | `explanations.full_data` |
| Categoria de dado sensível consumida | `data_type ∈ {GPS_LOCATION, HEALTH_DATA, FINANCIAL, BIOMETRIC}` | **Metadado sobre dado sensível** | `privacy_usage` |
| Contexto de tratamento | `profile` (ex.: `healthcare`, `finance`) | **Inferência de dado sensível** | `decisions.jsonl`, payload de webhook (R-032) |
| Credencial de operador | `username`, `password_hash` (bcrypt cost 12) | Pessoal | `users` |
| Chave pública de agente | `public_key_hex`, `registration_proof` | Técnico | `agent_pubkeys` |
| Preferências e histórico no navegador | tema, idioma, `verdict_history` (até 100), `trust_score_history` (até 200) | Pessoal | `localStorage` (R-025) |
| Token de sessão | JWT (`sub`, `role`, `iat`, `exp`) | Pessoal | `sessionStorage` (R-025) |

### 2.2 Tabelas e atributos de ciclo de vida

**Nenhuma das nove tabelas possui `finalidade`, `base_legal`, `retencao_ate` ou `status_retentivo`
(R-022).** Os campos temporais existentes são carimbos de entrada, não controles de expiração.

| Tabela | Definição | Campos com dado pessoal | `retencao_ate` |
|---|---|---|---|
| `sessions` | `api/_db.py:20-27` | `session_id`, `last_action` | ❌ |
| `agent_pubkeys` | `api/_db.py:40-46` | `agent_id`, `public_key_hex`, `registration_proof` | ❌ |
| `users` | `routes/auth.py:112-118` | `username`, `password_hash` | ❌ |
| `appeals` | `governance/contestability/_loop.py:60` | `user_id`, `reason`, `evidence`, `reviewer_notes` | ❌ (há `sla_deadline`, que é prazo de resposta) |
| `explanations` | `governance/explanation_store.py:75-112` | `full_data` (JSON com `ip_address`, `findings_detail[].title`) | ❌ (retenção de 90 d documentada, nunca executada) |
| `privacy_usage` | `governance/privacy_budget.py:423-431` | `agent_id`, `session_id`, `data_type` | ❌ |
| `escrow_ledger` | `governance/trust_score.py:266-274` | `session_id`, `delegation_id` | ❌ |
| `threats` | `intelligence/threat_feed.py:24` | `indicators` (JSON livre) | ❌ |
| `appeal_records` | `rust/btv-core/src/appeal_writer.rs:74-84` | `explanation_text` (texto integral em claro) | ❌ |

Não há migrations nem ORM: todo DDL é `CREATE TABLE IF NOT EXISTS` inline, sem versionamento —
o que significa que a introdução de um campo de dado pessoal não deixa rastro revisável.

### 2.3 Sinks persistentes

| Sink | Conteúdo | Contém PII? | Expurgável? |
|---|---|---|---|
| **WAL** (`kernel/ledger/wal.rs:32-45`) | `evidence_snapshot` — `TechnicalEvidence` de 9632 B, com `Finding[].matched_text` | **Sim — inclusive dado do Art. 11 em claro (R-001)** | ❌ append-only; `BTV-RUN-008:26` proíbe `DELETE` |
| Ledger binário (`kernel/ledger/entry.rs:52-70`) | `LedgerEntry` de 384 B — apenas hashes, encadeados por BLAKE3 + Merkle | Não | ❌ por design |
| `decisions.jsonl` (`gateway/routes/validate.rs:336`) | `ts`, `session`, `profile`, ações, risco, contagens, `verdict_id`, latência | Pseudonimizado (`session`, `profile`) | ⚠️ arquivo simples, sem TTL |
| `DurableLedger` Python (`governance/durable_ledger.py:101`) | payloads discriminados por `type:` | Variável | ⚠️ **in-memory** — não sobrevive a restart |
| Σ / btv-sigma (`btv-sigma/src/merkle.rs:31`) | folhas Merkle `[u8; 32]` | Não | ⚠️ store in-memory, chave Ed25519 efêmera (R-036) |
| SQLite (9 tabelas acima) | ver §2.2 | Sim | ❌ sem job de expurgo (R-003) |
| PVC `buildtovalue-explanations-pvc` (100 Gi) / `ledger-pvc` (50 Gi) | volumes dos sinks acima | Sim | ❌ sem criptografia declarada no `StorageClass` |

### 2.4 Fluxo de dados

```
                    ┌─────────────────────────────────────────────┐
   Agente do        │  1. INGESTÃO                                │
   cliente  ───────▶│  POST /v1/proxy/*  ·  /v1/decide            │
                    │  /v1/validate  ·  /v1/scan/semantic         │
                    │  ⚠️ sem propósito declarado (R-005)          │
                    │  ⚠️ sem verificação de consentimento          │
                    └──────────────────┬──────────────────────────┘
                                       ▼
                    ┌─────────────────────────────────────────────┐
                    │  2. PROCESSAMENTO                           │
                    │  Kernel Rust — 21 módulos, BLAKE3           │
                    │  Finding[] com matched_text                 │
                    │  ⚠️ Art. 11 → input bruto (R-001)            │
                    └────┬─────────────────────────┬──────────────┘
                         │                         │
                         ▼                         ▼
        ┌────────────────────────────┐  ┌──────────────────────────────┐
        │  3a. GOVERNANÇA (Python)   │  │  3b. PERSISTÊNCIA            │
        │  POST /v1/decide           │  │  WAL (PII em claro)          │
        │  ⚠️ input_text bruto via    │  │  Ledger 384 B (hashes)       │
        │     HTTP simples (R-009/C1)│  │  decisions.jsonl             │
        └────────────┬───────────────┘  │  ⚠️ sem ator/propósito (R-020)│
                     │                  │  ⚠️ falha silenciosa          │
                     ▼                  └──────────────────────────────┘
        ┌────────────────────────────┐
        │  4. VEREDITO               │
        │  ALLOW → encaminha         │
        │  BLOCK → HTTP 451          │
        └────────────┬───────────────┘
                     │ ALLOW
                     ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │  5. TRANSFERÊNCIA INTERNACIONAL — corpo original, sem redação   │
   │  BTV_PROXY_UPSTREAM_URL (default api.openai.com — EUA)          │
   │  demo → api.deepseek.com (CHINA)                                │
   │  policy_elicitor → Anthropic (EUA)                              │
   │  sync do WAL, quando habilitado → S3 us-east-1 (EUA)            │
   │  ❌ sem SCC · sem adequação · sem gate de região (R-009)         │
   └─────────────────────────────────────────────────────────────────┘

   ┌─────────────────────────────────────────────────────────────────┐
   │  6. EXPURGO                                                     │
   │  ❌ NÃO EXISTE. Nenhum job. Nenhum TTL enforçado.                │
   │  A única função de retenção não tem call-site (R-003).          │
   │  O ledger é, por design, inexpurgável.                          │
   └─────────────────────────────────────────────────────────────────┘
```

### 2.5 Transferências internacionais

| Destino | País | Adequação ANPD | SCC | Registro | Evidência |
|---|---|---|---|---|---|
| OpenAI | EUA | ❌ | ❌ | ❌ | `gateway/routes/proxy.rs:76`; `intelligence/llm_async_client.py:354`; `fly.toml:6` |
| DeepSeek | **China** | ❌ | ❌ | ❌ | `demo/proxy.py:28`; `demo/js/deepseek.js:27` |
| Anthropic | EUA | ❌ | ❌ | ❌ | `agentic/policy_elicitor.py:118` |
| AWS S3 `us-east-1` | EUA | ❌ | ❌ | ❌ | `kernel/ledger/remote/config.rs:22` (sync desabilitado por default) |
| Google (Fonts, Analytics) | EUA | ❌ | ❌ | ❌ | `demo/*.html:7-9`; `demo/css/btv.css:2`; `mkdocs.yml:144-147` |
| Fly.io | BR (`gru`) | n/a | n/a | ✅ declarado | `fly.toml:13` |

**Nenhuma das hipóteses do Art. 33 está documentada para nenhum destes fluxos.** Não há registro
de subprocessadores, não há cláusulas-padrão contratuais versionadas, não há decisão de
adequação aplicável, e não há gate técnico que impeça o envio.

O ROPA gerado pelo sistema declara `cross_border_transfer=False`
(`compliance/ropa_generator.py:163,177`) — declaração inexata sob o Art. 37 (R-010).

O gateway carrega um campo de jurisdição no contrato, mas ele está fixado em constante
(`proxy.rs:189`: `ip_jurisdiction: "XX"`), de modo que nenhuma política territorial pode ser
aplicada no caminho do proxy.

---

## 3. Bases legais

### 3.1 Base legal por finalidade — estado atual vs. avaliação

| # | Finalidade | Base declarada | Avaliação | Artigo |
|---|---|---|---|---|
| F1 | Validação de segurança e detecção de PII | Art. 7º, IX — legítimo interesse (`ropa_generator.py:146`) | ⚠️ **Sustentável apenas para dado pessoal comum.** Exige teste de proporcionalidade documentado e registro de LIA, que não existem | Art. 7º, IX; Art. 10 |
| F2 | Decisão automatizada | Art. 7º, IX + Art. 20 (`ropa_generator.py:172`) | ⚠️ Art. 20 é **direito do titular**, não base legal. A base é o Art. 7º, IX ou o Art. 7º, V (execução de contrato com o cliente) | Art. 7º; Art. 20 |
| F3 | Registro de evidência para auditoria | Art. 37 (`ropa_generator.py:81`) | ⚠️ O Art. 37 impõe **obrigação de registrar**, e o Art. 7º, II (cumprimento de obrigação legal) é a base correta. A retenção "indefinida" declarada não é sustentável | Art. 7º, II; Art. 16 |
| F4 | Contestação (Art. 20) | não declarada | ⚠️ Art. 7º, II — atendimento a direito do titular | Art. 7º, II |
| F5 | Score de confiança por sessão | não declarada | ⚠️ Art. 7º, IX, com LIA documentado | Art. 7º, IX |
| F6 | Encaminhamento a LLM externo | **não declarada** | ❌ **Sem base legal e sem mecanismo do Art. 33.** É a finalidade de maior exposição e a única sem qualquer declaração | Art. 7º; Art. 33 |
| F7 | Site público e documentação | **não declarada** | ❌ Google Fonts e Analytics carregam sem consentimento; a base para cookies/analytics não-essenciais é Art. 7º, I (consentimento) | Art. 7º, I; Art. 8º |
| F8 | Treinamento de modelo | **não declarada** | ❌ Dado coletado sob F1 não pode alimentar F8 sem base legal nova — mudança de finalidade | Art. 6º, I |

### 3.2 O problema do Art. 11

**Este é o defeito jurídico mais grave do sistema.**

O ROPA declara `Art. 7, IX — Interesse legitimo` como base legal para todo o tratamento
(`ropa_generator.py:146,172`). Mas o sistema **explicitamente detecta, classifica e trata dado
pessoal sensível**:

- `rust/kernel/src/validators/sensitive/lgpd.rs:12-35` — padrões de saúde, biometria, origem
  racial, convicção religiosa, opinião política e orientação sexual.
- `python/buildtovalue/governance/privacy_budget.py:52-56` — categorias `HEALTH_DATA`,
  `BIOMETRIC`, `FINANCIAL`, `GPS_LOCATION`, com as próprias anotações normativas citando
  `LGPD Art. 11`.

O **Art. 7º** disciplina o tratamento de dado pessoal comum. O **Art. 11** enumera de forma
exaustiva as hipóteses para dado sensível, e **legítimo interesse não está entre elas**. As
hipóteses aplicáveis seriam:

- **Art. 11, I** — consentimento específico e destacado, para finalidades específicas; ou
- **Art. 11, II, "a"** — cumprimento de obrigação legal ou regulatória pelo controlador; ou
- **Art. 11, II, "g"** — garantia da prevenção à fraude e à segurança do titular, nos processos de
  identificação e autenticação de cadastro.

A hipótese do Art. 11, II, "g" é a mais próxima da finalidade F1 (segurança), mas seu escopo é
restrito a *processos de identificação e autenticação em sistemas eletrônicos* — não cobre o
tratamento genérico de conteúdo livre de prompt.

**Consequência prática.** Enquanto o pipeline tratar conteúdo que ele mesmo classifica como
sensível sob base do Art. 7º, o tratamento é **sem base legal**. O sistema precisa, no mínimo:

1. Ramificar a base legal por categoria de dado no ROPA (R-010).
2. Verificar consentimento por registro quando o conteúdo for classificado como sensível.
3. Ou, alternativamente, **não persistir** o conteúdo sensível — o que também resolveria R-001 e
   deslocaria o tratamento para fora do escopo do Art. 11.

A opção 3 é a mais alinhada ao design do produto: o BTV precisa saber *que* houve dado sensível,
não *qual* era.

### 3.3 Mapeamento campo → finalidade → base legal

Este mapeamento **não existe no sistema** (R-022: nenhuma tabela tem `finalidade` ou
`base_legal`). A tabela abaixo é a proposta de estado-alvo, a ser materializada como colunas e
como catálogo executável:

| Campo | Finalidade | Base legal proposta | Retenção proposta |
|---|---|---|---|
| `Finding.matched_text` | F1 | Art. 7º, IX (comum) / **não persistir** se Art. 11 | não persistir o valor; apenas hash |
| `sessions.session_id`, `trust_score` | F5 | Art. 7º, IX + LIA | 180 dias após última atividade |
| `appeals.user_id`, `reason`, `evidence` | F4 | Art. 7º, II (direito do titular) | 5 anos após resolução (prazo prescricional) |
| `appeals.reviewer_notes`, `reviewer_id` | F4 | Art. 7º, II + Art. 20, §1º | 5 anos |
| `explanations.full_data` | F3 | Art. 7º, II | 90 dias (o que já está documentado) |
| `explanations.…ip_address` | F3 | Art. 7º, IX | hashear na ingestão |
| `privacy_usage.data_type` | F1 | Art. 7º, IX | 90 dias |
| `users.username`, `password_hash` | operação | Art. 7º, V (execução de contrato) | enquanto durar o vínculo |
| `decisions.jsonl` (linha de auditoria) | F3 | Art. 7º, II | 5 anos, sem PII |
| WAL `evidence_snapshot` | F3 | Art. 7º, II | 5 anos, com cripto-shredding por titular |
| `localStorage` `verdict_history` | F7 | Art. 7º, I (consentimento) | 24h (TTL já implementado) |

---

## 4. Medidas de segurança

### 4.1 Controles implementados e verificados

| Controle | Implementação | Avaliação |
|---|---|---|
| Resolução central da chave HMAC | `security/keys.py` — fail-closed em produção, zeroização via `ctypes.memset` sobre `bytearray`, remoção de `BTV_HMAC_KEY` do `environ` após leitura | ✅ Bem construído. A justificativa contra `lru_cache`/`bytes` internados está correta |
| Autenticação de endpoints internos | `gateway/middleware/internal_auth.rs:69-82` — `subtle::ConstantTimeEq`, `Zeroizing`, mínimo 32 B, fail-secure 503 | ✅ Melhor controle do repositório |
| Cabeçalhos de segurança na API | `api/response_sanitizer.py:74-92` — CSP estrito, HSTS 1 ano, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, `Permissions-Policy` | ✅ Aplicado globalmente às respostas da API. ❌ Ausente no nginx que serve o frontend (R-028) |
| Hash de senha | `routes/auth.py` — bcrypt cost 12, salt por hash, sem senha default, rate limit 10/min no login | ✅ |
| Mascaramento de PII na resposta | `kernel/output_guard/sanitizer.rs:68-79` — CPF, CNPJ, e-mail, telefone, cartão, SSN, todos ligados por default, com *rescan* de verificação | ✅ Correto no escopo em que atua (mensagem HTTP). ❌ Não cobre o que é gravado no ledger |
| Ledger sem texto bruto | `gateway/routes/validate.rs:314-330` — grava o hash do input | ✅ |
| Isolamento multi-tenant | `kernel/ledger/tenant_router.rs:139` — `{base}/{tenant}/ledger.db`; `security/tenant_key.rs` — HKDF-SHA256 por tenant com validação contra path traversal | ✅ |
| Webhook sem input original | `api/webhook_dispatcher.py:49` | ✅ no essencial. ⚠️ envia `profile` e não é assinado (R-032) |
| Fail-secure | `gateway/routes/proxy.rs:206-208` — governança indisponível → `BLOCK`; `appeals.py:36-42` — estado nulo → 503 | ✅ Consistente em todo o sistema, exceto `VisualReasoningGuard` |
| Pod Security e NetworkPolicy | `ops/k8s/security/pod-security-policy.yaml:17-26,38-121` — PSS `restricted`, default-deny; `10-deployment.yaml:35-38` — `runAsNonRoot`, `runAsUser: 1000` | ✅ na base. ❌ `compliance-deployment.yaml` sem `securityContext` (R-041) |
| CI de segurança | `bandit -lll`, `cargo audit`, TruffleHog `--only-verified` bloqueante, 3 guards estáticos | ⚠️ existe, mas sem nenhum gate de privacidade (R-031) |
| Residência de dados declarada | `fly.toml:13` — `primary_region = "gru"` | ✅ para compute. ❌ contradito pelo upstream e pelo sync (R-009) |
| CORS na API Python | `api/app.py:54-68` — lista explícita, `RuntimeError` se ausente em produção | ✅. ❌ gateway usa `Any` (R-014) |

### 4.2 Controles ausentes

| Controle exigido | Status | Risco |
|---|---|---|
| **Criptografia em repouso** | ❌ zero implementações em todo o repositório | R-002 |
| **Envelope encryption (DEK por registro + KEK em KMS)** | ❌ a "TEK" derivada por HKDF é usada apenas como chave de MAC | R-002 |
| **Chave própria por campo sensível** | ❌ | R-002 |
| **Rotação automática com recifragem gradual** | ❌ API existe (`rotate_hmac_key()`), sem caller nem agendamento | R-002 |
| **Auditoria de acesso ao KMS** | ❌ não há KMS | R-002 |
| **Controle de finalidade (`X-Purpose`)** | ❌ zero ocorrências | R-005 |
| **Checagem de posse de recurso** | ❌ zero ocorrências (`if x.user_id != current_user` não existe) | R-008 |
| **RBAC** | ❌ `role` presente no token, nunca verificado | R-016 |
| **MFA** | ❌ inexistente | R-017 |
| **Rate limit por ator** | ❌ por header controlado pelo cliente (Rust) e por IP em uma rota (Python) | R-026 |
| **CSP no frontend** | ❌ | R-028 |
| **SRI** | ❌ zero ocorrências | R-029 |
| **Linter de PII em URL** | ❌ | R-031 |
| **Log de auditoria com propósito e base legal** | ❌ | R-020 |
| **Redação de PII em logs** | ❌ `message` verbatim, stack trace em produção | R-019 |
| **k-anonimato em agregações** | ❌ | R-027 |
| **Backup com TTL, chave segregada e destruição auditada** | ❌ único mecanismo é `cp -r` em claro no killswitch | R-002 |

### 4.3 Adequação das medidas (Art. 46)

O Art. 46 não exige medidas quaisquer — exige medidas **aptas** a proteger os dados. Os relatórios
de red-team versionados no próprio repositório medem a aptidão do principal controle:

| Cenário | Detecção medida | Bypass medido | FNR declarado na `BiasDeclaration` |
|---|---|---|---|
| RT-002 — evasão de PII | **32,5%** | **42,5%** | 18,0% |
| RT-001 — injeção de prompt (26/02) | 44,1% | 41,2% | 18,0% |

Fonte: `ops/red-team/reports/RT-002-20260226-202212.json`,
`ops/red-team/reports/RT-001-20260226-202007.json`.

O bypass medido é 2,4× o declarado. Isso tem duas consequências independentes:

1. **Aptidão da medida.** Um detector de PII com 32,5% de eficácia em cenários de ofuscação não
   pode ser a única medida de proteção para dado sensível.
2. **Exatidão da declaração.** O número que o sistema publica sobre si mesmo
   (`BiasDeclaration::from_static(0.18, 0.12, ...)`) está desalinhado da medição própria — o que
   afeta a confiabilidade de toda a documentação de conformidade (R-040).

---

## 5. Retenção e expurgo

### 5.1 Estado atual

| Requisito | Estado |
|---|---|
| Regra de retenção por campo | ❌ nenhuma tabela tem `retencao_ate` (R-022) |
| `retencao_ate` calculada na ingestão | ❌ |
| Job de expurgo | ❌ **não existe**. A única função de retenção do repositório, `explanation_store.cleanup_old_entries()` (`:269`), **não tem call-site** (R-003) |
| Evidência de exclusão (hash de tombstone) | ❌ `BTV_AUDIT_HASH_LEDGER` está documentada no catálogo mas tem zero ocorrências em código (R-034) |
| Backup | ❌ sem Litestream, sem snapshot job, sem TTL, sem restauração testada. O único mecanismo de cópia é `scripts/ops/emergency_killswitch.sh:87-89` — `cp -r data/ledger "$BACKUP_DIR"`, em claro, no mesmo volume, sem expiração |
| Expurgo pós-restore | ❌ |
| Destruição auditada de backup antigo | ❌ |

### 5.2 A contradição do ledger

O ledger é **inexpurgável por design**. `docs/runbooks/BTV-RUN-008.md:26` proíbe explicitamente
`DELETE` sobre o ledger, sob pena de quebrar a cadeia BLAKE3. Isso é arquiteturalmente correto
para um log de evidência — e incompatível com o Art. 16 **enquanto o ledger contiver dado
pessoal em claro**.

A solução para essa tensão é o **cripto-shredding**, e o próprio `BTV-RUN-008` a descreve. O
problema é que o runbook é inexecutável (R-035): `--execute-shred`, `ephemeral_key`,
`aws kms enable-key-rotation` e `/mgmt/cache/flush-all` têm **zero ocorrências** no repositório,
e o documento cita "host Java" e "buffer JNI" numa base que é Rust + Python. O procedimento
oficial de Direito ao Esquecimento, com campo de aprovação pelo DPO preenchido, não pode ser
executado.

Consequência direta: **um pedido de eliminação do Art. 18, VI não pode ser atendido hoje**, nem
tecnicamente nem processualmente.

### 5.3 Estado-alvo

| Dado | Retenção | Mecanismo |
|---|---|---|
| Logs operacionais | 30 dias | rotação automática |
| Log de auditoria (sem PII) | 5 anos | `decisions.jsonl` encadeado, com ator e propósito (R-020) |
| WAL de evidência | 5 anos | **cripto-shredding**: DEK por titular; eliminar = destruir a DEK, preservando a cadeia de hashes |
| `explanations` | 90 dias | job diário chamando `cleanup_old_entries()` |
| `appeals` | 5 anos após resolução | job diário; prazo prescricional |
| `sessions` / trust | 180 dias após última atividade | job diário |
| Backup | TTL documentado, chave segregada com rotação | expurgo obrigatório pós-restore; hash antes da destruição; registro em livro de ocorrências |

Pré-requisitos: **R-002** (envelope encryption, sem a qual não há cripto-shredding) e **R-022**
(atributos de ciclo de vida, sem os quais não há o que o job consulte).

---

## 6. Direitos dos titulares

### 6.1 Estado atual

| Direito | Artigo | Endpoint | Prazo | Auth | Log | Status |
|---|---|---|---|---|---|---|
| Confirmação da existência de tratamento | 18, I | — | — | — | — | ❌ |
| Acesso aos dados | 18, II | — | — | — | — | ❌ |
| Correção | 18, III | — | — | — | — | ❌ |
| Anonimização, bloqueio ou eliminação de dado desnecessário | 18, IV | — | — | — | — | ❌ |
| Portabilidade | 18, V | — | — | — | — | ❌ |
| Eliminação de dado tratado com consentimento | 18, VI | — | — | — | — | ❌ |
| Informação sobre compartilhamento | 18, VII | — | — | — | — | ❌ |
| Informação sobre não consentir | 18, VIII | — | — | — | — | ❌ |
| Revogação do consentimento | 18, IX | — | — | — | — | ❌ |
| Revisão de decisão automatizada | 20 | `/v1/appeals` | SLA 24h | API key / JWT | parcial | ⚠️ |

O único direito com implementação parcial é o do Art. 20, e ele tem três defeitos:

1. **Quebrado no caminho documentado.** O gateway proxeia para `POST {gov}/v1/appeals/submit`
   (`gateway/routes/appeals.rs:26`), path que não existe no serviço Python — a requisição cai no
   catch-all 404 e o gateway devolve `BAD_GATEWAY` (R-039).
2. **Sem controle de posse.** `GET /v1/appeals?user_id=X` permite a qualquer portador de API key
   ler a narrativa de contestação de qualquer titular (R-008).
3. **Revisão humana não comprovada.** O `reviewer_id` vem do corpo da requisição, não do token, e
   nenhuma rota verifica papel — qualquer JWT resolve qualquer contestação, declarando ser quem
   quiser (R-016). Isso ataca diretamente o Art. 20, §1º, que exige revisão por pessoa natural
   identificável.

`GET /v1/auth/me` não é o direito de acesso: retorna `username` e `role` de uma conta de
**operador do dashboard** (`routes/auth.py:223-225`), não do titular cujos dados foram tratados.

Os únicos `DELETE` do sistema são operacionais:
`DELETE /v1/agents/{id}/revoke` faz `UPDATE ... SET revoked_at` sem apagar `public_key_hex` nem
`registration_proof`; `DELETE /internal/v1/tenants/{id}` é eviction de cache em memória.

### 6.2 Canal do titular

Não existe. `SECURITY.md:8` traz um endereço Gmail pessoal, destinado a **reporte de
vulnerabilidades** — não é canal de exercício de direitos, e não há nomeação formal de encarregado.

O **Art. 41, §1º** exige que a identidade e as informações de contato do encarregado sejam
divulgadas publicamente, de forma clara e objetiva, preferencialmente no sítio eletrônico do
controlador.

### 6.3 Estado-alvo

| Direito | Endpoint | Auth | Resposta | Prazo legal |
|---|---|---|---|---|
| 18, I | `GET /v1/me/tratamento` | JWT | `200 OK` — apenas confirma | imediato (Art. 19, I) |
| 18, II | `GET /v1/me/dados` | JWT + MFA | JSON compacto | imediato (Art. 19, I) |
| 18, II (declaração completa) | `POST /v1/me/declaracao` | JWT + MFA | `202 Accepted`, geração assíncrona | 15 dias (Art. 19, II) |
| 18, III | `PATCH /v1/me/dados` | JWT + MFA | `200` + log de correção | 15 dias |
| 18, V | `GET /v1/me/portabilidade` | JWT + MFA | formato interoperável | 15 dias |
| 18, VI | `DELETE /v1/me/dados` | JWT + MFA | efeito cascata; cripto-shredding | 15 dias |
| 18, VII | `GET /v1/me/compartilhamentos` | JWT | lista de subprocessadores acionados | 15 dias |
| 18, IX | `DELETE /v1/me/consentimento` | JWT | revogação com efeito imediato | imediato |

Cada endpoint deve registrar no log de auditoria: ator, recurso, propósito, base legal, campos
acessados e timestamp (R-020). Verificação biométrica ou video-selfie, se usada na eliminação
permanente, só se estritamente necessária, e o dado de verificação **descartado após o uso**.

---

## 7. Riscos residuais

Todos os 48 achados permanecem **não mitigados** na data de emissão. A tabela abaixo consolida os
riscos por severidade, com o dispositivo sancionatório aplicável.

### 7.1 Riscos P0 — referência ao Art. 52

O **Art. 52** prevê, para infrações às normas da LGPD: advertência; multa simples de até 2% do
faturamento no Brasil, limitada a R$ 50.000.000,00 por infração; multa diária; publicização da
infração; bloqueio dos dados pessoais; eliminação dos dados pessoais; suspensão parcial do
funcionamento do banco de dados por até 6 meses; suspensão do exercício da atividade de
tratamento por até 6 meses; e proibição parcial ou total do exercício de atividades de tratamento.

O **Art. 52, §1º** lista os critérios de dosimetria. Três deles são especialmente relevantes ao
conjunto de achados abaixo: a **gravidade e natureza da infração** (inciso I), a **boa-fé do
infrator** (inciso II) e a **adoção reiterada e demonstrada de mecanismos internos capazes de
minimizar o dano** (inciso VIII). Este último é o que a existência de um RIPD honesto, com plano
de ação, contribui para demonstrar.

| ID | Risco residual | Artigo violado | Sanção aplicável | Plano de ação | Prazo sugerido |
|---|---|---|---|---|---|
| **R-001** | Dado sensível do Art. 11 gravado em claro no WAL inexpurgável | Art. 11; Art. 16; Art. 46 | Art. 52, II a VI — inclusive **eliminação dos dados** e **bloqueio do banco de dados** | Substituir `input` por hash no `SensitiveDataValidator`; mascarar os 3 ramos restantes; teste de invariante | Imediato |
| **R-002** | Ausência total de criptografia em repouso | Art. 46 | Art. 52, I a III | Envelope encryption DEK/KEK com KMS; chave por campo sensível; cifra das bases SQLite | 90 dias |
| **R-003** | Nenhum expurgo em execução | Art. 15; Art. 16 | Art. 52, II, VI, VII | Job diário com evidência de exclusão; cripto-shredding do ledger | 90 dias (depende de R-002) |
| **R-004** | Nenhum endpoint de direito do titular | Art. 18, I a IX; Art. 19 | Art. 52, I a IV — **exposição direta a reclamação de titular** | Implementar os 8 endpoints com prazo, MFA e log | 60 dias |
| **R-005** | Nenhum controle de finalidade | Art. 6º, I, II, III | Art. 52, I, II | `X-Purpose` obrigatório; enum de finalidades; propósito no log | 60 dias |
| **R-006** | Bypass de autenticação por sufixo | Art. 46 | Art. 52, I a III; **Art. 48** se explorado | Roteamento explícito de estáticos | Imediato |
| **R-007** | JWT de `admin` emitido a qualquer origem | Art. 46 | Art. 52, I a III; **Art. 48** se explorado | Remover auto-login; origem restrita; papel `viewer` | Imediato |
| **R-008** | Enumeração de titulares com API key | Art. 6º, VII; Art. 46 | Art. 52, I a IV | Checagem de posse; escopo pelo token; DTOs por escopo | 30 dias |
| **R-009** | Transferência internacional sem mecanismo do Art. 33 | Art. 33; Art. 34; Art. 35 | Art. 52, I a IX — inclusive **suspensão da atividade de tratamento** | Gate de jurisdição; redação antes do encaminhamento; registro de subprocessadores com SCC | 60 dias |
| **R-010** | ROPA falso e base legal inválida para dado sensível | Art. 11; Art. 33; Art. 37 | Art. 52, I a IV — **declaração inexata a autoridade agrava a dosimetria (Art. 52, §1º, II)** | Derivar ROPA do catálogo; ramificar base legal por categoria | 30 dias |

### 7.2 Riscos P1 — resumo

17 riscos. Os de maior exposição:

| ID | Risco | Artigo | Prazo |
|---|---|---|---|
| R-011 | `verdict_id` assinado com chave zero no caminho legado — evidência forjável | Art. 37; Art. 46 | 60 dias |
| R-016 | Sem RBAC; `reviewer_id` auto-declarado — revisão humana não comprovada | Art. 20, §1º | 30 dias |
| R-018 | 422 ecoa o payload do titular; sem `errorId` | Art. 46 | Imediato |
| R-020 | Log de auditoria sem ator/propósito/base legal; falha silenciosa | Art. 37 | 60 dias |
| R-022 | Nenhum atributo de ciclo de vida nos schemas | Art. 15; Art. 16; Art. 37 | 90 dias |
| R-024 | Nenhum consentimento; terceiros carregados antes de qualquer interação | Art. 7º, I; Art. 8º; Art. 9º | 30 dias |
| R-027 | Agregações sem k-anonimato e sem auth | Art. 12, §2º | 60 dias |

Demais P1: R-012, R-013, R-014, R-015, R-017, R-019, R-021, R-023, R-025, R-026 — ver relatório técnico.

### 7.3 Riscos P2 — resumo

21 riscos. Prioridade de tratamento por efeito estrutural:

| ID | Risco | Por que priorizar |
|---|---|---|
| R-031 | Nenhum gate de privacidade no CI/CD | É o controle que impede a **reintrodução** de todos os demais |
| R-040 | Eficácia medida do detector muito abaixo da declarada | Afeta a aptidão da medida (Art. 46) e a exatidão da documentação |
| R-035 | Runbook de Direito ao Esquecimento inexecutável, com aprovação de DPO | Numa fiscalização, é apresentado como evidência — e a inexecutabilidade prova que nunca foi testado |
| R-044 | `docs/compliance.md` afirma "100% on-premises" | Informação incorreta em documento público de conformidade |
| R-045 | Sem Política de Privacidade, DPA, SCC, subprocessadores, canal do titular | Art. 9º, 33, 37, 39, 41 |
| R-024/R-028/R-029 | Fontes externas, CSP e SRI | Auto-hospedar as fontes resolve os três de uma só vez |

Demais P2: R-030, R-032, R-033, R-034, R-036, R-037, R-038, R-039, R-041, R-042, R-043, R-046,
R-047 — ver relatório técnico.

### 7.4 Pendência de verificação

**R-048** — `scripts/ci/lint_guards.sh:86` contém o comentário
*"ops/.env will be excised by the scheduled git filter-repo"*, cujo tempo verbal indica que a
reescrita de histórico não havia ocorrido. **Não foi possível verificar** neste ambiente: o clone
é raso (50 commits).

Ação obrigatória, em clone completo:

```bash
git log --all --diff-filter=A -- 'ops/.env'
```

Se houver qualquer ocorrência, tratar como **incidente de segurança sob o Art. 48**: rotacionar
todas as credenciais afetadas, executar `git filter-repo`, notificar forks e clones, e registrar
na cadeia de evidências.

### 7.5 Recomendação de tratamento

Com base nos riscos residuais acima:

1. **Não processar dados pessoais reais** — em especial dados sensíveis do Art. 11 — até que os
   dez riscos P0 estejam mitigados. O conjunto R-001 + R-002 + R-003 significa que dado sensível
   entra no sistema, é gravado em claro e não pode ser eliminado.
2. **Não apresentar o BTV como instrumento de conformidade** enquanto R-010, R-040 e R-044
   permanecerem — as três são afirmações de conformidade contraditadas pelo próprio código e pelos
   próprios relatórios de teste.
3. **Ambientes de demonstração** devem operar exclusivamente com dados sintéticos, com
   `BTV_DEMO_PASSWORD` não provisionada e sem exposição pública das portas 8080/8501.
4. **Priorizar R-031** (gates de CI) em paralelo às correções P0 — sem ele, cada correção é
   reversível pelo próximo commit.

---

## 8. Aprovação

Este RIPD documenta um estado com dez riscos P0 não mitigados. A assinatura abaixo não deve ser
aposta como aceite de risco sem que a seção 7 tenha sido endereçada, ou sem decisão expressa e
fundamentada de aceitação de risco residual, registrada em separado.

<br>

**Encarregado pelo Tratamento de Dados Pessoais (DPO)** — Art. 41

Nome: ________________________________________________

Assinatura: ___________________________________________

Data: _____ / _____ / __________

<br>

**Revisor de Engenharia**

Nome: ________________________________________________

Assinatura: ___________________________________________

Data: _____ / _____ / __________

<br>

**Parecer (preencher no ato da aprovação):**

☐ Aprovado — riscos residuais aceitáveis para as finalidades declaradas
☐ Aprovado com condições — ver plano de ação da seção 7, com prazos vinculantes
☐ Não aprovado — tratamento não deve prosseguir até mitigação dos riscos P0

Observações: _________________________________________________________________

____________________________________________________________________________

____________________________________________________________________________

---

## Anexo A — Base normativa citada

| Dispositivo | Assunto | Onde aparece neste RIPD |
|---|---|---|
| Art. 5º, VI e VII | Definições de controlador e operador | §1.2 |
| Art. 5º, XVII | Definição de relatório de impacto | Cabeçalho |
| Art. 6º, I a VII | Princípios (finalidade, adequação, necessidade, transparência, segurança) | §3, §4 |
| Art. 7º | Bases legais para dado pessoal | §3.1 |
| Art. 8º | Forma do consentimento | §3.1 (F7) |
| Art. 9º | Informação ao titular | §3.1 (F7), §6.2 |
| Art. 10 | Legítimo interesse e teste de proporcionalidade | §3.1 |
| **Art. 11** | **Bases legais para dado sensível** | **§3.2** |
| Art. 12, §2º | Dado que permite reversão é dado pessoal | §7.2 (R-027) |
| Art. 15 e 16 | Término do tratamento e eliminação | §5 |
| Art. 18, I a IX | Direitos do titular | §6 |
| Art. 19 | Prazos de resposta | §6.3 |
| Art. 20 e §1º | Revisão de decisão automatizada | §6.1 |
| Art. 33 a 35 | Transferência internacional | §2.5 |
| Art. 37 | Registro das operações de tratamento | §2.2, §3.1 |
| Art. 38 | Requisição de RIPD pela ANPD | Cabeçalho |
| Art. 39 | Instruções ao operador | §7.3 (R-045) |
| Art. 41 e §1º | Encarregado e divulgação do contato | §6.2 |
| Art. 42 | Responsabilidade solidária controlador/operador | §1.4 |
| Art. 46 | Medidas de segurança aptas | §4 |
| Art. 48 | Comunicação de incidente | §7.4 |
| Art. 50 | Boas práticas e governança | §4.2 |
| **Art. 52 e §1º** | **Sanções administrativas e dosimetria** | **§7.1** |

---

*Documento produzido por revisão de engenharia em 2026-07-29, sobre o commit `ac6ac79`.
Evidência técnica completa em [RELATORIO_TECNICO_LGPD.md](RELATORIO_TECNICO_LGPD.md).*
