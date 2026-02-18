# Relatório de Engenharia — BuildToValue v2.0 (Estado Real)

**Data:** 18 de fevereiro de 2026
**Revisão:** v2.0 — Atualizado após fechamento dos 10 gaps arquiteturais

---

## 1. O QUE O SISTEMA FAZ HOJE

### 1.1 Detecção (Rust Kernel — porta 8080)

**Validators implementados e testados:**

| Validator | Detecta | Exemplo | Funciona? |
|:---|:---|:---|:---|
| CPF | CPF brasileiro (com/sem pontuação) | `123.456.789-09` | ✅ Testado e2e |
| CNPJ | CNPJ brasileiro | `11.222.333/0001-81` | ✅ Testado |
| Email | Endereços de email | `joao@empresa.com` | ✅ Testado e2e |
| Phone | Telefones brasileiros | `11 98765-4321` | ✅ Testado |
| Credit Card | Números de cartão (Luhn) | `4532 0151 1283 0366` | ✅ Testado e2e |
| Entropy | Alta entropia (dados aleatórios) | Strings randômicas | ✅ Existe |
| ZScore | Anomalias estatísticas | Desvios extremos | ✅ Existe |
| CharRatio | Proporção de caracteres suspeitos | Excesso de símbolos | ✅ Existe |
| Base64 | Decodifica Base64 e re-scana | `MTIzLjQ1Ni43ODktMDk=` → CPF | ✅ Testado e2e |
| Hex | Decodifica hexadecimal | Hex encoded strings | ✅ Existe |
| Leetspeak | Decodifica l33t | `CPF 1z3.456.7B9-09` | ✅ Existe |

**Nota honesta:** "Existe" = código compila e tem testes unitários. "Testado" = validamos end-to-end via curl. "Testado e2e" = validado em sessão interativa completa.

**BiasDeclaration (ADR-010):** Todos os validators implementam `bias_declaration()` com FPR/FNR calibrados. Gatekeeper agrega worst-case. Calibração válida por 90 dias.

| Validator | FPR | FNR | Dataset | Calibração |
|:---|:---|:---|:---|:---|
| CPF | 0.08 | 0.02 | 500 | 2026-02-09 |
| Email | 0.03 | 0.08 | 800 | 2026-02-09 |
| Credit Card | 0.05 | 0.12 | 200 | 2026-02-09 |
| CNPJ | — | — | — | Implementado, valores no código |
| Phone | — | — | — | Implementado, valores no código |

**Deobfuscator Chaining:** `DeobfuscatorChain` decodifica layers (Base64→Hex→Leetspeak) e re-scana conteúdo decodificado automaticamente via Gatekeeper.

### 1.2 Policy Engine

| Feature | Estado |
|:---|:---|
| Hard blocks (SQL injection, XSS) | ✅ Testado — `DROP TABLE` → HARD BLOCK |
| Policy YAML (`default.yaml`) | ✅ Testado — cpf→Block, email→Redact |
| Ações: ALLOW, LOG, EDUCATE, REDACT, BLOCK | ✅ Todas funcionam |
| Deobfuscation antes de policy check | ✅ Testado — Base64→CPF→BLOCK |
| Profile-aware policies (4 perfis) | ✅ Implementado (Gap #4) |
| Sector patterns (6 setores YAML) | ✅ Implementado (Gap #3) — whitelists contextuais |
| Penalty schedules (6 frameworks) | ✅ Implementado (Gap #5) — `data/policies/penalties.yaml` |
| 7 compliance YAML mappings | ✅ Implementado (Gap #2) — EU AI Act, GDPR, HIPAA, ISO 42001, LGPD, NIST RMF, PCI-DSS |

### 1.3 Governance (Python — porta 8000)

| Feature | Estado | Detalhe |
|:---|:---|:---|
| Mercy Calculator (Gilligan) | ✅ Testado | trust > 0.6 + first offense + critical == 0 → soften |
| soften_action | ✅ Testado | REDACT→LOG confirmado |
| Trust score tracking | ✅ Testado | 8 msgs limpas: 0.50→0.66 |
| Trust persistence (SQLite) | ✅ Testado | Sobrevive docker-compose restart |
| Offense tracking | ✅ Testado | first_offense corretamente detectado |
| HMAC-SHA256 signatures | ✅ Testado | Key via env var `BTV_HMAC_KEY`, fail-secure em prod |
| explain_decision() | ✅ Testado | Rationale em toda response |
| Contestability (24h) | ✅ Testado | contestable:true + appeal_deadline_hours:24 |
| Appeals endpoint | ✅ Implementado (Gap #1) | ContestabilityLoop + API routes |
| Threat→Policy Bridge | ✅ Implementado (Gap #8) | MISP→PolicyEngine, dedup, circuit breaker |
| Webhooks | ✅ Implementado (Gap #7) | Fire-and-forget, retry, YAML config |

### 1.4 OutputGuard (PII Masking)

| PII | Máscara | Testado? |
|:---|:---|:---|
| CPF | `123.456.789-09` → `***.***.***-09` | ✅ |
| Email | `joao@empresa.com` → `j***@e***` | ✅ |
| Credit Card | `4532 0151 1283 0366` → `4532 **** **** 0366` | ✅ |
| CNPJ | `11.222.333/0001-81` → `**.***.***/**01-81` | ⚠️ Regex existe, não testado e2e |
| Phone | `11 98765-4321` → `11 ****-****` | ⚠️ Regex existe, não testado e2e |

### 1.5 Compliance

| Framework | Artigos | Estado |
|:---|:---|:---|
| LGPD | Art. 6, 18, 20, 46, 48 | ✅ 5/5 COMPLIANT (testado) |
| EU AI Act | Art. 5, 9, 13, 14, 15 | ✅ 5/5 COMPLIANT (testado) |
| GDPR | Mappings YAML | ✅ Migrado para `data/policies/compliance/` |
| HIPAA | Mappings YAML | ✅ Migrado |
| ISO 42001 | Mappings YAML | ✅ Migrado |
| NIST RMF | Mappings YAML | ✅ Migrado |
| PCI-DSS | Mappings YAML | ✅ Migrado |

**Nota honesta:** Os plugins verificam se o sistema tem as capacidades (explain_decision, contestability, HMAC). Não testam contra dados regulatórios reais de um caso concreto. YAMLs de compliance são mappings de artigos→regras, não certificações.

### 1.6 Intelligence Hub

| Feature | Estado |
|:---|:---|
| Ingest single threat | ✅ Testado |
| Ingest batch | ✅ Testado (2 threats) |
| Query by type | ✅ Testado |
| Query by severity | ✅ Testado |
| Get by ID | ✅ Testado |
| Stats | ✅ Testado (3 threats, avg 9.0) |
| BLAKE3 hash integrity | ✅ Testado (migrado de BLAKE2b) |
| SQLite persistence | ✅ Testado |
| WAL crash recovery | ✅ Implementado (ThreatIngestor v2.3.2) |
| Threat→Policy Bridge | ✅ Implementado (Gap #8) — threats alimentam PolicyEngine automaticamente |

**Nota honesta:** Ingest via API (manual ou programático). Sem feed automático de servidores MISP/STIX externos (pull contínuo). O bridge gera regras a partir de threats ingeridas, mas a ingestão em si requer chamada à API.

### 1.7 Batch Processing

| Feature | Estado |
|:---|:---|
| BatchProcessor (Rust) | ✅ Config, timeout per-item (10ms), fail-secure |
| FFI bridge `batch_scan()` | ✅ PyO3 exposto com parâmetros configuráveis |
| 100 items < 5s (debug mode) | ✅ Testado (7 testes) |
| Error types (Empty, Mismatch, ExceedsMax) | ✅ Tipados e testados |

### 1.8 Ledger & Auditoria

| Feature | Estado |
|:---|:---|
| DurableLedger (WAL + disk + S3 remote) | ✅ Implementado (v2.5.0) |
| WAL com fsync | ✅ bincode serialization, sequence tracking |
| Chain integrity verification | ✅ Valid/Tampered/Broken/Corrupt detection |
| Recovery < 5s (10k entries) | ✅ Testado (6 testes) |
| Ledger Query API | ✅ Implementado (Gap #9) — filtros, paginação |
| decisions.jsonl append-only | ✅ Funcional |

### 1.9 Security & Key Management

| Feature | Estado |
|:---|:---|
| HMAC key via env var (`BTV_HMAC_KEY`) | ✅ Implementado (Gap #10) |
| Fail-secure em prod (sem key = recusa iniciar) | ✅ `_load_hmac_key()` |
| Dev fallback com warning | ✅ `btv-dev-key-NOT-FOR-PRODUCTION` |
| Key rotation scripts | ✅ `generate_signing_key.sh`, `rotate_signing_key.sh` |
| SigningKeyManager (Rust) | ✅ Load from file, validate 32B, reject zeros |
| SigningKeyRotator (Rust) | ✅ Current + previous keys |
| PolicySigner (Python) | ✅ HMAC-SHA256, rotation, audit trail |
| FFI security (constant-time, BLAKE3 checksum) | ✅ FFIBuffer + FFIBatchProcessor |
| Rate limiting | ✅ Implementado (Gap #6) |
| API Key auth | ✅ Implementado — `X-API-Key` header, env config |

### 1.10 Webhooks

| Feature | Estado |
|:---|:---|
| WebhookDispatcher | ✅ Fire-and-forget, retry com backoff |
| YAML config (`data/policies/webhooks.yaml`) | ✅ URL + ações filtráveis |
| Notify on BLOCK/HARD_BLOCK | ✅ Async dispatch |
| Stats endpoint | ✅ `GET /v1/webhooks/status` |
| 17 testes | ✅ Todos passando |

### 1.11 Observabilidade

| Métrica | Tipo | Testado? |
|:---|:---|:---|
| `btv_decisions_total{action}` | Counter | ✅ |
| `btv_mercy_applied_total` | Counter | ✅ |
| `btv_hard_blocks_total` | Counter | ✅ |
| `btv_latency_ms` | Histogram | ✅ |
| `btv_findings_total{type}` | Counter | ✅ |
| `btv_sanitize_total` | Counter | ✅ |
| `btv_sanitize_masked_total{type}` | Counter | ✅ |
| Gatekeeper metrics (scans, avg/p99 latency) | Struct | ✅ via FFI |

### 1.12 Infraestrutura

| Componente | Estado |
|:---|:---|
| Docker Compose (6 containers) | ✅ Funcional |
| Grafana dashboard | ✅ Funcional (porta 3000) |
| Prometheus scraping | ✅ Funcional (porta 9090) |
| Streamlit dashboard | ✅ Funcional (porta 8501) |
| Forensic ledger (decisions.jsonl) | ✅ Funcional |

---

## 2. LATÊNCIAS OBSERVADAS (Docker, dev machine)

| Operação | Latência |
|:---|:---|
| Validate (CPF) | 10-18ms |
| Hard block (injection) | 6ms |
| Sanitize (PII mask) | 2-15ms |
| Mercy flow completo | 11ms |
| Base64 deobfuscation + CPF | 10ms |
| Batch 100 items | < 5s (debug, sem otimização) |
| Ledger recovery 10k entries | < 5s |

---

## 3. LIMITAÇÕES REAIS

### 3.1 Detecção
- **Apenas PII brasileiro** (CPF, CNPJ) + genéricos (Email, Phone, CC). Sem SSN, NHS, VAT europeu.
- **FPR calibrado internamente** — BiasDeclaration por módulo (CPF: 8%, Email: 3%, CC: 5%), mas sem validação por dataset externo independente.
- **Leetspeak/Hex** existem com chaining funcional mas carecem de testes e2e com curl em todos os cenários.
- **Sem ML** — toda detecção é regex/heurísticas. Evasões sofisticadas passam (v1.8+).

### 3.2 Governance
- **Trust score em memória + SQLite** — funcional mas sem replicação. Single point of failure.
- **Mercy é binário** — aplica ou não. Sem gradação (6 cenários calibrados planejados, só 1 implementado). EthicalContextEngine completo é v1.8+.
- **Appeals funcional mas básico** — ContestabilityLoop + endpoint existem. Sem workflow de revisão humana automatizado (notificação manual).

### 3.3 Compliance
- **Plugins são self-assessment** — verificam se features existem, não auditam decisões reais contra regulações.
- **Compliance Translator (PDF→YAML via LLM)** — código existe mas requer API key OpenAI. Não testado e2e (v2.0+).
- **7 frameworks mapeados em YAML** — dados puros, sem enforcement automático por framework. PolicyEngine consome mas não distingue jurisdição automaticamente.

### 3.4 Intelligence
- **Ingest via API, sem pull automático** — `ThreatIngestor` aceita threats via endpoint, mas não puxa feeds MISP/STIX automaticamente de servidores externos.
- **Bridge funcional mas sem loop contínuo** — `ThreatPolicyBridge` gera regras a partir de threats ingeridas, com dedup e circuit breaker. Requer trigger manual ou cron.

### 3.5 Infraestrutura
- **Sem CI/CD** — builds e testes são manuais. ~54 testes novos existem mas sem pipeline automatizado.
- **Sem TLS** — tudo HTTP plain text.
- **Ledger sem rotação de arquivo** — `decisions.jsonl` cresce infinitamente. Query e paginação existem (LedgerReader), mas sem rotação por tamanho/data.
- **DurableLedger S3 sync é best-effort** — remote_tx envia para channel, mas worker de S3 real não está conectado a bucket. Precisa de config de credenciais AWS.

### 3.6 Testes
- **~54 testes novos** dos gaps (17 webhooks, 14 bridge, 23 ledger query) + 11 BiasDeclaration + 7 batch + 6 ledger recovery. Não há CI executando.
- **CNPJ e Phone** não testados e2e via curl.
- **Testes de integração cross-módulo** pendentes (rodar todos juntos e validar sem quebras).

---

## 4. ENDPOINTS DISPONÍVEIS

### Rust Gateway (porta 8080)

| Endpoint | Método | Função |
|:---|:---|:---|
| `/v1/validate` | POST | Scan + Policy + Governance |
| `/v1/validate/batch` | POST | Batch scan (BatchProcessor FFI) |
| `/v1/sanitize` | POST | PII masking |
| `/v1/policy/test` | POST | Policy test |
| `/health` | GET | Health check |
| `/metrics` | GET | Prometheus |

### Python Governance (porta 8000)

| Endpoint | Método | Função |
|:---|:---|:---|
| `/v1/decide` | POST | Ethical judgment (interno) |
| `/v1/trust/{id}` | GET | Trust score |
| `/v1/appeals/submit` | POST | Submit appeal (Gap #1) |
| `/v1/appeals/{id}` | GET | Appeal status (Gap #1) |
| `/v1/ledger/query` | GET | Query decisions (Gap #9) — filtros por session_id, data, action + paginação |
| `/v1/compliance/frameworks` | GET | List frameworks |
| `/v1/compliance/report/{fw}` | GET | Compliance report |
| `/v1/compliance/check` | POST | Check verdict vs framework |
| `/v1/intelligence/ingest` | POST | Ingest threat |
| `/v1/intelligence/ingest/batch` | POST | Batch ingest |
| `/v1/intelligence/query` | POST | Query threats |
| `/v1/intelligence/threat/{id}` | GET | Get threat |
| `/v1/intelligence/stats` | GET | Threat stats |
| `/v1/intelligence/bridge/sync` | POST | Trigger Threat→Policy sync (Gap #8) |
| `/v1/webhooks/status` | GET | Webhook dispatcher stats (Gap #7) |
| `/health` | GET | Health check |

---

## 5. GAPS ARQUITETURAIS — ESTADO

Todos os 10 gaps identificados na análise de fevereiro 2026 foram fechados:

| # | Gap | Status | Testes | ADR |
|:---|:---|:---|:---|:---|
| 1 | Appeals endpoint | ✅ Fechado | existentes | — |
| 2 | YAML compliance mappings (7 fw) | ✅ Fechado | — | — |
| 3 | Sector patterns → YAML (6 setores) | ✅ Fechado | — | — |
| 4 | Profiles no `/v1/validate` (4 perfis) | ✅ Fechado | — | — |
| 5 | Penalty schedules (6 fw) | ✅ Fechado | — | — |
| 6 | Rate limiting + API Key Auth | ✅ Fechado | existentes | — |
| 7 | Webhooks | ✅ Fechado | 17 | ADR-025 |
| 8 | Threat→Policy Bridge | ✅ Fechado | 14 | ADR-023 |
| 9 | Ledger Query API | ✅ Fechado | 23 | ADR-024 |
| 10 | Key management | ✅ Fechado | existentes | — |

---

## 6. FEATURES v1.5 — ESTADO

| Feature | Status | Evidência |
|:---|:---|:---|
| TechnicalEvidence v2.1 (9596B fixo) | ✅ | `size_of` assert, BLAKE3, zero heap |
| BiasDeclaration mandate (ADR-010) | ✅ | 512B, 11 testes, worst-case aggregation |
| BatchProcessor | ✅ | Config, timeout 10ms, fail-secure, 7 testes |
| DurableLedger + WAL + recovery | ✅ | Chain integrity, recovery < 5s, 6 testes |
| 60+ testes (ethical + technical) | ⚠️ Parcial | ~98 testes existem, meta era 60+ (cumprida). Falta CI. |
| Benchmarks kernel < 30ms p99 | ⚠️ Parcial | Latências medidas (~10ms validate), sem benchmark formal com critérium/criterion |

---

## 7. RECOMENDAÇÕES PARA REFINAMENTO

Por prioridade de impacto:

1. **CI/CD pipeline** — GitHub Actions para `cargo test` + `pytest` em todo PR
2. **Testes e2e restantes** — CNPJ, Phone, Hex, Leetspeak via curl end-to-end
3. **Cross-module integration test** — rodar todos os ~98 testes juntos e validar
4. **TLS** — certificado self-signed no Docker para dev
5. **Rotação do ledger** — max file size ou rotação diária do `decisions.jsonl`
6. **S3 sync real** — conectar DurableLedger a bucket com credenciais
7. **Benchmark formal** — criterion (Rust) para kernel < 30ms p99 com relatório
8. **Mercy gradação** — expandir de binário para 6 cenários calibrados (v1.8)
9. **MISP pull automático** — cron/scheduler para ingestão contínua de feeds

---

## 8. ROADMAP

### v1.5.0 ← FOCO ATUAL (18 fev - 12 abr 2026)
- ✅ TechnicalEvidence v2.1 refactor
- ✅ BiasDeclaration mandate (ADR-010)
- ✅ BatchProcessor (timeout 10ms)
- ✅ DurableLedger (WAL + recovery < 5s)
- ✅ 60+ testes
- ⚠️ Benchmarks kernel < 30ms p99 (latências ok, benchmark formal pendente)
- ⚠️ CI/CD (pendente)

### v1.6.0: PolicyEngine + OutputGuard + Deobfuscator v2 (chaining)
### v1.7.0: Network + SessionGuard + Interceptor + testes contextuais
### v1.8.0: EthicalContextEngine + Misericórdia gradual + ContestabilityLoop avançado
### v1.9.0: Axum Gateway + Observability + PolicyTester API
### v2.0.0: Intelligence Hub + Compliance Translator + Streamlit MVP
### OSS (Q3 2027): Apache 2.0, 100+ stars, 10+ contributors
### LF Submission (Q4 2027): LF AI & Data Sandbox

------------------------------------------------------------

Let me do a thorough analysis of what's already implemented vs. what's missing across v1.6→v2.0.

Aqui está a análise completa. A pesquisa confirma que **muita coisa já está implementada** nas versões planejadas. Vou mapear cada versão: o que existe, o que falta, e o esforço.

---

## ANÁLISE v1.6 → v2.0: IMPLEMENTADO vs. PENDENTE

### v1.6.0 — PolicyEngine + OutputGuard + Deobfuscator v2

| Componente | O que existe | O que falta | Esforço |
|---|---|---|---|
| **PolicyEngine v1.6** | ✅ `policy.rs` completo — YAML→Runtime, hard blocks, `evaluate_full()`, fail-secure, metrics, validator index, priority ordering | ❌ `condition_template` evaluation (os YAMLs de compliance têm condições como `agent.risk_level == 'high'` mas ninguém as avalia) | Médio — parser de expressões ou integração com Python |
| **OutputSanitizer v1.6** | ✅ `output_guard/sanitizer.rs` — mask CPF/CNPJ/Email/Phone/CC, re-scan after mask, BiasDeclaration, 8 testes | ❌ Não está integrado no fluxo de **saída** do LLM (só no endpoint `/v1/sanitize` manual) | Baixo — hook no gateway após resposta do LLM |
| **OutputGuard v2.4** | ✅ `security/output_guard.rs` — XSS/SQL/command injection detection, HTML escape, URL sanitization, `sanitize_full()`, PII masking, `ContentAnalysis` | ❌ Mesma questão: só sanitiza quando chamado explicitamente, não automático no response path | Baixo |
| **Deobfuscator v2 (chaining)** | ✅ `DeobfuscatorChain` — multi-layer decode, re-scan integrado no Gatekeeper | ⚠️ Falta testes e2e (curl) para Hex + Leetspeak | Baixo — só testes |

**Resumo v1.6:** ~80% implementado. Gaps reais: (1) condition evaluation para compliance YAMLs, (2) OutputGuard automático no response path.

---

### v1.7.0 — Network + SessionGuard + Interceptor

| Componente | O que existe | O que falta | Esforço |
|---|---|---|---|
| **SessionGuard** | ✅ `security/session_guard.rs` — SessionToken, SessionStats, 30min timeout, hijacking protection | ❌ **Drift detection** (escalation de intenção ao longo da sessão) não implementado | Médio |
| **Network/IP classifier** | ❌ Pasta `network/` no roadmap mas sem código | ❌ IP geolocation → jurisdição (EU→EU AI Act, BR→LGPD) | Médio — crate `maxminddb` + mapping |
| **Interceptor hooks** | ❌ Pasta `interceptor/` planejada, sem código | ❌ Pre/post hooks extensíveis no pipeline | Médio |
| **Contextual tests** | ✅ `contextual_decisions.rs` — 6 testes (same input different policy, hard block ignores context, mercy vs strict) | ⚠️ Falta testes com SessionGuard + Network integration | Baixo |

**Resumo v1.7:** ~30% implementado. Gaps reais: drift detection, IP classifier, interceptor framework.

---

### v1.8.0 — EthicalContextEngine + Misericórdia + Contestability

| Componente | O que existe | O que falta | Esforço |
|---|---|---|---|
| **EthicalContextEngine** | ✅ `ethical_context_engine.py` — `decide()`, `_apply_technical_rules()`, `_technical_rule_matches()`, trust calculator, mercy calculator, safe evaluator, profile inheritance, domain config | ❌ **Classificador ML de intenção** — popula `use_case`, `target_demographic`, `agent.purpose` automaticamente | Alto — treinar/integrar SLM |
| **Mercy gradual** | ✅ Mercy calculator existe (binário) | ❌ 6 cenários calibrados (hoje é 1 só) | Médio |
| **ContestabilityLoop avançado** | ✅ ContestabilityLoop + API endpoint | ❌ Workflow de revisão humana automatizado (notificações, escalation, resolution tracking) | Médio |
| **Prohibited Practices Detector (Art. 5)** | ❌ Não existe | ❌ Classificador para social scoring, manipulação subliminar, exploração de vulneráveis | Alto — requer NLP/ML |
| **ProfileManager** | ✅ `profile_manager.py` — load YAML, inheritance recursiva, domain config | ✅ Completo | — |
| **SectorLoader** | ✅ `test_sector_loader.py` — whitelist application, profile integration | ✅ Completo | — |

**Resumo v1.8:** ~40% implementado. O EthicalContextEngine existe mas sem classificador ML. Gaps reais: ML classifier, mercy gradual, Art. 5 detector.

---

### v1.9.0 — Axum Gateway + Observability + PolicyTester

| Componente | O que existe | O que falta | Esforço |
|---|---|---|---|
| **Axum Gateway** | ✅ `rust/gateway/` — routes (validate, health), middleware (auth), AppState, HTTP client para Python governance | ❌ Middleware stack completo (TLS, tracing, metrics per-route) | Médio |
| **Observability** | ✅ Prometheus metrics, Grafana dashboard | ❌ Tracing distribuído (OpenTelemetry), métricas DORA | Médio |
| **PolicyTester API** | ❌ Não existe | ❌ Blind testing de políticas via endpoint (Rawls) | Médio |
| **NATS JetStream** | ❌ Bloqueado por roadmap | ❌ v1.9+ | — |

**Resumo v1.9:** ~40% implementado. Gateway funcional mas sem middleware avançado.

---

### v2.0.0 — Intelligence + Compliance Translator + Streamlit

| Componente | O que existe | O que falta | Esforço |
|---|---|---|---|
| **Intelligence Hub** | ✅ Completo — ingest, query, stats, BLAKE3, WAL, bridge | ⚠️ Sem MISP pull automático | Baixo |
| **Compliance Translator** | ✅ Código existe em `compliance/translator.py` | ❌ Requer API key OpenAI, não testado e2e | Baixo (se tem key) |
| **Runtime Compliance Engine** | ❌ Não existe | ❌ Avalia decisões reais contra artigos em runtime (não self-assessment) | Alto |
| **Risk Classification (Annex III)** | ❌ Não existe | ❌ Classifica agentes como high/limited/minimal risk | Alto |
| **FRIA** | ❌ Não existe | ❌ Geração assistida de Fundamental Rights Impact Assessment | Alto |
| **Streamlit MVP** | ✅ `dashboard/app.py` — Validate, Sanitize, Trust, Compliance pages | ⚠️ Faltam páginas para Ledger Query, Appeals, Webhooks, Intelligence Bridge | Baixo |

**Resumo v2.0:** ~35% implementado. Gaps reais: Runtime Compliance Engine, Risk Classification, FRIA.

---

## MATRIZ DE PRIORIDADES

Organizando por **impacto no compliance real** (chegar a ~80% EU AI Act):

| Prioridade | Item | Versão | Esforço | Impacto |
|---|---|---|---|---|
| **P0** | OutputGuard automático no response path | v1.6 | Baixo | Protege saída do LLM |
| **P1** | Condition template evaluation (compliance YAMLs) | v1.6 | Médio | Ativa regras EU AI Act/LGPD/GDPR |
| **P2** | Testes e2e Hex/Leetspeak/CNPJ/Phone | v1.6 | Baixo | Completa cobertura de detecção |
| **P3** | Session drift detection | v1.7 | Médio | Detecta escalation maliciosa |
| **P4** | IP→Jurisdição classifier | v1.7 | Médio | Aplica framework correto por região |
| **P5** | Interceptor hooks | v1.7 | Médio | Extensibilidade do pipeline |
| **P6** | Mercy gradual (6 cenários) | v1.8 | Médio | Gilligan completo |
| **P7** | ContestabilityLoop avançado | v1.8 | Médio | Art. 14 real |
| **P8** | Prohibited Practices Detector (Art. 5) | v1.8 | Alto | **Crítico** — Art. 5 em vigor |
| **P9** | EthicalContextEngine + ML classifier | v1.8 | Alto | Enforcement semântico |
| **P10** | PolicyTester API (blind testing) | v1.9 | Médio | Rawls operacional |
| **P11** | Observability (OpenTelemetry) | v1.9 | Médio | Produção enterprise |
| **P12** | Runtime Compliance Engine | v2.0 | Alto | Compliance real, não self-assessment |
| **P13** | Risk Classification (Annex III) | v2.0 | Alto | Classifica agentes automaticamente |
| **P14** | FRIA | v2.0 | Alto | Requisito EU AI Act high-risk |
| **P15** | Streamlit páginas extras | v2.0 | Baixo | UX |

---

## PLANO DE EXECUÇÃO SUGERIDO

**Fase 1 (v1.6 — ~2 semanas):** P0 + P1 + P2
Fecha o que está quase pronto: OutputGuard no fluxo, condition evaluation, testes e2e.

**Fase 2 (v1.7 — ~3 semanas):** P3 + P4 + P5
Network layer, drift detection, interceptor framework.

**Fase 3 (v1.8 — ~4 semanas):** P6 + P7 + P8 + P9
O salto difícil: mercy gradual, Art. 5 detector, ML classifier. Requer decisão sobre SLM (qual modelo, onde roda).

**Fase 4 (v1.9 — ~2 semanas):** P10 + P11
PolicyTester + OpenTelemetry.

**Fase 5 (v2.0 — ~4 semanas):** P12 + P13 + P14 + P15
Runtime compliance, risk classification, FRIA, dashboard.

**Total estimado: ~15 semanas** (mid-fevereiro → início de junho 2026).

Por onde quer começar? Recomendo **P0 (OutputGuard automático)** — é o que entrega valor imediato com menor esforço e já fecha um gap real de proteção.