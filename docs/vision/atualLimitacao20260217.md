# Relatório de Engenharia — BuildToValue v2.0 (Estado Real)

**Data:** 17 de fevereiro de 2026

---

## 1. O QUE O SISTEMA FAZ HOJE

### 1.1 Detecção (Rust Kernel — porta 8080)

**Validators implementados e testados:**

| Validator | Detecta | Exemplo | Funciona? |
|:---|:---|:---|:---|
| CPF | CPF brasileiro (com/sem pontuação) | `123.456.789-09` | ✅ Testado |
| CNPJ | CNPJ brasileiro | `11.222.333/0001-81` | ✅ Testado |
| Email | Endereços de email | `joao@empresa.com` | ✅ Testado |
| Phone | Telefones brasileiros | `11 98765-4321` | ✅ Testado |
| Credit Card | Números de cartão (Luhn) | `4532 0151 1283 0366` | ✅ Testado |
| Entropy | Alta entropia (dados aleatórios) | Strings randômicas | ✅ Existe |
| ZScore | Anomalias estatísticas | Desvios extremos | ✅ Existe |
| CharRatio | Proporção de caracteres suspeitos | Excesso de símbolos | ✅ Existe |
| Base64 | Decodifica Base64 e re-scana | `MTIzLjQ1Ni43ODktMDk=` → CPF | ✅ Testado |
| Hex | Decodifica hexadecimal | Hex encoded strings | ✅ Existe |
| Leetspeak | Decodifica l33t | `CPF 1z3.456.7B9-09` | ✅ Existe |

**Nota honesta:** "Existe" = código compila e tem testes unitários. "Testado" = validamos end-to-end via curl nesta sessão.

### 1.2 Policy Engine

| Feature | Estado |
|:---|:---|
| Hard blocks (SQL injection, XSS) | ✅ Testado — `DROP TABLE` → HARD BLOCK |
| Policy YAML (`default.yaml`) | ✅ Testado — cpf→Block, email→Redact |
| Ações: ALLOW, LOG, EDUCATE, REDACT, BLOCK | ✅ Todas funcionam |
| Deobfuscation antes de policy check | ✅ Testado — Base64→CPF→BLOCK |

### 1.3 Governance (Python — porta 8000)

| Feature | Estado | Detalhe |
|:---|:---|:---|
| Mercy Calculator (Gilligan) | ✅ Testado | trust > 0.6 + first offense + critical == 0 → soften |
| soften_action | ✅ Testado | REDACT→LOG confirmado |
| Trust score tracking | ✅ Testado | 8 msgs limpas: 0.50→0.66 |
| Trust persistence (SQLite) | ✅ Testado | Sobrevive docker-compose restart |
| Offense tracking | ✅ Testado | first_offense corretamente detectado |
| HMAC-SHA256 signatures | ✅ Testado | Toda decisão assinada |
| explain_decision() | ✅ Testado | Rationale em toda response |
| Contestability (24h) | ✅ Testado | contestable:true + appeal_deadline_hours:24 |

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

**Nota honesta:** Os plugins verificam se o sistema tem as capacidades (explain_decision, contestability, HMAC). Não testam contra dados regulatórios reais de um caso concreto.

### 1.6 Intelligence Hub

| Feature | Estado |
|:---|:---|
| Ingest single threat | ✅ Testado |
| Ingest batch | ✅ Testado (2 threats) |
| Query by type | ✅ Testado |
| Query by severity | ✅ Testado |
| Get by ID | ✅ Testado |
| Stats | ✅ Testado (3 threats, avg 9.0) |
| BLAKE2b hash integrity | ✅ Testado |
| SQLite persistence | ✅ Testado |

**Nota honesta:** As threats ingeridas são manuais. Não há integração real com feeds MISP/STIX externos. O hub armazena e consulta, mas não enriquece automaticamente o PolicyEngine.

### 1.7 Observabilidade

| Métrica | Tipo | Testado? |
|:---|:---|:---|
| `btv_decisions_total{action}` | Counter | ✅ |
| `btv_mercy_applied_total` | Counter | ✅ |
| `btv_hard_blocks_total` | Counter | ✅ |
| `btv_latency_ms` | Histogram | ✅ |
| `btv_findings_total{type}` | Counter | ✅ |
| `btv_sanitize_total` | Counter | ✅ |
| `btv_sanitize_masked_total{type}` | Counter | ✅ |

### 1.8 Infraestrutura

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

---

## 3. LIMITAÇÕES REAIS

### 3.1 Detecção
- **Apenas PII brasileiro** (CPF, CNPJ). Sem SSN, NHS, VAT europeu.
- **FPR ~15%** estimado, não validado externamente.
- **Leetspeak/Hex** existem mas não foram testados e2e nesta sessão.
- **Sem ML** — toda detecção é baseada em regex/heurísticas. Evasões sofisticadas passam.

### 3.2 Governance
- **Trust score em memória + SQLite** — funcional mas sem replicação. Single point of failure.
- **Appeals não implementados** — contestable:true aparece, mas não existe endpoint para submeter appeal.
- **Mercy é binário** — aplica ou não. Sem gradação (6 cenários calibrados planejados, só 1 implementado).

### 3.3 Compliance
- **Plugins são self-assessment** — verificam se features existem, não auditam decisões reais contra regulações.
- **Compliance Translator (PDF→YAML via LLM)** — código existe mas requer API key OpenAI. Não testado e2e.

### 3.4 Intelligence
- **Sem integração real com MISP/STIX** — ingest é manual via API.
- **Threats não alimentam PolicyEngine** — o hub armazena mas não enriquece detecção automaticamente.

### 3.5 Infraestrutura
- **Sem CI/CD** — builds e testes são manuais.
- **Sem TLS** — tudo HTTP plain text.
- **HMAC key hardcoded** — `b"btv-sovereign-trust-os-v1"` em código.
- **Sem rate limiting** — qualquer um pode fazer flood.
- **Ledger append-only sem rotação** — decisions.jsonl cresce infinitamente.

---

## 4. ENDPOINTS DISPONÍVEIS

| Endpoint | Método | Porta | Função |
|:---|:---|:---|:---|
| `/v1/validate` | POST | 8080 | Scan + Policy + Governance |
| `/v1/sanitize` | POST | 8080 | PII masking |
| `/v1/policy/test` | POST | 8080 | Policy test |
| `/v1/decide` | POST | 8000 | Ethical judgment (interno) |
| `/v1/trust/{id}` | GET | 8000 | Trust score |
| `/v1/compliance/frameworks` | GET | 8000 | List frameworks |
| `/v1/compliance/report/{fw}` | GET | 8000 | Compliance report |
| `/v1/compliance/check` | POST | 8000 | Check verdict vs framework |
| `/v1/intelligence/ingest` | POST | 8000 | Ingest threat |
| `/v1/intelligence/ingest/batch` | POST | 8000 | Batch ingest |
| `/v1/intelligence/query` | POST | 8000 | Query threats |
| `/v1/intelligence/threat/{id}` | GET | 8000 | Get threat |
| `/v1/intelligence/stats` | GET | 8000 | Threat stats |
| `/health` | GET | 8080/8000 | Health check |
| `/metrics` | GET | 8080 | Prometheus |

---

## 5. RECOMENDAÇÕES PARA REFINAMENTO (sem novas features)

Por prioridade de impacto:

1. **Testar e2e todos os validators** — CNPJ, phone, hex, leetspeak, entropy via curl
2. **Implementar Appeals endpoint** — contestable:true sem endpoint real é promessa vazia
3. **Externalizar HMAC key** — env var, não hardcoded
4. **Rate limiting no gateway** — tower-http `RateLimitLayer`
5. **TLS** — certificado self-signed no Docker para dev
6. **Testes automatizados** — script bash que roda todos os cenários validados nesta sessão
7. **Rotação do ledger** — max file size ou rotação diária
8. **Threat→Policy bridge** — threats ingeridas geram regras automaticamente