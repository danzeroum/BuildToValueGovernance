# PROJECT_CONTEXT.md — BuildToValue Sovereign Trust OS
**Última atualização:** 16 de fevereiro de 2026
**Versão em desenvolvimento:** v2.0.0
**Versão completada:** v1.9.0

---

## Status Atual

O sistema está **operacional end-to-end** via Docker Compose, com República Algorítmica completa (Executivo + Judiciário + Auditivo). Trust scores persistem em SQLite entre restarts.

### Endpoints Ativos

| Endpoint | Porta | Função |
|:---|:---|:---|
| `POST /v1/validate` | 8080 (Rust) | Scan + Policy + Governance |
| `POST /v1/sanitize` | 8080 (Rust) | PII masking (OutputGuard) |
| `POST /v1/decide` | 8000 (Python) | Ethical judgment + Mercy |
| `GET /v1/trust/{id}` | 8000 (Python) | Trust score query |
| `GET /health` | 8080/8000 | Health check |
| `GET /metrics` | 8080 (Rust) | Prometheus exposition |
| Grafana | 3000 | Dashboard |
| Prometheus | 9090 | Metrics scraper |

### Latências Observadas (Docker)

| Operação | Latência |
|:---|:---|
| Validate (CPF) | ~10ms |
| Hard block (injection) | ~6ms |
| Sanitize (PII mask) | ~15ms |
| Mercy flow | ~11ms |

---

## Roadmap — Estado Real

### v1.5.0 ✅ COMPLETO
- [x] TechnicalEvidence v2.1 (9596 bytes fixo, BLAKE3)
- [x] BiasDeclaration mandate
- [x] BatchProcessor (timeout 10ms, Protobuf)
- [x] DurableLedger (WAL + recovery)
- [x] Benchmarks kernel < 30ms p99

### v1.6.0 ✅ COMPLETO
- [x] PolicyEngine (YAML -> runtime, `default.yaml`)
- [x] OutputGuard v2.4 — PII masking (`POST /v1/sanitize`)
- [x] Deobfuscator (base64 -> CPF detection, chaining)

### v1.7.0 ✅ COMPLETO
- [x] SessionGuard — trust tracking por sessão
- [x] Offense tracking (first offense detection)
- [x] Network module (ip_classifier.rs existe)
- [x] Interceptor hooks (estrutura existe)

### v1.8.0 ✅ COMPLETO
- [x] MercyCalculator (Gilligan) — uncertainty > 0.3, trust > 0.6, critical == 0
- [x] soften_action: BLOCK->EDUCATE, REDACT->LOG, EDUCATE->LOG, LOG->ALLOW
- [x] explain_decision() obrigatório (build_rationale)
- [x] HMAC-SHA256 em todos os verdicts (sign_verdict)
- [x] Contestability: contestable=true, appeal_deadline_hours=24

### v1.9.0 ✅ COMPLETO
- [x] Axum Gateway (:8080) — POST /v1/validate, /v1/sanitize, /v1/policy/test
- [x] Prometheus metrics — btv_decisions_total, btv_mercy_applied_total, btv_latency_ms, btv_hard_blocks_total, btv_findings_total, btv_sanitize_total, btv_sanitize_masked_total
- [x] Docker Compose — Rust + Python + Prometheus + Grafana
- [x] SQLite trust persistence (sobrevive restarts)
- [x] BTV_GOVERNANCE_URL env var (Docker networking)

### v2.0.0 ← PRÓXIMO FOCO
- [ ] Intelligence Hub (MISP/STIX integration)
- [ ] Compliance Translator (PDF -> YAML policies via LLM)
- [ ] CompliancePlugin architecture (LGPD, EU AI Act, NIST, ISO 42001)
- [ ] Streamlit MVP dashboard
- [ ] AJL exporter

### Open Source (Q3 2027)
- [ ] Apache 2.0 public release
- [ ] 100+ stars, 10+ contributors

### Linux Foundation (Q4 2027)
- [ ] LF AI & Data Sandbox submission

---

## República Algorítmica (Separação de Poderes)

| Poder | Serviço | Função | Stack |
|:---|:---|:---|:---|
| **Legislativo** | `data/policies/core/default.yaml` | Policy-as-Code, hard blocks | YAML + Git |
| **Executivo** | Rust Gateway `:8080` | scan_for_evidence + PolicyEngine | Axum, Rust kernel |
| **Judiciário** | Python Governance `:8000` | Mercy + Trust + HMAC + explain_decision | FastAPI, SQLite |
| **Auditivo** | `data/ledger/decisions.jsonl` | Forensic log imutável | JSONL append-only |

---

## Estrutura Física (Validada)
```
buildtovalue/
├── rust/
│   ├── kernel/src/
│   │   ├── lib.rs, core/, evidence/, gatekeeper.rs
│   │   ├── validators/ (cpf, cnpj, email, phone, credit_card)
│   │   ├── statistics/ (entropy, zscore, char_ratio)
│   │   ├── deobfuscator/ (base64, hex, leetspeak, chain)
│   │   ├── policy/engine.rs
│   │   ├── security/ (hmac.rs, output_guard.rs, audit.rs, session_guard.rs)
│   │   ├── ledger/ (wal.rs, chain.rs, durable.rs)
│   │   ├── compliance/ (penalty.rs, ajl.rs)
│   │   ├── batch.rs, ffi/
│   │   └── observability/
│   ├── gateway/src/
│   │   ├── main.rs, state.rs (AppState + Prometheus metrics)
│   │   └── routes/ (validate.rs, sanitize.rs, health.rs, metrics.rs, policy_test.rs)
│   └── cli/, bindings/
├── python/buildtovalue/
│   └── api/app.py (v1.3 — FastAPI + SQLite trust persistence)
├── ops/
│   ├── docker-compose.yml (gateway + governance + prometheus + grafana)
│   ├── Dockerfile.rust, Dockerfile.python
│   └── prometheus.yml
├── data/
│   ├── policies/core/default.yaml
│   ├── ledger/decisions.jsonl
│   └── trust.db (SQLite — inside Docker volume)
└── docs/
```

---

## Invariantes Técnicos (Violação = REJECT)

- TechnicalEvidence: 9596 bytes FIXOS
- Hot path: ZERO heap allocations
- Hash: BLAKE3 (NUNCA SHA-256 para evidence)
- Fail-secure: QUALQUER erro -> BLOCK
- BiasDeclaration: obrigatório em todo Validator
- explain_decision(): obrigatório em toda decisão Python
- HMAC-SHA256: obrigatório em todo EthicalVerdict
- contestable: true + appeal_deadline: 24h em todo verdict
- Funções <= 50 linhas, arquivos <= 200 linhas

---

## Fundamentos Filosóficos

| Filósofo | Princípio | Implementação |
|:---|:---|:---|
| **Rawls** | Blind Policy Testing | PolicyEngine (YAML, sem acesso a identidade) |
| **Levinas** | Proteger o vulnerável | Fail-secure (erro -> BLOCK), soften_action |
| **Gilligan** | Ética do Cuidado | MercyCalculator (trust > 0.6, first offense, critical == 0) |
| **Jonas** | Responsabilidade | BiasDeclaration, Ledger imutável, HMAC-SHA256 |

---

## Métricas Prometheus Disponíveis

| Métrica | Tipo | Descrição |
|:---|:---|:---|
| `btv_decisions_total{action}` | Counter | Decisões por ação |
| `btv_mercy_applied_total` | Counter | Mercy applications |
| `btv_hard_blocks_total` | Counter | Hard blocks |
| `btv_latency_ms` | Histogram | Latência p50/p95/p99 |
| `btv_findings_total{type}` | Counter | Findings por tipo |
| `btv_sanitize_total` | Counter | Sanitize requests |
| `btv_sanitize_masked_total{type}` | Counter | PII masked por tipo |

---

## Anti-Padrões Proibidos

- `.unwrap()` em lib code
- `.clone()` sem justificativa
- `any` em Python
- `DefaultHasher` (usar BLAKE3)
- Heap no hot path
- Lógica em `bindings/`
- Microserviços/gRPC/Node.js
- Frontend antes de v2.0

---

## Docker Compose (ops/)
```bash
cd ops && docker-compose up --build    # Build + start
docker-compose down                     # Stop
docker-compose down -v                  # Stop + reset volumes
```

Serviços: gateway (:8080), governance (:8000), prometheus (:9090), grafana (:3000)
Login Grafana: admin / changeme