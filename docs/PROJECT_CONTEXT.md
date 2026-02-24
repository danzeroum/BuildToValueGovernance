# BuildToValue — PROJECT_CONTEXT.md
# Versão: 4.0 | Atualizado: 18 fev 2026

## 1. O QUE É

Sovereign Trust OS — infraestrutura de governança ética para agentes de IA.
Rust kernel (fatos técnicos) + Python governance (julgamentos éticos).
República Algorítmica: Legislativo (Policy-as-Code) → Executivo (Rust < 30ms) →
Judiciário (Python < 10ms) → Auditivo (Ledger imutável).

## 2. ESTADO ATUAL

**Versão:** v2.0.0-alpha (Fase B completa)
**Versões completadas:** v1.5 → v1.9 (operacional end-to-end via Docker Compose)

Sistema operacional com:
- Rust Gateway (:8080) — validate, sanitize, batch, policy test, metrics
- Python Governance (:8000) — decide, trust, appeals, ledger query, compliance, intelligence, webhooks
- Streamlit Dashboard (:8501) — 9 páginas
- Prometheus (:9090) + Grafana (:3000) — observabilidade
- SLM Classifier — Qwen 2.5 3B local (zona de ambiguidade, fail-open)
- CI/CD — GitHub Actions (Rust + Python + Ethical tests)
- Runtime Compliance Engine — RiskClassifier + ComplianceEvaluator no pipeline /v1/decide
- FRIA Generator — Fundamental Rights Impact Assessment (Art. 27, 10 seções auto-preenchidas)

Latências observadas (Docker, dev): ~10ms validate, ~6ms hard block, ~11ms mercy flow.
## 3. 10 GAPS — TODOS FECHADOS

| # | Gap | Status |
|---|---|---|
| 1 | Appeals endpoint | ✅ ContestabilityLoop + SQLite persistence |
| 2 | Compliance YAML mappings (7 frameworks) | ✅ `data/policies/compliance/` |
| 3 | Sector patterns (6 setores) | ✅ `data/policies/sectors/` |
| 4 | Profiles no `/v1/validate` | ✅ ProfileManager + SectorLoader |
| 5 | Penalty schedules | ✅ `data/policies/penalties.yaml` |
| 6 | Rate limiting + API Key Auth | ✅ `X-API-Key` header |
| 7 | Webhooks | ✅ WebhookDispatcher + YAML config |
| 8 | Threat→Policy Bridge | ✅ ThreatPolicyBridge + SQLite hydration |
| 9 | Ledger Query API | ✅ LedgerReader + pagination |
| 10 | Key management | ✅ Env var + rotation scripts |

## 4. CLEANUP REALIZADO (T3)

- 14 scripts legados arquivados em `docs/legacy/`
- `database.py` removido (código inseguro educacional)
- 3 `requirements*.txt` removidos (pyproject.toml é fonte única)
- 4 workflows CI/CD quebrados substituídos por `ci.yml` funcional
- FastAPI `on_event` migrado para `lifespan`
- `test_profile_manager.py` movido de produção para `tests/unit/`

## 5. TESTES

- 357 testes passando (unit + integration + ethical)
- 12 deselected (benchmarks opcionais)
- 17 warnings restantes (httpx deprecation — cosmético)

## 6. ENDPOINTS

### Rust Gateway (:8080)

| Endpoint | Método | Função |
|---|---|---|
| `/v1/validate` | POST | Scan + Policy + Governance |
| `/v1/validate/batch` | POST | Batch scan |
| `/v1/sanitize` | POST | PII masking |
| `/v1/policy/test` | POST | Policy test |
| `/health` | GET | Health check |
| `/metrics` | GET | Prometheus |
| `/v1/compliance/classify-risk` | POST | EU AI Act risk classification (Annex III) |
| `/v1/compliance/fria/generate` | POST | FRIA document generation (Art. 27) |

### Python Governance (:8000)

| Endpoint | Método | Função |
|---|---|---|
| `/v1/decide` | POST | Ethical judgment (SLM + mercy + trust + HMAC) |
| `/v1/trust/{id}` | GET | Trust score |
| `/v1/appeals` | POST/GET | Submit/list appeals |
| `/v1/appeals/{id}` | GET | Appeal status |
| `/v1/appeals/{id}/resolve` | POST | Resolve appeal |
| `/v1/appeals/metrics` | GET | Appeal metrics |
| `/v1/ledger/query` | GET | Query decisions (filtros + paginação) |
| `/v1/ledger/stats` | GET | Ledger stats |
| `/v1/compliance/report/{fw}` | GET | Compliance report |
| `/v1/compliance/check` | POST | Check verdict vs framework |
| `/v1/intelligence/ingest` | POST | Ingest threat |
| `/v1/intelligence/bridge/sync` | POST | Threat→Policy sync |
| `/v1/intelligence/stats` | GET | Threat stats |
| `/v1/webhooks/status` | GET | Webhook stats |
| `/health` | GET | Health check |

## 7. INVARIANTES (Violação = REJECT)

- TechnicalEvidence: 9596 bytes fixos (`size_of` assert)
- Hot path: ZERO heap allocations
- Hash: BLAKE3 (nunca SHA-256 para evidence)
- Ring buffer: [Finding; 10] + [Finding; 3] critical
- Fail-secure: erro/timeout → BLOCK
- BiasDeclaration obrigatório em todo Validator
- `explain_decision()` obrigatório em decisões éticas
- HMAC-SHA256 em todo EthicalVerdict
- `contestable: true` + `appeal_deadline: 24h` em todo verdict
- SLM é fail-open (nunca bloqueia pipeline)

## 8. ANTI-PADRÕES PROIBIDOS

`.unwrap()` em lib, `.clone()` sem justificativa, `any` em Python,
`DefaultHasher`, heap no hot path, lógica em `bindings/`, microserviços,
gRPC, Node.js.

## 9. LIMITAÇÕES CONHECIDAS

- FPR ~15% (adversarial, 70 amostras — não validado externamente)
- FNR leetspeak ~12% (homoglyphs Unicode não cobertos)
- Sem TLS (HTTP plain text)
- Ledger sem rotação de arquivo (cresce infinitamente)
- DurableLedger S3 sync best-effort (sem bucket configurado)
- MISP ingest via API (sem pull automático de servidores externos)
- SLM timeout agressivo em CPU-only (~500ms-5s real vs 2s config)

## 10. ROADMAP

| Versão | Estado | Escopo |
|---|---|---|
| v1.5 — v1.9 | ✅ Completo | Kernel, Policy, Guard, Session, Mercy, Gateway, Observability |
| v2.0 Fase A | 🚧 Em andamento | CI/CD ✅, Streamlit 9 páginas ✅, Lifespan ✅, Docs, SLM config |
| v2.0 Fase B | 🔒 Planejado | Runtime Compliance Engine, Risk Classification (Annex III), FRIA |
| OSS Q3/2027 | 🔒 | Apache 2.0, 100+ stars, 10+ contributors |
| LF Q4/2027 | 🔒 | LF AI & Data Sandbox |

## 11. AI SQUAD WORKFLOW

Humano → Arquiteta (ADR+traits) → Dev Rust/Python → Reviewer → Humano integra.
Max 3 iterações Dev↔Reviewer. Compilar antes de review.
Handoff templates em `docs/HANDOFF_TEMPLATES.md`.

## Premissas de Produção — TLS/Segurança de Rede

- Nginx como reverse proxy terminando TLS (já implementado em dev com self-signed)
- Let's Encrypt + Certbot para certificado válido (requer domínio DNS)
- Portas internas apenas: gateway e governance sem `ports:` expostos — só `expose:`
- mTLS entre serviços internos
- Zero mudança de código — 100% configuração de infraestrutura