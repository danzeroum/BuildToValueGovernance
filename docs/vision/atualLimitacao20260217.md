# Relatório de Engenharia — BuildToValue (Estado Real)

**Data:** 20 de fevereiro de 2026  
**Revisão:** v3.0 — Após SSN Validator, Benchmark Criterion, OutputGuard SSN, Prompt Injection  
**Substitui:** `atualLimitacao20260217.md`

---

## 1. DETECÇÃO (Rust Kernel — 13 Módulos)

### 1.1 Pipeline Gatekeeper v2.7.0

| Estágio | Módulo | Detecta | Status | Testes |
|:---|:---|:---|:---|:---|
| Deobfuscate | Base64Detector | Encoding Base64 | ✅ e2e | 6 |
| Deobfuscate | HexDecoder | Encoding hexadecimal | ✅ unit | 3 |
| Deobfuscate | LeetspeakDetector | L33tspeak obfuscation | ✅ unit | 3 |
| Analyze | EntropyCalculator | Alta entropia | ✅ unit | 2 |
| Analyze | ZScoreCalculator | Anomalias estatísticas | ✅ unit | 2 |
| Analyze | CharRatioAnalyzer | Proporção de chars suspeitos | ✅ unit | 2 |
| Validate | CpfValidator | CPF brasileiro | ✅ e2e | 5 |
| Validate | CnpjValidator | CNPJ brasileiro | ✅ e2e | 4 |
| Validate | EmailValidator | Endereços de email | ✅ e2e | 3 |
| Validate | CreditCardValidator | Cartões (Luhn) | ✅ e2e | 3 |
| Validate | PhoneValidator | Telefones brasileiros | ✅ unit | 3 |
| Validate | PromptInjectionDetector | Prompt injection (3 camadas) | ✅ unit | 26 |
| Validate | SsnValidator | US Social Security Number | ✅ unit | 17 |

**Total: 13 módulos, 3 estágios + re-scan automático via DeobfuscatorChain.**

### 1.2 BiasDeclaration (ADR-010)

Todos os 13 módulos implementam `bias_declaration()`. Gatekeeper agrega worst-case.
Calibração válida por 90 dias. 11 testes dedicados.

| Validator | FPR | FNR | Dataset | Calibração |
|:---|:---|:---|:---|:---|
| CPF | 0.08 | 0.02 | 500 | 2026-02-09 |
| Email | 0.03 | 0.08 | 800 | 2026-02-09 |
| Credit Card | 0.05 | 0.12 | 200 | 2026-02-09 |
| SSN | 0.12 | 0.05 | 300 | 2026-02-20 |
| PromptInjection | 0.10 | 0.15 | 300 | 2026-02-18 |

### 1.3 Benchmark Criterion (Formal)

Executado em 20/02/2026 com 13 módulos. Target: < 30ms p99.

| Cenário | Latência | vs Target |
|:---|:---|:---|
| clean_input | 1.55ms | 5.2% |
| cpf_direct | 3.52ms | 11.7% |
| multi_pii | 3.31ms | 11.0% |
| base64_cpf_rescan | 1.62ms | 5.4% |
| long_input_1kb | 1.74ms | 5.8% |
| sql_injection | 1.58ms | 5.3% |
| leetspeak_encoded | 1.69ms | 5.6% |
| adversarial_10kb_dense_pii | 5.71ms | 19.0% |

**Veredicto: ✅ APROVADO. Pior caso 5.71ms — 5.3x abaixo do target.**

Throughput sustentado: ~440 req/s (mixed), ~392 req/s (bulk CPF).

---

## 2. POLICY ENGINE

| Feature | Status |
|:---|:---|
| Hard blocks (SQL injection, XSS, 12 patterns) | ✅ |
| Policy YAML (default.yaml) | ✅ |
| Ações: ALLOW, LOG, EDUCATE, REDACT, BLOCK | ✅ |
| Profile-aware (4 perfis) | ✅ |
| Sector patterns (6 setores YAML) | ✅ |
| Penalty schedules (6 frameworks) | ✅ |
| 7 compliance YAML mappings | ✅ |
| SSN → BLOCK policy | ✅ |

---

## 3. OUTPUT GUARD

| Componente | PII Types | SSN | Status |
|:---|:---|:---|:---|
| OutputSanitizer (PII mask + rescan) | CPF, CNPJ, Email, Phone, CC, SSN | ✅ | 11 testes |
| OutputGuard (XSS + PII) | CPF, CNPJ, Email, Phone, CC, SSN | ✅ | 8 testes |
| Auto no /v1/validate response | Integrado | ✅ | — |
| /v1/guard endpoint (combinado) | XSS + PII | ✅ | 7 testes |
| /v1/sanitize endpoint (PII only) | PII masking | ✅ | — |

---

## 4. GOVERNANCE (Python)

| Feature | Status |
|:---|:---|
| EthicalContextEngine + safe evaluator | ✅ |
| MercyCalculator (Gilligan) | ✅ |
| TrustScore (SQLite persistent) | ✅ |
| HMAC-SHA256 signatures | ✅ |
| explain_decision() | ✅ |
| Contestability (24h SLA, SQLite) | ✅ |
| Appeals endpoint + persistence | ✅ |
| Webhooks (fire-and-forget, retry) | ✅ |
| Threat→Policy Bridge (MISP→PolicyEngine) | ✅ |
| SLM Classifier (Qwen 2.5 3B, fail-open) | ✅ |
| Output Schema Validation | ✅ |
| ComplianceEvaluator (condition templates) | ✅ |

---

## 5. COMPLIANCE

| Framework | Artigos | Runtime | Status |
|:---|:---|:---|:---|
| LGPD | Art. 6, 18, 20, 46, 48 | ✅ Plugin | 5/5 COMPLIANT |
| EU AI Act | Art. 5, 6, 13, 14, 15, 43, 51, 71 | ✅ Evaluator | condition_template |
| NIST AI RMF | GOVERN, MAP, MEASURE, MANAGE | ✅ Evaluator | condition_template |
| ISO 42001 | Clauses 4-10 | ✅ Evaluator | condition_template |
| GDPR | Art. 5, 6, 9, 17, 22, 25 | ✅ Evaluator | condition_template |
| HIPAA | Privacy, Security, Breach | ✅ Evaluator | condition_template |
| PCI-DSS | Req 3, 4, 9, 10, 12 | ✅ Evaluator | condition_template |

RiskClassifier (Annex III) + FRIA Generator (Art. 27) implementados.

---

## 6. INFRAESTRUTURA

| Componente | Status |
|:---|:---|
| CI/CD GitHub Actions | ✅ cargo test + pytest + clippy |
| Docker Compose (Gateway + Governance + Streamlit + Prometheus + Grafana) | ⚠️ Funcional mas llama-cpp paths pendentes |
| Axum Gateway (:8080) | ✅ |
| FastAPI Governance (:8000) | ✅ |
| Streamlit Dashboard (:8501) | ✅ 9 páginas |
| Prometheus (:9090) + Grafana (:3000) | ✅ |

---

## 7. TESTES

| Escopo | Contagem | Status |
|:---|:---|:---|
| Rust kernel (unit + integration) | 153 | ✅ |
| Rust gateway | 7+ | ✅ |
| Python (unit + integration + ethical) | 357+ | ✅ |
| Benchmark Criterion | 11 cenários | ✅ |
| **Total** | **520+** | ✅ |

---

## 8. LIMITAÇÕES REAIS (Honestas)

### Blockers para adoção

- **Sem TLS** — HTTP plain text. Resolve com reverse proxy mas não ideal.
- **Docker SLM** — `llama-cpp-python` não instala no Dockerfile atual. SLM funciona local, não em container.
- **Sem quickstart curl** — README não tem 5-min demo path.

### Limitações técnicas

- FPR ~15% (adversarial, 70 amostras, não validado externamente)
- FNR leetspeak ~12% (homoglyphs Unicode não cobertos)
- SSN bare (9 dígitos sem separador) tem FPR ~25% — confidence 60 vs 95 para formatted
- PromptInjection é heurístico (regex + estrutural + cross-signal), não ML
- Ledger cresce indefinitamente (sem rotação)
- DurableLedger S3 sync best-effort (sem bucket configurado)
- Compliance é enforcement — não substitui assessoria jurídica

### Débitos técnicos menores

- Trait `Validator` ainda existe (obsoleto, todos usam `Module`)
- Testes e2e curl para Hex + Leetspeak pendentes
- OTEL tracing incompleto (Prometheus funciona)
- `GatekeeperBuilder` para plugin extensível não implementado

---

## 9. ROADMAP ATUALIZADO

| Versão | Status | Escopo |
|:---|:---|:---|
| v1.5 | ✅ Completo | TechnicalEvidence, BiasDeclaration, Batch, Ledger, Benchmark |
| v1.6 | ✅ Completo | PolicyEngine, OutputGuard+SSN, Deobfuscator v2, ComplianceEvaluator |
| v1.7 | ✅ Completo | Network, SessionGuard, Interceptor, testes contextuais |
| v1.8 | ✅ Completo | EthicalContextEngine, MercyCalculator, ContestabilityLoop |
| v1.9 | ✅ Completo | Axum Gateway, Observability, PolicyTester, PromptInjection |
| v2.0 Fase A | ✅ Completo | CI/CD, Streamlit, Lifespan, SLM, Docs |
| v2.0 Fase B | ✅ Completo | RiskClassifier, ComplianceEvaluator runtime, FRIA |
| v2.1 | 🚧 Em andamento | US SSN, Benchmark formal, Docker fixes, Quickstart |
| OSS Q3/2027 | 🔒 Planejado | Apache 2.0, 100+ stars, 10+ contributors |
| LF Q4/2027 | 🔒 Planejado | LF AI & Data Sandbox submission |

---

## 10. PRÓXIMAS PRIORIDADES

1. **Docker fixes** — llama-cpp-python, policy paths, compose funcional out-of-box
2. **Quickstart 5min** — `docker compose up` + curl demo (CPF→BLOCK→appeal)
3. **Testes e2e curl** — Hex, Leetspeak, SSN via gateway
4. **TLS** — self-signed para dev, ou nginx reverse proxy
5. **Red-teaming formal** — HarmBench/AdvBench datasets contra PromptInjection
6. **Multi-language PII** — UK NHS, EU VAT (seguindo padrão SSN)