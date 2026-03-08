# PROJECT_CONTEXT.md — BuildToValue v2.1

> Documento de contexto para AI Squad. Colar no início de cada chat de IA.
> Última atualização: 04 março 2026.

## O que é

BuildToValue é um Trust OS ético para agentes de IA. Arquitetura híbrida Rust (fatos técnicos) + Python (julgamentos éticos), organizada como "República Algorítmica" com separação de poderes.

## Estado Real do Código

### Rust Kernel (rust/kernel/src/)

**Pipeline do Gatekeeper v2.6.1 — 15 módulos registrados:**

| Estágio | Módulos | Qtd |
|:---|:---|:---:|
| Deobfuscate | Normalizer, Base64Detector, HexDecoder, LeetspeakDetector | 4 |
| Analyze | EntropyCalculator, ZScoreCalculator, CharRatioAnalyzer, LanguageDetector (ADR-034) | 4 |
| Validate | CpfValidator, CnpjValidator, EmailValidator, CreditCardValidator, PhoneValidator, PromptInjectionDetector (ADR-028), SsnValidator | 7 |
| **Stage 3.5a** | NhsValidator (UK), VatValidator, IbanValidator (EU) — jurisdiction-gated via JURISDICTION_ALL (ADR-035 ✅) | 3 |
| **Ledger** | DurableLedger, WriteAheadLog, EffectLog (ADR-0048, PROP-029 ✅) | 3 |

**Structs canônicos (tamanhos verificados compile-time):**

| Struct | Tamanho | Arquivo |
|:---|:---|:---|
| TechnicalEvidence | 9600 bytes | evidence/technical.rs |
| ScanContextFlags | 64 bytes | core/module.rs |
| Finding | 144 bytes | evidence/finding.rs |
| LedgerEntry | 384 bytes | ledger/entry.rs |

**ScanContextFlags (ADR-032):**
- `lang_bitmask` (u64): idiomas detectados (EN=bit0, PT=bit1, ES=bit2...)
- `jurisdiction_bitmask` (u64): jurisdições (BR=bit0, US=bit1, EU=bit2, UK=bit3)
- `capability_mask` (u64): features ativas (CAP_PII, CAP_INJECTION, CAP_DEOBFUSC, CAP_OUTPUT)
- `tenant_key` ([u8;16]): BLAKE3-128 do tenant_id (placeholder [0;16] até multi-tenant)
- `pattern_epoch` (u64): versão do PatternRegistry, escrito em `_reserved_metadata[0..8]`
- `lang_scores` ([u16;4]): confiança top-4 idiomas (fixed-point u16)

**PatternRegistry (ADR-033):**
- ArcSwap global, lock-free no hot path
- Tier 0: Universal (delimiters, structural) — sempre executa
- Tier 1: Primary (EN, PT) — executa se `lang_bitmask` ativo
- Tier 2: Secondary — confiança > 0.3 (reservado)
- `epoch` incrementa em `reload()`, rastreável no TechnicalEvidence

**Security:**
- PromptInjectionDetector: 3 camadas (regex + structural + cross-signal)
- PatternRegistry integrado: `REGISTRY.load()` → `snap.epoch` → `ctx.flags.pattern_epoch`
- OutputGuard: sanitização XSS/injection + PII masking
- SessionGuard: proteção hijacking (30min timeout)

### Python Governance (python/buildtovalue/)

**EthicalContextEngine — duas versões coexistem:**

| Arquivo | Versão | Uso |
|:---|:---|:---|
| `context_engine.py` | v1.8 (pipeline Mercy) | `app.py` via `EthicalContextEngine(signing_key=...)` |
| `ethical_context_engine.py` | v1.0 (unified technical+governance) | `EthicalContextEngineV3` alias, testes v3 |

**Pipeline filosófico (ADR-038, spec — integração parcial):**
- RawlsStage: Blind testing, detecta anomalias policy/evidence
- LevinasStage: Dever de cuidado, gera `appeal_hint`
- JonasStage: Responsabilidade proporcional, escala riscos, verifica BiasDeclaration expirada
- GilliganStage: 6 cenários calibrados (S1-S6), mercy NUNCA escala severidade

**Componentes ativos:**
- BiasGuardian (ADR-036): `DivergenceLevel.OK/WARNING/BLOCK`, thresholds FNR 5/8pp, FPR 3/6pp
- PersuasionGuard (ADR-0049, PROP-037 ✅): AnnotatedCoT, BiasDeclarationV2, HMAC-SHA256, heuristicos paper 209
- GoalDriftSentinel (ADR-0038, PROP-038 ✅): Rust kernel + Python governance, drift ABORT fail-secure
- ContestabilityLoop: submit/status/resolve/expire, SLA 24h
- TrustScoreCalculator: get/set/adjust, decay temporal, cache TTL
- MercyCalculator: mercy_score baseado em trust + first_offense + risk
- PolicySigner: HMAC-SHA256 em todo EthicalVerdict
- AppealEngine: via endpoints FastAPI (submit, resolve, metrics, pending)

**Observability (ADR-041):**
- 21+ famílias de métricas Prometheus
- Pipeline: `btv_pipeline_stage_duration_seconds{stage=rawls|levinas|jonas|gilligan}`
- Appeals: `btv_appeal_sla_compliance_rate`, `btv_appeal_sla_breaches_total`
- Bias: `btv_bias_fnr_divergence_pct{validator_id}`, `btv_bias_gate_status`
- Trust: `btv_trust_score_adjustments_total{type}`

### Gateway Axum v2.0 (ADR-040)

**Rotas:**
- v1.9: `/v1/validate`, `/v1/sanitize`, `/v1/policy/test`, `/v1/guard`, `/health`, `/metrics`
- v2.0: `/v1/decide`, `/v1/appeals` (CRUD + metrics), `/health/bias`, `/v1/trust/:session`
- Middleware: ApiKeyLayer, RateLimitLayer (per-IP, per-tenant), CORS, Timeout 20s

### Testes

- Rust: `cargo test --workspace` — 357+ testes
- Python: `pytest tests/ -v`
- E2E: `ops/e2e-tests.sh` — 27 testes (21 pass, 4 fail, 2 skip — mercy/compliance gaps conhecidos)
- Red-team: `ops/red-team/run-all.sh` — RT-001..RT-008

### ADRs (42 total)

| Grupo | IDs | Status |
|:---|:---|:---|
| A: Fundamentos | 001-009 | ✅ 8 ativos, 002 obsoleto |
| B: Governança | 010, 016 | ✅ 010 ativo, 016→038 |
| C: Segurança | 011-015 | 🔒 Planejados v1.6-v1.7 |
| D: API/Obs | 017-019 | ✅ Ativos |
| E: Intel/Compliance | 020-022 | ✅ Ativos |
| F: Gap Implementations | 023-026 | ✅ Ativos |
| G: Prompt Injection | 028 | ✅ Ativo |
| H: Integration Profiles | 029-031 | ✅ Ativos |
| J: Multi-lang Foundation | 032-035 | ✅ Implementados (035 sem wiring) |
| K: Red-team & Governance | 036-039 | ✅ Implementados |
| L: Gateway & Obs v2.0 | 040-041 | ✅ Implementados |
| M: Policy Automation | 042 | ✅ Implementado (21 testes, CaseCategory, CI gate) |
| N: Effect + CoT Safety | 0048-0049 | ✅ Implementados (PROP-029, PROP-037) |

### Débitos Técnicos Ativos

| # | Débito | Prioridade | Estimativa |
|:---|:---|:---:|:---:|
| DT-001 | NHS/VAT/IBAN wired no Gatekeeper pipeline (Stage 3.5a) | ✅ Fechado v1.7.0 | — |
| DT-002 | `bias_guardian` tipado como `Any` no ethical_context_engine.py | ✅ Fechado — falso positivo (tipo correto) | — |
| DT-003 | ADR-036.md enum values minúsculas vs código maiúsculas | ✅ Fechado — falso positivo (ambos uppercase) | — |
| DT-004 | e2e mercy/compliance (4 fails) — schema mismatch governance | Média | 2-4h |
| DT-005 | `ethical_context_engine.py` excede 200 linhas | Média | Decomposição T1.3 |
| DT-006 | `bridge.rs` em bindings/ tem placeholder Gatekeeper (não usa real) | Média | 1h |
| DT-007 | Trait `Validator` legado coexiste com `Module` | Baixa | Cleanup |

### Anti-padrões Proibidos

- `.unwrap()` em lib code (usar `?` ou `expect` com mensagem)
- `.clone()` sem justificativa documentada
- `any` como type hint em Python (usar tipo concreto)
- `DefaultHasher` (usar BLAKE3)
- Heap allocations no hot path
- Lógica de negócio em `bindings/`
- Microserviços, gRPC, Node.js
- Referência a 9596 ou 9632 bytes (valor correto: 9600)
- `lazy_static!` para patterns que podem usar `PatternRegistry` (ADR-033)

### Dependências Principais

**Rust (Cargo.toml workspace):**
blake3, arc_swap, whatlang, regex, lazy_static, static_assertions, phf, pyo3, serde, axum, tower-http, prometheus, reqwest

**Python (pyproject.toml):**
fastapi, uvicorn, pyyaml, prometheus-client, httpx, pydantic, llama-cpp-python (optional)