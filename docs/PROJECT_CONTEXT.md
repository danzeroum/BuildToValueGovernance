[Docs](./README.md) › **Project Context**

![Interno](https://img.shields.io/badge/Trilha-Contribuidor%20%2F%20Interno-6e7681)

<!-- audience: internal -->

---

# PROJECT_CONTEXT.md — BuildToValue v2.4.0

> Documento de contexto para AI Squad. Colar no início de cada chat de IA.
> Última atualização: 08 março 2026 (sessão noturna — YAML-driven threshold pattern consolidado).

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
| **Sensitive** | ConsentValidator, ConsentRevocationValidator (LGPD Art.7/Art.8§5) | 2 |
| **Stage 3.5a** | NhsValidator (UK), VatValidator, IbanValidator (EU) — jurisdiction-gated via JURISDICTION_ALL (ADR-035 ✅) | 3 |
| **Ledger** | DurableLedger, WriteAheadLog, EffectLog (ADR-0048, PROP-029 ✅) | 3 |

**Structs canônicos (tamanhos verificados compile-time):**

| Struct | Tamanho | Arquivo | Nota |
|:---|:---|:---|:---|
| TechnicalEvidence | 9632 bytes | evidence/technical.rs | EVIDENCE_SIZE em core/types.rs (ADR-044) |
| ScanContextFlags | 64 bytes | core/module.rs | — |
| Finding | 144 bytes | evidence/finding.rs | — |
| LedgerEntry | 384 bytes | ledger/entry.rs | `verdict_id [u8;32]` adicionado, `_reserved` 196→164 (ADR-043) |

**LedgerEntry v2.4.0 (ADR-043):**
- `verdict_id: [u8; 32]` — HMAC-SHA256(signing_key, evidence_hash ‖ action_u8 ‖ trail_id)
- `finalize()` — computa `entry_hash` + `verdict_id` com chave zero (default seguro)
- `finalize_with_key(signing_key)` — produção com chave do operador (ADR-042)
- `validate()` / `validate_with_key()` — verificam `entry_hash` + `verdict_id`
- `_reserved` 196→164 bytes (total 384 mantido)

**EthicalVerdict enum (types.rs):**
`Pending=0 | Allow=1 | Educate=2 | Redact=3 | Block=4 | Report=5 (ADR-043)`
- `Report`: flagging auditável sem alteração de output, SLA 24h

**ActionType enum (ledger/entry.rs):**
`Allow=0 | Log=1 | Educate=2 | Redact=3 | Block=4 | Report=5 (ADR-043)`

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
- `supply_guard.rs` (PROP-031): BLAKE3 keyed-MAC + registry lookup, fail-secure
- `model_integrity.rs` (ADR-051 Fase 1): BLAKE3 hash de manifesto, fail-secure, ring buffer 256 eventos

### Python Governance (python/buildtovalue/)

**EthicalContextEngine — duas versões coexistem:**

| Arquivo | Versão | Uso |
|:---|:---|:---|
| `context_engine.py` | v1.9.1 (YAML-driven threshold) | `app.py` via `EthicalContextEngine(signing_key=..., policy_engine=...)` |
| `ethical_context_engine.py` | v1.0 (unified technical+governance) | `EthicalContextEngineV3` alias, testes v3 |

**EthicalContextEngine v1.9.1 (ADR-043):**
- `__init__` aceita `policy_engine: Optional[PolicyEngine] = None`
- `report_threshold` lido de `policy_engine.report_threshold` se fornecido; fallback `0.65` (backward compat total)
- Step 5b: `ALLOW + composite_risk >= report_threshold + finding_count > 0` → `REPORT`
- `EthicalVerdict.report_triggered: bool` — rastreável em `to_dict()`
- `explain_decision()` documenta REPORT com SLA 24h
- BLOCK/REDACT/EDUCATE **nunca** são downgraded para REPORT

**PolicyEngine v1.1.0 (ADR-043):**
- `_governance_config: dict` — lido do campo `governance:` de qualquer YAML em `data/policies/`
- `report_threshold` property: `max(floor, min(ceiling, raw))` com defaults `floor=0.50`, `ceiling=0.85`
- Fail-secure: YAML malformado → skip, `_governance_config` permanece `{}` → fallback `0.65`

**AbliterationDetector / IntegrityVerifier v1.1.0 (ADR-051 — sessão 2026-03-08 noturna):**
- `AbliterationDetector.__init__` aceita `policy_engine: Optional[PolicyEngine] = None`
- `_refusal_threshold`: lido de `model_integrity_refusal_threshold` do YAML; floor `0.50`, ceiling `0.95`; fallback `0.70`
- `_sample_size`: lido de `model_integrity_sample_size` do YAML; fallback `len(PROBE_PROMPTS)`
- `IntegrityVerifier.__init__` repassa `policy_engine` ao `AbliterationDetector`
- `verify_model_integrity()` API pública aceita `policy_engine` opcional
- `PROBE_PROMPTS` e `refusal_markers` permanecem constantes internas (dados sensíveis de segurança — nunca em YAML público)
- Blacklist/whitelist inalteradas; backward compat total

**Padrão YAML-driven threshold (consolidado — ADR-043 + ADR-051):**
```
default.yaml  governance:
  meu_threshold: X.XX
  meu_threshold_min: X.XX   ← floor
  meu_threshold_max: X.XX   ← ceiling

PolicyEngine._governance_config  ← lê automaticamente
↓
MeuComponente.__init__(policy_engine=None)
  → gc.get("meu_threshold", FALLBACK)
  → max(floor, min(ceiling, valor))
  → sem policy_engine → usa constante (backward compat)
```

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

### Policy-as-Code (data/policies/)

**governance_v1.yaml — regras ativas:**
- GOV-001: `composite_risk > 0.9` → BLOCK (Jonas)
- GOV-002: `composite_risk > 0.7` → ESCALATE/REPORT (Rawls, anotado ADR-043)
- GOV-003: PII detectado → REDACT (Levinas)
- GOV-004: Prompt injection → BLOCK (Jonas)
- GOV-005: Supply chain não verificada → BLOCK (Jonas)
- GOV-006: Goal drift crítico → BLOCK (Jonas)
- GOV-007: Persuasion attack → ESCALATE (Levinas)
- **GOV-008**: `composite_risk [0.65–0.90] + ALLOW + findings > 0` → REPORT (ADR-043)
  — `output_altered: false`, `contestable: true`, `escalates_to_human: true`

**default.yaml — 8 campos configuráveis em `governance:` (ADR-043 + ADR-051):**
```yaml
governance:
  report_threshold: 0.65          # EthicalContextEngine — floor 0.50 / ceiling 0.85
  report_threshold_min: 0.50
  report_threshold_max: 0.85
  report_sla_hours: 24            # Contestability SLA (ADR-017)
  model_integrity_refusal_threshold: 0.70   # AbliterationDetector — floor 0.50 / ceiling 0.95
  model_integrity_refusal_threshold_min: 0.50
  model_integrity_refusal_threshold_max: 0.95
  model_integrity_sample_size: 3  # Nº de probes por verificação
```

### Testes

- Rust: `cargo test --workspace` — 357+ testes
- Python: `pytest tests/ -v`
- E2E: `ops/e2e-tests.sh` — 27 testes (21 pass, 4 fail, 2 skip — mercy/compliance gaps conhecidos)
- Red-team: `ops/red-team/run-all.sh` — RT-001..RT-008

### ADRs (44 total)

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
| **N: Unified Verdict Identity** | **043** | ✅ **Implementado completo (Rust + Python + Policy + YAML-driven threshold)** |
| O: Effect + CoT Safety | 0048-0049 | ✅ Implementados (PROP-029, PROP-037) |
| P: Model Integrity Verifier | 051 | ✅ Fase 1 completa + thresholds YAML-driven (ADR-043 pattern) |
| Q: Model Integrity CI | 052 | ✅ Implementado (fail-secure UNKNOWN→BLOCK, blacklist Heretic +6, ops/ci_gate_g0.py) |

### Commits desta sessão (2026-03-08)

| Commit | Artefato |
|:---|:---|
| `61a81b9` | ConsentValidator + ConsentRevocationValidator (LGPD Art.7/Art.8§5) |
| `d7991cc` | PROJECT_CONTEXT.md v2.1.2 |
| `7ad82f3` | ADR-051 Model Integrity (documento) |
| `4e3500e` | `model_integrity.rs` BLAKE3 — ADR-051 Fase 1 |
| `45bdb8b` | ADR-043 Unified Verdict Identity (documento) |
| `5baf141` | `EthicalVerdict::Report=5` + `verdict_id` struct + `ActionType::Report=5` |
| `2228139` | `verdict_id` HMAC-SHA256 em `finalize()` + `validate()` + 7 testes |
| `038ac45` | `EthicalContextEngine v1.9.0` — emite `REPORT`, `report_triggered` |
| `a1adae8` | `GOV-008 REPORT` + `report_threshold=0.65` em policies YAML |
| `97d64c7` | PROJECT_CONTEXT.md v2.2.0 |
| `230b402` | `PolicyEngine._governance_config` + `report_threshold` property (floor/ceiling) + `EthicalContextEngine` aceita `policy_engine` opcional |
| `3eeac64` | **`AbliterationDetector._refusal_threshold` + `_sample_size` YAML-driven; `IntegrityVerifier` + `verify_model_integrity()` aceitam `policy_engine`** |

### Débitos Técnicos Ativos

| # | Débito | Prioridade | Estimativa |
|:---|:---|:---:|:---:|
| DT-001 | NHS/VAT/IBAN wired no Gatekeeper pipeline (Stage 3.5a) | ✅ Fechado v1.7.0 | — |
| DT-002 | `bias_guardian` tipado como `Any` no ethical_context_engine.py | ✅ Fechado — falso positivo (tipo correto) | — |
| DT-003 | ADR-036.md enum values minúsculas vs código maiúsculas | ✅ Fechado — falso positivo (ambos uppercase) | — |
| DT-004 | e2e mercy/compliance (4 fails) — schema mismatch governance | Média | 2-4h |
| DT-005 | `ethical_context_engine.py` excede 200 linhas | Média | Decomposição T1.3 |
| DT-006 | `bridge.rs` em bindings/ tem placeholder Gatekeeper (não usa real) | ✅ Fechado — falso positivo (já usa Gatekeeper real, v2.0) | — |
| DT-007 | Trait `Validator` legado coexiste com `Module` | ✅ Fechado v2.1.1 | — |

### Roadmap Pendente

| Item | Release | ADR |
|:---|:---:|:---:|
| ADR-051 Fase 2 — `abliteration_detector.py` refusal probe + LoRA scan | v1.7.0 | ADR-051 |
| ADR-051 Fase 3 — Contestability flow manifesto alternativo | v1.7.0 | ADR-051 |
| DT-004 — E2E 4 failures (mercy/compliance schema mismatch) | v1.6.0 | — |
| DT-005 — `ethical_context_engine.py` decomposição T1.3 | v1.6.0 | — |

### Anti-padrões Proibidos

- `.unwrap()` em lib code (usar `?` ou `expect` com mensagem)
- `.clone()` sem justificativa documentada
- `any` como type hint em Python (usar tipo concreto)
- `DefaultHasher` (usar BLAKE3)
- Heap allocations no hot path
- Lógica de negócio em `bindings/`
- Microserviços, gRPC, Node.js
- Singleton global em módulos Python de runtime (usar `IntegrityVerifier()` por chamada ou `Depends()` no FastAPI)
- Referência a 9596 ou 9600 bytes para TechnicalEvidence (valor correto: 9632, ver EVIDENCE_SIZE em core/types.rs)
- `lazy_static!` para patterns que podem usar `PatternRegistry` (ADR-033)
- Thresholds de risco hardcoded em Python (usar padrão YAML-driven — veja PolicyEngine._governance_config)

### Dependências Principais

**Rust (Cargo.toml workspace):**
blake3, arc_swap, whatlang, regex, lazy_static, static_assertions, phf, pyo3, serde, axum, tower-http, prometheus, reqwest, hmac, sha2, ring

**Python (pyproject.toml):**
fastapi, uvicorn, pyyaml, prometheus-client, httpx, pydantic, llama-cpp-python (optional)

---

### Próximos passos / Relacionados

- [Arquitetura (Atlas)](./ARCHITECTURE_ATLAS.md)
- [Índice de ADRs](./adr/0000-adr-index.md)
- [Handoff Templates](./HANDOFF_TEMPLATES.md)

---

<sub>[↑ Hub](./README.md) · [Trilha Engenheiro](./for-engineers.md) · [Trilha DPO/CISO](./for-dpo-ciso.md) · [Links de Referência](./reference-links.md)</sub>
