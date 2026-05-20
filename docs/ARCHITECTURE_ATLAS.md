[Docs](./README.md) · [Engenheiro](./for-engineers.md) › **Arquitetura**

![Engenheiro](https://img.shields.io/badge/Trilha-Engenheiro-1f6feb)

<!-- audience: engineer -->

---

# BuildToValue — Architecture Atlas & Vision (v3.0)

> **NOTA DE CONTEXTO:** Este documento contém a VISÃO COMPLETA do projeto (v1.0 até v3.0).
> O `README.md` na raiz reflete apenas o estado atual de implementação.
> O `PROJECT_CONTEXT.md` é a verdade técnica para a versão em desenvolvimento.
> Use este Atlas para decisões arquiteturais de longo prazo e compatibilidade futura.

---

## 📚 Hierarquia de Verdade (Ordem de Precedência)

| Prioridade | Documento | Função | Aviso |
|:---:|---|---|---|
| 1 | `docs/PROJECT_CONTEXT.md` | Verdade técnica absoluta | Fonte primária para código e estrutura |
| 2 | `docs/ARCHITECTURE_ATLAS.md` | Verdade arquitetural (visão v3.0) | Consultar para compatibilidade futura |
| 3 | `README.md` | Estado público atual | Deve refletir apenas o que existe |
| 4 | `documentacao.md` | Regras de negócio detalhadas | ⚠️ Paths e stack de rede OBSOLETOS |
| 5 | `documentacaoInicial.md` | Filosofia e missão (imutável) | ⚠️ IGNORE tecnologias e estrutura de pastas |

### Regras de Conflito

- **Estrutura de pastas** → `PROJECT_CONTEXT.md` vence sempre
- **Lógica de negócio** → `documentacao.md` pode ser consultado, adaptado ao Monolito Modular
- **Princípios éticos** → `documentacaoInicial.md` é canônico e imutável
- **Decisões futuras** → Este Atlas é referência, mas não autoriza implementação fora do roadmap

---

## 🗺️ Roadmap de Evolução Arquitetural

### FASE 1: Fundação + Model Integrity (Completa — v1.5 → v2.2)

- **Foco original (v1.5):** Determinismo, segurança de memória, ponte Rust↔Python funcional.
- **Tech:** Rust Kernel (`buildtovalue-kernel`), PyO3/Maturin (`rust/bindings/`), Evidence Protocol v2.1 (9596 bytes).
- **Infra:** Processo único, logs locais (WAL), FastAPI para API.
- **Entregáveis v1.5:** BiasDeclaration mandate, BatchProcessor, DurableLedger, 60+ testes.
- **Entregáveis v2.2 (model integrity):** PolicyEngine typed accessors (`ModelIntegrityConfig`, `AbliterationConfig`), `AbliterationDetector` v1.2.0 (probe_timeout_ms, threading+queue), `ManifestHashVerifier` v1.0.0 (SHA-256 fast-path), `IntegrityVerifier` v1.2.0 (cadeia Python→Rust), `data/policies/security/model_integrity.yaml` (Policy-as-Code), 39 testes Python governance.

### FASE 2: Expansão de Contexto e Governança (v1.6 — v1.9)

- **Foco:** Detecção avançada, governança ética runtime, observabilidade.
- **v1.6:** PolicyEngine (Rust), OutputGuard, Deobfuscator v2 (chaining).
- **v1.7:** IpClassifier, SessionDriftDetector, Interceptor, testes contextuais.
- **v1.8:** EthicalContextEngine (Python), MercyCalculator, ContestabilityLoop.
- **v1.9:** Axum Gateway (substitui FastAPI para serving), Prometheus, NATS JetStream (logs duráveis).
- **Infra:** Docker hardening (Distroless), distributed tracing.

### FASE 3: Inteligência Soberana (Futuro — v2.0+)

- **Foco:** Elucidação ética automatizada, compliance multi-framework, interface enterprise.
- **v2.0:** Intelligence Hub (MISP/STIX), Compliance Translator (PDF→YAML), Streamlit MVP.
- **Futuro (pós v2.0):** Local SLM (Phi-4 Mini via `llama-cpp-2`), Angular Enterprise Dashboard.
- **Infra:** Orquestração de recursos (CPU pinning, mmap para SLM), multi-tenant.

### FASE 4: Comunidade e Governança Aberta (2027)

- **Q3 2027:** Apache 2.0 release, 100+ stars, 10+ contributors, ISO 42001 assessment.
- **Q4 2027:** LF AI & Data Sandbox submission, 3+ co-submitting orgs.

---

## 📚 Catálogo Completo de ADRs

### Grupo A: Fundamentos Estabelecidos (ADR-001 a ADR-009)

| ID | Título | Status | Versão | Resumo |
|:---|:---|:---|:---|:---|
| **001** | Hybrid Architecture | ✅ Ativo | v1.0 | Rust = Fatos Técnicos, Python = Julgamentos Éticos. Ponte via PyO3. |
| **002** | Evidence Protocol v1.0 | ⛔ Obsoleto | v1.0 | Substituído por ADR-005 (v2.1). |
| **003** | Mercy Algorithm | ✅ Ativo | v1.0 | Gilligan: uncertainty > 0.7 + trust > 0.6 + critical == 0 → abrandar. |
| **004** | Immutable Ledger | ✅ Ativo | v1.0 | WAL + BLAKE3 chain. Sync remoto via S3 (ADR-007). |
| **005** | Evidence Protocol v2.1 | ✅ Ativo | v1.5 | TechnicalEvidence: 9596 bytes fixos, BLAKE3, ring buffer [10]+[3]. |
| **006** | Policy-as-Code | ✅ Ativo | v1.0 | YAML versionado, herança hierárquica, blind testing (Rawls). |
| **007** | Remote Sync (S3) | ✅ Ativo | v1.5 | S3 upload real com retry (3x, backoff exp.), DLQ, idempotência. |
| **008** | Timing Mitigation | ✅ Ativo | v1.0 | Validadores constant-time para evitar side-channel leaks. |
| **009** | Modular Monolith | ✅ Ativo | v3.0 | Processo único, módulos lógicos. Sem microserviços/gRPC/Node.js. |

### Grupo B: v1.5 — Evidence & Transparency (ADR-010)

| ID | Título | Status | Versão | Resumo |
|:---|:---|:---|:---|:---|
| **010** | BiasDeclaration Mandate | 🚧 Em Implementação | v1.5 | `bias_declaration()` obrigatório em todo Validator. FPR/FNR + calibration_date. |

### Grupo C: v1.6 — Policy & Output (ADR-011 a ADR-013)

| ID | Título | Status | Alvo | Resumo |
|:---|:---|:---|:---|:---|
| **011** | PolicyEngine (Rust) | 🔒 Planejado | v1.6 | YAML → runtime. `phf` para hard blocks O(1). Pattern matching regex pré-compilado. |
| **012** | OutputGuard | 🔒 Planejado | v1.6 | PII masking em respostas de agentes. Re-scan após sanitização. |
| **013** | Deobfuscator v2 (Chaining) | 🔒 Planejado | v1.6 | Cadeia base64→hex→leet, max 3 layers. Overhead máx 5ms. 3 falhas = critical. |

### Grupo D: v1.7 — Context (ADR-014 a ADR-015)

| ID | Título | Status | Alvo | Resumo |
|:---|:---|:---|:---|:---|
| **014** | IpClassifier + SessionDrift | 🔒 Planejado | v1.7 | Tor/VPN/datacenter detection. Cosine similarity para drift comportamental. |
| **015** | Interceptor (Pre/Post Hooks) | 🔒 Planejado | v1.7 | Trait `RequestInterceptor` + `ResponseInterceptor`. Chain ordenada, fail-secure. |

### Grupo E: v1.8 — Governance (ADR-016 a ADR-017)

| ID | Título | Status | Alvo | Resumo |
|:---|:---|:---|:---|:---|
| **016** | EthicalContextEngine v4.0 | 🔒 Planejado | v1.8 | Fluxo completo: Rawls → Levinas → Jonas → Gilligan. `explain_decision()` obrigatório. |
| **017** | ContestabilityLoop (SLA 24h) | 🔒 Planejado | v1.8 | Submit → Status → Resolve. Feedback loop: appeals bem-sucedidas melhoram sistema. |

### Grupo F: v1.9 — API & Observability (ADR-018 a ADR-019)

| ID | Título | Status | Alvo | Resumo |
|:---|:---|:---|:---|:---|
| **018** | Axum Gateway | 🔒 Planejado | v1.9 | Substitui FastAPI para HTTP serving. `rust/gateway/` (único crate novo). Tokio runtime. |
| **019** | Observability (Prometheus + Tracing) | 🔒 Planejado | v1.9 | Métricas Prometheus, W3C Trace Context. Kernel + Governance. |

### Grupo G: v2.0 — Intelligence & Compliance (ADR-020 a ADR-022)

| ID | Título | Status | Alvo | Resumo |
|:---|:---|:---|:---|:---|
| **020** | Intelligence Hub (MISP/STIX) | 🔒 Planejado | v2.0 | Threat intel ingest → auto-policy generation. |
| **021** | Compliance Translator | 🔒 Planejado | v2.0 | PDF regulations → YAML policies via LLM. Multi-framework (LGPD, GDPR, EU AI Act). |
| **022** | Frontend MVP | 🔒 Planejado | v2.0 | Streamlit para MVP. Angular Enterprise é meta pós-v2.0. |

### Grupo H: v2.1 — Multi-lang, Red-team e Gateway (ADR-023 a ADR-041)

Todos implementados em `v2.1`. Documentação formal em `docs/adr/`.

| Faixa | Scope | Status |
|:---|:---|:---|
| ADR-023–026 | Gap Implementation: Appeals HTTP, Threat→Policy, Ledger Query, Webhooks | ✅ Ativo |
| ADR-028 | Prompt Injection Detector (3-layer: regex+structural+cross-signal) | ✅ Ativo |
| ADR-029–031 | Integrations: External Agent PDP, Internal LLM, External LLM | ✅ Ativo |
| ADR-032–035 | Multi-lang: ScanContextFlags, PatternRegistry, Language Detection, Multi-jurisdiction PII | ✅ Ativo |
| ADR-036–039 | Red-team & Gov: BiasGuardian, AppealEngine v2, ECE v4, TrustScore v2 | ✅ Ativo |
| ADR-040–041 | Gateway & Obs v2: Gateway extensions, República metrics | ✅ Ativo |

### Grupo I: v2.2 — Model Integrity Governance (ADR-042, ADR-049, ADR-051)

Implementados em `v2.2` (commit `8ee8994`, março 2026). **39 testes Python**, 0 regressões.

| ID | Título | Status | Versão | Resumo |
|:---|:---|:---|:---|:---|
| **042** | PolicyEngine — Model Integrity typed accessors | ✅ Ativo | v2.2 | `ModelIntegrityConfig` + `AbliterationConfig` frozen dataclasses. `abliteration_threshold` clamped `[min, max]`. `manifest_path_for(model_id)`. `data/policies/security/model_integrity.yaml` (Policy-as-Code). rglob YAML discovery. |
| **049** | IntegrityVerifier | ✅ Ativo | v2.2 | Orquestra: `ManifestHashVerifier` (Python SHA-256) → blacklist → whitelist → `AbliterationDetector`. Cadeia de responsabilidade Python→Rust (Jonas). `verify()` retorna `bool` fail-secure. |
| **051** | AbliterationDetector Fase 2 | ✅ Ativo | v2.2 | 8 probes calibradas: 5 HARMFUL + 3 BENIGN. Refusal probe via NLP regex (12 padrões). `probe_timeout_ms` enforçado via `threading.Thread + queue.Queue` (cross-platform). Timeout = recusa implícita (Jonas: fail-secure). |

### Grupo J: Pós-v2.0 — Visão de Longo Prazo (Não numerados)

Estas decisões **não têm ADR formal** e só serão formalizadas quando entrarem no roadmap ativo.

| Tema | Alvo | Notas |
|:---|:---|:---|
| Local SLM (Phi-4 Mini) | Pós-v2.0 | `llama-cpp-2`, GGUF Q4_K_M, CPU-only, mmap. Privacidade total. |
| Angular Enterprise Dashboard | Pós-v2.0 | Substitui Streamlit. Multi-tenant, XSS/CSP nativo. |
| NATS JetStream (full) | v1.9+ | Logs duráveis com criptografia em repouso. Complementa S3 (ADR-007). |
| Hardened Container (Distroless) | v1.9+ | Dockerfile 4 estágios. Non-root, sem compiladores na imagem final. |
| Zero-Knowledge Proofs | Pós-v2.0 | Validar permissão sem revelar identidade. Conceito exploratório. |
| Verificação Formal (Kani/Prusti) | Pós-v2.0 | Provas matemáticas de ausência de panic no Kernel. |
| Rust BLAKE3 weights verification | v2.3 | Full weights hash check via Rust kernel (ADR-005 integration). Complementa ManifestHashVerifier (SHA-256 manifesto). |

---

## 🔍 Detalhamento dos ADRs Críticos

### ADR-005: Evidence Protocol v2.1 (Ativo)

O coração forense do sistema. Cada scan produz exatamente 9596 bytes.
```
TechnicalEvidence (9596 bytes)
├── Header (64B): version, audit_trail_id, timestamp, evidence_hash, composite_risk
├── Findings normais (1280B): Ring buffer [Finding; 10] × 128B
├── Findings críticos (384B): [Finding; 3] preservados (nunca sobrescritos)
├── Statistics (256B): Entropy, Z-Score, CharRatio agregados
├── BiasDeclaration (512B): FPR, FNR, calibration_date, known_limitations
├── Metadata (7092B): request_hash, input_size, executed_modules, processing_time
└── Checksum (8B): BLAKE3 de toda a struct
```

**Invariantes:** Zero heap no hot path. `size_of::<TechnicalEvidence>()` é assert estático. Hash BLAKE3 (nunca SHA-256 ou DefaultHasher).

### ADR-007: Remote Sync via S3 (Ativo)

Resolve a promessa de 99.99% durabilidade do Ledger.
```
Entry → WAL (RAM, <1ms) → Disk (SSD, <5ms) → S3 (async, <10ms)
                                                ├─ Retry 1 (100ms)
                                                ├─ Retry 2 (200ms)
                                                ├─ Retry 3 (400ms)
                                                └─ DLQ (se falhar)
```

Key format: `{prefix}/{year}/{month}/{day}/{entry_id:08x}.bin` — idempotente (mesmo entry_id = mesma chave S3).

### ADR-009: Modular Monolith (Ativo)

Decisão reconciliada v2.2→v3.0. Estrutura física preservada:
```
rust/kernel/         → buildtovalue-kernel (crate único, módulos internos)
rust/bindings/       → buildtovalue-bindings (PyO3/Maturin)
rust/cli/            → buildtovalue-cli
rust/gateway/        → btv-gateway (v1.9+ APENAS, único crate novo)
python/buildtovalue/ → Namespace hierárquico (governance/, compliance/, etc.)
```

**Rejeitado:** 7 crates `btv-*` separados (overhead CI/CD, namespace break, rewrite risk).

### ADR-010: BiasDeclaration Mandate (Em Implementação)

Todo Validator, StatisticsModule e DeobfuscatorModule deve implementar `bias_declaration()`:
```rust
fn bias_declaration(&self) -> BiasDeclaration {
    BiasDeclaration {
        false_positive_rate: u8,     // 0-255 (resolução ~0.4%)
        false_negative_rate: u8,     // 0-255
        calibration_date: u32,       // YYYYMMDD (< 90 dias validade)
        known_limitations: [u8; 128] // null-padded string
    }
}
```

Gatekeeper agrega: max(FPR), max(FNR), min(calibration_date) — worst-case de todos os módulos executados.

**Filosofia (Jonas):** Ocultar margem de erro viola responsabilidade proporcional. BiasDeclaration é o "rótulo nutricional" do sistema.

### ADR-042: PolicyEngine typed accessors + ManifestHashVerifier (Ativo v2.2)

Cadeia de verificação de integridade de modelos AI: Python SHA-256 fast-path → Rust BLAKE3 full-path.

**Policy-as-Code (`data/policies/security/model_integrity.yaml`):**
```yaml
governance:
  model_integrity:
    verification_enabled: true
    block_on_failure: true       # Jonas: fail-secure
    models:
      phi-3-mini-v1:
        manifest_path: "data/manifests/phi-3-mini-v1.json"
        expected_hash_env: "BTV_PHI3_MANIFEST_HASH"
  abliteration:
    refusal_threshold: 0.6       # clamped [min=0.4, max=0.9]
    probe_timeout_ms: 5000
```

**Fluxo `IntegrityVerifier.verify(model_id)` — 5 estágios:**
```
1. ManifestHashVerifier.verify()  ← SHA-256 manifesto JSON    (Python, <1ms)
2. is_known_abliterated()         ← blacklist lookup           (Python, <1ms)
3. get_model_info() whitelist     ← registry fast-path         (Python, <1ms)
4. AbliterationDetector.detect()  ← behavioral probe (opt.)   (Python, timeout-bound)
5. Rust kernel BLAKE3             ← full weights hash          (planned v2.3)
```

**6 caminhos auditados em `ManifestHashVerifier.verify()` (Rawls: blind equality):**

| # | Condição | Resultado |
|:--|:--|:--|
| 1 | `verification_enabled=False` | `is_valid=True`, skip (warn log) |
| 2 | `manifest_path` não configurado | `_resolve_on_failure` |
| 3 | Env var ausente | `_resolve_on_failure` |
| 4 | Arquivo não encontrado | `is_valid=False` (fail) |
| 5 | Hash SHA-256 match | `is_valid=True` |
| 6 | Hash mismatch | `is_valid=False` (MODEL_INTEGRITY_HASH_MISMATCH) |

`_resolve_on_failure`: `block_on_failure=True` → fail; `False` → warn + pass.

**Invariantes (Jonas + Levinas):** `explain_decision()` obrigatório em todos os caminhos. `ManifestVerificationResult` frozen (imutável após construção). SHA-256 normalizado lowercase (case-insensitive comparison).

**`AbliterationDetector` v1.2.0 — probe timeout (ADR-051):**
```
probe_with_fn(model_id, response_fn)
  │ timeout_s = probe_timeout_ms / 1000.0
  └─ para cada probe:
       threading.Thread(target=response_fn, daemon=True).start()
       queue.Queue.get(timeout=timeout_s)
       queue.Empty → "" (fail-secure: timeout = recusou)
```

Timeout = recusa implícita (Jonas): modelo sem safety rails responde *rápido*; modelo lento/suspenso é tratado como alinhado para fins de safety check. Disponibilidade é verificada por mecanismo separado.

---

## 🧠 Fundamentos Filosóficos (Imutáveis)

Estes princípios são a Constituição da República Algorítmica. Não mudam entre versões.

| Filósofo | Princípio | Implementação |
|:---|:---|:---|
| **Rawls** (1971) | Justiça como equidade | Blind Policy Testing: avaliar sem saber se é autor, alvo ou auditor. Princípio da Diferença: favorecer continuidade em alta incerteza. 8 probes idênticas para todos os modelos (AbliterationDetector). |
| **Levinas** (1961) | Dever de cuidado | Fail-secure: erros protegem o usuário (BLOCK, não bypass). Educar antes de punir (EDUCATE → BLOCK). `explain_decision()` obrigatório em todos os resultados. |
| **Gilligan** (1982) | Ética do cuidado | Misericórdia algorítmica: uncertainty > 0.7 + trust > 0.6 + critical == 0 → abrandar. Contexto > regra rígida. |
| **Jonas** (1984) | Responsabilidade proporcional | BiasDeclaration obrigatório. Ledger imutável. Cada decisão assinada (HMAC-SHA256). Auditoria externa. `block_on_failure=True`. Cadeia de responsabilidade Python→Rust para integridade de modelos. |

---

## 🔮 Diretriz para Compatibilidade Futura

Ao implementar features, a Squad deve garantir:

1. **Interfaces limpas:** Traits de validação devem aceitar extensão sem quebrar assinatura. Novos módulos (v1.6+) plugam no Gatekeeper sem alterar os existentes.

2. **Separação Kernel↔Governance:** Nenhuma lógica ética em Rust. Nenhuma lógica de detecção em Python. A ponte FFI (PyO3) é o único ponto de contato.

3. **Evidence extensível:** Os 7000 bytes de `_reserved_metadata` em TechnicalEvidence existem para módulos futuros (Network, SessionGuard, PolicyEngine) sem alterar o tamanho total.

4. **Ledger preparado para NATS:** O `DurableLedger` atual (WAL + S3) deve usar uma trait `LedgerBackend` que permita plugar NATS JetStream na v1.9 sem rewrite.

5. **Sem dependências prematuras:** Não importar crates/libs que só serão necessários em versões futuras. Cada versão deve compilar com o mínimo necessário.

6. **ManifestHashVerifier extensível:** Interface `verify(model_id, policy_engine)` aceita novos campos em `ModelConfig` sem quebrar callers. SHA-256 é substituível por BLAKE3 Python (`blake3` crate) sem alterar contrato.

---

## 📊 Compliance Roadmap (Multi-Framework)

Baseado nas análises ISO 42001, NIST CSF e EU AI Act realizadas em fevereiro 2026:

| Framework | Score Atual | Alvo | Gaps Críticos |
|:---|:---|:---|:---|
| ISO 42001 | 78% (Silver) | Gold (Q3 2027) | SoA formal, AI Impact Assessment, Competence docs, Incident Comm. Plan |
| NIST CSF 2.0 | ~70% | 85% (Q2 2027) | Supply chain risk, formal recovery testing, external audit |
| EU AI Act | ~40% | 80% (Q3 2026) | Prohibited Practices Detector (⚠️ Art.5 já em vigor), Risk Classification, FRIA, Conformity Assessment |

**Prioridade:** EU AI Act Art. 5 (práticas proibidas) está em vigor desde fev/2025. Art. 4 (literacia IA) idem. Maioria dos requisitos high-risk aplica-se a partir de ago/2026 (~6 meses).

**Model Integrity como requisito de compliance:** `ManifestHashVerifier` + `AbliterationDetector` contribuem diretamente para EU AI Act Art. 9 (Risk Management) e ISO 42001 §6.1 (AI risk assessment).

**Arquitetura de compliance:** Runtime Engine é único. Cada framework gera artefatos diferentes via plugins `CompliancePlugin`:
```python
class CompliancePlugin(Protocol):
    def framework_id(self) -> str: ...
    def generate_artifacts(self, evidence, verdict) -> list[ComplianceArtifact]: ...
    def validate_requirements(self) -> ComplianceReport: ...
```

---

## ⚠️ Headers de Aviso para Documentos Legados

### Para `documentacaoInicial.md`
```
┌─────────────────────────────────────────────────────────────┐
│ Status: 🏛️ Manifesto Filosófico (Imutável)                 │
│ Como usar: APENAS para princípios éticos e missão.          │
│ Aviso: IGNORE tecnologias e estrutura de pastas.            │
│ Este é o documento de fundação (v1.0).                      │
└─────────────────────────────────────────────────────────────┘
```

### Para `documentacao.md`
```
┌─────────────────────────────────────────────────────────────┐
│ Status: 📚 Referência Lógica (Legado)                       │
│ Como usar: Regras de negócio, algoritmos, specs de          │
│ conformidade (LGPD/AI Act).                                 │
│ Aviso: Estrutura física (src/, gRPC, Node.js) OBSOLETA.     │
│ Se conflitar com PROJECT_CONTEXT.md → PROJECT_CONTEXT vence.│
│ Se conflitar em lógica → adaptar ao Monolito Modular.       │
└─────────────────────────────────────────────────────────────┘
```

---

*Última atualização: 09 de março de 2026*
*Versão do Atlas: 2.0 (sincronizado com v2.2 — ADR-042/049/051 Model Integrity Governance)*

---

### Próximos passos / Relacionados

- [Conceitos](./concepts.md)
- [Índice de ADRs](./adr/0000-adr-index.md)
- [Changelog](./changelog.md)

---

<sub>[↑ Hub](./README.md) · [Trilha Engenheiro](./for-engineers.md) · [Trilha DPO/CISO](./for-dpo-ciso.md) · [Links de Referência](./reference-links.md)</sub>
