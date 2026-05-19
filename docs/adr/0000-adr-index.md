Aqui está o arquivo completo atualizado:

***

# ADR-0000: Architecture Decision Record Index

**Status:** 🟢 ATIVO (Documento Vivo)
**Última Atualização:** 09 de março de 2026
**Escopo:** BuildToValue v1.0 → v3.0

***

## 📖 Como usar este Índice

Este catálogo documenta todas as decisões arquiteturais significativas (ADRs) tomadas no projeto.

* **Status:** ✅ Ativo (Vigente), 🚧 Em Implementação, 🔒 Planejado (Futuro), ⛔ Obsoleto (Histórico), 🔮 Visão (sem spec detalhada ainda).
* **Versão:** Indica em qual release a decisão foi ou será implementada.

> **Nota para Desenvolvedores:**
> Antes de iniciar qualquer feature, verifique se existe um ADR correspondente.
> Se o código desviar do ADR, o Pull Request será rejeitado. Para propor
> mudanças, crie um novo ADR e submeta para aprovação do Staff Engineer.

***

## 🏗️ Grupo A: Fundamentos Arquiteturais (Core)

*Decisões estruturais que definem "o que é" o sistema.*

| ID | Título | Status | Versão | Link | Resumo |
|:---|:---|:---:|:---:|:---|:---|
| **0001** | **Hybrid Architecture** | ✅ Ativo | v1.0 | [Ver Detalhes](./0001-hybrid-architecture.md) | Rust (Fatos) + Python (Valores). Ponte via PyO3. |
| **0002** | **Evidence Protocol v1.0** | ⛔ Obsoleto | v1.0 | [Ver Detalhes](./0002-evidence-protocol-v1-obsolete.md) | Tentativa inicial com heap allocation (falhou). Substituído por ADR-0005. |
| **0003** | **Mercy Algorithm** | ✅ Ativo | v1.0 | [Ver Detalhes](./0003-mercy-algorithm.md) | Lógica de Gilligan: Contexto > Regra Rígida. mercy_score > 0.5 → EDUCATE. |
| **0004** | **Immutable Ledger** | ✅ Ativo | v1.0 | [Ver Detalhes](./0004-immutable-ledger.md) | BLAKE3 Chain multi-camada (WAL→Disk→Remote). NATS JetStream na v3.0. |
| **0005** | **Evidence Protocol v2.1** | ✅ Ativo | v1.5 | [Ver Detalhes](./0005-evidence-protocol-v2-fixed-size.md) | Struct fixo de 9596 bytes. Zero-heap no hot path. Ring buffer FIFO. |
| **0006** | **Policy-as-Code** | ✅ Ativo | v1.0 | [Ver Detalhes](./0006-policy-as-code.md) | YAML versionado com herança hierárquica. Blind Policy Testing (≥95%). |
| **0007** | **Trust Score Algorithm** | ✅ Ativo | v2.0 | [Ver Detalhes](./0007-trust-score-algorithm.md) | Algoritmo multifatorial: base + history + appeals + decay + consistency. |
| **0008** | **Timing Mitigation** | ✅ Ativo | v1.0 | [Ver Detalhes](./0008-side-channel-timing-mitigation.md) | Constant-time validators. ORAM blacklist lookup. T-test p=0.67. |
| **0009** | **Modular Monolith** | ✅ Ativo | v3.0 | [Ver Detalhes](./0009-modular-monolith-pivot.md) | Estrutura v2.2 preservada. `rust/gateway/` único crate novo (v1.9+). |

***

## 🧠 Grupo B: Governança & Transparência (v1.5 – v1.8)

*Decisões sobre ética, explicabilidade e confiança.*

| ID | Título | Status | Versão | Link | Resumo |
|:---|:---|:---:|:---:|:---|:---|
| **0010** | **Bias Declaration Mandate** | 🚧 Impl. | v1.5 | [Ver Detalhes](./0010-bias-declaration-mandate.md) | Todo `Validator` deve declarar FPR/FNR (Jonas). `bias_declaration()` obrigatório no trait. |
| **0016** | **Ethical Context Engine v4** | ✅ Futuro | v1.8 | [Ver Detalhes](./0016-ethical-context-engine-v4.md) | Pipeline ético completo (Rawls→Levinas→Jonas→Gilligan). `explain_decision()` obrigatório. |
| **0036** | **Red-team Formal e Bias Guardian** | ✅ Planejado | v1.7.0 | [Ver Detalhes](./0036-redteam-bias-guardian.md) | Protocolo formal de red-team com cadência CI obrigatória. `BiasGuardian` Python verifica divergência FPR/FNR declarado vs medido. Thresholds: warning 5pp / block 15pp (FNR). Fecha loop de ADR-010. |
| **0038** | **EthicalContextEngine v4.0 — Pipeline Filosófico Explícito** | ✅ Planejado | v1.8.0 | [Ver Detalhes](./0038-ethical-context-engine-v4.md) | 4 estágios nomeados: Rawls→Levinas→Jonas→Gilligan. `ExplainDecision` estruturado (EU AI Act Art. 13). `pipeline_trace` auditável. Integração AppealEngine. Substitui esboço ADR-016. |
| **0039** | **TrustScoreCalculator v2.0** | ✅ Planejado | v1.8.0 | [Ver Detalhes](./0039-trust-score-calculator-v2.md) | Fórmula 5 componentes (ADR-007) com TrustStore Protocol (InMemory\|SQLite\|Redis-ready). Fix decay overflow. `adjust()` para AppealEngine (+0.1/−0.05). `TrustExplain` estruturado. Substitui esboço ADR-007. |

***

## 🛡️ Grupo C: Segurança & Detecção Avançada (v1.6 – v2.2)

*Decisões para combater evasão, ataques e vazamento de dados.*

| ID | Título | Status | Versão | Link | Resumo |
|:---|:---|:---:|:---:|:---|:---|
| **0011** | **Policy Engine Design** | ✅ Futuro | v1.6 | [Ver Detalhes](./0011-policy-engine.md) | Compilação de YAML para Runtime Rust (phf). Lookup O(1) para Hard Blocks. |
| **0012** | **Output Guard** | ✅ Futuro | v1.6 | [Ver Detalhes](./0012-output-guard.md) | Sanitização de PII nas respostas da IA antes de entregar ao usuário. |
| **0013** | **Deobfuscator Chain v2** | ✅ Futuro | v1.6 | [Ver Detalhes](./0013-deobfuscator-chaining-v2.md) | Loop de decodificação (max 3 níveis) anti-evasão. CRITICAL_RISK após 3 tentativas. |
| **0014** | **IP & Session Drift** | ✅ Futuro | v1.7 | [Ver Detalhes](./0014-ip-classifier-session-drift.md) | Classificação de origem (Tor/VPN). Cosseno de similaridade → IdentityChallenge. |
| **0015** | **Interceptor Hooks** | ✅ Futuro | v1.7 | [Ver Detalhes](./0015-interceptor-hooks.md) | Traits `RequestInterceptor`/`ResponseInterceptor`. Chain of Responsibility + fail-secure. |
| **0028** | **Heuristic Prompt Injection Detector** | ✅ Ativo | v2.2 | [Ver Detalhes](./0028-heuristic-prompt-injection-detector.md) | Detecção heurística de prompt injection sem ML. Padrões PTBR + EN. Integra Gate 3 de RAG. |

***

## 🔮 Grupo D: Visão de Longo Prazo

*Conceitos aprovados sem especificação técnica detalhada ou com ADR formal em andamento.*

| ID | Título | Status | Alvo | Resumo |
|:---|:---:|:---:|:---:|:---|
| **0027** | **Local SLM Strategy** | 🔒 Futuro | v2.1 | Phi-4 Mini local via `btv-slm` (mmap, CPU-only). ADR formal criado. Ver Grupo H. |
| **---** | **Angular Dashboard** | 🔮 Visão | v3.0+ | Interface Enterprise para gestão de políticas e contestabilidade. |
| **---** | **NATS JetStream** | 🔮 Visão | v1.9+ | Logs duráveis e mensageria assíncrona. Alternativa ao S3 (ver ADR-004 Emenda v3.0). |

***

## 🏛️ Grupo E: Governance (v1.8)

*Contestabilidade, appeals e ciclo de feedback ético.*

| ID | Título | Status | Versão | Link | Resumo |
|:---|:---|:---:|:---:|:---|:---|
| **0017** | **Contestability Loop** | ✅ Ativo | v1.8 | [Ver Detalhes](./0017-contestability-loop.md) | Appeals HTTP: submit, status, resolve. SLA 24h. Levinas. Trust score feedback. |
| **0037** | **Contestability Loop — AppealEngine v2.0 + SLA 24h Enforcement** | 🔒 Planejado | v1.8.0 | [Ver Detalhes](./0037-contestability-loop-appeal-engine.md) | Judiciário de segundo grau. HMAC verify antes de aceitar appeal. SLAMonitor worker ativo (Jonas). Trust bidirecional: +0.1 aceito / −0.05 rejeitado (Gilligan). Toda appeal no Ledger. Substitui esboço ADR-017. |

***

## 🌐 Grupo F: API & Observability (v1.9 – v2.0)

*Gateway, métricas, endpoints públicos e notificações.*

| ID | Título | Status | Versão | Link | Resumo |
|:---|:---|:---:|:---:|:---|:---|
| **0018** | **Axum Gateway** | ✅ Ativo | v1.9 | [Ver Detalhes](./0018-axum-gateway.md) | Gateway HTTP Rust. Orquestra kernel + governance. Latência 6–18ms observada. |
| **0019** | **Observability** | ✅ Ativo | v1.9 | [Ver Detalhes](./0019-observability.md) | Prometheus + Grafana. 7 famílias de métricas. Scrape 5s. |
| **0023** | **Appeals HTTP Endpoint** | ✅ Ativo | v2.0 | [Ver Detalhes](./0023-appeals-http-endpoint.md) | Expõe ContestabilityLoop via 5 endpoints REST. LGPD Art. 20 + EU AI Act Art. 86. |
| **0025** | **Ledger Query API** | ✅ Ativo | v2.1 | [Ver Detalhes](./0025-ledger-query-api.md) | API de consulta ao DurableLedger por `evidence_id`, janela temporal e `agent_id`. |
| **0026** | **Webhook Notifications** | ✅ Futuro | v2.1 | [Ver Detalhes](./0026-webhook-notifications.md) | Notificações push para eventos de BLOCK, appeal e deploy. Payload HMAC-assinado. |
| **0040** | **Axum Gateway v2.0 — Extensões República Algorítmica** | ✅ Planejado | v1.9.0 | [Ver Detalhes](./0040-axum-gateway-v2-extensions.md) | +3 rotas: /v1/decide, /v1/appeals (proxy), /health/bias. Rate limit per-tenant (BLAKE3 hash). X-BTV-Jurisdiction → jurisdiction_bitmask. Estende ADR-018. |
| **0041** | **Observability v2.0 — Métricas da República Algorítmica** | ✅ Planejado | v1.9.0 | [Ver Detalhes](./0041-observability-v2-republic-metrics.md) | +17 métricas: pipeline filosófico por estágio, SLA compliance rate, BiasDeclaration divergência em tempo real, mercy scenarios. 5 alerting rules. Dashboard Grafana 4 poderes. Estende ADR-019. |

***

## 🧠 Grupo G: Intelligence & Compliance (v2.0 – v2.1)

*Inteligência de ameaças, plugins de compliance e dashboards.*

| ID | Título | Status | Versão | Link | Resumo |
|:---|:---|:---:|:---:|:---|:---|
| **0020** | **Intelligence Hub** | ✅ Ativo | v2.0 | [Ver Detalhes](./0020-intelligence-hub.md) | Threat feed MISP/STIX. SQLite + BLAKE2b. Endpoints ingest/query/stats. |
| **0021** | **Compliance Plugins** | ✅ Ativo | v2.0 | [Ver Detalhes](./0021-compliance-plugins.md) | Plugin architecture. LGPD (Art. 6, 18, 20, 46, 48) + EU AI Act (Art. 5, 9, 13, 14, 15). |
| **0022** | **Streamlit Dashboard** | ✅ Ativo | v2.0 | [Ver Detalhes](./0022-streamlit-dashboard.md) | MVP visual. 6 pages. Democratiza acesso. Angular Enterprise planejado para v3.0+. |
| **0024** | **Threat→Policy Bridge** | ✅ Ativo | v2.1 | [Ver Detalhes](./0024-threat-policy-bridge.md) | MispIngestor→ThreatClassifier→PolicyGenerator. `enabled: false` + human-in-the-loop obrigatório. |

***

## 🤖 Grupo H: Local Intelligence (v2.1)

*Inferência local com modelos de linguagem leves, sem dependência de vendor.*

| ID | Título | Status | Versão | Link | Resumo |
|:---|:---|:---:|:---:|:---|:---|
| **0027** | **Local SLM Strategy** | ✅ Futuro | v2.1 | [Ver Detalhes](./0027-local-slm-strategy.md) | Phi-4 Mini via `btv-slm` (mmap, CPU-only, zero GPU). Contexto de governança local sem vendor. Alternativa soberana ao vendor externo. |

***

## 🔗 Grupo I: Integrações de Agentes IA (v2.0+)

*Contratos e perfis para integração de agentes externos com o BTV como PDP.*
*Leia ADR-0029 (contrato canônico) antes de ler qualquer perfil de integração.*

| ID | Título | Status | Versão | Link | Resumo |
|:---|:---|:---:|:---:|:---|:---|
| **0029** | **External Agent PDP** | 🔒 Proposto | v2.0 | [Ver Detalhes](./0029-external-agent-pdp.md) | Contrato canônico para qualquer agente externo usar o BTV como Policy Decision Point. `AgentDecisionRequest` / `VerdictEnvelope` / `ActionImpact`. Base de todos os perfis de integração. |
| **0030** | **Chatbot — LLM Self-Hosted** | 🔒 Proposto | v2.0 | [Ver Detalhes](./0030-internal-chatbot-selfhosted-llm.md) | Perfil de integração BTV para chatbot com Llama 70B/vLLM. 5 gates: mensagem, indexação, RAG, training batch, LoRA deploy (`Irreversible`). Evidence LGPD. BiasDeclaration em treino. |
| **0031** | **Chatbot — LLM Vendor Externo** | ✅ Proposto | v2.0 | [Ver Detalhes](./0031-external-chatbot-vendor-llm.md) | Delta do ADR-0030 para vendors externos (OpenAI, Anthropic, Google, Azure). Toda mensagem é `Irreversible`. `/v1/sanitize` obrigatório antes de cada envio. Gate de aprovação de vendor por `sector_id`. LGPD Art. 33. |

***

## 📐 Grupo J: v1.6 — Multilingual & Multi-tenant Foundation (ADR-0032 a ADR-0035)

| ID | Título | Status | Versão | Link | Resumo |
|:---|:---|:---:|:---:|:---|:---|
| **0032** | **ScanContextFlags** | 🚧 Impl. | v1.6.0 | [Ver Detalhes](./0032-scan-context-flags.md) | Substitui `_reserved: [u8; 64]` por struct nomeado de 64 bytes exatos. Fundação para language detection, jurisdição, capability mask e multi-tenant. |
| **0033** | **PatternRegistry (Tier 0/1/2)** | ✅ Planejado | v1.6.0 | [Ver Detalhes](./0033-pattern-registry-tiers.md) | Substitui lazy_static por 3 tiers: Tier 0 hardcoded, Tier 1 build-time YAML, Tier 2 runtime ArcSwap. Epoch versionado para auditoria forense. |
| **0034** | **Language Detection Strategy** | ✅ Planejado | v1.6.1 | [Ver Detalhes](./0034-language-detection-strategy.md) | whatlang-rs no Stage 1 do pipeline. Preenche `lang_bitmask` e `lang_scores` em ScanContextFlags. Threshold 0.75 + min 20 chars. Inputs ambíguos → undetermined → apenas Tier 0. |
| **0035** | **Multi-jurisdiction PII Validators** | ✅ Planejado | v1.7.0 | [Ver Detalhes](./0035-multi-jurisdiction-pii-validators.md) | NHS Number (Mod 11), EU VAT (DE/FR/IT/ES/PT), IBAN (Mod 97). Dispatcher por `jurisdiction_bitmask`. Novos `ValidatorModule` entries. |

***

## 🔐 Grupo K: v2.2 — Model Integrity Governance (ADR-0042, ADR-0049, ADR-0051)

*Verificação de integridade de modelos AI: cadeia Python SHA-256 fast-path → Rust BLAKE3 full-path. Implementado em commit `8ee8994`, março 2026. 39 testes Python, 0 regressões.*

| ID | Título | Status | Versão | Link | Resumo |
|:---|:---|:---:|:---:|:---|:---|
| **0042** | **PolicyEngine — Model Integrity typed accessors** | ✅ Ativo | v2.2 | [Ver Detalhes](./0042-policy-engine-model-integrity.md) | `ModelIntegrityConfig` + `AbliterationConfig` frozen dataclasses. `abliteration_threshold` clamped `[min, max]`. `manifest_path_for(model_id)`. `data/policies/security/model_integrity.yaml` (Policy-as-Code ADR-006). rglob YAML discovery. |
| **0049** | **IntegrityVerifier** | ✅ Ativo | v2.2 | [Ver Detalhes](./0049-integrity-verifier.md) | Orquestra 4 estágios: `ManifestHashVerifier` (SHA-256) → blacklist `is_known_abliterated()` → whitelist `get_model_info()` → `AbliterationDetector`. `verify()` bool fail-secure. Cadeia de responsabilidade Python→Rust (Jonas). |
| **0051** | **AbliterationDetector Fase 2** | ✅ Ativo | v2.2 | [Ver Detalhes](./0051-abliteration-detector-phase2.md) | 8 probes calibradas: 5 HARMFUL + 3 BENIGN. Refusal detection via NLP regex (12 padrões). `probe_timeout_ms` enfor­çado via `threading.Thread + queue.Queue` (cross-platform, sem `signal.alarm`). Timeout = recusa implícita (Jonas: fail-secure). Rawls: todas as probes idênticas para todos os modelos (blind). |

> ADR-0043 a ADR-0070 formalizados no Sprint 0/Sprint 2 (2026-05-19). Ver Grupo M abaixo.

***

## 🚀 Grupo L: v3.0 — SaaS Deployment (ADR-0059, ADR-0060)

*Gateway como serviço gerenciado. Zero instalação para o cliente: `OPENAI_BASE_URL=https://buildtovalue-gateway.fly.dev/v1/proxy`. ADR-0059 formaliza a fronteira Rust/Python; ADR-0060 documenta a escolha Fly.io sobre Cloudflare Workers e K8s gerenciado.*

| ID | Título | Status | Versão | Link | Resumo |
|:---|:---|:---:|:---:|:---|:---|
| **0059** | **Rust/Python Boundary** | ✅ Ativo | v3.0 | [Ver Detalhes](./0059-rust-python-boundary.md) | Formaliza plano de controle Rust (crypto, routing, proxy, tipos afins) vs plano analítico Python (LLMs, ML, contestability). `common.rs` como ponto DRY. Dual auth: BTV `x-api-key` (gateway) + LLM provider `Authorization` (forwarded). |
| **0070** | **SaaS Deployment — Fly.io** | ✅ Ativo | v3.0 | [Ver Detalhes](./0070-saas-deployment.md) | Fly.io sobre Cloudflare Workers (WASM incompatível com binário Rust standalone) e K8s gerenciado (overhead operacional). `primary_region = "gru"` (São Paulo) — LGPD Art. 44. `PORT` env var configurável. `force_https = true`. `fly.toml` na raiz do repo. Renumerado de ADR-0060 (Sprint 2). |

***

## 🔐 Grupo M: Sprint 0/1/2 — Segurança, Invariantes e Higiene (ADR-0043 a ADR-0070)

*Formalizados em 2026-05-19. Cobrem os fixes de Sprint 0 (segurança), Sprint 1 (invariantes), e Sprint 2 (higiene/renumerações).*

| ID | Título | Status | Versão | Link | Resumo |
|:---|:---|:---:|:---:|:---|:---|
| **0043** | **Unified Verdict Identity** | ✅ Ativo | v2.3 | [Ver Detalhes](./0043-unified-verdict-identity.md) | Verdict `REPORT` como nova ação (ADR-043); `blake3_hash` em `EthicalVerdict` para auto-verificação; `verify_signature()` com `hmac.compare_digest()`. |
| **0044** | **TechnicalEvidence Size Canonical** | ✅ Ativo | v2.3 | [Ver Detalhes](./0044-technical-evidence-size-canonical.md) | `EVIDENCE_SIZE = 9632` bytes como constante canônica. Substitui ADR-005. |
| **0045** | **Policy Schema v2** | ✅ Ativo | v2.3 | [Ver Detalhes](./0045-policy-dchema-v2-threat-model-required-fields.md) | Schema v2 para YAMLs de policy: campos obrigatórios de threat model. |
| **0046** | **ML Prompt Injection Layer** | ✅ Ativo | v2.3 | [Ver Detalhes](./0046-ml-prompt-injection-layer.md) | Camada ML sobre o detector heurístico (ADR-028). Reduz FNR de 18% para <3%. |
| **0047** | **Semantic PII Detection via NER** | ✅ Ativo | v2.3 | [Ver Detalhes](./0047-semantic-pii-ner.md) | NER (SLM-based) para PII semântico além de validators determinísticos. |
| **0048** | **Compliance-as-Code (Ledger Real)** | ✅ Ativo | v2.3 | [Ver Detalhes](./0048-compliance-as-code.md) | LGPD/EU AI Act via documentos reais do ledger (ROPA/RAT) em vez de parâmetros estáticos. |
| **0050** | **Multi-run Consensus Validator** | 🔒 Proposto | v2.4 | [Ver Detalhes](./0050-multi-run-consensus-validator.md) | Consenso multi-execução para reduzir variância em decisões de alto risco. |
| **0052** | **Forensic Audit Storage** | ✅ Ativo | v2.4 | [Ver Detalhes](./0052-forensic-audit-storage.md) | Armazenamento forense de evidências com imutabilidade garantida. |
| **0053** | **Visual Reasoning Guard** | 🔒 Proposto | v2.4 | [Ver Detalhes](./0053-visual-reasoning-guard.md) | Guard para entradas multimodais (imagens + texto). |
| **0054** | **Agentic Layer** | 🔒 Proposto | v2.4 | [Ver Detalhes](./0054-agentic-layer.md) | Camada de orquestração para agentes compostos. |
| **0055** | **Policy Elicitor** | 🔒 Proposto | v2.4 | [Ver Detalhes](./0055-policy-elicitor.md) | Elicitação interativa de políticas por domínio. |
| **0056** | **Negotiation Engine** | 🔒 Proposto | v2.4 | [Ver Detalhes](./0056-negotiation-engine.md) | Motor de negociação de permissões entre agentes. |
| **0057** | **Grant Decision Adapter** | ✅ Ativo | v3.0 | [Ver Detalhes](./0057-grant-decision-adapter.md) | Adapter para governança de propostas de grants (BTV v3.0). `use_decide=True`, HMAC-SHA256, JSON minified, `hard_blocked` fail-secure. |
| **0058** | **Arena Reporter** | 🔒 Proposto | v3.0 | [Ver Detalhes](./0058-arena-reporter.md) | Reporting de resultados de avaliações em arena. |
| **0060** | **BiasDeclaration Validated Constructor** | ✅ Ativo | v3.0 | [Ver Detalhes](./0060-bias-declaration-enforced-constructor.md) | Constructor de `BiasDeclaration` com validação: rejeita `calibration_date=0`. Estende ADR-010. |
| **0061** | **Decision Block Deadlock Reason** | ✅ Ativo | v3.0 | [Ver Detalhes](./0061-decision-block-deadlock-reason.md) | Código de razão estruturado para bloqueios deadlock em decisões. |
| **0062** | **Appeal Record Off-Chain Verification** | ✅ Ativo | v3.0 | [Ver Detalhes](./0062-appeal-record-off-chain-verification.md) | Verificação off-chain de registros de appeal via `blake3_hash`. |
| **0063** | **TechnicalEvidence Size Invariant** | ✅ Ativo | v3.0 | [Ver Detalhes](./0063-technical-evidence-size-invariant.md) | `const assert!(size_of::<TechnicalEvidence>() == 9632)` em `core/types.rs`. `from_bytes()` valida campo `version`. |
| **0064** | **Policy Reload Ed25519** | ✅ Ativo | v3.0 | [Ver Detalhes](./0064-policy-reload-ed25519.md) | Recarga de políticas verificada via assinatura Ed25519. |
| **0065** | **Gateway Context Enrichment** | 🚧 Impl. | v3.0 | [Ver Detalhes](./0065-gateway-context-enrichment-ip-classifier-session-drift.md) | IP Classifier + Session Drift no gateway. Renumerado de ADR-0044. |
| **0066** | **Hybrid Alignment: Session Sensitivity** | 🔒 Proposto | v3.0 | [Ver Detalhes](./0066-hybrid-alignment-session-sensitivity-accumulator.md) | Acumulador de sensibilidade de sessão para LLMs. Renumerado de ADR-0046. |
| **0067** | **Contestability Structured Mediation** | ✅ Ativo | v3.0 | [Ver Detalhes](./0067-contestability-structured-mediation-protocol.md) | Protocolo estruturado de mediação para contestações. Renumerado de ADR-0047. |
| **0068** | **Transactional Effect Buffering** | ✅ Ativo | v3.0 | [Ver Detalhes](./0068-transactional-effect-buffering.md) | Buffer atômico para side effects de governança (PROP-029). Renumerado de ADR-0048. |
| **0069** | **Protocol Designer (ARIA)** | ✅ Ativo | v3.0 | [Ver Detalhes](./0069-protocol-designer.md) | Registry e designer de protocolo para ARIA (sub-componente 3a). Renumerado de ADR-0057. |
| **0070** | **SaaS Deployment — Fly.io** | ✅ Ativo | v3.0 | [Ver Detalhes](./0070-saas-deployment.md) | Deploy Fly.io como proxy-as-a-service. Renumerado de ADR-0060. Ver Grupo L (ADR-0059). |

***

## 📐 Mapa de Dependências entre ADRs

```
ADR-0001 (Hybrid)
  └─► ADR-0005 (Evidence v2.1) ──► ADR-0010 (BiasDeclaration)
  └─► ADR-0009 (Monolito)     ──► ADR-0018 (Axum Gateway)
                                        └─► ADR-0019 (Observability)
                                        └─► ADR-0023 (Appeals HTTP)
                                        └─► ADR-0025 (Ledger Query)
                                        └─► ADR-0026 (Webhooks)

ADR-0004 (Ledger) ──► ADR-0025 (Ledger Query)
                  ──► ADR-0029/0030/0031 (evidence_id forense)

ADR-0006 (Policy-as-Code)
  └─► ADR-0011 (Policy Engine Rust)
  └─► ADR-0024 (Threat→Policy Bridge)
  └─► ADR-0029/0030/0031 (YAML por sector_id)
  └─► ADR-0042 (model_integrity.yaml — Policy-as-Code para modelos AI)

ADR-0017 (Contestability)
  └─► ADR-0023 (Appeals HTTP)
  └─► ADR-0029/0030/0031 (contestable: true, SLA 24h)

ADR-0020 (Intelligence Hub)
  └─► ADR-0024 (Threat→Policy Bridge)
  └─► ADR-0028 (Heuristic Detector — padrões do feed)

ADR-0028 (Heuristic Detector)
  └─► ADR-0029 (Gate 3 RAG — anti-injection)
  └─► ADR-0030 (Gate 3 RAG interno)
  └─► ADR-0031 (Gate 4 RAG externo — padrões adicionais PTBR)

ADR-0029 (External Agent PDP — contrato canônico)
  └─► ADR-0030 (Chatbot LLM Interna)
  └─► ADR-0031 (Chatbot LLM Externa)

ADR-0042 (PolicyEngine Model Integrity)     ← Policy-as-Code (ADR-0006)
  └─► ADR-0049 (IntegrityVerifier)
        └─► ManifestHashVerifier (SHA-256 fast-path)
        └─► AbliterationDetector (ADR-0051)
        └─► Rust kernel BLAKE3 weights (ADR-0005, v2.3)
  └─► ADR-0051 (AbliterationDetector Fase 2)
        └─► probe_timeout_ms (threading + queue, cross-platform)
        └─► ADR-0010 (BiasDeclaration — refusal calibration)

ADR-0018 (Axum Gateway)
  └─► ADR-0059 (Rust/Python Boundary — common.rs DRY)
        └─► ADR-0060 (SaaS Deployment — Fly.io)
              └─► fly.toml (primary_region=gru, force_https, PORT env var)
              └─► ops/k8s/ (Enterprise on-premise path preservado)
```

***

## 📁 Arquivos de Integração Associados

Os ADRs do Grupo I possuem documentos de referência de implementação em `docs/integrations/` (perfis prontos para copy-paste):

| Perfil | ADR | Arquivo | Descrição |
|:---|:---:|:---|:---|
| Chatbot LLM Interna | 0030 | `docs/integrations/chatbot-internal-llm.md` | Implementação completa dos 5 gates, Angular + Rust + Python, Docker Compose dev, políticas YAML. |
| Chatbot LLM Externa | 0031 | `docs/integrations/chatbot-external-llm.md` | Delta completo: 4 gates, catálogo de vendors, políticas por sector_id, evidência LGPD Art. 33. |

***

## 📋 Políticas YAML Versionadas por Perfil

| Arquivo | ADR | Finalidade |
|:---|:---:|:---|
| `data/policies/base.yaml` | 0006 | Regras raiz — herança global |
| `data/policies/general.yaml` | 0006 | Perfil geral (agentes sem sector_id) |
| `data/policies/medical-agent.yaml` | 0006 | Override para setor saúde |
| `data/policies/auto-generated/` | 0024 | Policies geradas pelo Threat→Policy Bridge (todas `enabled: false`) |
| `data/policies/chatbot-internal-message.yaml` | 0030 | Mensagens com PII/CONFIDENTIAL no chatbot interno |
| `data/policies/chatbot-rag-injection.yaml` | 0030 | Anti-injection nos chunks RAG (chatbot interno) |
| `data/policies/chatbot-lora-deploy.yaml` | 0030 | Threshold de qualidade para deploy de LoRA |
| `data/policies/chatbot-lora-deploy-health.yaml` | 0030 | Override para sector_id: health (refusal ≥ 90%) |
| `data/policies/chatbot-vendor-approval.yaml` | 0031 | Quais vendors são aprovados por sector_id |
| `data/policies/chatbot-vendor-send.yaml` | 0031 | Regras por mensagem enviada a vendor externo |
| `data/policies/chatbot-vendor-response.yaml` | 0031 | Padrões de exfiltração na resposta do vendor |
| `data/policies/chatbot-rag-external.yaml` | 0031 | Anti-injection para RAG em prompts externos |
| **`data/policies/security/model_integrity.yaml`** | **0042** | **Integridade de modelos AI: hash manifest, abliteration threshold, probe_timeout_ms** |

***

## 📝 Legenda de Status

| Símbolo | Significado |
|:---:|:---|
| ✅ | **Ativo:** Decisão tomada, implementada e em vigor. Código deve seguir estritamente. |
| ⛔ | **Obsoleto:** Decisão revogada ou substituída. Mantida apenas para histórico. |
| 🚧 | **Em Implementação:** Decisão aprovada, trabalho em andamento na versão atual. |
| 🔒 | **Planejado / Proposto:** Aprovado para versão futura ou proposto aguardando implementação. Não implementar agora, mas não bloquear. |
| 🔮 | **Visão:** Conceito aprovado, sem especificação técnica detalhada ainda. |

***

## 📊 Estatísticas do Índice

| Métrica | Valor |
|:---|:---:|
| Total de ADRs | 70 |
| ✅ Ativos | 40 |
| 🚧 Em Implementação | 3 |
| 🔒 Planejados / Propostos | 19 |
| ⛔ Obsoletos | 1 |
| 🔮 Visão (sem ADR formal) | 2 |
| Arquivados (drafts/duplicatas) | 3 |
| Testes (governance Python) | 39 |
| Última entrada | ADR-0070 |
| Próximo disponível | ADR-0071 |

***

## O que foi atualizado

| Seção | Mudança |
|:---|:---|
| **Cabeçalho** | Data atualizada para 09/03/2026 |
| **Grupo K** | ✨ **Novo** — Model Integrity Governance: ADR-042, ADR-049, ADR-051 (✅ Ativo v2.2) |
| **Nota de lacuna** | Reserva intencional ADR-043–048 e ADR-050 documentada |
| **Mapa de dependências** | Adicionada cadeia `ADR-0042 → ADR-0049 → ADR-0051 → Rust BLAKE3` |
| **Políticas YAML** | Adicionado `data/policies/security/model_integrity.yaml` (ADR-0042) |
| **Grupo L** | ✨ **Novo** — SaaS Deployment: ADR-0059 (Rust/Python Boundary), ADR-0060 (Fly.io) (✅ Ativo v3.0) |
| **Mapa de dependências** | Adicionada cadeia `ADR-0018 → ADR-0059 → ADR-0060 → fly.toml` |
| **Estatísticas** | Total 46 (+2), Ativos 23 (+2), Última entrada ADR-0060, Próximo ADR-0061 |