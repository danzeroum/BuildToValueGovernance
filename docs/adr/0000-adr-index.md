# Índice de ADRs — BuildToValue Governance

**Versão do Índice:** v4.2.3  
**Última atualização:** 2026-05-28  
**Commit de referência:** push atômico ADR 0013 + 0015 (Grupo B encerrado)  
**Total de ADRs ativos:** 0001–0081 + arquivo  

---

## Estado do Repositório

| Grupo | Escopo | Status |
|:---|:---|:---|
| **Grupo A** (0001–0012) | Fundações do Kernel — pilar de entrada, avaliação e saída | ✅ **Consolidado e auditado** |
| **Grupo B** (0013–0016) | Guardrails de Entrada e Contexto Ético | ✅ **Encerrado** (0013✅, 0014⚠️Obs, 0015✅, 0016⚠️Obs) |
| **Grupo C** (0017–0081) | Extensões, Integrações e Domínios Especializados | 🔄 Em evolução contínua |

---

## Grupo A — Fundações do Kernel (✅ Consolidado)

| ID | Título | Status | Bytes |
|:---|:---|:---:|:---:|
| [0001](0001-hybrid-architecture.md) | Hybrid Architecture (Rust + Python) | ✅ Aceito | 2.353 |
| [0002](0002-evidence-protocol-v1-obsolete.md) | Evidence Protocol v1 | ⚠️ Obsoleto | 852 |
| [0003](0003-mercy-algorithm.md) | Mercy Algorithm (Gilligan) | ✅ Aceito | 1.922 |
| [0004](0004-immutable-ledger.md) | Immutable Ledger (BLAKE3) | ✅ Aceito | 2.565 |
| [0005](0005-evidence-protocol-v2-fixed-size.md) | Evidence Protocol v2 — 9.596 bytes fixos | ✅ Aceito | 2.153 |
| [0006](0006-policy-as-code.md) | Policy as Code v1 | ✅ Aceito | 2.036 |
| [0007](0007-trust-score-algorithm.md) | Trust Score Algorithm v1 | ✅ Aceito | 2.406 |
| [0008](0008-side-channel-timing-mitigation.md) | Side-Channel Timing Mitigation | ✅ Aceito | 2.096 |
| [0009](0009-modular-monolith-pivot.md) | Modular Monolith Pivot | ✅ Aceito | 3.633 |
| [0010](0010-bias-declaration-mandate.md) | Bias Declaration Mandate | ✅ Aceito | 6.382 |
| [0011](0011-policy-engine.md) | Policy Engine | ✅ Aceito | 6.954 |
| [0012](0012-output-guard.md) | Output Guard (FFI Boundary) | ✅ Aceito | 10.732 |

---

## Grupo B — Guardrails de Entrada e Contexto Ético (✅ Encerrado)

| ID | Título | Status | Resolução |
|:---|:---|:---:|:---|
| [0013](0013-deobfuscator-chaining-v2.md) | Deobfuscator Chaining v2 | ✅ Aceito | Âncora: 47.852 bytes em `rust/kernel/src/deobfuscator/` |
| [0014](0014-ip-classifier-session-drift.md) | IP Classifier / Session Drift | ⚠️ Obsoleto | Coberto por ADR 0044 e ADR 0065 |
| [0015](0015-interceptor-hooks.md) | Interceptor Hooks | ✅ Aceito | Âncora: 13.311 bytes em `rust/kernel/src/interceptor/` |
| [0016](0016-ethical-context-engine-v4.md) | Ethical Context Engine v4 | ⚠️ Obsoleto | Coberto por ADR 0038 (40.133 bytes) |

---

## Grupo C — Extensões e Domínios Especializados (🔄 Em evolução)

| ID | Título | Status |
|:---|:---|:---:|
| [0017](0017-contestability-loop.md) | Contestability Loop v1 | ✅ Aceito |
| [0018](0018-axum-gateway.md) | Axum Gateway v1 | ✅ Aceito |
| [0019](0019-observability.md) | Observability v1 | ✅ Aceito |
| [0020](0020-intelligence-hub.md) | Intelligence Hub | ✅ Aceito |
| [0021](0021-compliance-plugins.md) | Compliance Plugins | ✅ Aceito |
| [0022](0022-streamlit-dashboard.md) | Streamlit Dashboard | ✅ Aceito |
| [0023](0023-appeals-http-endpoint.md) | Appeals HTTP Endpoint | ✅ Aceito |
| [0024](0024-threat-policy-bridge.md) | Threat Policy Bridge | ✅ Aceito |
| [0025](0025-ledger-query-api.md) | Ledger Query API | ✅ Aceito |
| [0026](0026-webhook-notifications.md) | Webhook Notifications | ✅ Aceito |
| [0027](0027-local-slm-strategy.md) | Local SLM Strategy | ✅ Aceito |
| [0028](0028-heuristic-prompt-injection-detector.md) | Heuristic Prompt Injection Detector | ✅ Aceito |
| [0029](0029-external-agent-pdp.md) | External Agent PDP | ✅ Aceito |
| [0030](0030-internal-chatbot-selfhosted-llm.md) | Internal Chatbot — Self-hosted LLM | ✅ Aceito |
| [0031](0031-external-chatbot-vendor-llm.md) | External Chatbot — Vendor LLM | ✅ Aceito |
| [0032](0032-scan-context-flags.md) | Scan Context Flags | ✅ Aceito |
| [0033](0033-pattern-registry-tiers.md) | Pattern Registry Tiers | ✅ Aceito |
| [0034](0034-language-detection-strategy.md) | Language Detection Strategy | ✅ Aceito |
| [0035](0035-multi-jurisdiction-pii-validators.md) | Multi-Jurisdiction PII Validators | ✅ Aceito |
| [0036](0036-redteam-bias-guardian.md) | Red Team Bias Guardian | ✅ Aceito |
| [0037](0037-contestability-loop-appeal-engine.md) | Contestability Loop — Appeal Engine | ✅ Aceito |
| [0038](0038-ethical-context-engine-v4.md) | Ethical Context Engine v4 (canônico) | ✅ Aceito |
| [0039](0039-trust-score-calculator-v2.md) | Trust Score Calculator v2 | ✅ Aceito |
| [0040](0040-axum-gateway-v2-extensions.md) | Axum Gateway v2 Extensions | ✅ Aceito |
| [0041](0041-observability-v2-republic-metrics.md) | Observability v2 — Republic Metrics | ✅ Aceito |
| [0042](0042-policy-as-code-v2.md) | Policy as Code v2 | ✅ Aceito |
| [0043](0043-unified-verdict-identity.md) | Unified Verdict Identity | ✅ Aceito |
| [0044](0044-gateway-context-enrichment-ip-classifier-session-drift.md) | Gateway Context Enrichment — IP Classifier & Session Drift | ✅ Aceito |
| [0045](0045-policy-dchema-v2-threat-model-required-fields.md) | Policy Schema v2 — Threat Model Required Fields | ✅ Aceito |
| [0046](0046-hybrid-alignment-session-sensitivity-accumulator.md) | Hybrid Alignment — Session Sensitivity Accumulator | ✅ Aceito |
| [0047](0047-contestability-structured-mediation-protocol.md) | Contestability Structured Mediation Protocol | ✅ Aceito |
| [0048](0048-transactional-effect-buffering.md) | Transactional Effect Buffering | ✅ Aceito |
| [0049](0049-cot-opacity-controlled.md) | CoT Opacity Controlled | ✅ Aceito |
| [0050](0050-multi-run-consensus-validator.md) | Multi-Run Consensus Validator | ✅ Aceito |
| [0051](0051-model-integrity-abliteration-detection.md) | Model Integrity — Abliteration Detection v1 | ✅ Aceito |
| [0052](0052-forensic-audit-storage.md) | Forensic Audit Storage | ✅ Aceito |
| [0053](0053-visual-reasoning-guard.md) | Visual Reasoning Guard | ✅ Aceito |
| [0054](0054-agentic-layer.md) | Agentic Layer | ✅ Aceito |
| [0055](0055-policy-elicitor.md) | Policy Elicitor | ✅ Aceito |
| [0056](0056-negotiation-engine.md) | Negotiation Engine | ✅ Aceito |
| [0057](0057-grant-decision-adapter.md) | Grant Decision Adapter | ✅ Aceito |
| [0058](0058-arena-reporter.md) | Arena Reporter | ✅ Aceito |
| [0059](0059-rust-python-boundary.md) | Rust/Python Boundary Contract | ✅ Aceito |
| [0060](0060-bias-declaration-enforced-constructor.md) | Bias Declaration — Enforced Constructor | ✅ Aceito |
| [0061](0061-decision-block-deadlock-reason.md) | Decision Block — Deadlock Reason | ✅ Aceito |
| [0062](0062-appeal-record-off-chain-verification.md) | Appeal Record Off-Chain Verification | ✅ Aceito |
| [0063](0063-technical-evidence-size-invariant.md) | Technical Evidence Size Invariant | ✅ Aceito |
| [0064](0064-policy-reload-ed25519.md) | Policy Reload — Ed25519 Signature | ✅ Aceito |
| [0065](0065-gateway-context-enrichment-ip-classifier-session-drift.md) | Gateway Context Enrichment v2 — IP Classifier & Session Drift | ✅ Aceito |
| [0066](0066-hybrid-alignment-session-sensitivity-accumulator.md) | Hybrid Alignment v2 — Session Sensitivity Accumulator | ✅ Aceito |
| [0067](0067-contestability-structured-mediation-protocol.md) | Contestability Structured Mediation Protocol v2 | ✅ Aceito |
| [0068](0068-transactional-effect-buffering.md) | Transactional Effect Buffering v2 | ✅ Aceito |
| [0069](0069-protocol-designer.md) | Protocol Designer | ✅ Aceito |
| [0070](0070-saas-deployment.md) | SaaS Deployment | ✅ Aceito |
| [0071](0071-philosophical-vocabulary-preservation.md) | Philosophical Vocabulary Preservation | ✅ Aceito |
| [0072](0072-gilligan-sla-mercy-algorithm.md) | Gilligan SLA — Mercy Algorithm | ✅ Aceito |
| [0073](0073-grant-decision-adapter.md) | Grant Decision Adapter v2 | ✅ Aceito |
| [0074](0074-model-integrity-abliteration-detection-v2.md) | Model Integrity — Abliteration Detection v2 | ✅ Aceito |
| [0075](0075-grant-decision-adapter-draft.md) | Grant Decision Adapter — Draft | ⚠️ Rascunho |
| [0076](0076-gateway-context-enrichment-ip-classifier-session-drift.md) | Gateway Context Enrichment v3 — IP Classifier & Session Drift | ✅ Aceito |
| [0077](0077-ml-prompt-injection-layer.md) | ML Prompt Injection Layer | ✅ Aceito |
| [0078](0078-semantic-pii-ner.md) | Semantic PII — NER | ✅ Aceito |
| [0079](0079-compliance-as-code.md) | Compliance as Code | ✅ Aceito |
| [0080](0080-protocol-designer.md) | Protocol Designer v2 | ✅ Aceito |
| [0081](0081-saas-deployment.md) | SaaS Deployment v2 | ✅ Aceito |

---

## Notas de Governança

### Decisões descartadas (laudo forense 2026-05-28)

- **ADR 0082 (AI Accountability Framework):** descartado. Escopo coberto por ADR 0010, 0038, 0060 e 0071 sem nova âncora física.
- **ADR 0083 (DDD/Hexagonal Standardization):** descartado. BTV adota Modular Monolith (ADR 0009) como padrão canônico; Hexagonal permanece em labs sem mandato de kernel.

### Duplicidades de numeração identificadas

O repositório contém duplicidades de números (ex.: dois arquivos com prefixo `0044`, `0046`, `0047`, `0048`, `0057`, `0060`, `0072`). Estes são artefatos de sprints anteriores e serão endereçados em sprint dedicada de normalização de índice.

### Princípio de integridade documental

> Nenhum ADR é redigido sem âncora física verificada no repositório. Stubs sem implementação correspondente são classificados como Obsoleto, não reescritos.
