# Índice Mestre de ADRs — BuildToValue Governance

**Versão do Índice:** v4.2.0  
**Data de Consolidação:** 2026-05-28  
**HEAD de Referência:** `24c9190b4fbb430012bb67c666e9129fc7c85b05`  
**Total de ADRs Catalogados:** 81 (numerações 0001–0081; colisões de numeração explicitadas)  
**Mantenedor:** AI Squad — Arquiteta (Opus) + Reviewer (Opus)  
**Classificação:** Documentação Arquitetural — Fonte Primária de Rastreabilidade

> **Nota de Integridade:** Este índice mapeia exclusivamente arquivos físicos confirmados no disco do repositório. Nenhuma entrada aponta para slug fictício ou arquivo inexistente. Qualquer divergência futura entre este índice e o estado do disco constitui um gatilho de não-conformidade de documentação (*documentation drift*) e deve ser tratada como incidente de rastreabilidade.

---

## Legenda de Status

| Símbolo | Significado |
|:---:|:---|
| ✅ Aceito | Decisão homologada, em vigor na base de código |
| 🔒 Rascunho | Proposta em elaboração, não vinculante |
| ⚠️ Obsoleto | Supersedido por ADR posterior; mantido para histórico |
| ⚠️ Stub | Arquivo físico existe, mas conteúdo arquitetural está ausente ou é apenas cabeçalho placeholder. Expansão pendente de sprint futura. |

---

## Grupo A — Fundamentos Arquiteturais (0001–0010)

| ID | Título | Arquivo | Status |
|:---|:---|:---|:---:|
| 0001 | Arquitetura Híbrida Rust/Python — Monolito Modular | [0001-hybrid-architecture.md](0001-hybrid-architecture.md) | ✅ Aceito |
| 0002 | Evidence Protocol v1 | [0002-evidence-protocol-v1-obsolete.md](0002-evidence-protocol-v1-obsolete.md) | ⚠️ Obsoleto |
| 0003 | Algoritmo de Misericórdia (Mercy Algorithm v1) | [0003-mercy-algorithm.md](0003-mercy-algorithm.md) | ✅ Aceito |
| 0004 | Ledger Imutável — Cadeia de Hashes BLAKE3 | [0004-immutable-ledger.md](0004-immutable-ledger.md) | ✅ Aceito |
| 0005 | Evidence Protocol v2 — Tamanho Fixo Canônico | [0005-evidence-protocol-v2-fixed-size.md](0005-evidence-protocol-v2-fixed-size.md) | ✅ Aceito |
| 0006 | Policy-as-Code — Legislativo da República Algorítmica | [0006-policy-as-code.md](0006-policy-as-code.md) | ✅ Aceito |
| 0007 | Algoritmo de Trust Score v1 | [0007-trust-score-algorithm.md](0007-trust-score-algorithm.md) | ✅ Aceito |
| 0008 | Mitigação de Side-Channel por Timing | [0008-side-channel-timing-mitigation.md](0008-side-channel-timing-mitigation.md) | ✅ Aceito |
| 0009 | Pivô para Monolito Modular | [0009-modular-monolith-pivot.md](0009-modular-monolith-pivot.md) | ✅ Aceito |
| 0010 | Mandato de BiasDeclaration | [0010-bias-declaration-mandate.md](0010-bias-declaration-mandate.md) | ✅ Aceito |

---

## Grupo B — Componentes do Kernel v1 (0011–0020)

> ⚠️ **Nota de Auditoria (2026-05-28):** Os ADRs 0011–0016 foram identificados por auditoria forense de densidade de conteúdo como stubs. Os arquivos existem fisicamente no disco, mas contêm apenas cabeçalhos Markdown sem decisão arquitetural substanciada. O 0015 está em estado de arquivo vazio. A expansão destes seis ADRs constitui débito técnico de documentação registrado e priorizado para sprint futura.

| ID | Título | Arquivo | Status |
|:---|:---|:---|:---:|
| 0011 | Policy Engine — Núcleo v1 | [0011-policy-engine.md](0011-policy-engine.md) | ⚠️ Stub |
| 0012 | Output Guard | [0012-output-guard.md](0012-output-guard.md) | ⚠️ Stub |
| 0013 | Deobfuscator Chaining v2 | [0013-deobfuscator-chaining-v2.md](0013-deobfuscator-chaining-v2.md) | ⚠️ Stub |
| 0014 | IP Classifier e Session Drift v1 | [0014-ip-classifier-session-drift.md](0014-ip-classifier-session-drift.md) | ⚠️ Stub |
| 0015 | Interceptor Hooks — JVM Bridge | [0015-interceptor-hooks.md](0015-interceptor-hooks.md) | ⚠️ Stub |
| 0016 | Ethical Context Engine v4 (stub) | [0016-ethical-context-engine-v4.md](0016-ethical-context-engine-v4.md) | ⚠️ Stub |
| 0017 | Contestability Loop v1 | [0017-contestability-loop.md](0017-contestability-loop.md) | ✅ Aceito |
| 0018 | Axum Gateway v1 | [0018-axum-gateway.md](0018-axum-gateway.md) | ✅ Aceito |
| 0019 | Observabilidade v1 | [0019-observability.md](0019-observability.md) | ✅ Aceito |
| 0020 | Intelligence Hub | [0020-intelligence-hub.md](0020-intelligence-hub.md) | ✅ Aceito |

---

## Grupo C — Camada Python e Interface (0021–0030)

| ID | Título | Arquivo | Status |
|:---|:---|:---|:---:|
| 0021 | Compliance Plugins | [0021-compliance-plugins.md](0021-compliance-plugins.md) | ✅ Aceito |
| 0022 | Dashboard Streamlit | [0022-streamlit-dashboard.md](0022-streamlit-dashboard.md) | ✅ Aceito |
| 0023 | Appeals HTTP Endpoint | [0023-appeals-http-endpoint.md](0023-appeals-http-endpoint.md) | ✅ Aceito |
| 0024 | Threat-Policy Bridge | [0024-threat-policy-bridge.md](0024-threat-policy-bridge.md) | ✅ Aceito |
| 0025 | Ledger Query API | [0025-ledger-query-api.md](0025-ledger-query-api.md) | ✅ Aceito |
| 0026 | Webhook Notifications | [0026-webhook-notifications.md](0026-webhook-notifications.md) | ✅ Aceito |
| 0027 | Estratégia Local SLM | [0027-local-slm-strategy.md](0027-local-slm-strategy.md) | ✅ Aceito |
| 0028 | Heuristic Prompt Injection Detector | [0028-heuristic-prompt-injection-detector.md](0028-heuristic-prompt-injection-detector.md) | ✅ Aceito |
| 0029 | External Agent PDP | [0029-external-agent-pdp.md](0029-external-agent-pdp.md) | ✅ Aceito |
| 0030 | Internal Chatbot — Self-hosted LLM | [0030-internal-chatbot-selfhosted-llm.md](0030-internal-chatbot-selfhosted-llm.md) | ✅ Aceito |

---

## Grupo D — Chatbots, Scanning e Pattern Registry (0031–0040)

| ID | Título | Arquivo | Status |
|:---|:---|:---|:---:|
| 0031 | External Chatbot — Vendor LLM | [0031-external-chatbot-vendor-llm.md](0031-external-chatbot-vendor-llm.md) | ✅ Aceito |
| 0032 | Scan Context Flags | [0032-scan-context-flags.md](0032-scan-context-flags.md) | ✅ Aceito |
| 0033 | Pattern Registry — Tiers | [0033-pattern-registry-tiers.md](0033-pattern-registry-tiers.md) | ✅ Aceito |
| 0034 | Estratégia de Detecção de Linguagem | [0034-language-detection-strategy.md](0034-language-detection-strategy.md) | ✅ Aceito |
| 0035 | Validadores PII Multi-Jurisdição | [0035-multi-jurisdiction-pii-validators.md](0035-multi-jurisdiction-pii-validators.md) | ✅ Aceito |
| 0036 | Red Team Bias Guardian | [0036-redteam-bias-guardian.md](0036-redteam-bias-guardian.md) | ✅ Aceito |
| 0037 | Contestability Loop — Appeal Engine | [0037-contestability-loop-appeal-engine.md](0037-contestability-loop-appeal-engine.md) | ✅ Aceito |
| 0038 | Ethical Context Engine v4 (full) | [0038-ethical-context-engine-v4.md](0038-ethical-context-engine-v4.md) | ✅ Aceito |
| 0039 | Trust Score Calculator v2 | [0039-trust-score-calculator-v2.md](0039-trust-score-calculator-v2.md) | ✅ Aceito |
| 0040 | Axum Gateway v2 — Extensions | [0040-axum-gateway-v2-extensions.md](0040-axum-gateway-v2-extensions.md) | ✅ Aceito |

---

## Grupo E — República Algorítmica v2 (0041–0050)

| ID | Título | Arquivo | Status |
|:---|:---|:---|:---:|
| 0041 | Observabilidade v2 — Republic Metrics | [0041-observability-v2-republic-metrics.md](0041-observability-v2-republic-metrics.md) | ✅ Aceito |
| 0042 | Policy-as-Code v2 — BlindEvaluator e PolicyTester | [0042-policy-as-code-v2.md](0042-policy-as-code-v2.md) | ✅ Aceito |
| 0043 | Unified Verdict Identity | [0043-unified-verdict-identity.md](0043-unified-verdict-identity.md) | ✅ Aceito |
| 0044 | Invariante de Tamanho da Evidência Técnica (Canonical Size) | [0044-technical-evidence-size-canonical.md](0044-technical-evidence-size-canonical.md) | ✅ Aceito |
| 0044 | Gateway Context Enrichment — IP Classifier e Session Drift (v1) | [0044-gateway-context-enrichment-ip-classifier-session-drift.md](0044-gateway-context-enrichment-ip-classifier-session-drift.md) [²] | ✅ Aceito |
| 0045 | Schema de Política v2 — Campos Obrigatórios do Modelo de Ameaças | [0045-policy-dchema-v2-threat-model-required-fields.md](0045-policy-dchema-v2-threat-model-required-fields.md) [¹] | ✅ Aceito |
| 0046 | Hybrid Alignment Session Sensitivity Accumulator | [0046-hybrid-alignment-session-sensitivity-accumulator.md](0046-hybrid-alignment-session-sensitivity-accumulator.md) | ✅ Aceito |
| 0046 | ML Prompt Injection Layer (v1) | [0046-ml-prompt-injection-layer.md](0046-ml-prompt-injection-layer.md) [⁴] | ✅ Aceito |
| 0047 | Contestability — Protocolo Estruturado de Mediação (v1) | [0047-contestability-structured-mediation-protocol.md](0047-contestability-structured-mediation-protocol.md) | ✅ Aceito |
| 0047 | Semantic PII NER (v1) | [0047-semantic-pii-ner.md](0047-semantic-pii-ner.md) [⁵] | ✅ Aceito |
| 0048 | Compliance as Code (v1) | [0048-compliance-as-code.md](0048-compliance-as-code.md) | ✅ Aceito |
| 0048 | Transactional Effect Buffering (v1) | [0048-transactional-effect-buffering.md](0048-transactional-effect-buffering.md) [⁶] | ✅ Aceito |
| 0049 | Chain-of-Thought Opacity Controlled | [0049-cot-opacity-controlled.md](0049-cot-opacity-controlled.md) | ✅ Aceito |
| 0050 | Multi-Run Consensus Validator | [0050-multi-run-consensus-validator.md](0050-multi-run-consensus-validator.md) | ✅ Aceito |

---

## Grupo F — Detecção de Integridade e Armazenamento Forense (0051–0060)

| ID | Título | Arquivo | Status |
|:---|:---|:---|:---:|
| 0051 | Model Integrity — Abliteration Detection (Fase 1) | [0051-model-integrity-abliteration-detection.md](0051-model-integrity-abliteration-detection.md) | ✅ Aceito |
| 0052 | Forensic Audit Storage | [0052-forensic-audit-storage.md](0052-forensic-audit-storage.md) | ✅ Aceito |
| 0053 | Visual Reasoning Guard | [0053-visual-reasoning-guard.md](0053-visual-reasoning-guard.md) | ✅ Aceito |
| 0054 | Agentic Layer | [0054-agentic-layer.md](0054-agentic-layer.md) | ✅ Aceito |
| 0055 | Policy Elicitor | [0055-policy-elicitor.md](0055-policy-elicitor.md) | ✅ Aceito |
| 0056 | Negotiation Engine | [0056-negotiation-engine.md](0056-negotiation-engine.md) | ✅ Aceito |
| 0057 | Grant Decision Adapter (v1) | [0057-grant-decision-adapter.md](0057-grant-decision-adapter.md) | ✅ Aceito |
| 0057 | Protocol Designer (v1) | [0057-protocol-designer.md](0057-protocol-designer.md) [⁷] | ✅ Aceito |
| 0058 | Arena Reporter | [0058-arena-reporter.md](0058-arena-reporter.md) | ✅ Aceito |
| 0059 | Fronteira Rust/Python — Contrato de Boundary | [0059-rust-python-boundary.md](0059-rust-python-boundary.md) | ✅ Aceito |
| 0060 | BiasDeclaration — Constructor Enforced | [0060-bias-declaration-enforced-constructor.md](0060-bias-declaration-enforced-constructor.md) | ✅ Aceito |
| 0060 | SaaS Deployment — Fly.io (v1) | [0060-saas-deployment.md](0060-saas-deployment.md) [⁸] | ✅ Aceito |

---

## Grupo G — Decisões de Bloqueio e Verificação (0061–0065)

| ID | Título | Arquivo | Status |
|:---|:---|:---|:---:|
| 0061 | Decision Block — Razão de Deadlock em Veredicto | [0061-decision-block-deadlock-reason.md](0061-decision-block-deadlock-reason.md) | ✅ Aceito |
| 0062 | Appeal Record — Verificação Off-Chain | [0062-appeal-record-off-chain-verification.md](0062-appeal-record-off-chain-verification.md) | ✅ Aceito |
| 0063 | Invariante de Tamanho da TechnicalEvidence (9596 bytes) | [0063-technical-evidence-size-invariant.md](0063-technical-evidence-size-invariant.md) | ✅ Aceito |
| 0064 | Policy Reload com Assinatura Ed25519 | [0064-policy-reload-ed25519.md](0064-policy-reload-ed25519.md) | ✅ Aceito |
| 0065 | Gateway Context Enrichment — IP Classifier e Session Drift (v2) | [0065-gateway-context-enrichment-ip-classifier-session-drift.md](0065-gateway-context-enrichment-ip-classifier-session-drift.md) | ✅ Aceito |

---

## Grupo H — Alinhamento Híbrido e Mediação (0066–0070)

| ID | Título | Arquivo | Status |
|:---|:---|:---|:---:|
| 0066 | Hybrid Alignment Session Sensitivity Accumulator (v2) | [0066-hybrid-alignment-session-sensitivity-accumulator.md](0066-hybrid-alignment-session-sensitivity-accumulator.md) | ✅ Aceito |
| 0067 | Contestability — Protocolo Estruturado de Mediação (v2) | [0067-contestability-structured-mediation-protocol.md](0067-contestability-structured-mediation-protocol.md) | ✅ Aceito |
| 0068 | Transactional Effect Buffering (v2) | [0068-transactional-effect-buffering.md](0068-transactional-effect-buffering.md) | ✅ Aceito |
| 0069 | Protocol Designer (v2) | [0069-protocol-designer.md](0069-protocol-designer.md) | ✅ Aceito |
| 0070 | SaaS Deployment — Fly.io (v2) | [0070-saas-deployment.md](0070-saas-deployment.md) | ✅ Aceito |

---

## Grupo I — Filosofia, Ética Operacional e Mercy SLA (0071–0072)

| ID | Título | Arquivo | Status |
|:---|:---|:---|:---:|
| 0071 | Preservação do Vocabulário Filosófico do BTV | [0071-philosophical-vocabulary-preservation.md](0071-philosophical-vocabulary-preservation.md) | ✅ Aceito |
| 0072 | Algoritmo de Misericórdia e SLA do Estágio Gilligan | [0072-gilligan-sla-mercy-algorithm.md](0072-gilligan-sla-mercy-algorithm.md) [³] | ✅ Aceito |

---

## Grupo J — Grant Decision e Model Integrity v2 (0073–0075)

| ID | Título | Arquivo | Status |
|:---|:---|:---|:---:|
| 0073 | Grant Decision Adapter (v2 — canônico) | [0073-grant-decision-adapter.md](0073-grant-decision-adapter.md) | ✅ Aceito |
| 0074 | Model Integrity — Abliteration Detection v2 | [0074-model-integrity-abliteration-detection-v2.md](0074-model-integrity-abliteration-detection-v2.md) | ✅ Aceito |
| 0075 | Grant Decision Adapter — Rascunho de Extensão | [0075-grant-decision-adapter-draft.md](0075-grant-decision-adapter-draft.md) | 🔒 Rascunho |

---

## Grupo K — Deduplicações Multi-Tenant (0076–0081)

> Estes ADRs foram gerados no commit `07c32c6` como especializações isoladas de funcionalidades que anteriormente colidiam em numerações duplas (0044-B, 0046-B, 0047-B, 0048-B, 0057-B, 0060-B). Cada entrada abaixo representa a versão canônica e definitiva da feature em numeração própria, com rastreabilidade completa à sua origem.

| ID | Título | Arquivo | Status |
|:---|:---|:---|:---:|
| 0076 | Gateway Context Enrichment — IP Classifier e Session Drift (canônico multi-tenant) | [0076-gateway-context-enrichment-ip-classifier-session-drift.md](0076-gateway-context-enrichment-ip-classifier-session-drift.md) | ✅ Aceito |
| 0077 | ML Prompt Injection Layer (canônico) | [0077-ml-prompt-injection-layer.md](0077-ml-prompt-injection-layer.md) | ✅ Aceito |
| 0078 | Semantic PII NER (canônico) | [0078-semantic-pii-ner.md](0078-semantic-pii-ner.md) | ✅ Aceito |
| 0079 | Compliance as Code (canônico) | [0079-compliance-as-code.md](0079-compliance-as-code.md) | ✅ Aceito |
| 0080 | Protocol Designer (canônico) | [0080-protocol-designer.md](0080-protocol-designer.md) | ✅ Aceito |
| 0081 | SaaS Deployment — Fly.io (canônico) | [0081-saas-deployment.md](0081-saas-deployment.md) | ✅ Aceito |

---

## Notas de Errata Forense e Rastreabilidade

**[¹] Errata Forense — ADR 0045:**  
O slug físico contém um desvio ortográfico original (`dchema` em lugar de `schema`). O nome do arquivo foi mantido inalterado para preservar a integridade do SHA de blob criptográfico `00683653` mapeado em esteiras de auditoria ativa. A correção do nome está pendente de formalização no ADR 0082 (Errata de Slugs), que documentará o rename com rastreabilidade de SHA origem → destino.

**[²] Rastreabilidade — ADR 0044-B (Gateway Context Enrichment v1):**  
Este artefato foi sucedido em escopo e isolamento multi-tenant pela especificação desduplicada e expandida contida no ADR 0076. A entrada dupla em 0044 preserva a rastreabilidade histórica da decisão original.

**[³] Localização — ADR 0072 (Gilligan SLA Mercy Algorithm):**  
Disponível em versão traduzida complementar para auditoria internacional em [0072-gilligan-sla-mercy-algorithm.en.md](0072-gilligan-sla-mercy-algorithm.en.md). O arquivo `.md` pt-BR é o canônico; o `.en.md` é suplementar.

**[⁴] Rastreabilidade — ADR 0046-B (ML Prompt Injection Layer v1):**  
Este artefato foi sucedido pela especificação canônica multi-tenant no ADR 0077.

**[⁵] Rastreabilidade — ADR 0047-B (Semantic PII NER v1):**  
Este artefato foi sucedido pela especificação canônica no ADR 0078.

**[⁶] Rastreabilidade — ADR 0048-B (Transactional Effect Buffering v1):**  
Versão v2 expandida registrada no ADR 0068.

**[⁷] Rastreabilidade — ADR 0057-B (Protocol Designer v1):**  
Este artefato foi sucedido pela especificação canônica no ADR 0080.

**[⁸] Rastreabilidade — ADR 0060-B (SaaS Deployment v1):**  
Este artefato foi sucedido pela especificação canônica no ADR 0081.

---

## Documentos Auxiliares

> Arquivos que não seguem o padrão `NNNN-slug.md` mas integram o corpus de governança arquitetural do repositório.

| Arquivo | Descrição | Idioma |
|:---|:---|:---:|
| [reserved_metadata_layout.md](reserved_metadata_layout.md) | Layout de metadados reservados para cabeçalhos de ADR | pt-BR |
| [reserved_metadata_layout.en.md](reserved_metadata_layout.en.md) | Layout de metadados reservados (versão internacional) | en |

---

## Runbooks Operacionais

> Procedimentos de contingência vinculados à arquitetura BTV. Mantidos em `docs/runbooks/` e indexados aqui para rastreabilidade entre decisões arquiteturais e resposta operacional.

| ID | Título | Arquivo | Status | Responsável |
|:---|:---|:---|:---:|:---:|
| BTV-RUN-008 | Retenção, Custódia e Cripto-Shredding | [docs/runbooks/BTV-RUN-008.md](../runbooks/BTV-RUN-008.md) | ✅ Ativo | DPO / SecOps / SRE |
| BTV-RUN-009 | Auditoria de Integridade Criptográfica e Verificação Forense | [docs/runbooks/BTV-RUN-009.md](../runbooks/BTV-RUN-009.md) | ✅ Ativo | SecOps / SRE / Core Security |
| BTV-RUN-010 | Resposta a Incidentes de Poluição Cruzada entre Tenants (E120) | [docs/runbooks/BTV-RUN-010.md](../runbooks/BTV-RUN-010.md) | ✅ Ativo | CSIRT / SecOps / SRE |

---

## 🗂️ Histórico de Depreciação e Supersessão (Archive)

> Artefatos custodiados em `docs/adr/archive/`. Estes arquivos foram expurgados da numeração ativa por obsolescência, duplicação de conteúdo ou status de rascunho não promovido. São mantidos para rastreabilidade forense completa e auditoria histórica. Nenhum linter de link deve considerar a ausência destes arquivos no índice ativo como não-conformidade.

| Arquivo | Motivo de Arquivamento | Status |
|:---|:---|:---:|
| [archive/0002-evidence-protocol-v1-obsolete.md](archive/0002-evidence-protocol-v1-obsolete.md) | Versão v1 do Evidence Protocol. Supersedida pelo ADR 0005 (Evidence Protocol v2 — Tamanho Fixo Canônico). Mantida para rastreabilidade de decisão. | ⚠️ Obsoleto |
| [archive/ADR-043-grant-decision-adapter.md](archive/ADR-043-grant-decision-adapter.md) | Rascunho zumbi com slug de numeração não-canônica (`ADR-NNN`). Conteúdo absorvido e formalizado no ADR 0057 e posteriormente no ADR 0073 (canônico). | ⚠️ Obsoleto |
| [archive/ADR-051.md](archive/ADR-051.md) | Rascunho zumbi com slug de numeração não-canônica. Conteúdo formalizado no ADR 0074 (Model Integrity — Abliteration Detection v2). | ⚠️ Obsoleto |
| [archive/TBD-grant-decision-adapter.md](archive/TBD-grant-decision-adapter.md) | Rascunho sem numeração atribuída (`TBD`). Conteúdo absorvido pelo ADR 0073. Mantido como evidência de iteração de design. | ⚠️ Obsoleto |
| [archive/README.md](archive/README.md) | Descritor de navegação interno do diretório archive/. Não é um ADR; serve como guia de orientação para auditores que acessam o diretório diretamente. | 📄 Auxiliar |

---

## Registro de Revisões deste Índice

| Versão | Data | HEAD | Alteração |
|:---|:---|:---|:---|
| v1.0.0 | 2026-01-01 | — | Criação inicial |
| v4.0.0 | 2026-05-27 | `07c32c6` | Adição dos ADRs 0073–0081 (commit de deduplicação multi-tenant) |
| v4.1.0 | 2026-05-28 | `0f2b728` | Reconstrução total: correção de slugs fantasmas Grupo K, errata forense 0044/0045/0072, expurgo de 3 arquivos zumbis (`ADR-043`, `ADR-051`, `TBD`), inclusão de documentos auxiliares e seção de runbooks operacionais |
| v4.1.1 | 2026-05-28 | `83b006c` | Correção de drift inverso: BTV-RUN-010 já existia no disco (não estava pendente); BTV-RUN-009 materializado; entradas da seção Runbooks agora refletem o estado real de `docs/runbooks/` |
| v4.2.0 | 2026-05-28 | `24c9190` | Auditoria forense retroativa completa: ADRs 0011–0016 retificados para status ⚠️ Stub (densidade de conteúdo insuficiente detectada); seção '🗂️ Histórico de Depreciação e Supersessão (Archive)' adicionada com os 5 artefatos reais de `docs/adr/archive/` catalogados; coluna Status adicionada à tabela de Runbooks; legenda expandida com símbolo Stub. Débito técnico documental zerado em totalidade forense. |
