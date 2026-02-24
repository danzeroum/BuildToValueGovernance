
# ADR-0030 — Perfil de Integração BTV: Chatbot Interno com LLM Self-Hosted

| Campo         | Valor                                            |
|:--------------|:-------------------------------------------------|
| **ID**        | 0030                                             |
| **Status**    | 🔒 Proposto                                      |
| **Padrão**    | BTV ADR-0029 (External Agent PDP)                |
| **Alvo**      | BTV v2.0+ / Chatbot Interno v1.0+                |
| **Autores**   | Arquiteta BTV                                    |
| **Data**      | 2026-02-23                                       |
| **Revisores** | Reviewer (Opus) — conformidade ADR + invariantes |

---

## 1. Contexto

Um chatbot corporativo interno com LLM self-hosted (Llama 3.3 70B via
vLLM) apresenta uma arquitetura de múltiplas camadas:

- **Frontend Angular**: filtragem client-side de PII, classificação de
  conteúdo, coleta de feedback (thumbs up/down/corrección).
- **Backend Rust (Axum)**: pipeline RAG (Qdrant), prompt builder, handler
  de streaming SSE, coleta de interações para treinamento.
- **Pipeline de treinamento contínuo (Python/Unsloth)**: ciclo semanal
  que coleta dados aprovados, gera QA sintético, treina LoRA incremental,
  avalia e faz hot-swap no vLLM.
- **Multi-tenancy**: dados isolados por `workspace_id`; cada empresa é
  um workspace.

O sistema já possui mecanismos internos: `DataFilterService` (Angular),
`sanitizer.interceptor`, `audit_log` em PostgreSQL e relatório LGPD
gerado internamente.

**O problema central:** todos esses controles residem no mesmo trust
boundary que os dados que controlam. Um audit log no mesmo banco de dados
que os dados do chat não é evidência forense defensável. Uma política de
PII aplicada pelo mesmo processo que envia a mensagem ao LLM não é
verificável externamente. O deploy de um LoRA que modifica o comportamento
do modelo em produção sem rastro forense externo é um risco regulatório
(LGPD Art. 5–6, EU AI Act).

Esta ADR define o perfil de integração do chatbot com o BTV como PDP
externo, seguindo o padrão canônico do ADR-0028, adaptado para os
ciclos específicos de RAG, curadoria e fine-tuning contínuo.

---

## 2. Decisão

O chatbot integra o BTV como PDP externo em **cinco gates**,
ordenados por criticidade:

1. **Gate de Transmissão** — mensagens com PII ou classificação ≥
   `CONFIDENTIAL` passam por `POST /v1/validate` antes de chegar ao LLM.
2. **Gate de Indexação** — documentos `CONFIDENTIAL`/`RESTRICTED` passam
   por `POST /v1/validate` antes de serem indexados no Qdrant.
3. **Gate de Contexto RAG** — chunks candidatos à injeção no prompt
   passam por `POST /v1/validate` para detecção de prompt injection.
4. **Gate de Treinamento** — aprovação de batch de treinamento (início
   do ciclo de fine-tune) requer veredicto BTV.
5. **Gate de Deploy** — hot-swap de LoRA no vLLM é `Irreversible`; exige
   `VerdictEnvelope` válido com HMAC antes de ocorrer.

**Invariante adicionado ao chatbot:**
> Nenhum dado `CONFIDENTIAL`/`RESTRICTED` alcança o LLM, o Qdrant ou
> um dataset de treinamento sem `evidence_id` BTV registrado.
> Nenhum LoRA entra em produção sem `VerdictEnvelope` com HMAC válido.

---

## 3. Taxonomia de Ações do Chatbot

```rust
/// Classificação de ações do chatbot para o contrato BTV ADR-0028.
/// Ausência de classificação = Irreversible (fail-secure).
pub enum ChatbotActionImpact {
    /// Leitura pura; sem dado sensível; sem efeito externo.
    Safe,
    /// Modifica estado; revertível (ex: indexar doc INTERNAL com backup).
    Destructive,
    /// Efeito permanente: deploy de modelo, export de dados, envio
    /// de dado RESTRICTED ao LLM.
    Irreversible,
}
```

| Ação do chatbot                        | Impact         | Gate BTV? |
|:---------------------------------------|:---------------|:----------|
| Mensagem `PUBLIC`/`INTERNAL` sem PII   | Safe           | ❌        |
| Mensagem com PII detectado             | Destructive    | ✅        |
| Mensagem classificação `CONFIDENTIAL`  | Destructive    | ✅        |
| Mensagem classificação `RESTRICTED`    | Irreversible   | ✅        |
| Upload doc `PUBLIC`/`INTERNAL`         | Safe           | ❌        |
| Upload doc `CONFIDENTIAL`              | Destructive    | ✅        |
| Upload doc `RESTRICTED`               | Irreversible   | ✅        |
| Chunk RAG injetado no prompt           | Destructive    | ✅        |
| Aprovação de batch de treinamento      | Destructive    | ✅        |
| Deploy de novo LoRA (hot-swap vLLM)    | Irreversible   | ✅        |
| Export de conversa/documento           | Irreversible   | ✅        |
| Geração de relatório LGPD              | Destructive    | ✅        |
| Consulta de usuário sem dados sensíveis| Safe           | ❌        |

---

## 4. Contrato de Comunicação

O chatbot segue o schema `AgentDecisionRequest` / `AgentDecisionResponse`
definido no ADR-0028. Os campos específicos deste perfil estão em
`agent_metadata`.

### 4.1 agent_id canônico

```
agent_id = "chatbot-internal-" + BLAKE3(workspace_id + version)[..16]
```

Cada workspace tem seu próprio `agent_id`; garante rastreabilidade
por empresa no DurableLedger do BTV.

### 4.2 profile_id e sector_id

```json
"profile_id": "internal-chatbot",
"sector_id": "<finance|health|legal|hr|general>"
```

`sector_id` é configurado por workspace no onboarding. Workspaces do
setor `health` e `legal` recebem políticas mais restritivas no BTV
(configuradas via YAML de policy).

### 4.3 agent_metadata obrigatório

```json
"agent_metadata": {
  "workspace_id": "<uuid>",
  "data_classification": "PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED",
  "pii_detected": true,
  "pii_types": ["CPF", "EMAIL"],
  "eligible_for_training": false,
  "rag_context": false,
  "action_subtype": "message|document_upload|rag_inject|training_batch|lora_deploy|export"
}
```

- `data_classification`: classificação do conteúdo, conforme regras
  do workspace.
- `pii_detected`: flag do `DataFilterService` angular ou do backend.
- `eligible_for_training`: false se a mensagem contém PII ou é
  `RESTRICTED`; o BTV registra no Evidence para auditoria futura.
- `action_subtype`: permite ao BTV aplicar política YAML específica
  por tipo de ação dentro do mesmo chatbot.

---

## 5. Gates Detalhados

### Gate 1 — Transmissão de Mensagem ao LLM

```
Frontend (Angular)
    │
    ├─ DataFilterService.processMessage()
    │       │
    │       ├─[PII detectado ou class ≥ CONFIDENTIAL]
    │       │       │
    │       │  POST /v1/validate
    │       │  action.name: "llm_message_send"
    │       │  action.impact: Destructive | Irreversible
    │       │  parameters_hash: BLAKE3(mensagem_sanitizada)
    │       │       │
    │       │  ALLOW ──► Backend Rust ──► vLLM
    │       │  EDUCATE ─► Backend Rust ──► vLLM + log explain_decision
    │       │  BLOCK ──► Feedback ao usuário com explain_decision
    │       │
    │       └─[PUBLIC/INTERNAL sem PII] ──► Backend direto
```

**Detalhe crítico:** `parameters_hash` contém o BLAKE3 da mensagem
já sanitizada (após `/v1/sanitize`), não da mensagem original.
A ordem é: sanitizar → hash → validar. Isso garante que o Evidence
no BTV referencia o dado limpo, não o dado com PII.

### Gate 2 — Indexação de Documento

```rust
// Chamada obrigatória antes de chunks serem enviados ao Qdrant
pub async fn gate_document_indexing(
    doc: &DocumentMetadata,
    btv: &dyn BTVClient,
) -> Result<EvidenceId, IndexingError> {
    if doc.classification < Classification::Confidential {
        return Ok(EvidenceId::skipped()); // Safe — sem gate
    }

    let req = AgentDecisionRequest {
        action: Action {
            name: "document_index".into(),
            impact: match doc.classification {
                Classification::Confidential => ActionImpact::Destructive,
                Classification::Restricted   => ActionImpact::Irreversible,
                _                            => unreachable!(),
            },
            capabilities: vec!["vector_db_write".into()],
        },
        agent_metadata: metadata_for_doc(doc),
        ..base_request(doc.workspace_id)
    };

    let envelope = btv.request_decision(&req).await
        .map_err(|_| IndexingError::BtvUnavailable)?; // fail-secure

    verify_verdict(&envelope, &btv.hmac_key())?;

    match envelope.verdict {
        Verdict::Allow | Verdict::Educate => Ok(envelope.evidence_id),
        Verdict::Block => Err(IndexingError::Blocked(envelope.explain_decision)),
    }
}
```

O `evidence_id` retornado é armazenado como metadado do documento no
PostgreSQL: `documents.btv_evidence_id`. Em auditoria futura: "quem
autorizou que este documento confidencial entrou na base vetorial?"
→ busca por `evidence_id` no DurableLedger do BTV.

### Gate 3 — Contexto RAG (Anti-Prompt Injection)

Este gate protege contra o "confused document attack": um documento
malicioso indexado que tenta injetar instruções no prompt do LLM.

```rust
// Chamada para cada chunk candidato, antes da injeção no prompt.
// Executa em paralelo para os top-K chunks retornados pelo Qdrant.
pub async fn gate_rag_chunks(
    chunks: Vec<RagChunk>,
    btv: &dyn BTVClient,
) -> Vec<RagChunk> {
    // Anti-padrão proibido: coletar evidências sem verificar HMAC.
    let mut safe_chunks = Vec::with_capacity(chunks.len());

    for chunk in chunks {
        let req = build_rag_request(&chunk);
        match btv.request_decision(&req).await {
            Ok(envelope) if verify_verdict(&envelope, &btv.hmac_key()).is_ok() => {
                match envelope.verdict {
                    Verdict::Allow | Verdict::Educate => safe_chunks.push(chunk),
                    Verdict::Block => {
                        // Chunk excluído do contexto; evidence_id registrado
                        log_blocked_chunk(&chunk, &envelope.evidence_id);
                    }
                }
            }
            // Falha de comunicação ou HMAC inválido = chunk excluído
            _ => log_chunk_gate_failure(&chunk),
        }
    }
    safe_chunks
}
```

**Configuração recomendada no YAML de política:**
```yaml
# data/policies/chatbot-rag-injection.yaml
rules:
  - name: block_prompt_injection_patterns
    action: "rag_chunk_inject"
    conditions:
      content_patterns:
        - "ignore previous instructions"
        - "você é agora"
        - "system: "
        - "INST]"
    verdict: BLOCK
    explain: "Padrão de prompt injection detectado no chunk RAG."
```

### Gate 4 — Início de Ciclo de Treinamento

```python
# training/continuous_trainer.py — integração BTV
class ContinuousTrainer:
    async def run_training_cycle(self):
        stats = await self.collect_approved_stats()

        if stats.total < self.config["min_examples"]:
            return  # Não atinge threshold mínimo

        # Gate BTV antes de iniciar o ciclo
        request = {
            "agent_id": self.agent_id,
            "action": {
                "name": "training_cycle_start",
                "impact": "Destructive",
                "capabilities": ["model_training", "gpu_allocation"]
            },
            "parameters_hash": blake3(json.dumps(stats.summary)),
            "parameters_preview": {
                "total_examples": stats.total,
                "positive_pct": stats.positive_pct,
                "synthetic_pct": stats.synthetic_pct,
                "negative_pct": stats.negative_pct,
                "base_lora_version": stats.current_lora
            },
            "agent_metadata": {
                "workspace_id": self.workspace_id,
                "action_subtype": "training_batch",
                "data_classification": "INTERNAL",
                "pii_detected": stats.pii_detected_count > 0,
                "eligible_for_training": True
            }
        }

        verdict = await self.btv_client.validate(request)

        if verdict["verdict"] == "BLOCK":
            logger.warning(
                f"Ciclo de treino bloqueado: {verdict['explain_decision']}"
            )
            return  # Fail-secure: não treina sem aprovação

        # evidence_id registrado no training_batch antes de iniciar
        await self.db.update_batch_evidence(
            batch_id=self.current_batch_id,
            evidence_id=verdict["evidence_id"]
        )
        await self.train_lora(stats)
```

**BiasDeclaration** é especialmente útil aqui: o BTV registra no
Evidence os campos `false_positive_rate_pct` e `known_limitations`
do processo de validação de QA — documentando formalmente a qualidade
estatística dos dados que entraram no treinamento.

### Gate 5 — Deploy de LoRA (Hot-Swap vLLM)

Este é o gate mais crítico: `Irreversible` por natureza.
O LoRA modifica o comportamento do modelo de produção para
todos os usuários do workspace, sem possibilidade de rollback
instantâneo transparente.

```python
async def deploy_lora(
    self,
    new_version: str,
    eval_metrics: dict
) -> None:
    """
    Deploy NUNCA ocorre sem VerdictEnvelope BTV válido.
    Fail-secure: qualquer erro = não deploy.
    """
    request = {
        "agent_id": self.agent_id,
        "action": {
            "name": "lora_deploy",
            "impact": "Irreversible",
            "capabilities": [
                "model_hot_swap",
                "production_write",
                "vllm_adapter_load"
            ]
        },
        "parameters_hash": blake3(f"{new_version}{json.dumps(eval_metrics)}"),
        "parameters_preview": {
            "new_lora_version": new_version,
            "eval_accuracy": eval_metrics["accuracy"],
            "eval_groundedness": eval_metrics["groundedness"],
            "eval_refusal_accuracy": eval_metrics["refusal_accuracy"],
            "training_loss": eval_metrics["training_loss"],
            "examples_trained": eval_metrics["total_examples"],
            "benchmark_vs_previous": eval_metrics["improvement_pct"]
        },
        "agent_metadata": {
            "workspace_id": self.workspace_id,
            "action_subtype": "lora_deploy",
            "data_classification": "INTERNAL",
            "pii_detected": False,
            "eligible_for_training": False
        }
    }

    try:
        verdict = await self.btv_client.validate(request)
    except Exception as e:
        logger.critical(f"BTV indisponível no gate de deploy: {e}")
        # Fail-secure absoluto: BTV down = deploy bloqueado
        raise DeployBlockedError("BTV unavailable — deploy aborted")

    if verdict["verdict"] == "BLOCK":
        logger.warning(
            f"Deploy LoRA {new_version} bloqueado: "
            f"{verdict['explain_decision']}"
        )
        await self.notify_operator(verdict)
        raise DeployBlockedError(verdict["explain_decision"])

    # HMAC verificado antes de confiar no veredicto
    if not verify_hmac(verdict, self.btv_hmac_key):
        raise DeployBlockedError("HMAC inválido — deploy aborted")

    # evidence_id persistido antes do hot-swap
    await self.db.record_deploy_evidence(
        lora_version=new_version,
        evidence_id=verdict["evidence_id"],
        policy_version=verdict["policy_version_applied"]
    )

    # Apenas agora o hot-swap ocorre
    await self.vllm_client.load_lora(new_version)
    logger.info(f"LoRA {new_version} em produção. Evidence: {verdict['evidence_id']}")
```

**Política YAML recomendada para deploy:**
```yaml
# data/policies/chatbot-lora-deploy.yaml
rules:
  - name: require_minimum_accuracy
    action: "lora_deploy"
    conditions:
      parameters_preview.eval_accuracy: { gte: 0.80 }
      parameters_preview.eval_groundedness: { gte: 0.75 }
      parameters_preview.eval_refusal_accuracy: { gte: 0.85 }
      parameters_preview.benchmark_vs_previous: { gte: -0.02 }
    verdict: ALLOW

  - name: block_regression
    action: "lora_deploy"
    conditions:
      parameters_preview.benchmark_vs_previous: { lt: -0.05 }
    verdict: BLOCK
    explain: "Regressão de qualidade > 5% vs versão anterior. Rollback recomendado."

  - name: block_low_refusal
    action: "lora_deploy"
    conditions:
      parameters_preview.eval_refusal_accuracy: { lt: 0.70 }
    verdict: BLOCK
    explain: "Taxa de recusa insuficiente. Risco de alucinação em perguntas fora do domínio."
```

---

## 6. Sanitização como Evidência LGPD

Para o relatório LGPD, o chatbot passa a ter **dois níveis de evidência**:

**Nível 1 — Interno (operacional):**
- `pii_stats.total_anonymized` no PostgreSQL.
- `audit_log` interno (como hoje).

**Nível 2 — Externo verificável (forense):**
- Cada chamada ao `/v1/sanitize` gera um `evidence_id` no
  DurableLedger BTV com BLAKE3 + HMAC.
- O relatório LGPD passa a incluir a série de `evidence_id`s como
  prova de sanitização — verificáveis independentemente, à prova
  de adulteração.

```rust
/// Sanitização com evidência forense.
/// Substitui o anonymizer.service.ts como fonte de verdade para LGPD.
pub async fn sanitize_with_evidence(
    raw: &str,
    btv: &dyn BTVClient,
    workspace_id: WorkspaceId,
) -> Result<SanitizedMessage, SanitizeError> {
    let sanitized = btv.sanitize_output(raw).await
        .map_err(|_| SanitizeError::BtvUnavailable)?;

    // evidence_id persistido na tabela de interações
    Ok(SanitizedMessage {
        content: sanitized.content,
        evidence_id: sanitized.evidence_id,
        pii_types_found: sanitized.pii_types,
        workspace_id,
    })
}
```

---

## 7. Contestabilidade no Contexto do Chatbot

Três cenários de contestação são relevantes:

**7a. Mensagem bloqueada (LGPD Art. 18 — direito de acesso)**
O usuário pode contestar o bloqueio de sua mensagem via
`POST /v1/appeals`. O `explain_decision` é apresentado em linguagem
natural na UI. O operador (admin do workspace) aprova ou rejeita
o recurso dentro do SLA de 24h.

**7b. Deploy de LoRA bloqueado**
A equipe de ML pode contestar o bloqueio de um deploy via
`POST /v1/appeals`, com justificativa técnica. O BTV registra a
contestação, o árbitro humano avalia e o `evidence_id` da decisão
final fica no DurableLedger.

**7c. Documento bloqueado para indexação**
O dono do documento pode contestar via UI do chatbot, que enfileira
um `POST /v1/appeals` com o `evidence_id` do bloqueio.

---

## 8. Métricas Exportadas

```
btv_chatbot_requests_total{gate, workspace_id, verdict}
btv_chatbot_lora_deploy_total{workspace_id, verdict, lora_version}
btv_chatbot_rag_blocks_total{workspace_id, reason}
btv_chatbot_pii_sanitized_total{workspace_id, pii_type}
btv_chatbot_training_cycle_total{workspace_id, verdict}
btv_chatbot_circuit_open{workspace_id}
btv_chatbot_evidence_ids_generated_total{workspace_id, gate}
```

---

## 9. Invariantes desta ADR

1. **Sem `evidence_id` → sem indexação de dado sensível.** Documentos
   `CONFIDENTIAL`/`RESTRICTED` sem `evidence_id` BTV não entram no
   Qdrant.
2. **Sem `evidence_id` → sem deploy de LoRA.** Hot-swap vLLM exige
   `evidence_id` persistido antes da chamada de swap.
3. **Sanitização antes do hash.** `parameters_hash` no
   `AgentDecisionRequest` sempre referencia o dado já sanitizado.
4. **TTL zero para `Irreversible`.** Nenhum veredicto de deploy de LoRA
   ou de mensagem `RESTRICTED` é cacheado.
5. **`eligible_for_training: false` para dados com PII.** Dado que passa
   pelo gate com `pii_detected: true` é automaticamente marcado como
   não-elegível para treinamento — registrado no Evidence.
6. **BiasDeclaration obrigatória em gates de treinamento.** O BTV
   registra `false_positive_rate_pct` e `known_limitations` no Evidence
   de todo gate de `training_cycle_start` e `lora_deploy`.
7. **Fail-secure absoluto em todos os gates.** BTV indisponível =
   BLOCK local. Jamais permitir por omissão.

---

## 10. Consequências

**Positivas:**
- DurableLedger do BTV substitui "confie no nosso log interno" por
  "aqui está a evidência forense verificável externamente" — útil
  em auditorias LGPD, ANPD e contratos enterprise.
- Policy-as-Code (YAML) permite que o time de compliance configure
  regras de deploy de modelo sem tocar em código: só edita o YAML
  e o BTV aplica na próxima tentativa.
- A `BiasDeclaration` nos gates de treinamento documenta formalmente
  a qualidade estatística de cada ciclo — rastreabilidade do modelo
  ao longo do tempo.
- Cada workspace pode ter `sector_id` diferente, recebendo políticas
  proporcionais ao seu nível de risco.

**Negativas:**
- Latência adicional nos gates (~10–15 ms por chamada BTV).
  Mitigada: gate de mensagem só ocorre para `CONFIDENTIAL`+, que
  é minoria do volume total.
- Gate de RAG (por chunk) pode impactar latência do chat.
  Mitigação: paralelizar validações dos top-K chunks; cache de
  TTL curto para chunks repetidos da mesma sessão.
- Operação de dois sistemas (chatbot + BTV).
  Mitigada por modo sidecar Docker Compose para dev.

---

## 11. Critérios de Aceitação

- [ ] Gate 1 implementado: mensagem `CONFIDENTIAL` bloqueada sem BTV
      nunca chega ao vLLM.
- [ ] Gate 2 implementado: `evidence_id` presente em 100% dos
      documentos `CONFIDENTIAL`/`RESTRICTED` no PostgreSQL.
- [ ] Gate 3 implementado: chunk com padrão de injection retorna
      `BLOCK` e é excluído do contexto RAG.
- [ ] Gate 4 implementado: `training_batch.btv_evidence_id` preenchido
      antes de qualquer ciclo de fine-tune iniciar.
- [ ] Gate 5 implementado: deploy de LoRA sem `evidence_id` válido
      lança `DeployBlockedError`.
- [ ] Teste: BTV indisponível → deploy bloqueado (fail-secure).
- [ ] Teste: HMAC inválido no veredicto → deploy bloqueado.
- [ ] Teste: LoRA com `benchmark_vs_previous < -0.05` → `BLOCK`
      via política YAML.
- [ ] Teste: mensagem com CPF → `pii_detected: true` →
      `eligible_for_training: false` persistido.
- [ ] Relatório LGPD inclui `evidence_id`s BTV como evidência forense.
- [ ] Métricas `btv_chatbot_*` visíveis no dashboard de observabilidade.
- [ ] `docs/integrations/chatbot-internal-llm.md` criado.
- [ ] ADR registrado no `0000-adr-index.md`.

---

## 12. Referências Cruzadas

- BTV ADR-0028 (External Agent PDP — contrato canônico)
- BTV ADR-0004 (Immutable Ledger — DurableLedger BLAKE3)
- BTV ADR-0005 (Evidence Protocol v2.1 — 9596 bytes)
- BTV ADR-0006 (Policy-as-Code — YAML)
- BTV ADR-0010 (BiasDeclaration Mandate)
- BTV ADR-0017 (ContestabilityLoop SLA 24h)
- `docs/integrations/chatbot-internal-llm.md` (perfil de integração)
- ADR-0030 (a criar — variante com LLM externa)
- Chatbot ADR-001 a ADR-034 (decisões do lado chatbot)
```
