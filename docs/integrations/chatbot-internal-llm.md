# Perfil de Integração BTV: Chatbot Interno com LLM Self-Hosted

| Campo               | Valor                                        |
|:--------------------|:---------------------------------------------|
| **Padrão**          | BTV ADR-0029 (External Agent PDP)            |
| **ADR deste perfil**| BTV ADR-0030                                 |
| **Versão chatbot**  | v1.0+ (Rust/Axum + Angular + Python/Unsloth) |
| **Versão BTV**      | v2.0+                                        |
| **Mantenedor**      | Equipe Chatbot Interno                       |
| **Data**            | 2026-02-23                                   |
| **Próximo perfil**  | `chatbot-external-llm.md` (ADR-0030)         |

---

## 1. Visão Geral do Sistema

O chatbot corporativo interno opera com a seguinte stack:

```
┌─────────────────────────────────────────────────────┐
│  Frontend Angular                                   │
│  DataFilterService → sanitizer.interceptor          │
│  audit.interceptor → feedback-panel                 │
└───────────────────────┬─────────────────────────────┘
                        │ HTTP/SSE
┌───────────────────────▼─────────────────────────────┐
│  Backend Rust (Axum)                                │
│  auth middleware → RAG pipeline (Qdrant)            │
│  prompt builder → vLLM streaming handler            │
│  training_interactions collector                    │
└──────┬────────────────┬────────────────┬────────────┘
       │                │                │
  ┌────▼────┐    ┌──────▼──────┐  ┌─────▼──────┐
  │ Qdrant  │    │ PostgreSQL  │  │  vLLM GPU  │
  │(vetores)│    │  (relac.)   │  │ Llama 70B  │
  └─────────┘    └─────────────┘  └────────────┘
                        │
┌───────────────────────▼─────────────────────────────┐
│  Pipeline Treinamento (Python/Unsloth)              │
│  ContinuousTrainer → QA Sintético → LoRA → vLLM    │
└─────────────────────────────────────────────────────┘
```

O BTV atua como **camada externa de governança** entre cada componente
sensível, sem residir dentro de nenhum deles.

---

## 2. agent_id Canônico

```rust
// crates/btv-client/src/identity.rs

use blake3::Hasher;

/// Derivação estável do agent_id por workspace.
/// Não muda entre reinicializações da mesma instância.
pub fn derive_agent_id(workspace_id: &WorkspaceId, version: &str) -> String {
    let mut hasher = Hasher::new();
    hasher.update(workspace_id.as_bytes());
    hasher.update(b":");
    hasher.update(version.as_bytes());
    let hash = hasher.finalize();
    format!("chatbot-internal-{}", &hash.to_hex()[..16])
}

// Exemplo:
// workspace_id: "ws_abc123"  version: "1.0.0"
// agent_id:     "chatbot-internal-f3a8c91d04e72b5a"
```

Cada workspace gera um `agent_id` distinto. Isso garante que o
DurableLedger do BTV correlacione evidências por empresa, não por
instância de servidor.

---

## 3. Mapeamento Completo de Ações → ActionImpact

### 3.1 Ações de Chat e Mensagens

| Ação                                   | `action.name`              | Impact         | Gate? |
|:---------------------------------------|:---------------------------|:---------------|:------|
| Mensagem `PUBLIC`/`INTERNAL` sem PII   | `chat_message_send`        | Safe           | ❌    |
| Mensagem com PII detectado             | `chat_message_send_pii`    | Destructive    | ✅    |
| Mensagem classificação `CONFIDENTIAL`  | `chat_message_confidential`| Destructive    | ✅    |
| Mensagem classificação `RESTRICTED`    | `chat_message_restricted`  | Irreversible   | ✅    |
| Export de conversa (PDF/MD)            | `chat_export`              | Irreversible   | ✅    |
| Exclusão de conversa                   | `chat_delete`              | Destructive    | ✅    |

### 3.2 Ações de Documentos e RAG

| Ação                                   | `action.name`              | Impact         | Gate? |
|:---------------------------------------|:---------------------------|:---------------|:------|
| Upload doc `PUBLIC`/`INTERNAL`         | `document_upload`          | Safe           | ❌    |
| Upload doc `CONFIDENTIAL`              | `document_upload_conf`     | Destructive    | ✅    |
| Upload doc `RESTRICTED`               | `document_upload_restr`    | Irreversible   | ✅    |
| Chunk RAG injetado no prompt           | `rag_chunk_inject`         | Destructive    | ✅    |
| Export de documento original           | `document_export`          | Irreversible   | ✅    |
| Exclusão de documento                  | `document_delete`          | Destructive    | ✅    |

### 3.3 Ações de Treinamento e Modelo

| Ação                                   | `action.name`              | Impact         | Gate? |
|:---------------------------------------|:---------------------------|:---------------|:------|
| Aprovação de QA para dataset           | `training_qa_approve`      | Destructive    | ✅    |
| Início de ciclo de fine-tuning         | `training_cycle_start`     | Destructive    | ✅    |
| Deploy de LoRA (hot-swap vLLM)         | `lora_deploy`              | Irreversible   | ✅    |
| Rollback de LoRA                       | `lora_rollback`            | Irreversible   | ✅    |
| Export de dataset de treinamento       | `training_dataset_export`  | Irreversible   | ✅    |

### 3.4 Ações Administrativas

| Ação                                   | `action.name`              | Impact         | Gate? |
|:---------------------------------------|:---------------------------|:---------------|:------|
| Suspensão de usuário                   | `user_suspend`             | Destructive    | ✅    |
| Alteração de role/permissão            | `user_role_change`         | Destructive    | ✅    |
| Revogação de API key                   | `api_key_revoke`           | Irreversible   | ✅    |
| Exclusão em massa (`bulk_delete`)      | `bulk_delete`              | Irreversible   | ✅    |
| Alteração de política de dados         | `data_policy_change`       | Irreversible   | ✅    |
| Geração de relatório LGPD              | `lgpd_report_generate`     | Destructive    | ✅    |

---

## 4. Configuração de profile_id e sector_id

```yaml
# Configurado no onboarding do workspace — salvo em workspaces.btv_config
profile_id: "internal-chatbot"

# Mapeamento por tipo de empresa:
sector_id:
  juridico:    "legal"
  saude:       "health"
  financeiro:  "finance"
  rh:          "hr"
  geral:       "general"
  tecnologia:  "general"
```

**Impacto do `sector_id` nas políticas BTV:**

| `sector_id` | Política aplicada                              |
|:------------|:-----------------------------------------------|
| `legal`     | Threshold de groundedness mais alto (≥ 0.85); bloqueia RAG com padrões de injection em PTBR jurídico |
| `health`    | Bloqueia `eligible_for_training: true` se PII de saúde detectado; threshold de refusal ≥ 0.90 |
| `finance`   | Bloqueia export sem MFA confirmado; threshold de accuracy ≥ 0.85 |
| `hr`        | Bloqueia mensagens com CPF/dados de RH para treino automático |
| `general`   | Política padrão do BTV |

---

## 5. Implementação dos 5 Gates

### Gate 1 — Transmissão de Mensagem ao LLM (Frontend + Backend)

**Angular — `btv-gate.service.ts`:**

```typescript
// core/services/btv-gate.service.ts
import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { WorkspaceContextService } from './workspace-context.service';
import { DataFilterService, FilteredMessage } from './data-filter.service';

export interface VerdictEnvelope {
  request_id: string;
  verdict: 'ALLOW' | 'EDUCATE' | 'BLOCK';
  verdict_code: number;
  explain_decision: string;
  bias_declaration: {
    false_positive_rate_pct: number;
    false_negative_rate_pct: number;
    calibration_date: string;
    known_limitations: string;
  };
  contestable: boolean;
  appeal_deadline_utc: string;
  policy_version_applied: string;
  evidence_id: string;
  hmac_sha256: string;
  timestamp_utc: string;
}

@Injectable({ providedIn: 'root' })
export class BtvGateService {
  private readonly http = inject(HttpClient);
  private readonly ctx = inject(WorkspaceContextService);
  private readonly filter = inject(DataFilterService);

  /**
   * Gate 1: valida mensagem antes de enviar ao backend/LLM.
   * Chamado apenas quando pii_detected=true ou class >= CONFIDENTIAL.
   * Mensagens Safe passam direto — nunca chamar BTV desnecessariamente.
   */
  async validateMessage(filtered: FilteredMessage): Promise<VerdictEnvelope> {
    const workspace = this.ctx.current();

    const request = {
      schema_version: '1.0',
      request_id: crypto.randomUUID(),
      agent_id: workspace.btvAgentId,
      session_id: workspace.sessionId,
      action: {
        name: filtered.piiDetected
          ? 'chat_message_send_pii'
          : `chat_message_${filtered.classification.toLowerCase()}`,
        impact: filtered.classification === 'RESTRICTED'
          ? 'Irreversible'
          : 'Destructive',
        capabilities: ['llm_message_send']
      },
      // hash da mensagem JÁ sanitizada — nunca hash do original
      parameters_hash: await this.blake3(filtered.content),
      parameters_preview: {
        message_length: filtered.content.length,
        classification: filtered.classification,
        pii_types: filtered.piiTypes
      },
      context: {
        profile_id: 'internal-chatbot',
        sector_id: workspace.sectorId,
        session_trust_score: workspace.trustScore ?? 0.5,
        agent_metadata: {
          workspace_id: workspace.workspaceId,
          data_classification: filtered.classification,
          pii_detected: filtered.piiDetected,
          pii_types: filtered.piiTypes,
          eligible_for_training: filtered.eligibleForTraining,
          rag_context: false,
          action_subtype: 'message'
        }
      },
      timestamp_utc: new Date().toISOString()
    };

    return firstValueFrom(
      this.http.post<VerdictEnvelope>('/api/btv/validate', request)
    );
  }

  /**
   * Apresenta o resultado do veredicto ao usuário.
   * BLOCK: mostra explain_decision + opção de contestar.
   * EDUCATE: permite envio mas registra aviso.
   */
  handleVerdict(verdict: VerdictEnvelope): 'proceed' | 'proceed_with_warning' | 'blocked' {
    switch (verdict.verdict) {
      case 'ALLOW':   return 'proceed';
      case 'EDUCATE': return 'proceed_with_warning';
      case 'BLOCK':   return 'blocked';
    }
  }

  private async blake3(input: string): Promise<string> {
    // Usa Web Crypto API como proxy — substituir por lib BLAKE3 WASM em prod
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  }
}
```

**Integração no `chat-container.component.ts`:**

```typescript
async sendMessage(rawText: string): Promise<void> {
  // 1. Filtra e classifica (já existente)
  const filtered = this.dataFilter.processMessage(rawText, this.workspace);

  // 2. Sanitiza via BTV se necessário
  if (filtered.piiDetected) {
    filtered.content = await this.sanitize(filtered.content);
  }

  // 3. Gate BTV apenas para mensagens sensíveis
  if (filtered.piiDetected || filtered.classification >= 'CONFIDENTIAL') {
    const verdict = await this.btvGate.validateMessage(filtered);

    if (verdict.verdict === 'BLOCK') {
      this.showBlockFeedback(verdict.explain_decision, verdict.evidence_id, verdict.contestable);
      return; // Mensagem não enviada
    }

    if (verdict.verdict === 'EDUCATE') {
      this.showEducateWarning(verdict.explain_decision);
    }

    // evidence_id persistido para correlação futura
    filtered.btvEvidenceId = verdict.evidence_id;
  }

  // 4. Envia ao backend — fluxo normal
  await this.chatStream.sendAndStream(filtered, this.workspace);
}

private showBlockFeedback(
  reason: string,
  evidenceId: string,
  contestable: boolean
): void {
  this.blockMessage = {
    reason,
    evidenceId,
    contestable,
    appealUrl: contestable ? `/appeals/new?evidence=${evidenceId}` : null
  };
}
```

---

### Gate 2 — Indexação de Documentos no Qdrant

**Rust — `crates/btv-client/src/gates/document.rs`:**

```rust
use crate::{BtvClient, AgentDecisionRequest, ActionImpact, BtvError};
use crate::evidence::EvidenceId;
use crate::models::{DocumentMetadata, Classification};

pub async fn gate_document_indexing(
    doc: &DocumentMetadata,
    btv: &dyn BtvClient,
    workspace_id: &WorkspaceId,
) -> Result<Option<EvidenceId>, BtvError> {
    // Documentos Safe passam sem gate
    if doc.classification < Classification::Confidential {
        return Ok(None);
    }

    let impact = match doc.classification {
        Classification::Confidential => ActionImpact::Destructive,
        Classification::Restricted   => ActionImpact::Irreversible,
        _                            => unreachable!(),
    };

    let req = AgentDecisionRequest {
        schema_version: "1.0".into(),
        request_id: uuid::Uuid::new_v4().to_string(),
        agent_id: derive_agent_id(workspace_id, env!("CARGO_PKG_VERSION")),
        session_id: format!("upload-{}", workspace_id),
        action: Action {
            name: format!("document_upload_{}", doc.classification.slug()),
            impact,
            capabilities: vec!["vector_db_write".into(), "document_index".into()],
        },
        parameters_hash: blake3_hex(doc.content_hash.as_bytes()),
        parameters_preview: serde_json::json!({
            "filename": doc.filename,
            "mime_type": doc.mime_type,
            "size_bytes": doc.size_bytes,
            "page_count": doc.page_count,
            "pii_detected": doc.pii_detected,
        }),
        context: Context {
            profile_id: "internal-chatbot".into(),
            sector_id: workspace_id.sector_id().to_string(),
            session_trust_score: 0.7,
            agent_metadata: serde_json::json!({
                "workspace_id": workspace_id,
                "data_classification": doc.classification,
                "pii_detected": doc.pii_detected,
                "eligible_for_training": !doc.pii_detected && doc.classification < Classification::Restricted,
                "rag_context": false,
                "action_subtype": "document_upload"
            }),
        },
        timestamp_utc: Utc::now().to_rfc3339(),
    };

    let envelope = btv.request_decision(&req).await?;
    btv.verify_hmac(&envelope)?;  // Fail-secure: HMAC inválido = BtvError

    match envelope.verdict.as_str() {
        "ALLOW" | "EDUCATE" => Ok(Some(envelope.evidence_id)),
        "BLOCK" => Err(BtvError::Blocked {
            reason: envelope.explain_decision,
            evidence_id: envelope.evidence_id,
            contestable: envelope.contestable,
        }),
        _ => Err(BtvError::UnexpectedVerdict),
    }
}
```

**No handler de upload (Axum):**

```rust
pub async fn upload_document_handler(
    State(app): State<AppState>,
    ctx: WorkspaceContext,
    mut multipart: Multipart,
) -> Result<Json<UploadResponse>, AppError> {
    let doc = extract_document_metadata(&mut multipart).await?;

    // Gate BTV — falha = documento não indexado (fail-secure)
    let evidence_id = gate_document_indexing(&doc, app.btv.as_ref(), &ctx.workspace_id)
        .await
        .map_err(|e| match e {
            BtvError::Blocked { reason, evidence_id, .. } =>
                AppError::DocumentBlocked { reason, evidence_id },
            _ =>
                AppError::BtvUnavailable, // BTV down = bloqueia indexação
        })?;

    // Indexa no Qdrant apenas após gate aprovado
    app.rag_service.index_document(&doc, &ctx.workspace_id).await?;

    // evidence_id persistido no metadado do documento
    app.doc_repo.save(DocumentRecord {
        id: doc.id,
        workspace_id: ctx.workspace_id,
        btv_evidence_id: evidence_id, // None para docs Safe
        ..doc.into()
    }).await?;

    Ok(Json(UploadResponse { document_id: doc.id, evidence_id }))
}
```

---

### Gate 3 — Contexto RAG (Anti-Prompt Injection)

**Rust — `crates/btv-client/src/gates/rag.rs`:**

```rust
use futures::future::join_all;

/// Valida os top-K chunks em paralelo antes de injetar no prompt.
/// Chunks bloqueados são excluídos silenciosamente do contexto.
/// Nunca falha aberto: erro de comunicação = chunk excluído.
pub async fn gate_rag_chunks(
    chunks: Vec<RagChunk>,
    btv: &dyn BtvClient,
    workspace_id: &WorkspaceId,
) -> Vec<RagChunk> {
    let futures: Vec<_> = chunks
        .iter()
        .map(|chunk| gate_single_chunk(chunk, btv, workspace_id))
        .collect();

    let results = join_all(futures).await;

    chunks
        .into_iter()
        .zip(results)
        .filter_map(|(chunk, result)| match result {
            Ok(true) => Some(chunk),    // ALLOW ou EDUCATE
            Ok(false) => {              // BLOCK
                tracing::warn!(
                    chunk_id = %chunk.id,
                    "Chunk RAG bloqueado pelo BTV — excluído do contexto"
                );
                None
            }
            Err(e) => {                 // Falha de comunicação
                tracing::error!(
                    chunk_id = %chunk.id,
                    error = %e,
                    "Falha no gate RAG — chunk excluído por fail-secure"
                );
                None
            }
        })
        .collect()
}

async fn gate_single_chunk(
    chunk: &RagChunk,
    btv: &dyn BtvClient,
    workspace_id: &WorkspaceId,
) -> Result<bool, BtvError> {
    let req = build_rag_request(chunk, workspace_id);
    let envelope = btv.request_decision(&req).await?;
    btv.verify_hmac(&envelope)?;
    Ok(matches!(envelope.verdict.as_str(), "ALLOW" | "EDUCATE"))
}
```

**No prompt builder (Rust):**

```rust
pub async fn build_prompt(
    query: &str,
    raw_chunks: Vec<RagChunk>,
    history: &ConversationHistory,
    ctx: &WorkspaceContext,
    btv: &dyn BtvClient,
) -> Result<Prompt, PromptError> {
    // Gate 3: filtra chunks antes da injeção
    let safe_chunks = gate_rag_chunks(raw_chunks, btv, &ctx.workspace_id).await;

    if safe_chunks.is_empty() {
        tracing::warn!("Todos os chunks foram bloqueados — prompt sem contexto RAG");
    }

    Ok(Prompt {
        system: build_system_prompt(ctx),
        rag_context: format_chunks(&safe_chunks),
        history: history.last_n(10),
        user_message: query.to_string(),
    })
}
```

---

### Gate 4 — Início de Ciclo de Treinamento

**Python — `training/btv_gates.py`:**

```python
import hashlib
import json
import logging
from dataclasses import dataclass
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass
class TrainingStats:
    total: int
    positive_pct: float
    synthetic_pct: float
    negative_pct: float
    pii_detected_count: int
    current_lora: str
    batch_id: str


class BtvGateClient:
    """
    Cliente BTV para o pipeline de treinamento.
    Todos os métodos são fail-secure: exceção = BLOCK implícito.
    """

    def __init__(self, btv_url: str, api_key: str, agent_id: str, workspace_id: str):
        self.btv_url = btv_url
        self.api_key = api_key
        self.agent_id = agent_id
        self.workspace_id = workspace_id
        self._client = httpx.AsyncClient(
            base_url=btv_url,
            headers={"X-API-Key": api_key},
            timeout=10.0,
        )

    async def gate_training_cycle(self, stats: TrainingStats) -> Optional[str]:
        """
        Gate 4: valida início de ciclo de fine-tuning.
        Retorna evidence_id se aprovado, None (com log) se bloqueado.
        Lança TrainingGateError se BTV indisponível.
        """
        summary = {
            "total_examples": stats.total,
            "positive_pct": round(stats.positive_pct, 2),
            "synthetic_pct": round(stats.synthetic_pct, 2),
            "negative_pct": round(stats.negative_pct, 2),
            "pii_detected_count": stats.pii_detected_count,
            "base_lora_version": stats.current_lora,
        }

        request = {
            "schema_version": "1.0",
            "request_id": self._new_uuid(),
            "agent_id": self.agent_id,
            "session_id": f"training-{stats.batch_id}",
            "action": {
                "name": "training_cycle_start",
                "impact": "Destructive",
                "capabilities": ["model_training", "gpu_allocation"]
            },
            "parameters_hash": self._blake3(json.dumps(summary, sort_keys=True)),
            "parameters_preview": summary,
            "context": {
                "profile_id": "internal-chatbot",
                "sector_id": self._sector_id(),
                "session_trust_score": 0.8,
                "agent_metadata": {
                    "workspace_id": self.workspace_id,
                    "data_classification": "INTERNAL",
                    "pii_detected": stats.pii_detected_count > 0,
                    "eligible_for_training": True,
                    "rag_context": False,
                    "action_subtype": "training_batch"
                }
            },
            "timestamp_utc": self._now_utc()
        }

        try:
            response = await self._client.post("/v1/validate", json=request)
            response.raise_for_status()
            verdict = response.json()
        except Exception as e:
            raise TrainingGateError(f"BTV indisponível: {e}")

        if not self._verify_hmac(verdict):
            raise TrainingGateError("HMAC inválido no veredicto BTV")

        if verdict["verdict"] == "BLOCK":
            logger.warning(
                "Ciclo de treino bloqueado | batch=%s | motivo=%s | evidence=%s",
                stats.batch_id,
                verdict["explain_decision"],
                verdict["evidence_id"]
            )
            return None

        logger.info(
            "Ciclo de treino aprovado | batch=%s | policy=%s | evidence=%s",
            stats.batch_id,
            verdict["policy_version_applied"],
            verdict["evidence_id"]
        )
        return verdict["evidence_id"]

    async def gate_lora_deploy(
        self,
        new_version: str,
        eval_metrics: dict
    ) -> str:
        """
        Gate 5: valida deploy de LoRA (Irreversible).
        Retorna evidence_id se aprovado.
        Lança DeployBlockedError em qualquer falha — fail-secure absoluto.
        TTL zero: nenhum cache para este veredicto.
        """
        payload = {
            "new_lora_version": new_version,
            "eval_accuracy": eval_metrics["accuracy"],
            "eval_groundedness": eval_metrics["groundedness"],
            "eval_refusal_accuracy": eval_metrics["refusal_accuracy"],
            "training_loss": eval_metrics["training_loss"],
            "examples_trained": eval_metrics["total_examples"],
            "benchmark_vs_previous": eval_metrics["improvement_pct"]
        }

        request = {
            "schema_version": "1.0",
            "request_id": self._new_uuid(),
            "agent_id": self.agent_id,
            "session_id": f"deploy-{new_version}",
            "action": {
                "name": "lora_deploy",
                "impact": "Irreversible",
                "capabilities": [
                    "model_hot_swap",
                    "production_write",
                    "vllm_adapter_load"
                ]
            },
            "parameters_hash": self._blake3(
                f"{new_version}{json.dumps(eval_metrics, sort_keys=True)}"
            ),
            "parameters_preview": payload,
            "context": {
                "profile_id": "internal-chatbot",
                "sector_id": self._sector_id(),
                "session_trust_score": 0.9,
                "agent_metadata": {
                    "workspace_id": self.workspace_id,
                    "data_classification": "INTERNAL",
                    "pii_detected": False,
                    "eligible_for_training": False,
                    "rag_context": False,
                    "action_subtype": "lora_deploy"
                }
            },
            "timestamp_utc": self._now_utc()
        }

        try:
            response = await self._client.post("/v1/validate", json=request)
            response.raise_for_status()
            verdict = response.json()
        except Exception as e:
            # BTV down = deploy bloqueado, sem exceção
            raise DeployBlockedError(f"BTV indisponível — deploy abortado: {e}")

        if not self._verify_hmac(verdict):
            raise DeployBlockedError("HMAC inválido — deploy abortado")

        if verdict["verdict"] == "BLOCK":
            raise DeployBlockedError(
                f"{verdict['explain_decision']} "
                f"[evidence={verdict['evidence_id']}]"
            )

        return verdict["evidence_id"]
```

**Integração no `ContinuousTrainer`:**

```python
class ContinuousTrainer:

    async def run_training_cycle(self):
        stats = await self.collect_approved_stats()

        if stats.total < self.config["min_examples"]:
            logger.info("Exemplos insuficientes (%d). Ciclo ignorado.", stats.total)
            return

        # Gate 4: aprovação BTV antes de consumir GPU
        try:
            evidence_id = await self.btv.gate_training_cycle(stats)
        except TrainingGateError as e:
            logger.critical("Gate BTV falhou: %s — ciclo abortado (fail-secure)", e)
            return

        if evidence_id is None:
            return  # BLOCK registrado pelo gate; não treina

        # Persiste evidence_id ANTES de consumir recurso
        await self.db.update_batch_evidence(stats.batch_id, evidence_id)

        train_file = await self.format_dataset(stats)
        new_version, eval_metrics = await self.train_lora(train_file)

        if not self.evaluate(eval_metrics):
            logger.warning("Avaliação reprovada. Sem deploy.")
            return

        # Gate 5: deploy (Irreversible) — sem cache
        try:
            deploy_evidence = await self.btv.gate_lora_deploy(
                new_version, eval_metrics
            )
        except DeployBlockedError as e:
            logger.warning("Deploy bloqueado: %s", e)
            await self.notify_operator(str(e))
            return

        # Persiste evidence do deploy ANTES do hot-swap
        await self.db.record_deploy_evidence(new_version, deploy_evidence)

        # Hot-swap vLLM — apenas aqui, após todos os gates
        await self.vllm_client.load_lora(new_version)
        logger.info("LoRA %s em produção. Evidence: %s", new_version, deploy_evidence)
```

---

## 6. Sanitização com Evidência LGPD

```rust
// crates/btv-client/src/gates/sanitize.rs

pub struct SanitizedMessage {
    pub content: String,
    pub evidence_id: Option<EvidenceId>, // None se conteúdo era Safe
    pub pii_types_found: Vec<String>,
}

/// Sanitização com evidência forense verificável.
/// Ordem obrigatória: sanitizar → hash → persistir evidence_id.
pub async fn sanitize_with_evidence(
    raw: &str,
    btv: &dyn BtvClient,
    ctx: &WorkspaceContext,
) -> Result<SanitizedMessage, SanitizeError> {
    let result = btv.sanitize_output(raw).await
        .map_err(|_| SanitizeError::BtvUnavailable)?;

    // evidence_id é a prova forense de que sanitização ocorreu
    // Armazenado na tabela training_interactions.btv_sanitize_evidence_id
    Ok(SanitizedMessage {
        content: result.content,
        evidence_id: Some(result.evidence_id),
        pii_types_found: result.pii_types,
    })
}
```

**Uso no relatório LGPD:**

O `ComplianceReportComponent` passa a exibir dois tipos de evidência:

```typescript
// Nível 1 (interno — operacional)
piiStats.totalAnonymized  // contagem no PostgreSQL

// Nível 2 (externo — forense, auditável)
btvEvidenceIds: string[]  // lista de evidence_ids do DurableLedger BTV
                          // verificáveis independentemente via hash BLAKE3
```

---

## 7. Políticas YAML por Gate

```yaml
# data/policies/chatbot-internal-message.yaml
id: chatbot-internal-message-v1
description: "Políticas para mensagens do chatbot interno (LLM self-hosted)"
applies_to:
  profile_id: "internal-chatbot"
  action_names:
    - "chat_message_send_pii"
    - "chat_message_confidential"
    - "chat_message_restricted"

rules:
  - name: allow_confidential_with_mfa
    conditions:
      action.name: "chat_message_confidential"
      agent_metadata.pii_detected: false
    verdict: ALLOW
    explain: "Mensagem confidencial sem PII aprovada."

  - name: educate_pii_detected
    conditions:
      agent_metadata.pii_detected: true
      agent_metadata.data_classification: { in: ["PUBLIC", "INTERNAL"] }
    verdict: EDUCATE
    explain: "PII detectado. Dado anonimizado antes do envio ao modelo."

  - name: block_restricted
    conditions:
      agent_metadata.data_classification: "RESTRICTED"
    verdict: BLOCK
    explain: "Dados RESTRICTED não são transmitidos ao LLM sem autorização explícita."
```

```yaml
# data/policies/chatbot-rag-injection.yaml
id: chatbot-rag-injection-v1
applies_to:
  profile_id: "internal-chatbot"
  action_names: ["rag_chunk_inject"]

rules:
  - name: block_injection_patterns
    conditions:
      content_patterns:
        - "ignore previous instructions"
        - "ignore as instruções anteriores"
        - "você é agora"
        - "system: "
        - "[INST]"
        - "###SYSTEM"
        - "act as"
    verdict: BLOCK
    explain: "Padrão de prompt injection detectado no chunk RAG."

  - name: allow_safe_chunk
    conditions:
      default: true
    verdict: ALLOW
```

```yaml
# data/policies/chatbot-lora-deploy.yaml
id: chatbot-lora-deploy-v1
applies_to:
  profile_id: "internal-chatbot"
  action_names: ["lora_deploy", "lora_rollback"]

rules:
  - name: block_regression
    conditions:
      parameters_preview.benchmark_vs_previous: { lt: -0.05 }
    verdict: BLOCK
    explain: "Regressão > 5% vs versão anterior. Rollback recomendado."

  - name: block_low_refusal
    conditions:
      parameters_preview.eval_refusal_accuracy: { lt: 0.70 }
    verdict: BLOCK
    explain: "Taxa de recusa insuficiente. Risco de alucinação em perguntas fora do domínio."

  - name: block_low_accuracy
    conditions:
      parameters_preview.eval_accuracy: { lt: 0.80 }
    verdict: BLOCK
    explain: "Acurácia abaixo do threshold mínimo de 80%."

  - name: allow_deploy
    conditions:
      parameters_preview.eval_accuracy: { gte: 0.80 }
      parameters_preview.eval_groundedness: { gte: 0.75 }
      parameters_preview.eval_refusal_accuracy: { gte: 0.70 }
      parameters_preview.benchmark_vs_previous: { gte: -0.02 }
    verdict: ALLOW
    explain: "Métricas atendem os critérios. Deploy autorizado."
```

```yaml
# data/policies/chatbot-lora-deploy-health.yaml
# Override para sector_id: health — threshold mais alto
id: chatbot-lora-deploy-health-v1
applies_to:
  profile_id: "internal-chatbot"
  sector_id: "health"
  action_names: ["lora_deploy"]

rules:
  - name: block_health_low_refusal
    conditions:
      parameters_preview.eval_refusal_accuracy: { lt: 0.90 }
    verdict: BLOCK
    explain: "Setor saúde exige refusal_accuracy >= 90%. Risco de alucinação clínica inaceitável."
```

---

## 8. Docker Compose — Desenvolvimento com BTV Sidecar

```yaml
# docker-compose.dev.yml
version: "3.9"

services:

  chatbot-backend:
    build: .
    ports:
      - "3000:3000"
    environment:
      BTV_URL: "http://btv-sidecar:8080"
      BTV_API_KEY: "dev-api-key-chatbot-internal"
      BTV_TIMEOUT_MS: "5000"
      BTV_CIRCUIT_BREAKER_FAILURES: "3"
      BTV_CIRCUIT_BREAKER_WINDOW_S: "30"
    depends_on:
      btv-sidecar:
        condition: service_healthy

  btv-sidecar:
    image: buildtovalue/btv:2.0-dev
    ports:
      - "8080:8080"
    environment:
      BTV_ENV: "development"
      BTV_HMAC_KEY: "dev-hmac-key-32-bytes-for-testing"
      BTV_LEDGER_MODE: "memory"        # DurableLedger em memória no dev
      BTV_POLICIES_DIR: "./data/policies"
    volumes:
      - ./data/policies:/app/data/policies:ro
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 5s
      timeout: 3s
      retries: 5

  postgres:
    image: postgres:16
    environment:
      POSTGRES_DB: chatbot_dev
      POSTGRES_USER: chatbot
      POSTGRES_PASSWORD: devpassword

  qdrant:
    image: qdrant/qdrant:latest
    ports:
      - "6333:6333"

  vllm-mock:
    image: buildtovalue/vllm-mock:latest  # Mock para dev local sem GPU
    ports:
      - "8000:8000"
```

---

## 9. Tratamento de Erros e Fallback

| Cenário | Comportamento |
|:--------|:--------------|
| BTV responde em < 5 s | Fluxo normal |
| BTV timeout (> 5 s) | BLOCK local + log `btv.timeout` |
| HTTP 5xx | 1 retry (100 ms) → BLOCK se falhar |
| Circuit aberto (≥ 3 falhas / 30 s) | BLOCK todas Destructive/Irreversible + alerta |
| HMAC inválido | BLOCK + log `btv.hmac_mismatch` + alerta crítico |
| BTV retorna 401/403 | BLOCK + log `btv.auth_failure` + sem retry |
| Veredicto desconhecido | BLOCK + log `btv.unknown_verdict` |

**Regra universal:** qualquer condição não prevista = BLOCK. Nunca permitir por omissão.

---

## 10. Métricas e Observabilidade

```
# Prometheus — prefixo btv_chatbot_*
btv_chatbot_requests_total{gate, workspace_id, verdict, sector_id}
btv_chatbot_latency_ms{gate, workspace_id, p50|p95|p99}
btv_chatbot_lora_deploy_total{workspace_id, verdict, lora_version}
btv_chatbot_rag_blocks_total{workspace_id, reason}
btv_chatbot_pii_sanitized_total{workspace_id, pii_type}
btv_chatbot_training_cycle_total{workspace_id, verdict}
btv_chatbot_circuit_open{workspace_id}           # 1 = aberto, 0 = fechado
btv_chatbot_evidence_ids_total{workspace_id, gate}
btv_chatbot_appeals_submitted_total{workspace_id, gate}
```

**Alertas recomendados:**

```yaml
# monitoring/alerts/btv-chatbot.yaml
alerts:
  - name: BtvCircuitOpen
    expr: btv_chatbot_circuit_open > 0
    severity: critical
    message: "BTV sidecar indisponível. Todos os gates estão bloqueando."

  - name: BtvHighBlockRate
    expr: rate(btv_chatbot_requests_total{verdict="BLOCK"}[5m]) > 0.20
    severity: warning
    message: "Taxa de bloqueio BTV > 20% nos últimos 5min. Verificar política."

  - name: BtvHmacMismatch
    expr: rate(btv_chatbot_requests_total{verdict="hmac_mismatch"}[5m]) > 0
    severity: critical
    message: "HMAC inválido detectado. Possível adulteração de resposta BTV."
```

---

## 11. Contestabilidade — Fluxo no Chatbot

```
Usuário recebe BLOCK
        │
        ▼
UI exibe explain_decision (linguagem natural)
UI exibe botão "Contestar" (se contestable=true)
        │
        ▼ [usuário clica "Contestar"]
        │
POST /v1/appeals
{
  "evidence_id": "<ev_hex>",
  "justification": "<texto do usuário>",
  "requested_by": "<user_id>",
  "timestamp_utc": "<ISO8601>"
}
        │
        ▼
UI exibe: "Recurso enviado. Prazo: <appeal_deadline_utc>."
appeal_id salvo localmente para acompanhamento.
        │
        ▼ [admin revisa no dashboard BTV]
        │
  ┌─────┴──────┐
APROVADO    REJEITADO
  │              │
Ação         Bloqueio
executada    mantido
  │              │
evidence_id  evidence_id
do recurso   do recurso
no ledger    no ledger
```

---

## 12. Tabela Resumo: Migração do que já existe → BTV

| Mecanismo atual do chatbot | Limitação | Como o BTV complementa |
|:--------------------------|:----------|:-----------------------|
| `anonymizer.service.ts` (Angular) | Client-side, sem evidência forense | `/v1/sanitize` gera `evidence_id` verificável |
| `audit_log` PostgreSQL | Mesmo trust boundary dos dados | DurableLedger BLAKE3 — externo, imutável, assinado |
| `data-classification.guard.ts` | Guarda de UI, bypassável no backend | Gate BTV server-side antes de cada ação sensível |
| Relatório LGPD interno | Números sem prova externa | `evidence_id`s do ledger como artefatos forenses |
| Deploy manual de LoRA | Sem trilha de aprovação formal | Gate `Irreversible` com policy YAML + `evidence_id` |
| `blockOnPii` toggle (workspace) | Binário — liga/desliga global | Políticas YAML por `sector_id` e `action_name` |

---

## 13. Checklist de Go-Live

```
Infraestrutura
  [ ] BTV v2.0 em produção com DurableLedger + S3 configurado
  [ ] API key de produção gerada para cada workspace ativo
  [ ] HMAC key rotacionada e armazenada no Vault
  [ ] Políticas YAML carregadas e testadas para cada sector_id ativo
  [ ] Métricas Prometheus coletadas e alertas configurados

Gates
  [ ] Gate 1 testado: mensagem CONFIDENTIAL sem BTV → nunca chega ao vLLM
  [ ] Gate 2 testado: doc RESTRICTED sem evidence_id → não entra no Qdrant
  [ ] Gate 3 testado: chunk com "ignore previous instructions" → BLOCK
  [ ] Gate 4 testado: ciclo de treino sem aprovação → não consome GPU
  [ ] Gate 5 testado: deploy de LoRA com regressão > 5% → BLOCK pela política

Fail-secure
  [ ] BTV sidecar derrubado → todos os gates Destructive/Irreversible bloqueiam
  [ ] HMAC key trocada propositalmente → deploy bloqueado imediatamente
  [ ] Circuit breaker abre após 3 falhas → alerta disparado

LGPD
  [ ] evidence_ids BTV presentes no relatório LGPD gerado
  [ ] Fluxo de contestação testado end-to-end com appeal_deadline
  [ ] DPO validou os artefatos do DurableLedger como evidência forense

Documentação
  [ ] Este arquivo registrado em docs/integrations/
  [ ] ADR-0029 registrado no 0000-adr-index.md
  [ ] Runbook de operação criado (restart BTV, rotação de keys, rollback)
```

---

## 14. Referências Cruzadas

- BTV ADR-0028 (External Agent PDP — contrato canônico)
- BTV ADR-0029 (este perfil — decisão arquitetural)
- BTV ADR-0004 (Immutable Ledger — DurableLedger BLAKE3)
- BTV ADR-0005 (Evidence Protocol v2.1 — 9596 bytes)
- BTV ADR-0006 (Policy-as-Code — YAML)
- BTV ADR-0008 (Timing Mitigation — constant-time HMAC)
- BTV ADR-0010 (BiasDeclaration Mandate)
- BTV ADR-0017 (ContestabilityLoop SLA 24h)
- `docs/integrations/chatbot-external-llm.md` (ADR-0030 — variante com LLM externa)
- Chatbot ADR-016 a ADR-020 (segurança e compliance lado chatbot)
```
