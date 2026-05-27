[BuildToValue](../../README.md) › [Documentation](../README.md) › [Engineer Track](../for-engineers.md) › [Integrations](./index.md) › **Internal Chatbot (Self-Hosted LLM)**

![Engineer](https://img.shields.io/badge/Track-Engineer-1f6feb)

<!-- audience: engineer -->

---

# BTV Integration Profile: Internal Chatbot with Self-Hosted LLM

| Field                | Value                                        |
|:---------------------|:---------------------------------------------|
| **Standard**         | BTV ADR-0029 (External Agent PDP)            |
| **ADR for this profile** | BTV ADR-0030                             |
| **Chatbot version**  | v1.0+ (Rust/Axum + Angular + Python/Unsloth) |
| **BTV version**      | v2.0+                                        |
| **Maintainer**       | Internal Chatbot Team                        |
| **Date**             | 2026-02-23                                   |
| **Next profile**     | `chatbot-external-llm.md` (ADR-0030)         |

---

## 1. System Overview

The internal corporate chatbot operates on the following stack:

```
┌─────────────────────────────────────────────────────┐
│  Angular Frontend                                   │
│  DataFilterService → sanitizer.interceptor          │
│  audit.interceptor → feedback-panel                 │
└───────────────────────┬─────────────────────────────┘
                        │ HTTP/SSE
┌───────────────────────▼─────────────────────────────┐
│  Rust Backend (Axum)                                │
│  auth middleware → RAG pipeline (Qdrant)            │
│  prompt builder → vLLM streaming handler            │
│  training_interactions collector                    │
└──────┬────────────────┬────────────────┬────────────┘
       │                │                │
  ┌────▼────┐    ┌──────▼──────┐  ┌─────▼──────┐
  │ Qdrant  │    │ PostgreSQL  │  │  vLLM GPU  │
  │(vectors)│    │ (relational)│  │ Llama 70B  │
  └─────────┘    └─────────────┘  └────────────┘
                        │
┌───────────────────────▼─────────────────────────────┐
│  Training Pipeline (Python/Unsloth)                 │
│  ContinuousTrainer → Synthetic QA → LoRA → vLLM     │
└─────────────────────────────────────────────────────┘
```

BTV acts as an **external governance layer** between each
sensitive component, without residing inside any of them.

---

## 2. Canonical agent_id

```rust
// crates/btv-client/src/identity.rs

use blake3::Hasher;

/// Stable derivation of agent_id per workspace.
/// Does not change between restarts of the same instance.
pub fn derive_agent_id(workspace_id: &WorkspaceId, version: &str) -> String {
    let mut hasher = Hasher::new();
    hasher.update(workspace_id.as_bytes());
    hasher.update(b":");
    hasher.update(version.as_bytes());
    let hash = hasher.finalize();
    format!("chatbot-internal-{}", &hash.to_hex()[..16])
}

// Example:
// workspace_id: "ws_abc123"  version: "1.0.0"
// agent_id:     "chatbot-internal-f3a8c91d04e72b5a"
```

Each workspace generates a distinct `agent_id`. This ensures that
BTV's DurableLedger correlates evidence by company, not by
server instance.

---

## 3. Complete Mapping of Actions → ActionImpact

### 3.1 Chat and Message Actions

| Action                                 | `action.name`              | Impact         | Gate? |
|:---------------------------------------|:---------------------------|:---------------|:------|
| `PUBLIC`/`INTERNAL` message without PII | `chat_message_send`       | Safe           | ❌    |
| Message with detected PII              | `chat_message_send_pii`    | Destructive    | ✅    |
| `CONFIDENTIAL` classified message      | `chat_message_confidential`| Destructive    | ✅    |
| `RESTRICTED` classified message        | `chat_message_restricted`  | Irreversible   | ✅    |
| Conversation export (PDF/MD)           | `chat_export`              | Irreversible   | ✅    |
| Conversation deletion                  | `chat_delete`              | Destructive    | ✅    |

### 3.2 Document and RAG Actions

| Action                                 | `action.name`              | Impact         | Gate? |
|:---------------------------------------|:---------------------------|:---------------|:------|
| `PUBLIC`/`INTERNAL` doc upload         | `document_upload`          | Safe           | ❌    |
| `CONFIDENTIAL` doc upload              | `document_upload_conf`     | Destructive    | ✅    |
| `RESTRICTED` doc upload                | `document_upload_restr`    | Irreversible   | ✅    |
| RAG chunk injected into prompt         | `rag_chunk_inject`         | Destructive    | ✅    |
| Original document export               | `document_export`          | Irreversible   | ✅    |
| Document deletion                      | `document_delete`          | Destructive    | ✅    |

### 3.3 Training and Model Actions

| Action                                 | `action.name`              | Impact         | Gate? |
|:---------------------------------------|:---------------------------|:---------------|:------|
| QA approval for dataset                | `training_qa_approve`      | Destructive    | ✅    |
| Start of fine-tuning cycle             | `training_cycle_start`     | Destructive    | ✅    |
| LoRA deploy (vLLM hot-swap)            | `lora_deploy`              | Irreversible   | ✅    |
| LoRA rollback                          | `lora_rollback`            | Irreversible   | ✅    |
| Training dataset export                | `training_dataset_export`  | Irreversible   | ✅    |

### 3.4 Administrative Actions

| Action                                 | `action.name`              | Impact         | Gate? |
|:---------------------------------------|:---------------------------|:---------------|:------|
| User suspension                        | `user_suspend`             | Destructive    | ✅    |
| Role/permission change                 | `user_role_change`         | Destructive    | ✅    |
| API key revocation                     | `api_key_revoke`           | Irreversible   | ✅    |
| Bulk deletion (`bulk_delete`)          | `bulk_delete`              | Irreversible   | ✅    |
| Data policy change                     | `data_policy_change`       | Irreversible   | ✅    |
| LGPD report generation                 | `lgpd_report_generate`     | Destructive    | ✅    |

---

## 4. profile_id and sector_id Configuration

```yaml
# Configured at workspace onboarding — saved in workspaces.btv_config
profile_id: "internal-chatbot"

# Mapping by company type:
sector_id:
  juridico:    "legal"
  saude:       "health"
  financeiro:  "finance"
  rh:          "hr"
  geral:       "general"
  tecnologia:  "general"
```

**Impact of `sector_id` on BTV policies:**

| `sector_id` | Policy applied                                 |
|:------------|:-----------------------------------------------|
| `legal`     | Higher groundedness threshold (≥ 0.85); blocks RAG with Portuguese-language legal injection patterns |
| `health`    | Blocks `eligible_for_training: true` if health PII is detected; refusal threshold ≥ 0.90 |
| `finance`   | Blocks export without confirmed MFA; accuracy threshold ≥ 0.85 |
| `hr`        | Blocks messages with CPF/HR data from being automatically used for training |
| `general`   | Default BTV policy |

---

## 5. Implementation of the 5 Gates

### Gate 1 — Message Transmission to the LLM (Frontend + Backend)

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
   * Gate 1: validates a message before sending it to the backend/LLM.
   * Called only when pii_detected=true or class >= CONFIDENTIAL.
   * Safe messages go straight through — never call BTV unnecessarily.
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
      // hash of the ALREADY sanitized message — never hash the original
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
   * Presents the verdict result to the user.
   * BLOCK: shows explain_decision + option to appeal.
   * EDUCATE: allows sending but records a warning.
   */
  handleVerdict(verdict: VerdictEnvelope): 'proceed' | 'proceed_with_warning' | 'blocked' {
    switch (verdict.verdict) {
      case 'ALLOW':   return 'proceed';
      case 'EDUCATE': return 'proceed_with_warning';
      case 'BLOCK':   return 'blocked';
    }
  }

  private async blake3(input: string): Promise<string> {
    // Uses the Web Crypto API as a proxy — replace with a BLAKE3 WASM lib in prod
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  }
}
```

**Integration in `chat-container.component.ts`:**

```typescript
async sendMessage(rawText: string): Promise<void> {
  // 1. Filter and classify (already existing)
  const filtered = this.dataFilter.processMessage(rawText, this.workspace);

  // 2. Sanitize via BTV if needed
  if (filtered.piiDetected) {
    filtered.content = await this.sanitize(filtered.content);
  }

  // 3. BTV gate only for sensitive messages
  if (filtered.piiDetected || filtered.classification >= 'CONFIDENTIAL') {
    const verdict = await this.btvGate.validateMessage(filtered);

    if (verdict.verdict === 'BLOCK') {
      this.showBlockFeedback(verdict.explain_decision, verdict.evidence_id, verdict.contestable);
      return; // Message not sent
    }

    if (verdict.verdict === 'EDUCATE') {
      this.showEducateWarning(verdict.explain_decision);
    }

    // evidence_id persisted for future correlation
    filtered.btvEvidenceId = verdict.evidence_id;
  }

  // 4. Send to backend — normal flow
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

### Gate 2 — Document Indexing in Qdrant

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
    // Safe documents pass without a gate
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
    btv.verify_hmac(&envelope)?;  // Fail-secure: invalid HMAC = BtvError

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

**In the upload handler (Axum):**

```rust
pub async fn upload_document_handler(
    State(app): State<AppState>,
    ctx: WorkspaceContext,
    mut multipart: Multipart,
) -> Result<Json<UploadResponse>, AppError> {
    let doc = extract_document_metadata(&mut multipart).await?;

    // BTV gate — failure = document not indexed (fail-secure)
    let evidence_id = gate_document_indexing(&doc, app.btv.as_ref(), &ctx.workspace_id)
        .await
        .map_err(|e| match e {
            BtvError::Blocked { reason, evidence_id, .. } =>
                AppError::DocumentBlocked { reason, evidence_id },
            _ =>
                AppError::BtvUnavailable, // BTV down = block indexing
        })?;

    // Index in Qdrant only after the gate is approved
    app.rag_service.index_document(&doc, &ctx.workspace_id).await?;

    // evidence_id persisted in the document metadata
    app.doc_repo.save(DocumentRecord {
        id: doc.id,
        workspace_id: ctx.workspace_id,
        btv_evidence_id: evidence_id, // None for Safe docs
        ..doc.into()
    }).await?;

    Ok(Json(UploadResponse { document_id: doc.id, evidence_id }))
}
```

---

### Gate 3 — RAG Context (Anti-Prompt Injection)

**Rust — `crates/btv-client/src/gates/rag.rs`:**

```rust
use futures::future::join_all;

/// Validates the top-K chunks in parallel before injecting them into the prompt.
/// Blocked chunks are silently excluded from the context.
/// Never fails open: communication error = chunk excluded.
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
            Ok(true) => Some(chunk),    // ALLOW or EDUCATE
            Ok(false) => {              // BLOCK
                tracing::warn!(
                    chunk_id = %chunk.id,
                    "RAG chunk blocked by BTV — excluded from context"
                );
                None
            }
            Err(e) => {                 // Communication failure
                tracing::error!(
                    chunk_id = %chunk.id,
                    error = %e,
                    "RAG gate failure — chunk excluded by fail-secure"
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

**In the prompt builder (Rust):**

```rust
pub async fn build_prompt(
    query: &str,
    raw_chunks: Vec<RagChunk>,
    history: &ConversationHistory,
    ctx: &WorkspaceContext,
    btv: &dyn BtvClient,
) -> Result<Prompt, PromptError> {
    // Gate 3: filter chunks before injection
    let safe_chunks = gate_rag_chunks(raw_chunks, btv, &ctx.workspace_id).await;

    if safe_chunks.is_empty() {
        tracing::warn!("All chunks were blocked — prompt without RAG context");
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

### Gate 4 — Start of Training Cycle

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
    BTV client for the training pipeline.
    All methods are fail-secure: exception = implicit BLOCK.
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
        Gate 4: validates the start of a fine-tuning cycle.
        Returns evidence_id if approved, None (with log) if blocked.
        Raises TrainingGateError if BTV is unavailable.
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
            raise TrainingGateError(f"BTV unavailable: {e}")

        if not self._verify_hmac(verdict):
            raise TrainingGateError("Invalid HMAC in BTV verdict")

        if verdict["verdict"] == "BLOCK":
            logger.warning(
                "Training cycle blocked | batch=%s | reason=%s | evidence=%s",
                stats.batch_id,
                verdict["explain_decision"],
                verdict["evidence_id"]
            )
            return None

        logger.info(
            "Training cycle approved | batch=%s | policy=%s | evidence=%s",
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
        Gate 5: validates LoRA deploy (Irreversible).
        Returns evidence_id if approved.
        Raises DeployBlockedError on any failure — absolute fail-secure.
        TTL zero: no cache for this verdict.
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
            # BTV down = deploy blocked, no exception
            raise DeployBlockedError(f"BTV unavailable — deploy aborted: {e}")

        if not self._verify_hmac(verdict):
            raise DeployBlockedError("Invalid HMAC — deploy aborted")

        if verdict["verdict"] == "BLOCK":
            raise DeployBlockedError(
                f"{verdict['explain_decision']} "
                f"[evidence={verdict['evidence_id']}]"
            )

        return verdict["evidence_id"]
```

**Integration in `ContinuousTrainer`:**

```python
class ContinuousTrainer:

    async def run_training_cycle(self):
        stats = await self.collect_approved_stats()

        if stats.total < self.config["min_examples"]:
            logger.info("Insufficient examples (%d). Cycle skipped.", stats.total)
            return

        # Gate 4: BTV approval before consuming GPU
        try:
            evidence_id = await self.btv.gate_training_cycle(stats)
        except TrainingGateError as e:
            logger.critical("BTV gate failed: %s — cycle aborted (fail-secure)", e)
            return

        if evidence_id is None:
            return  # BLOCK recorded by the gate; do not train

        # Persist evidence_id BEFORE consuming resource
        await self.db.update_batch_evidence(stats.batch_id, evidence_id)

        train_file = await self.format_dataset(stats)
        new_version, eval_metrics = await self.train_lora(train_file)

        if not self.evaluate(eval_metrics):
            logger.warning("Evaluation failed. No deploy.")
            return

        # Gate 5: deploy (Irreversible) — no cache
        try:
            deploy_evidence = await self.btv.gate_lora_deploy(
                new_version, eval_metrics
            )
        except DeployBlockedError as e:
            logger.warning("Deploy blocked: %s", e)
            await self.notify_operator(str(e))
            return

        # Persist deploy evidence BEFORE the hot-swap
        await self.db.record_deploy_evidence(new_version, deploy_evidence)

        # vLLM hot-swap — only here, after all gates
        await self.vllm_client.load_lora(new_version)
        logger.info("LoRA %s in production. Evidence: %s", new_version, deploy_evidence)
```

---

## 6. Sanitization with LGPD Evidence

```rust
// crates/btv-client/src/gates/sanitize.rs

pub struct SanitizedMessage {
    pub content: String,
    pub evidence_id: Option<EvidenceId>, // None if content was Safe
    pub pii_types_found: Vec<String>,
}

/// Sanitization with verifiable forensic evidence.
/// Mandatory order: sanitize → hash → persist evidence_id.
pub async fn sanitize_with_evidence(
    raw: &str,
    btv: &dyn BtvClient,
    ctx: &WorkspaceContext,
) -> Result<SanitizedMessage, SanitizeError> {
    let result = btv.sanitize_output(raw).await
        .map_err(|_| SanitizeError::BtvUnavailable)?;

    // evidence_id is the forensic proof that sanitization occurred
    // Stored in the training_interactions.btv_sanitize_evidence_id table
    Ok(SanitizedMessage {
        content: result.content,
        evidence_id: Some(result.evidence_id),
        pii_types_found: result.pii_types,
    })
}
```

**Use in the LGPD report:**

The `ComplianceReportComponent` now displays two types of evidence:

```typescript
// Level 1 (internal — operational)
piiStats.totalAnonymized  // count in PostgreSQL

// Level 2 (external — forensic, auditable)
btvEvidenceIds: string[]  // list of evidence_ids from the BTV DurableLedger
                          // independently verifiable via BLAKE3 hash
```

---

## 7. YAML Policies per Gate

```yaml
# data/policies/chatbot-internal-message.yaml
id: chatbot-internal-message-v1
description: "Policies for internal chatbot messages (self-hosted LLM)"
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
    explain: "Confidential message without PII approved."

  - name: educate_pii_detected
    conditions:
      agent_metadata.pii_detected: true
      agent_metadata.data_classification: { in: ["PUBLIC", "INTERNAL"] }
    verdict: EDUCATE
    explain: "PII detected. Data anonymized before sending to the model."

  - name: block_restricted
    conditions:
      agent_metadata.data_classification: "RESTRICTED"
    verdict: BLOCK
    explain: "RESTRICTED data is not transmitted to the LLM without explicit authorization."
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
    explain: "Prompt injection pattern detected in the RAG chunk."

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
    explain: "Regression > 5% vs previous version. Rollback recommended."

  - name: block_low_refusal
    conditions:
      parameters_preview.eval_refusal_accuracy: { lt: 0.70 }
    verdict: BLOCK
    explain: "Insufficient refusal rate. Risk of hallucination on out-of-domain questions."

  - name: block_low_accuracy
    conditions:
      parameters_preview.eval_accuracy: { lt: 0.80 }
    verdict: BLOCK
    explain: "Accuracy below the minimum 80% threshold."

  - name: allow_deploy
    conditions:
      parameters_preview.eval_accuracy: { gte: 0.80 }
      parameters_preview.eval_groundedness: { gte: 0.75 }
      parameters_preview.eval_refusal_accuracy: { gte: 0.70 }
      parameters_preview.benchmark_vs_previous: { gte: -0.02 }
    verdict: ALLOW
    explain: "Metrics meet the criteria. Deploy authorized."
```

```yaml
# data/policies/chatbot-lora-deploy-health.yaml
# Override for sector_id: health — higher threshold
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
    explain: "Health sector requires refusal_accuracy >= 90%. Risk of clinical hallucination is unacceptable."
```

---

## 8. Docker Compose — Development with BTV Sidecar

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
      BTV_LEDGER_MODE: "memory"        # In-memory DurableLedger for dev
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
    image: buildtovalue/vllm-mock:latest  # Mock for local dev without GPU
    ports:
      - "8000:8000"
```

---

## 9. Error Handling and Fallback

| Scenario | Behavior |
|:---------|:---------|
| BTV responds in < 5 s | Normal flow |
| BTV timeout (> 5 s) | Local BLOCK + `btv.timeout` log |
| HTTP 5xx | 1 retry (100 ms) → BLOCK on failure |
| Open circuit (≥ 3 failures / 30 s) | BLOCK all Destructive/Irreversible + alert |
| Invalid HMAC | BLOCK + `btv.hmac_mismatch` log + critical alert |
| BTV returns 401/403 | BLOCK + `btv.auth_failure` log + no retry |
| Unknown verdict | BLOCK + `btv.unknown_verdict` log |

**Universal rule:** any unforeseen condition = BLOCK. Never allow by omission.

---

## 10. Metrics and Observability

```
# Prometheus — prefix btv_chatbot_*
btv_chatbot_requests_total{gate, workspace_id, verdict, sector_id}
btv_chatbot_latency_ms{gate, workspace_id, p50|p95|p99}
btv_chatbot_lora_deploy_total{workspace_id, verdict, lora_version}
btv_chatbot_rag_blocks_total{workspace_id, reason}
btv_chatbot_pii_sanitized_total{workspace_id, pii_type}
btv_chatbot_training_cycle_total{workspace_id, verdict}
btv_chatbot_circuit_open{workspace_id}           # 1 = open, 0 = closed
btv_chatbot_evidence_ids_total{workspace_id, gate}
btv_chatbot_appeals_submitted_total{workspace_id, gate}
```

**Recommended alerts:**

```yaml
# monitoring/alerts/btv-chatbot.yaml
alerts:
  - name: BtvCircuitOpen
    expr: btv_chatbot_circuit_open > 0
    severity: critical
    message: "BTV sidecar unavailable. All gates are blocking."

  - name: BtvHighBlockRate
    expr: rate(btv_chatbot_requests_total{verdict="BLOCK"}[5m]) > 0.20
    severity: warning
    message: "BTV block rate > 20% over the last 5 min. Review policy."

  - name: BtvHmacMismatch
    expr: rate(btv_chatbot_requests_total{verdict="hmac_mismatch"}[5m]) > 0
    severity: critical
    message: "Invalid HMAC detected. Possible tampering with BTV response."
```

---

## 11. Contestability — Flow in the Chatbot

```
User receives BLOCK
        │
        ▼
UI displays explain_decision (natural language)
UI displays "Appeal" button (if contestable=true)
        │
        ▼ [user clicks "Appeal"]
        │
POST /v1/appeals
{
  "evidence_id": "<ev_hex>",
  "justification": "<user text>",
  "requested_by": "<user_id>",
  "timestamp_utc": "<ISO8601>"
}
        │
        ▼
UI displays: "Appeal submitted. Deadline: <appeal_deadline_utc>."
appeal_id saved locally for tracking.
        │
        ▼ [admin reviews in BTV dashboard]
        │
  ┌─────┴──────┐
APPROVED    REJECTED
  │              │
Action        Block
executed     upheld
  │              │
evidence_id  evidence_id
of the appeal of the appeal
in the ledger in the ledger
```

---

## 12. Summary Table: Migrating What Already Exists → BTV

| Current chatbot mechanism | Limitation | How BTV complements it |
|:--------------------------|:-----------|:-----------------------|
| `anonymizer.service.ts` (Angular) | Client-side, no forensic evidence | `/v1/sanitize` generates verifiable `evidence_id` |
| `audit_log` PostgreSQL | Same trust boundary as the data | BLAKE3 DurableLedger — external, immutable, signed |
| `data-classification.guard.ts` | UI guard, bypassable on the backend | Server-side BTV gate before each sensitive action |
| Internal LGPD report | Numbers without external proof | Ledger `evidence_id`s as forensic artifacts |
| Manual LoRA deploy | No formal approval trail | `Irreversible` gate with YAML policy + `evidence_id` |
| `blockOnPii` toggle (workspace) | Binary — global on/off | YAML policies per `sector_id` and `action_name` |

---

## 13. Go-Live Checklist

```
Infrastructure
  [ ] BTV v2.0 in production with DurableLedger + S3 configured
  [ ] Production API key generated for each active workspace
  [ ] HMAC key rotated and stored in the Vault
  [ ] YAML policies loaded and tested for each active sector_id
  [ ] Prometheus metrics collected and alerts configured

Gates
  [ ] Gate 1 tested: CONFIDENTIAL message without BTV → never reaches vLLM
  [ ] Gate 2 tested: RESTRICTED doc without evidence_id → does not enter Qdrant
  [ ] Gate 3 tested: chunk with "ignore previous instructions" → BLOCK
  [ ] Gate 4 tested: training cycle without approval → does not consume GPU
  [ ] Gate 5 tested: LoRA deploy with regression > 5% → BLOCK by policy

Fail-secure
  [ ] BTV sidecar taken down → all Destructive/Irreversible gates block
  [ ] HMAC key deliberately swapped → deploy blocked immediately
  [ ] Circuit breaker opens after 3 failures → alert fired

LGPD
  [ ] BTV evidence_ids present in the generated LGPD report
  [ ] Appeal flow tested end-to-end with appeal_deadline
  [ ] DPO validated the DurableLedger artifacts as forensic evidence

Documentation
  [ ] This file registered under docs/integrations/
  [ ] ADR-0029 registered in 0000-adr-index.md
  [ ] Operations runbook created (BTV restart, key rotation, rollback)
```

---

## 14. Cross-References

- BTV ADR-0028 (External Agent PDP — canonical contract)
- BTV ADR-0029 (this profile — architectural decision)
- BTV ADR-0004 (Immutable Ledger — BLAKE3 DurableLedger)
- BTV ADR-0005 (Evidence Protocol v2.1 — 9596 bytes)
- BTV ADR-0006 (Policy-as-Code — YAML)
- BTV ADR-0008 (Timing Mitigation — constant-time HMAC)
- BTV ADR-0010 (BiasDeclaration Mandate)
- BTV ADR-0017 (ContestabilityLoop SLA 24h)
- `docs/integrations/chatbot-external-llm.md` (ADR-0030 — variant with external LLM)
- Chatbot ADR-016 through ADR-020 (chatbot-side security and compliance)

---

## 16. SLM Integration — Current State, Prompts, and Expansion Points

### 16.1 What Already Exists

BTV already has a functional SLM integration, implemented in
`python/buildtovalue/intelligence/slm_classifier.py` per ADR-027. The
architecture follows two inviolable philosophical principles: **Jonas** (data
never leaves the perimeter — local model, zero external API) and **Levinas**
(the SLM output is a Finding, not a Verdict — humans can contest it).

**Component 1 — SLMClassifier**

A class that wraps a GGUF model via `llama-cpp-python`. Configured at
`app.py` startup: model loaded from disk (path via YAML
`data/policies/core/slm.yaml` or env var `BTV_SLM_MODEL_PATH`), 512-token
context, 2 CPU threads, 100ms timeout, optional GPU with automatic CPU
fallback. Candidate models defined in ADR-027: Phi-4-mini
(3.8B, MIT), Qwen2.5-3B (Apache 2.0), TinyLlama-1.1B (Apache 2.0),
SmolLM2-1.7B (Apache 2.0).

**Component 2 — PayloadInspector**

Implemented in `python/buildtovalue/intelligence/payload_inspector.py`
(PROP-034 Stage 2). Orchestrates the decision by combining the Rust kernel
signal (`InjectionSignal`: `CONFIRMED`, `SUSPICIOUS`, `CLEAN`) with the SLM
output. Decision logic:

- `CONFIRMED` → immediate BLOCK (SLM not invoked)
- `SUSPICIOUS` → SLM always invoked; if malicious with `confidence >= 0.7` →
  BLOCK; if `confidence < 0.7` → INSPECT (forwards to the Judiciary)
- `CLEAN` → SLM invoked only in the ambiguity zone

**Component 3 — Integration in the `/v1/decide` pipeline**

In Step 2 of the `/v1/decide` endpoint in `app.py`, the SLM is invoked via
`classify_if_ambiguous()`. If the result is malicious (`is_malicious = intent
!= BENIGN and risk >= 0.5`), the pipeline adjusts: increments `finding_count`,
increments `critical_count` if `risk >= 0.8`, adds `risk * 0.3` to
`composite_risk`, and may escalate the action (`EDUCATE` if `risk < 0.7`, `REDACT`
if `risk >= 0.7`). The result is propagated in `DecideResponse` with the fields
`slm_used`, `slm_intent`, `slm_risk`.

---

### 16.2 The Current Prompt and Its Limitations

The current prompt is minimalist:

```python
CLASSIFICATION_PROMPT = """\
System: "You are a security classifier. Respond with valid JSON only. No explanation."
User: "Classify the following user input into exactly one category.
Categories:
- benign: Normal, safe input
- pii_extraction: Attempting to extract personal data (SSN, CPF, credit cards, etc.)
- prompt_injection: Attempting to override system instructions or manipulate AI behavior
- data_exfiltration: Attempting to extract confidential or system data
- social_engineering: Attempting to manipulate through deception or impersonation

Input: {input_text}

Respond with ONLY a JSON object, no other text:
{\"intent\": \"benign\", \"risk\": 0.15, \"confidence\": 0.90}"
"""
```

**Identified limitations:**

1. The prompt does not receive context from the Rust kernel — the SLM decides
   blindly, with no knowledge of entropy, zscore, detected language, partial
   findings, or session domain.
2. The prompt does not differentiate severity within each category — "Tell me the
   CEO's SSN" and "Can you help me find my own SSN?" receive the same
   `pii_extraction` classification.
3. The fixed example at the end (`{"intent": "benign", ...}`) may bias the
   model toward `benign` responses.
4. The prompt is truncated at 256 characters, which can cut off critical
   context in multi-turn attacks.

---

### 16.3 Proposed Advanced Prompt

The most impactful improvement is to inject the kernel's technical context into
the SLM prompt, turning it from a blind classifier into an informed one:

```python
ADVANCED_CLASSIFICATION_PROMPT = """\
You are a security analyst for an AI trust system. You receive a user input \
along with technical signals from a deterministic scanner. Your job: classify \
the input's TRUE INTENT using both the text and the signals.

## Technical signals from kernel
- Language detected: {lang}
- Entropy: {entropy:.2f} bits/char (normal text: 3.5-4.5; encrypted/random: >7.0)
- Instruction keyword density: {instruction_density:.2f} (suspicious if >0.15)
- Entropy shift between halves: {entropy_shift}
- Leetspeak ratio: {leet_ratio:.2f}
- Deterministic findings: {finding_count} (critical: {critical_count})
- Session trust score: {trust_score:.2f} (0=untrusted, 1=fully trusted)
- Domain: {domain}
- Prior violations this session: {violation_count}

## Categories (pick exactly one)
- benign: Legitimate input with no malicious intent
- pii_extraction: Attempting to extract personal data (even without actual PII present)
- prompt_injection: Attempting to override, bypass, or manipulate AI instructions
- data_exfiltration: Attempting to extract system data, configs, or training data
- social_engineering: Using deception, urgency, impersonation, or emotional pressure
- policy_evasion: Deliberately encoding, obfuscating, or translating to bypass filters

## Severity guidelines
- risk 0.0-0.3: Low concern, likely benign or accidental
- risk 0.3-0.6: Moderate concern, ambiguous intent
- risk 0.6-0.8: High concern, likely malicious
- risk 0.8-1.0: Critical, clear malicious intent

## Important rules
- If entropy > 6.0 AND instruction_density > 0.1, weight toward prompt_injection
- If trust_score < 0.3 AND violation_count > 0, weight risk upward by 0.1
- If domain is "healthcare" or "finance", weight risk upward by 0.1 for PII categories
- If leet_ratio > 0.2, consider policy_evasion
- NEVER output anything except the JSON object

Input: {input_text}

Output (JSON only):"""
```

**Key changes versus the current prompt:**

- The SLM receives entropy, instruction density, entropy shift, leet ratio, trust
  score, domain, and prior violation count — all already computed by the
  kernel.
- Adds the `policy_evasion` category for inputs that try to bypass
  filters via encoding.
- Defines explicit severity guidelines instead of letting the model decide
  arbitrarily.
- Encodes cross-signal rules (high entropy + high instruction density = weight
  toward injection).
- Removes the fixed example at the end that biased toward `benign`.

---

### 16.4 Implementing Context Injection

The change is surgical. In `python/buildtovalue/api/app.py`, in Step 2, where the
SLM is called:

```python
# Before (current):
slm_result = _slm.classify_if_ambiguous(
    text=req.input_text,
    finding_count=req.finding_count,
    critical_count=req.critical_count,
)

# After (proposed):
slm_result = _slm.classify_with_context(
    text=req.input_text,
    finding_count=req.finding_count,
    critical_count=req.critical_count,
    context=SLMContext(
        lang=req.detected_language or "unknown",
        entropy=req.entropy,
        instruction_density=req.instruction_density or 0.0,
        entropy_shift=req.entropy_shift or False,
        leet_ratio=req.leet_ratio or 0.0,
        trust_score=get_trust_score(session_id),
        domain=_resolve_domain(req.profile),
        violation_count=db_get_session(session_id)["offenses"],
    ),
)
```

The `classify_with_context()` method formats the advanced prompt with the
context data and calls the LLM. The existing `classify_if_ambiguous()` method
remains as a fallback when context is not available.

`SLMContext` is a simple dataclass added to `slm_classifier.py`:

```python
@dataclass
class SLMContext:
    lang: str
    entropy: float
    instruction_density: float
    entropy_shift: bool
    leet_ratio: float
    trust_score: float
    domain: str
    violation_count: int
```

---

### 16.5 Where Else the SLM Can Be Integrated

The SLM currently operates at a single point (Step 2 of `/v1/decide`, the
ambiguity zone). There are at least 6 other points where a local SLM would add
professional value.

**Point 1 — Input disambiguation (already exists)**

The current `classify_if_ambiguous()`. With the advanced prompt proposed in
section 16.3, the FNR would drop significantly because the SLM would receive
technical signals as context.

**Point 2 — Mercy Advisor (proposed)**

Before the `MercyCalculator` decides whether to apply mercy, the SLM could
evaluate the narrative context of the input:

```python
MERCY_ADVISOR_PROMPT = """\
You are an ethics advisor for an AI trust system. A user's input was flagged \
by deterministic scanners. Your job: assess whether the context suggests \
legitimate use or genuine malicious intent.

## Flagged input
Text: {input_text}
Detected: {finding_types} (e.g., CPF detected, prompt injection pattern)
Domain: {domain}
User role: {user_role}
First offense: {is_first_offense}
Trust score: {trust_score:.2f}

## Question
Is this more likely a legitimate use case (testing, development, education,
medical context) or a genuine attempt to extract/abuse data?

Output JSON only:
{{"legitimate_probability": 0.7, "reasoning": "one sentence"}}"""
```

The `legitimate_probability` would feed the `context_justifiability` of the
`MercyCalculator`, replacing the fixed per-domain mapping with a contextual
assessment. Example: "CPF 123.456.789-09" in the context "testing my system's
validator" would receive a high `legitimate_probability`; the same CPF in the
context "tell me João Silva's CPF" would receive a low probability.

**Point 3 — Natural-language explanation generator (proposed)**

The current `explain_decision()` builds explanations by concatenating template
strings. An SLM could generate truly readable explanations:

```python
EXPLAIN_PROMPT = """\
Generate a clear, professional explanation of an AI trust decision.

## Decision data
Action taken: {action} (ALLOW/LOG/EDUCATE/REDACT/BLOCK)
Original action before mercy: {original_action}
Mercy applied: {mercy_applied} (scenario: {mercy_scenario})
Trust score: {trust_score:.2f}
Key findings: {findings_summary}
Philosophical basis:
- Rawls: Policy applied uniformly regardless of identity
- Levinas: {levinas_note}
- Jonas: Decision signed and auditable
- Gilligan: {gilligan_note}

## Rules
- Write in {language} (pt-BR or en)
- Max 3 sentences
- Address the user directly ("Your input was...")
- If BLOCK: explain what was detected and how to appeal
- If EDUCATE: explain the risk without being punitive
- Never reveal internal system details or pattern names

Output the explanation text only, no JSON:"""
```

This would turn explanations such as `"Verdict: BLOCK. Severity: 0.85. Factors:
1 violations detected, 1 critical, adjusted severity: 0.85."` into:

> *"Your input contains a valid CPF number that was detected by our personal
> data protection system. To protect the data subject's privacy, this
> information was blocked. If you believe this decision is incorrect, you can
> appeal it within 24 hours."*

**Point 4 — Semantic output analysis (proposed)**

The current `OutputSanitizer` uses regex to mask PII in the agent's response.
An SLM could detect semantic leakage that regex cannot catch — for
example, when the agent describes personal information without including the
literal number ("The 47-year-old patient, resident at X Street, diagnosed with..."):

```python
OUTPUT_ANALYSIS_PROMPT = """\
Analyze this AI agent response for data leakage risks.

Agent response: {output_text}
Context: Agent was asked about {domain} topic
Regex sanitizer already masked: {masked_count} items

Check for:
1. Indirect PII disclosure (describing someone identifiably without numbers)
2. Sensitive information inference (enough details to identify a person)
3. Internal system leakage (config, prompts, model details)
4. Compliance risk (medical/financial details that shouldn't be shared)

Output JSON:
{{"leak_detected": false, "leak_type": "none", "risk": 0.1, "recommendation": "safe"}}"""
```

**Point 5 — Appeal evidence analyzer (proposed, off-path)**

When a user submits an appeal with `reason` and `evidence`, the SLM could
automatically assess whether the evidence is plausible, producing a
recommendation for the human reviewer. With no timeout constraint (off-path):

```python
APPEAL_ANALYZER_PROMPT = """\
You are a pre-reviewer for AI trust decision appeals.

## Original decision
Action: {action}
Reason for block: {block_reason}
Findings: {findings}

## User's appeal
Reason: {appeal_reason}
Evidence provided: {evidence_url_or_text}

## Task
Assess if the appeal has merit. Consider:
- Is the user's explanation plausible?
- Could this be a false positive?
- Does the evidence support the claim?

Output JSON:
{{"merit_score": 0.7, "recommendation": "likely_legitimate",
  "suggested_action": "ACCEPT", "reasoning": "brief explanation"}}"""
```

The output would be displayed in the dashboard alongside the appeal, not as an
automatic decision.

**Point 6 — Compliance report generator (proposed, off-path)**

Automatically generate sections of LGPD/EU AI Act reports from ledger data.
The SLM would receive the raw data (decision counts, types of PII detected,
mercy rates, SLA compliance) and produce report text in compliance language.
Run on demand or in a daily batch.

**Point 7 — Policy YAML generator (proposed, off-path)**

The Threat→Policy Bridge (ADR-024) already exists in concept but uses
`enabled: false` and mandatory human-in-the-loop. The SLM could analyze new
threats from the ThreatFeed and propose YAML rules for human review,
accelerating the policy update cycle.

---

### 16.6 Model Selection — Updated Recommendation

ADR-027 listed Phi-4-mini, Qwen2.5-3B, TinyLlama-1.1B, and SmolLM2-1.7B as
candidates. Based on recent tamper resistance benchmarks (TRI scores) and
classification performance:

**For points 1–4 (hot path, 100ms timeout):** Phi-4-mini Q4_K_M (~2.3 GB
RAM) is the best choice. Best TRI among SLM models (0.358), strong reasoning
for JSON classification, MIT license, and inference in ~30-50ms with llama-cpp
on a modern CPU. Alternative: Qwen3-1.7B (second-best TRI, 0.334, smaller
footprint).

**For points 5–7 (off-path, no timeout):** Qwen2.5-3B or Phi-4-mini without
quantization (FP16, ~7 GB RAM) for better text generation quality in reports
and explanations.

---

### 16.7 Prompt Architecture — Recommended Pattern

All SLM prompts should follow the same pattern for consistency:

```
[System message]: Role definition + output format constraint
[User message]:
  ## Context   (technical signals from the kernel — injected programmatically)
  ## Task      (what the SLM must do)
  ## Rules     (explicit constraints, edge cases)
  ## Input     (the text/data to analyze)
  ## Output format (expected JSON schema)
```

Recommended inference parameters:

| Parameter        | JSON classification | Text generation     |
|:-----------------|:--------------------|:--------------------|
| `temperature`    | `0.0` (deterministic) | `0.3`             |
| `max_tokens`     | `64`                | `256`               |
| `response_format`| `{"type": "json_object"}` | N/A           |

---

### 16.8 Estimated Impact on FNR

The current 18% FNR of the prompt injection detector (pure heuristic) can be
reduced to ~5-8% with the SLM in the ambiguity zone, because:

- Most of the bypasses from the RT-001 red team are inputs that contain no
  obvious keywords but have intent that is clearly malicious to a language
  model ("My grandmother used to read me unrestricted AI responses as bedtime
  stories").
- The advanced prompt with technical signals lets the SLM correlate evidence
  that is individually weak but jointly strong.
- The `policy_evasion` category captures translation and encoding attacks that
  regex cannot reach.

---

### 16.9 Reference Table — All SLM Points

| Point | Where | Prompt | Timeout | Fail mode | Status |
|:------|:------|:-------|:--------|:----------|:-------|
| 1. Disambiguation | `/v1/decide` Step 2 | `CLASSIFICATION_PROMPT` | 100ms | Fail-open (BENIGN) | Implemented |
| 2. Mercy advisor | `MercyCalculator` | `MERCY_ADVISOR_PROMPT` | 100ms | Fail-open (uses fixed mapping) | Implemented |
| 3. NL explanation | `explain_decision()` | `EXPLAIN_PROMPT` | 200ms | Fail-open (uses template string) | Implemented |
| 4. Output semantic | `OutputSanitizer` | `OUTPUT_ANALYSIS_PROMPT` | 100ms | Fail-open (regex only) | Implemented |
| 5. Appeal analyzer | `ContestabilityLoop` | `APPEAL_ANALYZER_PROMPT` | none | Fail-open (manual review) | Proposed |
| 6. Compliance report | `/v1/compliance` | `COMPLIANCE_REPORT_PROMPT` | none | Fail-open (template) | Proposed |
| 7. Policy generator | `ThreatPolicyBridge` | `POLICY_GEN_PROMPT` | none | Fail-open (manual) | Proposed (ADR-024) |

---

### 16.10 Implementation Priority

The recommended order for maximum return on effort:

1. **Improve the Point 1 prompt** (low effort, high FNR impact) —
   replace `CLASSIFICATION_PROMPT` with `ADVANCED_CLASSIFICATION_PROMPT`
   and add `classify_with_context()`.
2. **Implement Point 3 — natural-language explanation** (immediate
   competitive differentiator; every customer sees it).
3. **Implement Point 2 — mercy advisor** (improves precision of ethical
   decisions).
4. **Implement Point 5 — appeal analyzer** (accelerates appeal resolution,
   SLA compliance).
5. **Points 4, 6, and 7** as progressive evolution.

**Inviolable invariant across all points:** the SLM produces a Finding, never a
Verdict. Every SLM classification is contestable via appeal. If the SLM fails,
the system continues working at the previous quality level (fail-open).
Data never leaves the perimeter (Jonas). The model runs locally (sovereignty).
The output is traceable via `model_id` and `latency_ms` in the Finding (transparency).
```

---

### Next steps / Related

- [Integrations — overview](./index.md)
- [API Reference](../api-reference.md)
- [Concepts](../concepts.md)

---

<sub>[↑ Hub](../README.md) · [Engineer Track](../for-engineers.md) · [DPO/CISO Track](../for-dpo-ciso.md) · [Reference Links](../reference-links.md)</sub>
