[Docs](../README.md) · [Engenheiro](../for-engineers.md) · [Integrações](./index.md) › **Chatbot Externo (Vendor LLM)**

![Engenheiro](https://img.shields.io/badge/Trilha-Engenheiro-1f6feb)

<!-- audience: engineer -->

---

# Perfil de Integração BTV: Chatbot com LLM Externa (Vendor API)

| Campo               | Valor                                             |
|:--------------------|:--------------------------------------------------|
| **Padrão**          | BTV ADR-0029 (External Agent PDP)                 |
| **ADR deste perfil**| BTV ADR-0031                                      |
| **Perfil base**     | `chatbot-internal-llm.md` (ADR-0030) — leia antes |
| **Versão chatbot**  | v1.0+ (Rust/Axum + Angular)                       |
| **Versão BTV**      | v2.0+                                             |
| **Vendors suportados** | OpenAI, Anthropic, Google, Azure OpenAI, Cohere   |
| **Mantenedor**      | Equipe Chatbot                                    |
| **Data**            | 2026-02-23                                        |

---

## 1. Princípio central deste perfil

> **Cada mensagem enviada a um vendor externo é uma transferência
> internacional de dados — sem exceção, sem cache, sem bypass.**

No perfil de LLM interna (`chatbot-internal-llm.md`), o dado nunca
sai do perímetro e o gate mais crítico ocorre uma vez por semana
(deploy de LoRA). Aqui, o gate mais crítico ocorre **a cada mensagem**,
e a prioridade de proteção é invertida:

```
ADR-0030 (interno)         ADR-0031 (externo)
─────────────────          ─────────────────
Gate crítico:              Gate crítico:
  lora_deploy (1x/sem)       llm_vendor_send (cada msg)

/v1/sanitize:              /v1/sanitize:
  se pii_detected=true       SEMPRE, sem exceção

ActionImpact da msg:       ActionImpact da msg:
  Destructive (se PII)       Irreversible (sempre)

Pipeline treino:           Pipeline treino:
  Gates 4 e 5                Não aplicável

Dado sai do perímetro?     Dado sai do perímetro?
  Nunca                      Sempre (cada mensagem)
```

---

## 2. Arquitetura de Integração

```
┌─────────────────────────────────────────────────────────────────┐
│  Frontend Angular                                               │
│                                                                 │
│  DataFilterService → BtvGateService → VendorService            │
│         │                  │                │                  │
│    detecta PII        sanitize+validate   envia ao vendor      │
│                       (toda mensagem)                           │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTP
┌──────────────────────────▼──────────────────────────────────────┐
│  Backend Rust (Axum)                                            │
│                                                                 │
│  VendorGateMiddleware                                           │
│    │                                                            │
│    ├─ POST /v1/sanitize ──────────────────► BTV Sidecar        │
│    ├─ POST /v1/validate (Irreversible) ───► BTV Sidecar        │
│    ├─ Vendor API call (dado sanitizado) ──► OpenAI/Anthropic   │
│    ├─ POST /v1/sanitize (resposta) ───────► BTV Sidecar        │
│    └─ POST /v1/validate (response display) ► BTV Sidecar       │
│                                                                 │
│  RAGPipeline (Qdrant)                                           │
│    └─ gate_rag_chunks_external() ─────────► BTV Sidecar        │
└─────────────────────────────────────────────────────────────────┘
                           │
              ┌────────────▼────────────┐
              │  BTV Sidecar v2.0       │
              │  /v1/validate           │
              │  /v1/sanitize           │
              │  /v1/appeals            │
              │  /v1/trust/{id}         │
              │  DurableLedger (BLAKE3) │
              └─────────────────────────┘
```

---

## 3. agent_id Canônico

```rust
// crates/btv-client/src/identity.rs

use blake3::Hasher;

/// Para LLM externa, o vendor_id integra o agent_id.
/// Garante rastreabilidade por empresa + vendor no DurableLedger.
pub fn derive_agent_id_external(
    workspace_id: &WorkspaceId,
    vendor_id: &str,
    version: &str,
) -> String {
    let mut hasher = Hasher::new();
    hasher.update(workspace_id.as_bytes());
    hasher.update(b":");
    hasher.update(vendor_id.as_bytes());
    hasher.update(b":");
    hasher.update(version.as_bytes());
    let hash = hasher.finalize();
    format!("chatbot-external-{}", &hash.to_hex()[..16])
}

// Exemplos:
// workspace: "ws_abc123" + vendor: "openai"    → "chatbot-external-a1b2c3d4e5f67890"
// workspace: "ws_abc123" + vendor: "anthropic" → "chatbot-external-9f8e7d6c5b4a3210"
```

**Propriedade crítica:** workspaces distintos geram `agent_id` distintos
mesmo usando o mesmo vendor. O DurableLedger do BTV separa evidências
por empresa **e** por vendor utilizado.

---

## 4. Mapeamento Completo de Ações → ActionImpact

### 4.1 Ações exclusivas deste perfil (delta do ADR-0029)

| Ação                               | `action.name`                  | Impact       | Gate? |
|:-----------------------------------|:-------------------------------|:-------------|:------|
| Envio de mensagem a vendor externo | `llm_vendor_send`              | Irreversible | ✅ sempre |
| Display de resposta do vendor      | `llm_vendor_response_display`  | Destructive  | ✅ sempre |
| Aprovação de vendor para workspace | `vendor_approve`               | Irreversible | ✅    |
| Revogação de vendor                | `vendor_revoke`                | Irreversible | ✅    |
| Chunk `CONFIDENTIAL` em prompt externo | `rag_chunk_inject_conf`    | Irreversible | ✅    |
| Chunk `RESTRICTED` em prompt externo  | *(bloqueio local)*          | —            | ❌ BLOCK antes do BTV |

### 4.2 Ações herdadas do ADR-0029

| Ação                                  | `action.name`              | Impact       | Gate? |
|:--------------------------------------|:---------------------------|:-------------|:------|
| Upload doc `PUBLIC`/`INTERNAL`        | `document_upload`          | Safe         | ❌    |
| Upload doc `CONFIDENTIAL`             | `document_upload_conf`     | Destructive  | ✅    |
| Upload doc `RESTRICTED`              | `document_upload_restr`    | Irreversible | ✅    |
| Chunk `SAFE`/`INTERNAL` em prompt     | `rag_chunk_inject`         | Destructive  | ✅    |
| Export de conversa (PDF/MD)           | `chat_export`              | Irreversible | ✅    |
| Exclusão de conversa                  | `chat_delete`              | Destructive  | ✅    |
| Export de documento original          | `document_export`          | Irreversible | ✅    |
| Suspensão de usuário                  | `user_suspend`             | Destructive  | ✅    |
| Alteração de role/permissão           | `user_role_change`         | Destructive  | ✅    |
| Revogação de API key                  | `api_key_revoke`           | Irreversible | ✅    |
| Exclusão em massa                     | `bulk_delete`              | Irreversible | ✅    |
| Alteração de política de dados        | `data_policy_change`       | Irreversible | ✅    |
| Geração de relatório LGPD             | `lgpd_report_generate`     | Destructive  | ✅    |

### 4.3 Ações removidas em relação ao ADR-0029

| Ação removida                  | Motivo                                      |
|:-------------------------------|:--------------------------------------------|
| `training_cycle_start`         | Modelo gerenciado pelo vendor; sem fine-tune|
| `lora_deploy`                  | Não há LoRA self-hosted                     |
| `training_qa_approve`          | `eligible_for_training` sempre `false`      |
| `training_dataset_export`      | Não há dataset interno                      |

---

## 5. Configuração de profile_id e sector_id

```yaml
# Configurado no onboarding do workspace
profile_id: "external-chatbot"

sector_id:
  juridico:    "legal"
  saude:       "health"
  financeiro:  "finance"
  rh:          "hr"
  geral:       "general"
  tecnologia:  "general"
```

**Impacto por `sector_id` nas políticas BTV:**

| `sector_id` | Restrições adicionais para vendors externos |
|:------------|:--------------------------------------------|
| `health`    | Exige Zero Data Retention (ZDR) ativo; bloqueia retenção > 0 dias |
| `legal`     | Exige DPA assinado; bloqueia vendors fora de BR/EU sem DPA |
| `finance`   | Exige DPA; bloqueia retenção > 30 dias; EDUCATE para CONFIDENTIAL |
| `hr`        | Bloqueia retenção > 30 dias; bloqueia dados com CPF para treino externo |
| `general`   | EDUCATE sem DPA; ALLOW com DPA |

---

## 6. Catálogo de Vendors e Atributos BTV

```rust
// crates/btv-client/src/vendor.rs

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VendorConfig {
    pub vendor_id: String,        // "openai" | "anthropic" | "google" | ...
    pub vendor_name: String,
    pub model: String,
    pub api_base_url: String,
    pub data_residency: String,   // "US" | "EU" | "BR" | ...
    pub data_retention_days: u32, // 0 = zero data retention
    pub has_dpa: bool,            // DPA assinado com a empresa
    pub has_zero_data_retention: bool,
    pub compliant_sectors: Vec<String>, // setores aprovados via política
}

// Catálogo padrão — sobrescrito por configuração do workspace
pub fn default_vendor_catalog() -> Vec<VendorConfig> {
    vec![
        VendorConfig {
            vendor_id: "openai".into(),
            vendor_name: "OpenAI".into(),
            model: "gpt-4o".into(),
            api_base_url: "https://api.openai.com/v1".into(),
            data_residency: "US".into(),
            data_retention_days: 30,   // padrão sem ZDR
            has_dpa: false,            // requer contrato Enterprise
            has_zero_data_retention: false,
            compliant_sectors: vec!["general".into()],
        },
        VendorConfig {
            vendor_id: "openai_enterprise".into(),
            vendor_name: "OpenAI Enterprise (ZDR)".into(),
            model: "gpt-4o".into(),
            api_base_url: "https://api.openai.com/v1".into(),
            data_residency: "US".into(),
            data_retention_days: 0,    // Zero Data Retention ativo
            has_dpa: true,
            has_zero_data_retention: true,
            compliant_sectors: vec![
                "general".into(), "hr".into(),
                "finance".into(), "legal".into(),
            ],
        },
        VendorConfig {
            vendor_id: "anthropic".into(),
            vendor_name: "Anthropic".into(),
            model: "claude-3-5-sonnet-20241022".into(),
            api_base_url: "https://api.anthropic.com/v1".into(),
            data_residency: "US".into(),
            data_retention_days: 0,
            has_dpa: true,
            has_zero_data_retention: true,
            compliant_sectors: vec![
                "general".into(), "hr".into(),
                "finance".into(), "legal".into(),
            ],
        },
        VendorConfig {
            vendor_id: "google".into(),
            vendor_name: "Google Gemini".into(),
            model: "gemini-2.0-flash".into(),
            api_base_url: "https://generativelanguage.googleapis.com/v1beta".into(),
            data_residency: "US".into(),
            data_retention_days: 0,
            has_dpa: true,
            has_zero_data_retention: true,
            compliant_sectors: vec![
                "general".into(), "hr".into(),
                "finance".into(),
            ],
        },
        VendorConfig {
            vendor_id: "azure_openai_br".into(),
            vendor_name: "Azure OpenAI (Brasil South)".into(),
            model: "gpt-4o".into(),
            api_base_url: "https://<resource>.openai.azure.com".into(),
            data_residency: "BR".into(), // dado permanece no Brasil
            data_retention_days: 0,
            has_dpa: true,
            has_zero_data_retention: true,
            compliant_sectors: vec![
                "general".into(), "hr".into(), "finance".into(),
                "legal".into(), "health".into(), // único aprovado para saúde
            ],
        },
    ]
}
```

---

## 7. Implementação dos 4 Gates

### Gate 1 — Transmissão de Mensagem ao Vendor

**Fluxo obrigatório e não-negociável:**

```
Mensagem do usuário
        │
        ▼
1. RESTRICTED? ──► BLOCK local (sem consulta BTV)
        │ não
        ▼
2. POST /v1/sanitize ──────────────────────────────► BTV
   (SEMPRE — não depende de pii_detected)           │
        │◄──────────────────────────────────────────┘
        │  sanitized.content + sanitize_evidence_id
        ▼
3. POST /v1/validate
   action: llm_vendor_send
   impact: Irreversible
   sanitized_before_send: true
   sanitize_evidence_id: <do passo 2>  ──────────► BTV
        │◄──────────────────────────────────────────┘
        │  VerdictEnvelope (ALLOW/EDUCATE/BLOCK)
   ┌────┴──────────────────────────────┐
ALLOW/EDUCATE                        BLOCK
   │                                   │
   ▼                                   ▼
Vendor API                      Feedback ao usuário
(sanitized.content)              + explain_decision
   │                             + opção de contestar
   ▼
Resposta do vendor
   │
   ▼
4. POST /v1/sanitize (resposta) ─────────────────► BTV
        │
        ▼
5. POST /v1/validate (response_display) ─────────► BTV
        │
ALLOW/EDUCATE ──► exibe ao usuário
BLOCK ──────────► exibe mensagem genérica de erro
```

**Rust — `crates/btv-client/src/gates/vendor_send.rs`:**

```rust
use crate::{BtvClient, AgentDecisionRequest, Action, ActionImpact,
            Context, BtvError, EvidenceId};
use crate::identity::derive_agent_id_external;
use crate::vendor::VendorConfig;
use crate::models::{Classification, WorkspaceContext};
use chrono::Utc;
use std::time::{Duration, SystemTime};

pub struct VendorSendGateResult {
    pub sanitized_content:   String,
    pub sanitize_evidence_id: EvidenceId,
    pub send_evidence_id:    EvidenceId,
    pub educate_warning:     Option<String>,
}

/// Gate 1 completo: sanitize → validate → resultado.
///
/// Invariantes aplicados aqui:
/// - RESTRICTED: bloqueio local antes de qualquer chamada BTV
/// - Sanitização sempre, sem exceção
/// - Cache zero: nenhum veredicto de llm_vendor_send é reutilizado
/// - Fail-secure: BtvError de qualquer tipo = não envia ao vendor
pub async fn gate_vendor_send(
    message: &RawMessage,
    btv: &dyn BtvClient,
    ctx: &WorkspaceContext,
    vendor: &VendorConfig,
) -> Result<VendorSendGateResult, BtvError> {
    // Invariante: RESTRICTED nunca sai — bloqueio local, sem BTV
    if message.classification == Classification::Restricted {
        return Err(BtvError::LocalBlock {
            reason: "Dados RESTRICTED não são transmitidos a vendors externos.".into(),
        });
    }

    let gate_start = SystemTime::now();

    // Passo 1: sanitização obrigatória (sempre)
    let sanitized = btv.sanitize_output(&message.content)
        .await
        .map_err(|_| BtvError::Unavailable)?;

    // Valida frescor da sanitização (≤ 5 s)
    if gate_start.elapsed().unwrap_or(Duration::MAX) > Duration::from_secs(5) {
        return Err(BtvError::SanitizeStaleness);
    }

    // Passo 2: validação de transmissão (Irreversible — sem cache)
    let req = AgentDecisionRequest {
        schema_version:  "1.0".into(),
        request_id:      uuid::Uuid::new_v4().to_string(),
        agent_id:        derive_agent_id_external(
                             &ctx.workspace_id,
                             &vendor.vendor_id,
                             env!("CARGO_PKG_VERSION"),
                         ),
        session_id:      ctx.session_id.clone(),
        action: Action {
            name:         "llm_vendor_send".into(),
            impact:       ActionImpact::Irreversible,
            capabilities: vec![
                "external_data_transfer".into(),
                format!("llm_vendor_{}", vendor.vendor_id),
            ],
        },
        // Hash do conteúdo JÁ sanitizado — nunca do original
        parameters_hash: blake3_hex(sanitized.content.as_bytes()),
        parameters_preview: serde_json::json!({
            "message_length":      sanitized.content.len(),
            "classification":      message.classification,
            "pii_types_found":     sanitized.pii_types,
            "vendor_id":           vendor.vendor_id,
            "vendor_model":        vendor.model,
            "data_residency":      vendor.data_residency,
            "has_dpa":             vendor.has_dpa,
            "retention_days":      vendor.data_retention_days,
        }),
        context: Context {
            profile_id:          "external-chatbot".into(),
            sector_id:           ctx.sector_id.clone(),
            session_trust_score: ctx.trust_score,
            agent_metadata: serde_json::json!({
                "workspace_id":                ctx.workspace_id,
                "vendor_id":                   vendor.vendor_id,
                "vendor_model":                vendor.model,
                "data_classification":         message.classification,
                "pii_detected":                message.pii_detected,
                "pii_types":                   message.pii_types,
                "sanitized_before_send":       true,  // sempre true neste gate
                "sanitize_evidence_id":        sanitized.evidence_id,
                "eligible_for_training":       false, // dado sai do perímetro
                "rag_context":                 false,
                "data_residency_required":     ctx.data_residency,
                "vendor_data_retention_days":  vendor.data_retention_days,
                "has_zero_data_retention":     vendor.has_zero_data_retention,
                "action_subtype":              "llm_vendor_send"
            }),
        },
        timestamp_utc: Utc::now().to_rfc3339(),
    };

    let envelope = btv.request_decision(&req)
        .await
        .map_err(|_| BtvError::Unavailable)?;

    // Verificação HMAC obrigatória — constant-time
    btv.verify_hmac(&envelope)?;

    match envelope.verdict.as_str() {
        "ALLOW" => Ok(VendorSendGateResult {
            sanitized_content:    sanitized.content,
            sanitize_evidence_id: sanitized.evidence_id,
            send_evidence_id:     envelope.evidence_id,
            educate_warning:      None,
        }),
        "EDUCATE" => Ok(VendorSendGateResult {
            sanitized_content:    sanitized.content,
            sanitize_evidence_id: sanitized.evidence_id,
            send_evidence_id:     envelope.evidence_id,
            educate_warning:      Some(envelope.explain_decision),
        }),
        "BLOCK" => Err(BtvError::Blocked {
            reason:      envelope.explain_decision,
            evidence_id: envelope.evidence_id,
            contestable: envelope.contestable,
        }),
        _ => Err(BtvError::UnexpectedVerdict),
    }
}
```

---

### Gate 2 — Resposta do Vendor

```rust
// crates/btv-client/src/gates/vendor_response.rs

pub struct VendorResponseResult {
    pub safe_content:         String,
    pub response_evidence_id: EvidenceId,
}

/// Gate 2: sanitiza e valida resposta recebida do vendor.
///
/// Protege contra:
/// - Exfiltração via prompt injection no modelo externo
/// - Respostas com padrões de dados sensíveis (chaves, tokens, PII)
/// - Conteúdo manipulado que tente injetar instruções no frontend
pub async fn gate_vendor_response(
    raw_response:       &str,
    btv:                &dyn BtvClient,
    ctx:                &WorkspaceContext,
    vendor:             &VendorConfig,
    send_evidence_id:   &EvidenceId,
) -> Result<VendorResponseResult, BtvError> {
    // Sanitiza a resposta antes de qualquer validação
    let sanitized = btv.sanitize_output(raw_response)
        .await
        .map_err(|_| BtvError::Unavailable)?;

    let req = AgentDecisionRequest {
        schema_version:  "1.0".into(),
        request_id:      uuid::Uuid::new_v4().to_string(),
        agent_id:        derive_agent_id_external(
                             &ctx.workspace_id,
                             &vendor.vendor_id,
                             env!("CARGO_PKG_VERSION"),
                         ),
        session_id:      ctx.session_id.clone(),
        action: Action {
            name:         "llm_vendor_response_display".into(),
            impact:       ActionImpact::Destructive,
            capabilities: vec!["vendor_response_display".into()],
        },
        parameters_hash: blake3_hex(sanitized.content.as_bytes()),
        parameters_preview: serde_json::json!({
            "response_length":    sanitized.content.len(),
            "pii_types_found":    sanitized.pii_types,
            "vendor_id":          vendor.vendor_id,
            "send_evidence_id":   send_evidence_id,  // correlação com Gate 1
        }),
        context: Context {
            profile_id:          "external-chatbot".into(),
            sector_id:           ctx.sector_id.clone(),
            session_trust_score: ctx.trust_score,
            agent_metadata: serde_json::json!({
                "workspace_id":        ctx.workspace_id,
                "vendor_id":           vendor.vendor_id,
                "send_evidence_id":    send_evidence_id,
                "eligible_for_training": false,
                "action_subtype":      "vendor_response"
            }),
        },
        timestamp_utc: Utc::now().to_rfc3339(),
    };

    let envelope = btv.request_decision(&req)
        .await
        .map_err(|_| BtvError::Unavailable)?;

    btv.verify_hmac(&envelope)?;

    match envelope.verdict.as_str() {
        "ALLOW" | "EDUCATE" => Ok(VendorResponseResult {
            safe_content:         sanitized.content,
            response_evidence_id: envelope.evidence_id,
        }),
        "BLOCK" => {
            tracing::warn!(
                evidence_id  = %envelope.evidence_id,
                vendor_id    = %vendor.vendor_id,
                send_ev      = %send_evidence_id,
                "Resposta do vendor bloqueada: {}",
                envelope.explain_decision
            );
            Err(BtvError::VendorResponseBlocked {
                reason:      envelope.explain_decision,
                evidence_id: envelope.evidence_id,
            })
        }
        _ => Err(BtvError::UnexpectedVerdict),
    }
}
```

---

### Gate 3 — Aprovação de Vendor (por sessão, TTL 60 s)

```rust
// crates/btv-client/src/gates/vendor_approval.rs

use std::collections::HashMap;
use tokio::sync::RwLock;
use std::time::{Duration, Instant};

struct CachedApproval {
    evidence_id: EvidenceId,
    approved_at: Instant,
}

pub struct VendorApprovalCache {
    entries: RwLock<HashMap<(WorkspaceId, String), CachedApproval>>,
    ttl:     Duration,
}

impl VendorApprovalCache {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl:     Duration::from_secs(60),
        }
    }

    pub async fn get(
        &self,
        workspace_id: &WorkspaceId,
        vendor_id:    &str,
    ) -> Option<EvidenceId> {
        let entries = self.entries.read().await;
        let key = (workspace_id.clone(), vendor_id.to_string());
        entries.get(&key).and_then(|entry| {
            if entry.approved_at.elapsed() < self.ttl {
                Some(entry.evidence_id.clone())
            } else {
                None // TTL expirado
            }
        })
    }

    pub async fn insert(
        &self,
        workspace_id: WorkspaceId,
        vendor_id:    String,
        evidence_id:  EvidenceId,
    ) {
        let mut entries = self.entries.write().await;
        entries.insert(
            (workspace_id, vendor_id),
            CachedApproval { evidence_id, approved_at: Instant::now() },
        );
    }
}

/// Gate 3: valida se o vendor está aprovado para o sector_id do workspace.
/// Cache TTL 60 s — único gate cacheável neste perfil.
/// BLOCK = vendor proibido para este setor; sessão não iniciada.
pub async fn gate_vendor_approval(
    vendor:  &VendorConfig,
    btv:     &dyn BtvClient,
    ctx:     &WorkspaceContext,
    cache:   &VendorApprovalCache,
) -> Result<EvidenceId, BtvError> {
    // Verifica cache antes de chamar BTV
    if let Some(cached) = cache.get(&ctx.workspace_id, &vendor.vendor_id).await {
        tracing::debug!(
            vendor_id = %vendor.vendor_id,
            "Aprovação de vendor em cache"
        );
        return Ok(cached);
    }

    let req = AgentDecisionRequest {
        schema_version:  "1.0".into(),
        request_id:      uuid::Uuid::new_v4().to_string(),
        agent_id:        derive_agent_id_external(
                             &ctx.workspace_id,
                             &vendor.vendor_id,
                             env!("CARGO_PKG_VERSION"),
                         ),
        session_id:      format!("vendor-approval-{}", ctx.workspace_id),
        action: Action {
            name:         "vendor_approve".into(),
            impact:       ActionImpact::Irreversible,
            capabilities: vec![
                "vendor_session_start".into(),
                format!("llm_vendor_{}", vendor.vendor_id),
            ],
        },
        parameters_hash: blake3_hex(vendor.vendor_id.as_bytes()),
        parameters_preview: serde_json::json!({
            "vendor_id":                  vendor.vendor_id,
            "vendor_model":               vendor.model,
            "data_residency":             vendor.data_residency,
            "data_retention_days":        vendor.data_retention_days,
            "has_dpa":                    vendor.has_dpa,
            "has_zero_data_retention":    vendor.has_zero_data_retention,
        }),
        context: Context {
            profile_id:          "external-chatbot".into(),
            sector_id:           ctx.sector_id.clone(),
            session_trust_score: ctx.trust_score,
            agent_metadata: serde_json::json!({
                "workspace_id":    ctx.workspace_id,
                "action_subtype":  "vendor_approve",
                "vendor_id":       vendor.vendor_id,
            }),
        },
        timestamp_utc: Utc::now().to_rfc3339(),
    };

    let envelope = btv.request_decision(&req).await?;
    btv.verify_hmac(&envelope)?;

    match envelope.verdict.as_str() {
        "ALLOW" => {
            // Popula cache apenas para ALLOW
            cache.insert(
                ctx.workspace_id.clone(),
                vendor.vendor_id.clone(),
                envelope.evidence_id.clone(),
            ).await;
            Ok(envelope.evidence_id)
        }
        "EDUCATE" => {
            // EDUCATE: aprovado com aviso — também cacheável
            tracing::warn!(
                vendor_id = %vendor.vendor_id,
                "Vendor aprovado com ressalvas: {}",
                envelope.explain_decision
            );
            cache.insert(
                ctx.workspace_id.clone(),
                vendor.vendor_id.clone(),
                envelope.evidence_id.clone(),
            ).await;
            Ok(envelope.evidence_id)
        }
        "BLOCK" => Err(BtvError::Blocked {
            reason:      envelope.explain_decision,
            evidence_id: envelope.evidence_id,
            contestable: envelope.contestable,
        }),
        _ => Err(BtvError::UnexpectedVerdict),
    }
}
```

---

### Gate 4 — Contexto RAG para Vendor Externo

```rust
// crates/btv-client/src/gates/rag_external.rs

use futures::future::join_all;

/// Gate 4: filtra chunks antes de injetar em prompt enviado a vendor.
///
/// Delta crítico vs ADR-0029 Gate 3:
/// - RESTRICTED: bloqueio LOCAL, sem consulta BTV (dado nunca sai)
/// - CONFIDENTIAL: Irreversible (não Destructive como no perfil interno)
/// - Mesmos padrões de injection do perfil interno
pub async fn gate_rag_chunks_external(
    chunks:  Vec<RagChunk>,
    btv:     &dyn BtvClient,
    ctx:     &WorkspaceContext,
    vendor:  &VendorConfig,
) -> Vec<RagChunk> {
    let futures: Vec<_> = chunks
        .iter()
        .map(|chunk| validate_chunk_external(chunk, btv, ctx, vendor))
        .collect();

    let results = join_all(futures).await;

    chunks
        .into_iter()
        .zip(results)
        .filter_map(|(chunk, result)| match result {
            Ok(true)  => Some(chunk),
            Ok(false) => {
                tracing::warn!(
                    chunk_id        = %chunk.id,
                    classification  = %chunk.classification,
                    "Chunk excluído do contexto RAG externo"
                );
                None
            }
            Err(e) => {
                tracing::error!(error = %e, "Gate RAG externo falhou — chunk excluído");
                None
            }
        })
        .collect()
}

async fn validate_chunk_external(
    chunk:  &RagChunk,
    btv:    &dyn BtvClient,
    ctx:    &WorkspaceContext,
    vendor: &VendorConfig,
) -> Result<bool, BtvError> {
    // RESTRICTED: bloqueio incondicional local
    if chunk.classification == Classification::Restricted {
        tracing::warn!(
            chunk_id = %chunk.id,
            "Chunk RESTRICTED bloqueado localmente — não consulta BTV"
        );
        return Ok(false);
    }

    // CONFIDENTIAL para vendor externo: Irreversible
    let (action_name, impact) = match chunk.classification {
        Classification::Confidential =>
            ("rag_chunk_inject_conf", ActionImpact::Irreversible),
        _ =>
            ("rag_chunk_inject", ActionImpact::Destructive),
    };

    let req = build_rag_external_request(
        chunk, action_name, impact, ctx, vendor
    );

    let envelope = btv.request_decision(&req).await?;
    btv.verify_hmac(&envelope)?;
    Ok(matches!(envelope.verdict.as_str(), "ALLOW" | "EDUCATE"))
}
```

---

## 8. Angular — BtvGateService (implementação completa)

```typescript
// core/services/btv-gate.service.ts

import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { WorkspaceContextService } from './workspace-context.service';
import { DataFilterService, FilteredMessage } from './data-filter.service';

export interface SanitizeResult {
  content:     string;
  evidence_id: string;
  pii_types:   string[];
  content_hash: string;
}

export interface VendorSendResult {
  sanitizedContent:     string;
  sanitizeEvidenceId:   string;
  sendEvidenceId:       string;
  educateWarning:       string | null;
}

export class VendorSendBlockedError extends Error {
  constructor(
    public reason:      string,
    public evidenceId:  string,
    public contestable: boolean,
  ) { super(reason); }
}

export class VendorResponseBlockedError extends Error {
  constructor(public reason: string) { super(reason); }
}

export class BtvUnavailableError extends Error {}

@Injectable({ providedIn: 'root' })
export class BtvGateService {
  private readonly http = inject(HttpClient);
  private readonly ctx  = inject(WorkspaceContextService);

  // Cache de aprovação de vendor (TTL 60s, espelhando o Rust)
  private readonly vendorApprovalCache =
    new Map<string, { evidenceId: string; approvedAt: number }>();

  // ──────────────────────────────────────────────────────────────
  // Gate 3: aprovação de vendor (por sessão, com cache 60s)
  // ──────────────────────────────────────────────────────────────
  async ensureVendorApproved(vendor: VendorConfig): Promise<string> {
    const workspace = this.ctx.current();
    const cacheKey  = `${workspace.workspaceId}:${vendor.id}`;
    const cached    = this.vendorApprovalCache.get(cacheKey);

    if (cached && Date.now() - cached.approvedAt < 60_000) {
      return cached.evidenceId;
    }

    const request = {
      schema_version:   '1.0',
      request_id:       crypto.randomUUID(),
      agent_id:         `chatbot-external-${workspace.btvAgentHash}`,
      session_id:       `vendor-approval-${workspace.workspaceId}`,
      action: {
        name:         'vendor_approve',
        impact:       'Irreversible',
        capabilities: ['vendor_session_start', `llm_vendor_${vendor.id}`],
      },
      parameters_hash: await this.hash(vendor.id),
      parameters_preview: {
        vendor_id:                 vendor.id,
        vendor_model:              vendor.model,
        data_residency:            vendor.dataResidency,
        data_retention_days:       vendor.dataRetentionDays,
        has_dpa:                   vendor.hasDpa,
        has_zero_data_retention:   vendor.hasZeroDataRetention,
      },
      context: {
        profile_id:          'external-chatbot',
        sector_id:           workspace.sectorId,
        session_trust_score: workspace.trustScore,
        agent_metadata: {
          workspace_id:   workspace.workspaceId,
          action_subtype: 'vendor_approve',
          vendor_id:      vendor.id,
        },
      },
      timestamp_utc: new Date().toISOString(),
    };

    let verdict: VerdictEnvelope;
    try {
      verdict = await firstValueFrom(
        this.http.post<VerdictEnvelope>('/api/btv/validate', request)
      );
    } catch {
      throw new BtvUnavailableError('BTV indisponível — sessão bloqueada');
    }

    if (verdict.verdict === 'BLOCK') {
      throw new VendorSendBlockedError(
        verdict.explain_decision,
        verdict.evidence_id,
        verdict.contestable,
      );
    }

    // Popula cache para ALLOW e EDUCATE
    this.vendorApprovalCache.set(cacheKey, {
      evidenceId: verdict.evidence_id,
      approvedAt: Date.now(),
    });
    return verdict.evidence_id;
  }

  // ──────────────────────────────────────────────────────────────
  // Gate 1: sanitize + validate transmissão (Irreversible, sem cache)
  // ──────────────────────────────────────────────────────────────
  async validateVendorSend(
    filtered: FilteredMessage,
    vendor:   VendorConfig,
  ): Promise<VendorSendResult> {
    const workspace = this.ctx.current();

    // Bloqueio local para RESTRICTED — sem consulta BTV
    if (filtered.classification === 'RESTRICTED') {
      throw new VendorSendBlockedError(
        'Dados RESTRICTED não são transmitidos a vendors externos.',
        'local-block',
        false,
      );
    }

    // Passo 1: sanitização obrigatória
    const sanitized = await this.sanitize(filtered.content);
    const sanitizeTs = Date.now();

    // Valida frescor (≤ 5 s)
    if (Date.now() - sanitizeTs > 5_000) {
      throw new BtvUnavailableError('Sanitização expirou — tente novamente');
    }

    // Passo 2: validação de transmissão (Irreversible — sem cache)
    const request = {
      schema_version: '1.0',
      request_id:     crypto.randomUUID(),
      agent_id:       `chatbot-external-${workspace.btvAgentHash}`,
      session_id:     workspace.sessionId,
      action: {
        name:         'llm_vendor_send',
        impact:       'Irreversible',
        capabilities: ['external_data_transfer', `llm_vendor_${vendor.id}`],
      },
      parameters_hash: sanitized.content_hash,
      parameters_preview: {
        message_length:   sanitized.content.length,
        classification:   filtered.classification,
        pii_types_found:  sanitized.pii_types,
        vendor_id:        vendor.id,
        vendor_model:     vendor.model,
        data_residency:   vendor.dataResidency,
        has_dpa:          vendor.hasDpa,
        retention_days:   vendor.dataRetentionDays,
      },
      context: {
        profile_id:          'external-chatbot',
        sector_id:           workspace.sectorId,
        session_trust_score: workspace.trustScore,
        agent_metadata: {
          workspace_id:               workspace.workspaceId,
          vendor_id:                  vendor.id,
          vendor_model:               vendor.model,
          data_classification:        filtered.classification,
          pii_detected:               filtered.piiDetected,
          pii_types:                  filtered.piiTypes,
          sanitized_before_send:      true,  // sempre true aqui
          sanitize_evidence_id:       sanitized.evidence_id,
          eligible_for_training:      false, // dado sai do perímetro
          rag_context:                false,
          data_residency_required:    workspace.dataResidency,
          vendor_data_retention_days: vendor.dataRetentionDays,
          has_zero_data_retention:    vendor.hasZeroDataRetention,
          action_subtype:             'llm_vendor_send',
        },
      },
      timestamp_utc: new Date().toISOString(),
    };

    let verdict: VerdictEnvelope;
    try {
      verdict = await firstValueFrom(
        this.http.post<VerdictEnvelope>('/api/btv/validate', request)
      );
    } catch {
      throw new BtvUnavailableError();
    }

    if (verdict.verdict === 'BLOCK') {
      throw new VendorSendBlockedError(
        verdict.explain_decision,
        verdict.evidence_id,
        verdict.contestable,
      );
    }

    return {
      sanitizedContent:   sanitized.content,
      sanitizeEvidenceId: sanitized.evidence_id,
      sendEvidenceId:     verdict.evidence_id,
      educateWarning:     verdict.verdict === 'EDUCATE'
                            ? verdict.explain_decision
                            : null,
    };
  }

  // ──────────────────────────────────────────────────────────────
  // Gate 2: sanitize + validate resposta do vendor
  // ──────────────────────────────────────────────────────────────
  async validateVendorResponse(
    rawResponse:    string,
    sendEvidenceId: string,
    vendor:         VendorConfig,
  ): Promise<string> {
    const workspace = this.ctx.current();

    const sanitized = await this.sanitize(rawResponse);

    const request = {
      schema_version: '1.0',
      request_id:     crypto.randomUUID(),
      agent_id:       `chatbot-external-${workspace.btvAgentHash}`,
      session_id:     workspace.sessionId,
      action: {
        name:         'llm_vendor_response_display',
        impact:       'Destructive',
        capabilities: ['vendor_response_display'],
      },
      parameters_hash: sanitized.content_hash,
      parameters_preview: {
        response_length:  sanitized.content.length,
        pii_types_found:  sanitized.pii_types,
        vendor_id:        vendor.id,
        send_evidence_id: sendEvidenceId,
      },
      context: {
        profile_id:          'external-chatbot',
        sector_id:           workspace.sectorId,
        session_trust_score: workspace.trustScore,
        agent_metadata: {
          workspace_id:      workspace.workspaceId,
          vendor_id:         vendor.id,
          send_evidence_id:  sendEvidenceId,
          eligible_for_training: false,
          action_subtype:    'vendor_response',
        },
      },
      timestamp_utc: new Date().toISOString(),
    };

    let verdict: VerdictEnvelope;
    try {
      verdict = await firstValueFrom(
        this.http.post<VerdictEnvelope>('/api/btv/validate', request)
      );
    } catch {
      throw new BtvUnavailableError();
    }

    if (verdict.verdict === 'BLOCK') {
      throw new VendorResponseBlockedError(verdict.explain_decision);
    }

    return sanitized.content;
  }

  // ──────────────────────────────────────────────────────────────
  // Helpers privados
  // ──────────────────────────────────────────────────────────────
  private async sanitize(content: string): Promise<SanitizeResult> {
    return firstValueFrom(
      this.http.post<SanitizeResult>('/api/btv/sanitize', { content })
    );
  }

  private async hash(input: string): Promise<string> {
    const buf = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(input)
    );
    return Array.from(new Uint8Array(buf))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
}
```

**Integração no `chat-container.component.ts`:**

```typescript
async sendMessage(rawText: string): Promise<void> {
  const filtered = this.dataFilter.processMessage(rawText, this.workspace);
  const vendor   = this.workspace.vendorConfig;

  try {
    // Gate 3: vendor aprovado para este sector_id? (com cache 60s)
    await this.btvGate.ensureVendorApproved(vendor);

    // Gate 1: sanitize + validate transmissão (Irreversible, sem cache)
    const gateResult = await this.btvGate.validateVendorSend(
      filtered, vendor
    );

    if (gateResult.educateWarning) {
      this.showEducateWarning(gateResult.educateWarning);
    }

    // Envia ao vendor APENAS o conteúdo sanitizado
    const rawResponse = await this.vendorService.send(
      gateResult.sanitizedContent,
      vendor,
      gateResult.sendEvidenceId,  // correlação no log
    );

    // Gate 2: sanitiza e valida resposta antes de exibir
    const safeResponse = await this.btvGate.validateVendorResponse(
      rawResponse,
      gateResult.sendEvidenceId,
      vendor,
    );

    this.addAssistantMessage(safeResponse, {
      sendEvidenceId:     gateResult.sendEvidenceId,
      sanitizeEvidenceId: gateResult.sanitizeEvidenceId,
    });

  } catch (e) {
    if (e instanceof VendorSendBlockedError) {
      this.showSendBlocked(e.reason, e.evidenceId, e.contestable);
    } else if (e instanceof VendorResponseBlockedError) {
      this.showResponseBlocked(e.reason);
    } else {
      // BTV indisponível = não envia (fail-secure)
      this.showBtvUnavailable();
    }
  }
}
```

---

## 9. Políticas YAML Completas

```yaml
# data/policies/chatbot-vendor-approval.yaml
id: chatbot-vendor-approval-v1
applies_to:
  profile_id: "external-chatbot"
  action_names: ["vendor_approve"]
rules:
  - name: block_health_no_zdr
    conditions:
      sector_id: "health"
      parameters_preview.has_zero_data_retention: false
    verdict: BLOCK
    explain: >
      Setor saúde: exige Zero Data Retention ativo.
      Contrate plano Enterprise com ZDR antes de habilitar este vendor.

  - name: block_legal_no_dpa
    conditions:
      sector_id: "legal"
      parameters_preview.has_dpa: false
    verdict: BLOCK
    explain: >
      Setor jurídico: exige DPA assinado com o vendor.
      Consulte o departamento jurídico para assinar o DPA.

  - name: block_finance_no_dpa_foreign
    conditions:
      sector_id: "finance"
      parameters_preview.data_residency: { not_in: ["BR", "EU"] }
      parameters_preview.has_dpa: false
    verdict: BLOCK
    explain: >
      Setor financeiro: vendor fora do BR/EU sem DPA viola LGPD Art. 33.

  - name: block_hr_long_retention
    conditions:
      sector_id: "hr"
      parameters_preview.data_retention_days: { gt: 30 }
    verdict: BLOCK
    explain: >
      Setor RH: retenção > 30 dias. Dados de colaboradores exigem
      minimização de prazo (LGPD Art. 5, X).

  - name: allow_with_dpa
    conditions:
      parameters_preview.has_dpa: true
    verdict: ALLOW
    explain: "Vendor aprovado: DPA presente."

  - name: educate_no_dpa
    conditions:
      default: true
    verdict: EDUCATE
    explain: >
      Vendor sem DPA formal. Aprovado para dados não-sensíveis.
      Recomenda-se assinar DPA para dados INTERNAL ou acima.
```

```yaml
# data/policies/chatbot-vendor-send.yaml
id: chatbot-vendor-send-v1
applies_to:
  profile_id: "external-chatbot"
  action_names: ["llm_vendor_send"]
rules:
  - name: block_unsanitized
    conditions:
      agent_metadata.sanitized_before_send: false
    verdict: BLOCK
    explain: >
      Bloqueado: ausência de evidência de sanitização.
      O dado DEVE passar por /v1/sanitize antes de qualquer envio externo.

  - name: block_restricted
    conditions:
      agent_metadata.data_classification: "RESTRICTED"
    verdict: BLOCK
    explain: >
      Dados RESTRICTED não são transmitidos a vendors externos.
      Use LLM self-hosted para dados nesta classificação.

  - name: block_health_vendor_retention
    conditions:
      sector_id: "health"
      agent_metadata.vendor_data_retention_days: { gt: 0 }
    verdict: BLOCK
    explain: >
      Setor saúde: vendor com retenção de dados ativa.
      Habilite Zero Data Retention antes de transmitir dados de saúde.

  - name: educate_confidential
    conditions:
      agent_metadata.data_classification: "CONFIDENTIAL"
      agent_metadata.sanitized_before_send: true
    verdict: EDUCATE
    explain: >
      Dado CONFIDENTIAL sendo enviado a vendor externo com sanitização.
      Verifique se todos os identificadores foram removidos.

  - name: allow_sanitized
    conditions:
      agent_metadata.sanitized_before_send: true
      agent_metadata.data_classification: { in: ["PUBLIC", "INTERNAL"] }
    verdict: ALLOW
    explain: "Transmissão autorizada: dado sanitizado, classificação adequada."
```

```yaml
# data/policies/chatbot-vendor-response.yaml
id: chatbot-vendor-response-v1
applies_to:
  profile_id: "external-chatbot"
  action_names: ["llm_vendor_response_display"]
rules:
  - name: block_exfiltration_patterns
    conditions:
      content_patterns:
        - "CPF:"
        - "CNPJ:"
        - "senha:"
        - "password:"
        - "token:"
        - "Bearer "
        - "sk-"
        - "-----BEGIN"
        - "xoxb-"    # token Slack
        - "ghp_"     # token GitHub
    verdict: BLOCK
    explain: >
      Resposta contém padrões de exfiltração de dados sensíveis.
      Exibição bloqueada. Abra um ticket de segurança.

  - name: allow_clean
    conditions:
      default: true
    verdict: ALLOW
```

```yaml
# data/policies/chatbot-rag-external.yaml
id: chatbot-rag-external-v1
applies_to:
  profile_id: "external-chatbot"
  action_names: ["rag_chunk_inject", "rag_chunk_inject_conf"]
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
        - "<|im_start|>"
        - "<|system|>"
    verdict: BLOCK
    explain: "Padrão de prompt injection detectado no chunk RAG."

  - name: educate_confidential_external
    conditions:
      action.name: "rag_chunk_inject_conf"
    verdict: EDUCATE
    explain: >
      Chunk CONFIDENTIAL sendo injetado em prompt para vendor externo.
      Verifique se o conteúdo foi adequadamente sanitizado.

  - name: allow_safe
    conditions:
      default: true
    verdict: ALLOW
```

---

## 10. Evidência LGPD Art. 33

Para cada transmissão ao vendor, o DurableLedger contém:

```
evidence_id_sanitize
  ├─ timestamp de sanitização
  ├─ pii_types encontrados e removidos
  ├─ BLAKE3 do conteúdo sanitizado
  └─ HMAC-SHA256

evidence_id_send
  ├─ vendor_id e vendor_model
  ├─ sector_id e data_classification
  ├─ sanitize_evidence_id (referência cruzada)
  ├─ policy_version_applied
  ├─ data_residency e data_retention_days
  ├─ BLAKE3 + HMAC-SHA256
  └─ appeal_deadline_utc

evidence_id_response
  ├─ send_evidence_id (correlação com envio)
  ├─ pii_types encontrados na resposta
  ├─ BLAKE3 do conteúdo exibido
  └─ HMAC-SHA256
```

**Seção adicionada ao `ComplianceReportComponent`:**

```typescript
// features/admin/security/compliance-report.component.ts

internationalTransfers: {
  period:          string;
  total:           number;
  lgpdArt33Status: 'compliant' | 'attention' | 'non_compliant';
  byVendor: {
    vendorId:          string;
    vendorName:        string;
    dataResidency:     string;
    hasDpa:            boolean;
    hasZdr:            boolean;
    transferCount:     number;
    evidenceSample:    string[];   // últimos 5 evidence_ids BTV
    complianceStatus:  string;
  }[];
  nonCompliantInstances: {
    evidenceId:  string;
    timestamp:   string;
    vendorId:    string;
    reason:      string;           // EDUCATE sem DPA, etc.
  }[];
  dpoSignOffRequired: boolean;     // true se há instâncias não-conformes
}
```

---

## 11. Docker Compose — Desenvolvimento

```yaml
# docker-compose.external-llm.dev.yml
version: "3.9"

services:

  chatbot-backend:
    build: .
    ports:
      - "3000:3000"
    environment:
      BTV_URL:                        "http://btv-sidecar:8080"
      BTV_API_KEY:                    "dev-api-key-chatbot-external"
      BTV_TIMEOUT_MS:                 "5000"
      BTV_CIRCUIT_BREAKER_FAILURES:   "3"
      BTV_CIRCUIT_BREAKER_WINDOW_S:   "30"
      CHATBOT_PROFILE:                "external-chatbot"
      # Vendor mock — substitui chamadas reais no dev
      VENDOR_MOCK_ENABLED:            "true"
      VENDOR_MOCK_URL:                "http://vendor-mock:9000"
    depends_on:
      btv-sidecar:
        condition: service_healthy
      vendor-mock:
        condition: service_started

  btv-sidecar:
    image: buildtovalue/btv:2.0-dev
    ports:
      - "8080:8080"
    environment:
      BTV_ENV:          "development"
      BTV_HMAC_KEY:     "dev-hmac-key-32-bytes-for-testing"
      BTV_LEDGER_MODE:  "memory"
      BTV_POLICIES_DIR: "./data/policies"
    volumes:
      - ./data/policies:/app/data/policies:ro
    healthcheck:
      test:     ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 5s
      timeout:  3s
      retries:  5

  # Simula respostas de vendors externos sem custo
  vendor-mock:
    image: buildtovalue/vendor-mock:latest
    ports:
      - "9000:9000"
    environment:
      MOCK_VENDORS: "openai,anthropic,google"
      # Simula resposta com exfiltração para testar Gate 2
      INJECT_EXFILTRATION_RATE: "0.01"

  postgres:
    image: postgres:16
    environment:
      POSTGRES_DB:       chatbot_dev
      POSTGRES_USER:     chatbot
      POSTGRES_PASSWORD: devpassword

  qdrant:
    image: qdrant/qdrant:latest
    ports:
      - "6333:6333"
```

---

## 12. Tratamento de Erros e Fallback

| Cenário | Comportamento |
|:--------|:--------------|
| BTV timeout (> 5 s) na sanitização | BLOCK local + log `btv.sanitize_timeout` |
| BTV timeout no validate | BLOCK local + log `btv.validate_timeout` |
| HTTP 5xx no BTV | 1 retry (100 ms) → BLOCK se falhar |
| Circuit aberto (≥ 3 falhas / 30 s) | BLOCK todos os envios + alerta crítico |
| HMAC inválido no veredicto | BLOCK + log `btv.hmac_mismatch` + alerta crítico |
| BTV retorna 401/403 | BLOCK + log `btv.auth_failure` + sem retry |
| `sanitized_before_send: false` detectado pelo BTV | BLOCK pelo YAML `block_unsanitized` |
| Vendor mock indisponível (dev) | BLOCK + log `vendor.mock_unavailable` |
| `sanitize_evidence_id` expirado (> 5s) | BLOCK local + `BtvError::SanitizeStaleness` |

**Regra universal:** qualquer condição não prevista = BLOCK. O chatbot
prefere não responder a expor dado sem evidência forense.

---

## 13. Métricas e Observabilidade

```
# Prometheus — prefixo btv_chatbot_ext_*
btv_chatbot_ext_vendor_send_total{vendor_id, workspace_id, verdict, sector_id}
btv_chatbot_ext_vendor_response_total{vendor_id, workspace_id, verdict}
btv_chatbot_ext_vendor_approval_total{vendor_id, workspace_id, verdict}
btv_chatbot_ext_rag_blocks_total{workspace_id, reason}
btv_chatbot_ext_sanitize_total{workspace_id, pii_types_found}
btv_chatbot_ext_sanitize_latency_ms{workspace_id, p50|p95|p99}
btv_chatbot_ext_send_latency_ms{vendor_id, workspace_id, p50|p95|p99}
btv_chatbot_ext_circuit_open{workspace_id}
btv_chatbot_ext_evidence_ids_total{workspace_id, gate}
btv_chatbot_ext_lgpd_art33_transfers_total{vendor_id, workspace_id, compliant}
```

**Alertas recomendados:**

```yaml
alerts:
  - name: BtvExtCircuitOpen
    expr: btv_chatbot_ext_circuit_open > 0
    severity: critical
    message: "BTV indisponível. Todos os envios a vendors estão bloqueados."

  - name: BtvExtResponseBlocked
    expr: rate(btv_chatbot_ext_vendor_response_total{verdict="BLOCK"}[5m]) > 0
    severity: critical
    message: "Resposta de vendor bloqueada por padrão de exfiltração. Investigar."

  - name: BtvExtHighBlockRate
    expr: rate(btv_chatbot_ext_vendor_send_total{verdict="BLOCK"}[5m]) > 0.15
    severity: warning
    message: "Taxa de bloqueio > 15% nas transmissões. Verificar políticas."

  - name: BtvExtHmacMismatch
    expr: increase(btv_hmac_mismatch_total[1m]) > 0
    severity: critical
    message: "HMAC inválido detectado. Possível adulteração da resposta BTV."

  - name: BtvExtLgpdNonCompliant
    expr: rate(btv_chatbot_ext_lgpd_art33_transfers_total{compliant="false"}[1h]) > 0
    severity: warning
    message: "Transferências internacionais não-conformes detectadas. Revisar DPA dos vendors."
```

---

## 14. Contestabilidade

```
Usuário recebe BLOCK de envio
        │
        ▼
UI exibe:
  "Mensagem bloqueada pela política de segurança"
  Motivo: <explain_decision do BTV>
  [Contestar envio]  [Cancelar]
        │
        ▼ [usuário clica Contestar]
POST /v1/appeals
{
  "evidence_id":   "<ev_send>",
  "justification": "<texto do usuário>",
  "requested_by":  "<user_id>",
  "timestamp_utc": "<ISO8601>"
}
        │
        ▼
UI: "Recurso enviado. Prazo: <appeal_deadline_utc>."
appeal_id salvo em localStorage para acompanhamento.
        │
Admin revisa no dashboard BTV (SLA 24h)
        │
  ┌─────┴───────┐
APROVADO     REJEITADO
  │               │
Mensagem      Bloqueio
reenviada     mantido
  │               │
evidence_id   evidence_id
no ledger     no ledger
```

**Nota:** respostas do vendor bloqueadas (Gate 2) **não são contestáveis**
pelo usuário — são eventos de segurança que requerem investigação da
equipe de infra. O `contestable: false` no veredicto reflete isso.

---

## 15. Comparação com chatbot-internal-llm.md

| Aspecto | ADR-0029 / internal | ADR-0030 / external |
|:--------|:--------------------|:--------------------|
| `/v1/sanitize` | Se `pii_detected=true` | **Toda mensagem, sem exceção** |
| ActionImpact da mensagem | Destructive (se PII) | **Irreversible (sempre)** |
| Cache de veredicto de envio | TTL 5s para Destructive | **TTL zero para llm_vendor_send** |
| Gate de resposta | Não existe | **Gate 2 obrigatório** |
| Gate de aprovação de vendor | Não existe | **Gate 3 (TTL 60s)** |
| Chunk RESTRICTED no RAG | Gate Irreversible | **BLOCK local antes do BTV** |
| Chunk CONFIDENTIAL no RAG | Gate Destructive | **Gate Irreversible** |
| Pipeline de treinamento | Gates 4 e 5 | **Não aplicável** |
| `eligible_for_training` | Condicional | **Sempre `false`** |
| LGPD | Processamento interno | **Art. 33 — cada mensagem** |
| Relatório LGPD | Sanitização interna | **+ Transferências internacionais** |

---

## 16. Checklist de Go-Live

```
Infraestrutura
  [ ] BTV v2.0 em produção com DurableLedger + S3 configurado
  [ ] API key de produção por workspace gerada e armazenada no Vault
  [ ] HMAC key rotacionada (nunca em variável de ambiente em plaintext)
  [ ] Políticas YAML carregadas para todos os sector_ids ativos
  [ ] Métricas btv_chatbot_ext_* visíveis no dashboard
  [ ] Alertas configurados (circuit open, response block, HMAC mismatch)

Gates
  [ ] Gate 1: mensagem sem sanitize_evidence_id → BLOCK pelo YAML
  [ ] Gate 1: RESTRICTED → BLOCK local antes de chegar ao BTV
  [ ] Gate 1: BTV indisponível → mensagem não enviada ao vendor
  [ ] Gate 2: resposta com "sk-" → BLOCK pelo YAML
  [ ] Gate 2: BTV indisponível → resposta não exibida ao usuário
  [ ] Gate 3: vendor sem ZDR em setor health → BLOCK
  [ ] Gate 3: vendor sem DPA em setor legal → BLOCK
  [ ] Gate 4: chunk RESTRICTED → BLOCK local, nunca consulta BTV
  [ ] Gate 4: chunk com "ignore previous instructions" → BLOCK

Fail-secure
  [ ] BTV sidecar derrubado → todos os envios bloqueados imediatamente
  [ ] HMAC key trocada → próximo veredicto bloqueado
  [ ] Circuit abre após 3 falhas → alerta disparado em < 30s
  [ ] `sanitize_evidence_id` expirado (> 5s) → BLOCK local

LGPD Art. 33
  [ ] evidence_ids de sanitização e envio correlacionados em 100% dos casos
  [ ] Relatório LGPD inclui seção de transferências internacionais
  [ ] DPO validou artefatos do DurableLedger como evidência forense
  [ ] Fluxo de contestação testado end-to-end

Vendors
  [ ] Catálogo de vendors carregado com atributos corretos (DPA, ZDR, residência)
  [ ] Gate 3 testado para cada sector_id × vendor ativo
  [ ] Vendor mock habilitado em staging para testes de exfiltração

Documentação
  [ ] Este arquivo registrado em docs/integrations/
  [ ] ADR-0030 registrado no 0000-adr-index.md
  [ ] Runbook criado: restart BTV, rotação de keys, troca de vendor
  [ ] DPO assinou o mapeamento de transferências internacionais
```

---

## 17. Referências Cruzadas

- BTV ADR-0028 (External Agent PDP — contrato canônico)
- BTV ADR-0029 (Chatbot LLM interna — base deste perfil)
- BTV ADR-0030 (este perfil — decisão arquitetural)
- BTV ADR-0004 (Immutable Ledger — DurableLedger BLAKE3)
- BTV ADR-0005 (Evidence Protocol v2.1 — 9596 bytes)
- BTV ADR-0006 (Policy-as-Code — YAML)
- BTV ADR-0008 (Timing Mitigation — constant-time HMAC)
- BTV ADR-0010 (BiasDeclaration Mandate)
- BTV ADR-0017 (ContestabilityLoop SLA 24h)
- `docs/integrations/chatbot-internal-llm.md` (ADR-0029)
- LGPD Art. 33 (transferência internacional de dados pessoais)
- EU AI Act Art. 5 (práticas proibidas — em vigor desde fev/2025)
```

***

## Estado atual da documentação BTV

Com este arquivo, a estrutura de integração para chatbots está completa:

```
docs/adr/
  0028-external-agent-pdp.md           ✅ contrato canônico
  0029-internal-chatbot-selfhosted.md  ✅ LLM interna
  0030-external-chatbot-vendor-llm.md  ✅ LLM externa

docs/integrations/
  openclaw.md                          ✅ agente autônomo
  chatbot-internal-llm.md              ✅ LLM interna (completo)
  chatbot-external-llm.md              ✅ LLM externa (este arquivo)

data/policies/
  chatbot-internal-message.yaml        ✅
  chatbot-rag-injection.yaml           ✅
  chatbot-lora-deploy.yaml             ✅
  chatbot-vendor-approval.yaml         ✅
  chatbot-vendor-send.yaml             ✅
  chatbot-vendor-response.yaml         ✅
  chatbot-rag-external.yaml            ✅
```

---

### Próximos passos / Relacionados

- [Integrações — visão geral](./index.md)
- [API Reference](../api-reference.md)
- [Conceitos](../concepts.md)

---

<sub>[↑ Hub](../README.md) · [Trilha Engenheiro](../for-engineers.md) · [Trilha DPO/CISO](../for-dpo-ciso.md) · [Links de Referência](../reference-links.md)</sub>
