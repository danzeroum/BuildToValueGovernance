[BuildToValue](../../README.md) › [Documentation](../README.md) › [Engineer Track](../for-engineers.md) › [Integrations](./index.md) › **External Chatbot (Vendor LLM)**

![Engineer](https://img.shields.io/badge/Track-Engineer-1f6feb)

<!-- audience: engineer -->

---

# BTV Integration Profile: Chatbot with External LLM (Vendor API)

| Field                  | Value                                             |
|:-----------------------|:--------------------------------------------------|
| **Standard**           | BTV ADR-0029 (External Agent PDP)                 |
| **ADR for this profile** | BTV ADR-0031                                    |
| **Base profile**       | `chatbot-internal-llm.md` (ADR-0030) — read first |
| **Chatbot version**    | v1.0+ (Rust/Axum + Angular)                       |
| **BTV version**        | v2.0+                                             |
| **Supported vendors**  | OpenAI, Anthropic, Google, Azure OpenAI, Cohere   |
| **Maintainer**         | Chatbot Team                                      |
| **Date**               | 2026-02-23                                        |

---

## 1. Core principle of this profile

> **Every message sent to an external vendor is an international
> data transfer — no exceptions, no caching, no bypass.**

In the internal LLM profile (`chatbot-internal-llm.md`), data never
leaves the perimeter and the most critical gate runs once a week
(LoRA deployment). Here, the most critical gate runs **on every message**,
and the protection priority is inverted:

```
ADR-0030 (internal)        ADR-0031 (external)
─────────────────          ─────────────────
Critical gate:             Critical gate:
  lora_deploy (1x/week)      llm_vendor_send (every msg)

/v1/sanitize:              /v1/sanitize:
  if pii_detected=true       ALWAYS, no exception

Message ActionImpact:      Message ActionImpact:
  Destructive (if PII)       Irreversible (always)

Training pipeline:         Training pipeline:
  Gates 4 and 5              Not applicable

Data leaves perimeter?     Data leaves perimeter?
  Never                      Always (every message)
```

---

## 2. Integration Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Angular Frontend                                               │
│                                                                 │
│  DataFilterService → BtvGateService → VendorService            │
│         │                  │                │                  │
│    detects PII        sanitize+validate   sends to vendor      │
│                       (every message)                           │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTP
┌──────────────────────────▼──────────────────────────────────────┐
│  Rust Backend (Axum)                                            │
│                                                                 │
│  VendorGateMiddleware                                           │
│    │                                                            │
│    ├─ POST /v1/sanitize ──────────────────► BTV Sidecar        │
│    ├─ POST /v1/validate (Irreversible) ───► BTV Sidecar        │
│    ├─ Vendor API call (sanitized data) ───► OpenAI/Anthropic   │
│    ├─ POST /v1/sanitize (response) ───────► BTV Sidecar        │
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

## 3. Canonical agent_id

```rust
// crates/btv-client/src/identity.rs

use blake3::Hasher;

/// For external LLMs, the vendor_id is part of the agent_id.
/// Ensures traceability per company + vendor in the DurableLedger.
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

// Examples:
// workspace: "ws_abc123" + vendor: "openai"    → "chatbot-external-a1b2c3d4e5f67890"
// workspace: "ws_abc123" + vendor: "anthropic" → "chatbot-external-9f8e7d6c5b4a3210"
```

**Critical property:** distinct workspaces produce distinct `agent_id`s
even when using the same vendor. The BTV DurableLedger separates evidence
by company **and** by vendor used.

---

## 4. Full Mapping of Actions → ActionImpact

### 4.1 Actions exclusive to this profile (delta from ADR-0029)

| Action                              | `action.name`                  | Impact       | Gate? |
|:------------------------------------|:-------------------------------|:-------------|:------|
| Sending a message to external vendor | `llm_vendor_send`             | Irreversible | ✅ always |
| Displaying vendor response          | `llm_vendor_response_display`  | Destructive  | ✅ always |
| Approving a vendor for the workspace | `vendor_approve`              | Irreversible | ✅    |
| Revoking a vendor                   | `vendor_revoke`                | Irreversible | ✅    |
| `CONFIDENTIAL` chunk in external prompt | `rag_chunk_inject_conf`    | Irreversible | ✅    |
| `RESTRICTED` chunk in external prompt | *(local block)*              | —            | ❌ BLOCK before BTV |

### 4.2 Actions inherited from ADR-0029

| Action                                | `action.name`              | Impact       | Gate? |
|:--------------------------------------|:---------------------------|:-------------|:------|
| Upload `PUBLIC`/`INTERNAL` doc        | `document_upload`          | Safe         | ❌    |
| Upload `CONFIDENTIAL` doc             | `document_upload_conf`     | Destructive  | ✅    |
| Upload `RESTRICTED` doc              | `document_upload_restr`    | Irreversible | ✅    |
| `SAFE`/`INTERNAL` chunk in prompt     | `rag_chunk_inject`         | Destructive  | ✅    |
| Conversation export (PDF/MD)          | `chat_export`              | Irreversible | ✅    |
| Conversation deletion                 | `chat_delete`              | Destructive  | ✅    |
| Original document export              | `document_export`          | Irreversible | ✅    |
| User suspension                       | `user_suspend`             | Destructive  | ✅    |
| Role/permission change                | `user_role_change`         | Destructive  | ✅    |
| API key revocation                    | `api_key_revoke`           | Irreversible | ✅    |
| Bulk deletion                         | `bulk_delete`              | Irreversible | ✅    |
| Data policy change                    | `data_policy_change`       | Irreversible | ✅    |
| LGPD report generation                | `lgpd_report_generate`     | Destructive  | ✅    |

### 4.3 Actions removed compared to ADR-0029

| Removed action                 | Reason                                      |
|:-------------------------------|:--------------------------------------------|
| `training_cycle_start`         | Model managed by vendor; no fine-tuning     |
| `lora_deploy`                  | No self-hosted LoRA                         |
| `training_qa_approve`          | `eligible_for_training` always `false`      |
| `training_dataset_export`      | No internal dataset                         |

---

## 5. profile_id and sector_id configuration

```yaml
# Configured at workspace onboarding
profile_id: "external-chatbot"

sector_id:
  juridico:    "legal"
  saude:       "health"
  financeiro:  "finance"
  rh:          "hr"
  geral:       "general"
  tecnologia:  "general"
```

**Impact of `sector_id` on BTV policies:**

| `sector_id` | Additional restrictions for external vendors |
|:------------|:---------------------------------------------|
| `health`    | Requires active Zero Data Retention (ZDR); blocks retention > 0 days |
| `legal`     | Requires signed DPA; blocks vendors outside BR/EU without a DPA |
| `finance`   | Requires DPA; blocks retention > 30 days; EDUCATE for CONFIDENTIAL |
| `hr`        | Blocks retention > 30 days; blocks data containing CPF for external training |
| `general`   | EDUCATE without DPA; ALLOW with DPA |

---

## 6. Vendor Catalog and BTV Attributes

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
    pub has_dpa: bool,            // DPA signed with the company
    pub has_zero_data_retention: bool,
    pub compliant_sectors: Vec<String>, // sectors approved by policy
}

// Default catalog — overridden by workspace configuration
pub fn default_vendor_catalog() -> Vec<VendorConfig> {
    vec![
        VendorConfig {
            vendor_id: "openai".into(),
            vendor_name: "OpenAI".into(),
            model: "gpt-4o".into(),
            api_base_url: "https://api.openai.com/v1".into(),
            data_residency: "US".into(),
            data_retention_days: 30,   // default without ZDR
            has_dpa: false,            // requires Enterprise contract
            has_zero_data_retention: false,
            compliant_sectors: vec!["general".into()],
        },
        VendorConfig {
            vendor_id: "openai_enterprise".into(),
            vendor_name: "OpenAI Enterprise (ZDR)".into(),
            model: "gpt-4o".into(),
            api_base_url: "https://api.openai.com/v1".into(),
            data_residency: "US".into(),
            data_retention_days: 0,    // Zero Data Retention active
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
            vendor_name: "Azure OpenAI (Brazil South)".into(),
            model: "gpt-4o".into(),
            api_base_url: "https://<resource>.openai.azure.com".into(),
            data_residency: "BR".into(), // data stays in Brazil
            data_retention_days: 0,
            has_dpa: true,
            has_zero_data_retention: true,
            compliant_sectors: vec![
                "general".into(), "hr".into(), "finance".into(),
                "legal".into(), "health".into(), // only one approved for health
            ],
        },
    ]
}
```

---

## 7. Implementing the 4 Gates

### Gate 1 — Message Transmission to the Vendor

**Mandatory, non-negotiable flow:**

```
User message
        │
        ▼
1. RESTRICTED? ──► local BLOCK (no BTV call)
        │ no
        ▼
2. POST /v1/sanitize ──────────────────────────────► BTV
   (ALWAYS — does not depend on pii_detected)       │
        │◄──────────────────────────────────────────┘
        │  sanitized.content + sanitize_evidence_id
        ▼
3. POST /v1/validate
   action: llm_vendor_send
   impact: Irreversible
   sanitized_before_send: true
   sanitize_evidence_id: <from step 2>  ──────────► BTV
        │◄──────────────────────────────────────────┘
        │  VerdictEnvelope (ALLOW/EDUCATE/BLOCK)
   ┌────┴──────────────────────────────┐
ALLOW/EDUCATE                        BLOCK
   │                                   │
   ▼                                   ▼
Vendor API                      Feedback to user
(sanitized.content)              + explain_decision
   │                             + option to appeal
   ▼
Vendor response
   │
   ▼
4. POST /v1/sanitize (response) ─────────────────► BTV
        │
        ▼
5. POST /v1/validate (response_display) ─────────► BTV
        │
ALLOW/EDUCATE ──► shown to user
BLOCK ──────────► generic error message shown
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

/// Complete Gate 1: sanitize → validate → result.
///
/// Invariants enforced here:
/// - RESTRICTED: local block before any BTV call
/// - Sanitization always, no exceptions
/// - Zero caching: no llm_vendor_send verdict is reused
/// - Fail-secure: any BtvError = do not send to vendor
pub async fn gate_vendor_send(
    message: &RawMessage,
    btv: &dyn BtvClient,
    ctx: &WorkspaceContext,
    vendor: &VendorConfig,
) -> Result<VendorSendGateResult, BtvError> {
    // Invariant: RESTRICTED never leaves — local block, no BTV
    if message.classification == Classification::Restricted {
        return Err(BtvError::LocalBlock {
            reason: "RESTRICTED data is not transmitted to external vendors.".into(),
        });
    }

    let gate_start = SystemTime::now();

    // Step 1: mandatory sanitization (always)
    let sanitized = btv.sanitize_output(&message.content)
        .await
        .map_err(|_| BtvError::Unavailable)?;

    // Validate sanitization freshness (≤ 5 s)
    if gate_start.elapsed().unwrap_or(Duration::MAX) > Duration::from_secs(5) {
        return Err(BtvError::SanitizeStaleness);
    }

    // Step 2: transmission validation (Irreversible — no caching)
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
        // Hash of the ALREADY sanitized content — never of the original
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
                "sanitized_before_send":       true,  // always true at this gate
                "sanitize_evidence_id":        sanitized.evidence_id,
                "eligible_for_training":       false, // data leaves the perimeter
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

    // Mandatory HMAC verification — constant-time
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

### Gate 2 — Vendor Response

```rust
// crates/btv-client/src/gates/vendor_response.rs

pub struct VendorResponseResult {
    pub safe_content:         String,
    pub response_evidence_id: EvidenceId,
}

/// Gate 2: sanitize and validate the response received from the vendor.
///
/// Protects against:
/// - Exfiltration via prompt injection in the external model
/// - Responses containing sensitive data patterns (keys, tokens, PII)
/// - Manipulated content trying to inject instructions into the frontend
pub async fn gate_vendor_response(
    raw_response:       &str,
    btv:                &dyn BtvClient,
    ctx:                &WorkspaceContext,
    vendor:             &VendorConfig,
    send_evidence_id:   &EvidenceId,
) -> Result<VendorResponseResult, BtvError> {
    // Sanitize the response before any validation
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
            "send_evidence_id":   send_evidence_id,  // correlation with Gate 1
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
                "Vendor response blocked: {}",
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

### Gate 3 — Vendor Approval (per session, TTL 60 s)

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
                None // TTL expired
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

/// Gate 3: validates whether the vendor is approved for the workspace's sector_id.
/// 60 s TTL cache — the only cacheable gate in this profile.
/// BLOCK = vendor forbidden for this sector; session not started.
pub async fn gate_vendor_approval(
    vendor:  &VendorConfig,
    btv:     &dyn BtvClient,
    ctx:     &WorkspaceContext,
    cache:   &VendorApprovalCache,
) -> Result<EvidenceId, BtvError> {
    // Check cache before calling BTV
    if let Some(cached) = cache.get(&ctx.workspace_id, &vendor.vendor_id).await {
        tracing::debug!(
            vendor_id = %vendor.vendor_id,
            "Vendor approval served from cache"
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
            // Populate cache only for ALLOW
            cache.insert(
                ctx.workspace_id.clone(),
                vendor.vendor_id.clone(),
                envelope.evidence_id.clone(),
            ).await;
            Ok(envelope.evidence_id)
        }
        "EDUCATE" => {
            // EDUCATE: approved with a warning — also cacheable
            tracing::warn!(
                vendor_id = %vendor.vendor_id,
                "Vendor approved with reservations: {}",
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

### Gate 4 — RAG Context for External Vendor

```rust
// crates/btv-client/src/gates/rag_external.rs

use futures::future::join_all;

/// Gate 4: filters chunks before injecting them into a prompt sent to a vendor.
///
/// Critical delta vs ADR-0029 Gate 3:
/// - RESTRICTED: LOCAL block, no BTV call (data never leaves)
/// - CONFIDENTIAL: Irreversible (not Destructive as in the internal profile)
/// - Same injection patterns as the internal profile
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
                    "Chunk excluded from external RAG context"
                );
                None
            }
            Err(e) => {
                tracing::error!(error = %e, "External RAG gate failed — chunk excluded");
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
    // RESTRICTED: unconditional local block
    if chunk.classification == Classification::Restricted {
        tracing::warn!(
            chunk_id = %chunk.id,
            "RESTRICTED chunk blocked locally — no BTV call"
        );
        return Ok(false);
    }

    // CONFIDENTIAL bound for external vendor: Irreversible
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

## 8. Angular — BtvGateService (full implementation)

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

  // Vendor approval cache (60s TTL, mirroring the Rust side)
  private readonly vendorApprovalCache =
    new Map<string, { evidenceId: string; approvedAt: number }>();

  // ──────────────────────────────────────────────────────────────
  // Gate 3: vendor approval (per session, 60s cache)
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
      throw new BtvUnavailableError('BTV unavailable — session blocked');
    }

    if (verdict.verdict === 'BLOCK') {
      throw new VendorSendBlockedError(
        verdict.explain_decision,
        verdict.evidence_id,
        verdict.contestable,
      );
    }

    // Populate cache for ALLOW and EDUCATE
    this.vendorApprovalCache.set(cacheKey, {
      evidenceId: verdict.evidence_id,
      approvedAt: Date.now(),
    });
    return verdict.evidence_id;
  }

  // ──────────────────────────────────────────────────────────────
  // Gate 1: sanitize + validate transmission (Irreversible, no cache)
  // ──────────────────────────────────────────────────────────────
  async validateVendorSend(
    filtered: FilteredMessage,
    vendor:   VendorConfig,
  ): Promise<VendorSendResult> {
    const workspace = this.ctx.current();

    // Local block for RESTRICTED — no BTV call
    if (filtered.classification === 'RESTRICTED') {
      throw new VendorSendBlockedError(
        'RESTRICTED data is not transmitted to external vendors.',
        'local-block',
        false,
      );
    }

    // Step 1: mandatory sanitization
    const sanitized = await this.sanitize(filtered.content);
    const sanitizeTs = Date.now();

    // Validate freshness (≤ 5 s)
    if (Date.now() - sanitizeTs > 5_000) {
      throw new BtvUnavailableError('Sanitization expired — please try again');
    }

    // Step 2: transmission validation (Irreversible — no caching)
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
          sanitized_before_send:      true,  // always true here
          sanitize_evidence_id:       sanitized.evidence_id,
          eligible_for_training:      false, // data leaves the perimeter
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
  // Gate 2: sanitize + validate vendor response
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
  // Private helpers
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

**Integration in `chat-container.component.ts`:**

```typescript
async sendMessage(rawText: string): Promise<void> {
  const filtered = this.dataFilter.processMessage(rawText, this.workspace);
  const vendor   = this.workspace.vendorConfig;

  try {
    // Gate 3: vendor approved for this sector_id? (60s cache)
    await this.btvGate.ensureVendorApproved(vendor);

    // Gate 1: sanitize + validate transmission (Irreversible, no cache)
    const gateResult = await this.btvGate.validateVendorSend(
      filtered, vendor
    );

    if (gateResult.educateWarning) {
      this.showEducateWarning(gateResult.educateWarning);
    }

    // Send ONLY the sanitized content to the vendor
    const rawResponse = await this.vendorService.send(
      gateResult.sanitizedContent,
      vendor,
      gateResult.sendEvidenceId,  // correlation in the log
    );

    // Gate 2: sanitize and validate the response before showing it
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
      // BTV unavailable = do not send (fail-secure)
      this.showBtvUnavailable();
    }
  }
}
```

---

## 9. Full YAML Policies

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
      Health sector: requires active Zero Data Retention.
      Contract an Enterprise plan with ZDR before enabling this vendor.

  - name: block_legal_no_dpa
    conditions:
      sector_id: "legal"
      parameters_preview.has_dpa: false
    verdict: BLOCK
    explain: >
      Legal sector: requires a DPA signed with the vendor.
      Contact the legal department to sign the DPA.

  - name: block_finance_no_dpa_foreign
    conditions:
      sector_id: "finance"
      parameters_preview.data_residency: { not_in: ["BR", "EU"] }
      parameters_preview.has_dpa: false
    verdict: BLOCK
    explain: >
      Finance sector: a vendor outside BR/EU without a DPA violates LGPD Art. 33.

  - name: block_hr_long_retention
    conditions:
      sector_id: "hr"
      parameters_preview.data_retention_days: { gt: 30 }
    verdict: BLOCK
    explain: >
      HR sector: retention > 30 days. Employee data requires
      retention-period minimization (LGPD Art. 5, X).

  - name: allow_with_dpa
    conditions:
      parameters_preview.has_dpa: true
    verdict: ALLOW
    explain: "Vendor approved: DPA present."

  - name: educate_no_dpa
    conditions:
      default: true
    verdict: EDUCATE
    explain: >
      Vendor without a formal DPA. Approved for non-sensitive data.
      Signing a DPA is recommended for INTERNAL data or above.
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
      Blocked: no sanitization evidence.
      Data MUST go through /v1/sanitize before any external send.

  - name: block_restricted
    conditions:
      agent_metadata.data_classification: "RESTRICTED"
    verdict: BLOCK
    explain: >
      RESTRICTED data is not transmitted to external vendors.
      Use a self-hosted LLM for data in this classification.

  - name: block_health_vendor_retention
    conditions:
      sector_id: "health"
      agent_metadata.vendor_data_retention_days: { gt: 0 }
    verdict: BLOCK
    explain: >
      Health sector: vendor has data retention active.
      Enable Zero Data Retention before transmitting health data.

  - name: educate_confidential
    conditions:
      agent_metadata.data_classification: "CONFIDENTIAL"
      agent_metadata.sanitized_before_send: true
    verdict: EDUCATE
    explain: >
      CONFIDENTIAL data being sent to an external vendor with sanitization.
      Verify that all identifiers have been removed.

  - name: allow_sanitized
    conditions:
      agent_metadata.sanitized_before_send: true
      agent_metadata.data_classification: { in: ["PUBLIC", "INTERNAL"] }
    verdict: ALLOW
    explain: "Transmission authorized: data sanitized, classification adequate."
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
        - "xoxb-"    # Slack token
        - "ghp_"     # GitHub token
    verdict: BLOCK
    explain: >
      Response contains patterns indicating sensitive-data exfiltration.
      Display blocked. Open a security ticket.

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
    explain: "Prompt-injection pattern detected in RAG chunk."

  - name: educate_confidential_external
    conditions:
      action.name: "rag_chunk_inject_conf"
    verdict: EDUCATE
    explain: >
      CONFIDENTIAL chunk being injected into a prompt for an external vendor.
      Verify the content has been adequately sanitized.

  - name: allow_safe
    conditions:
      default: true
    verdict: ALLOW
```

---

## 10. LGPD Art. 33 Evidence

For each vendor transmission, the DurableLedger contains:

```
evidence_id_sanitize
  ├─ sanitization timestamp
  ├─ pii_types found and removed
  ├─ BLAKE3 of sanitized content
  └─ HMAC-SHA256

evidence_id_send
  ├─ vendor_id and vendor_model
  ├─ sector_id and data_classification
  ├─ sanitize_evidence_id (cross-reference)
  ├─ policy_version_applied
  ├─ data_residency and data_retention_days
  ├─ BLAKE3 + HMAC-SHA256
  └─ appeal_deadline_utc

evidence_id_response
  ├─ send_evidence_id (correlation with the send)
  ├─ pii_types found in the response
  ├─ BLAKE3 of displayed content
  └─ HMAC-SHA256
```

**Section added to `ComplianceReportComponent`:**

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
    evidenceSample:    string[];   // last 5 BTV evidence_ids
    complianceStatus:  string;
  }[];
  nonCompliantInstances: {
    evidenceId:  string;
    timestamp:   string;
    vendorId:    string;
    reason:      string;           // EDUCATE without DPA, etc.
  }[];
  dpoSignOffRequired: boolean;     // true if non-compliant instances exist
}
```

---

## 11. Docker Compose — Development

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
      # Vendor mock — replaces real calls in dev
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

  # Simulates external-vendor responses at no cost
  vendor-mock:
    image: buildtovalue/vendor-mock:latest
    ports:
      - "9000:9000"
    environment:
      MOCK_VENDORS: "openai,anthropic,google"
      # Simulates an exfiltration response to test Gate 2
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

## 12. Error Handling and Fallback

| Scenario | Behavior |
|:---------|:---------|
| BTV timeout (> 5 s) on sanitization | Local BLOCK + log `btv.sanitize_timeout` |
| BTV timeout on validate | Local BLOCK + log `btv.validate_timeout` |
| HTTP 5xx from BTV | 1 retry (100 ms) → BLOCK if it fails |
| Circuit open (≥ 3 failures / 30 s) | BLOCK every send + critical alert |
| Invalid HMAC on verdict | BLOCK + log `btv.hmac_mismatch` + critical alert |
| BTV returns 401/403 | BLOCK + log `btv.auth_failure` + no retry |
| `sanitized_before_send: false` detected by BTV | BLOCK via YAML `block_unsanitized` |
| Vendor mock unavailable (dev) | BLOCK + log `vendor.mock_unavailable` |
| `sanitize_evidence_id` expired (> 5s) | Local BLOCK + `BtvError::SanitizeStaleness` |

**Universal rule:** any unforeseen condition = BLOCK. The chatbot prefers
not to respond rather than expose data without forensic evidence.

---

## 13. Metrics and Observability

```
# Prometheus — prefix btv_chatbot_ext_*
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

**Recommended alerts:**

```yaml
alerts:
  - name: BtvExtCircuitOpen
    expr: btv_chatbot_ext_circuit_open > 0
    severity: critical
    message: "BTV unavailable. All vendor sends are blocked."

  - name: BtvExtResponseBlocked
    expr: rate(btv_chatbot_ext_vendor_response_total{verdict="BLOCK"}[5m]) > 0
    severity: critical
    message: "Vendor response blocked by exfiltration pattern. Investigate."

  - name: BtvExtHighBlockRate
    expr: rate(btv_chatbot_ext_vendor_send_total{verdict="BLOCK"}[5m]) > 0.15
    severity: warning
    message: "Block rate > 15% on transmissions. Review policies."

  - name: BtvExtHmacMismatch
    expr: increase(btv_hmac_mismatch_total[1m]) > 0
    severity: critical
    message: "Invalid HMAC detected. Possible tampering of BTV response."

  - name: BtvExtLgpdNonCompliant
    expr: rate(btv_chatbot_ext_lgpd_art33_transfers_total{compliant="false"}[1h]) > 0
    severity: warning
    message: "Non-compliant international transfers detected. Review vendor DPAs."
```

---

## 14. Contestability

```
User receives a send BLOCK
        │
        ▼
UI shows:
  "Message blocked by the security policy"
  Reason: <BTV explain_decision>
  [Appeal send]  [Cancel]
        │
        ▼ [user clicks Appeal]
POST /v1/appeals
{
  "evidence_id":   "<ev_send>",
  "justification": "<user text>",
  "requested_by":  "<user_id>",
  "timestamp_utc": "<ISO8601>"
}
        │
        ▼
UI: "Appeal submitted. Deadline: <appeal_deadline_utc>."
appeal_id saved to localStorage for tracking.
        │
Admin reviews in the BTV dashboard (24h SLA)
        │
  ┌─────┴───────┐
APPROVED     REJECTED
  │               │
Message       Block
resent        upheld
  │               │
evidence_id   evidence_id
in ledger     in ledger
```

**Note:** blocked vendor responses (Gate 2) are **not contestable** by the user
— they are security events that require investigation by the infrastructure
team. The `contestable: false` flag in the verdict reflects this.

---

## 15. Comparison with chatbot-internal-llm.md

| Aspect | ADR-0029 / internal | ADR-0030 / external |
|:-------|:--------------------|:--------------------|
| `/v1/sanitize` | If `pii_detected=true` | **Every message, no exceptions** |
| Message ActionImpact | Destructive (if PII) | **Irreversible (always)** |
| Send-verdict cache | 5s TTL for Destructive | **Zero TTL for llm_vendor_send** |
| Response gate | Does not exist | **Gate 2 mandatory** |
| Vendor-approval gate | Does not exist | **Gate 3 (60s TTL)** |
| RESTRICTED chunk in RAG | Irreversible gate | **Local BLOCK before BTV** |
| CONFIDENTIAL chunk in RAG | Destructive gate | **Irreversible gate** |
| Training pipeline | Gates 4 and 5 | **Not applicable** |
| `eligible_for_training` | Conditional | **Always `false`** |
| LGPD | Internal processing | **Art. 33 — every message** |
| LGPD report | Internal sanitization | **+ International transfers** |

---

## 16. Go-Live Checklist

```
Infrastructure
  [ ] BTV v2.0 in production with DurableLedger + S3 configured
  [ ] Production API key per workspace generated and stored in Vault
  [ ] HMAC key rotated (never as a plaintext environment variable)
  [ ] YAML policies loaded for all active sector_ids
  [ ] btv_chatbot_ext_* metrics visible on the dashboard
  [ ] Alerts configured (circuit open, response block, HMAC mismatch)

Gates
  [ ] Gate 1: message without sanitize_evidence_id → BLOCK via YAML
  [ ] Gate 1: RESTRICTED → local BLOCK before reaching BTV
  [ ] Gate 1: BTV unavailable → message not sent to vendor
  [ ] Gate 2: response containing "sk-" → BLOCK via YAML
  [ ] Gate 2: BTV unavailable → response not shown to user
  [ ] Gate 3: vendor without ZDR in health sector → BLOCK
  [ ] Gate 3: vendor without DPA in legal sector → BLOCK
  [ ] Gate 4: RESTRICTED chunk → local BLOCK, never calls BTV
  [ ] Gate 4: chunk containing "ignore previous instructions" → BLOCK

Fail-secure
  [ ] BTV sidecar down → all sends blocked immediately
  [ ] HMAC key swapped → next verdict blocked
  [ ] Circuit opens after 3 failures → alert fires in < 30s
  [ ] `sanitize_evidence_id` expired (> 5s) → local BLOCK

LGPD Art. 33
  [ ] Sanitization and send evidence_ids correlated in 100% of cases
  [ ] LGPD report includes the international transfers section
  [ ] DPO validated DurableLedger artifacts as forensic evidence
  [ ] Appeal flow tested end-to-end

Vendors
  [ ] Vendor catalog loaded with correct attributes (DPA, ZDR, residency)
  [ ] Gate 3 tested for each active sector_id × vendor combination
  [ ] Vendor mock enabled in staging for exfiltration tests

Documentation
  [ ] This file registered under docs/integrations/
  [ ] ADR-0030 listed in 0000-adr-index.md
  [ ] Runbook created: BTV restart, key rotation, vendor swap
  [ ] DPO signed off on the international transfer mapping
```

---

## 17. Cross-References

- BTV ADR-0028 (External Agent PDP — canonical contract)
- BTV ADR-0029 (Internal Chatbot LLM — base for this profile)
- BTV ADR-0030 (this profile — architectural decision)
- BTV ADR-0004 (Immutable Ledger — DurableLedger BLAKE3)
- BTV ADR-0005 (Evidence Protocol v2.1 — 9596 bytes)
- BTV ADR-0006 (Policy-as-Code — YAML)
- BTV ADR-0008 (Timing Mitigation — constant-time HMAC)
- BTV ADR-0010 (BiasDeclaration Mandate)
- BTV ADR-0017 (ContestabilityLoop SLA 24h)
- `docs/integrations/chatbot-internal-llm.md` (ADR-0029)
- LGPD Art. 33 (international transfer of personal data)
- EU AI Act Art. 5 (prohibited practices — in force since Feb 2025)
```

***

## Current state of BTV documentation

With this file, the integration structure for chatbots is complete:

```
docs/adr/
  0028-external-agent-pdp.md           ✅ canonical contract
  0029-internal-chatbot-selfhosted.md  ✅ internal LLM
  0030-external-chatbot-vendor-llm.md  ✅ external LLM

docs/integrations/
  openclaw.md                          ✅ autonomous agent
  chatbot-internal-llm.md              ✅ internal LLM (complete)
  chatbot-external-llm.md              ✅ external LLM (this file)

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

### Next steps / Related

- [Integrations — overview](./index.md)
- [API Reference](../api-reference.md)
- [Concepts](../concepts.md)

---

<sub>[↑ Hub](../README.md) · [Engineer Track](../for-engineers.md) · [DPO/CISO Track](../for-dpo-ciso.md) · [Reference Links](../reference-links.md)</sub>
