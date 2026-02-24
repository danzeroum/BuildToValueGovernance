```markdown
# ADR-0030 — Perfil de Integração BTV: Chatbot com LLM Externa (Vendor API)

| Campo         | Valor                                               |
|:--------------|:----------------------------------------------------|
| **ID**        | 0031                                               |
| **Status**    | 🔒 Proposto                                         |
| **Padrão**    | BTV ADR-0029 (External Agent PDP)                   |
| **Alvo**      | BTV v2.0+ / Chatbot com LLM externa v1.0+           |
| **Autores**   | Arquiteta BTV                                       |
| **Data**      | 2026-02-23                                          |
| **Revisores** | Reviewer (Opus) — conformidade ADR + invariantes    |
| **Contexto**  | Leia ADR-0029 antes — este ADR documenta o delta    |

---

## 1. Contexto

### 1.1 O que muda radicalmente em relação ao ADR-0029

No ADR-0029 (LLM self-hosted), o dado **nunca sai do perímetro**.
O gate mais crítico é o deploy de LoRA, que ocorre uma vez por semana.

Com LLM externa (OpenAI GPT-4o, Anthropic Claude, Google Gemini, etc.),
**cada mensagem enviada é uma transferência de dado para fora do Brasil**.
Isso implica:

- **LGPD Art. 33**: transferência internacional de dados pessoais exige
  base legal específica ou garantias adequadas. Cada transmissão precisa
  de evidência forense de que foi autorizada, sanitizada e conforme.
- **ActionImpact universal**: toda mensagem enviada ao vendor é
  `Irreversible` por definição — o dado saiu; não há rollback.
- **Deslocamento do gate crítico**: de `lora_deploy` (1x/semana) para
  `llm_vendor_send` (cada mensagem, potencialmente centenas por minuto).
- **Superfície de risco ampliada**: prompt injection, exfiltração via
  resposta do vendor, retenção de dados pelo vendor, custos descontrolados.
- **Ausência de pipeline de treinamento**: o modelo é gerenciado pelo
  vendor; os gates de `training_cycle_start` e `lora_deploy` do ADR-0029
  não se aplicam aqui.

### 1.2 O que permanece igual

A estrutura de ADR-0028 (contrato canônico), os gates de documento
(Gate 2), RAG (Gate 3), ações administrativas e contestabilidade
são idênticos ao ADR-0029. Este ADR documenta apenas o **delta**.

---

## 2. Decisão

O chatbot integra o BTV em **cinco gates**, com prioridades distintas
do ADR-0029:

1. **Gate de Transmissão ao Vendor** ← *gate mais crítico neste perfil*
   Toda mensagem enviada a qualquer vendor é `Irreversible`. Sanitização
   via `/v1/sanitize` é obrigatória antes de cada envio.
2. **Gate de Resposta do Vendor** ← *novo em relação ao ADR-0029*
   A resposta recebida do vendor pode conter dados exfiltrados via
   prompt injection; passa por `/v1/sanitize` antes de chegar ao usuário.
3. **Gate de Indexação de Documentos**
   Idêntico ao ADR-0029 Gate 2.
4. **Gate de Contexto RAG**
   Idêntico ao ADR-0029 Gate 3, com regra adicional: chunks com dados
   `RESTRICTED` são bloqueados independentemente de injection patterns —
   nunca injetar dado `RESTRICTED` em prompt enviado a vendor externo.
5. **Gate de Aprovação de Vendor**
   Antes de qualquer sessão que use um vendor específico, o BTV valida
   se aquele vendor está aprovado para o `sector_id` do workspace.
   Configurado por Policy-as-Code YAML — sem tocar em código.

**Invariante central deste ADR:**
> Nenhum dado alcança um vendor externo sem `evidence_id` BTV registrado
> provando que: (1) foi sanitizado via `/v1/sanitize`, (2) o vendor está
> aprovado para o `sector_id` do workspace, (3) a transmissão foi
> autorizada como `Irreversible` com HMAC válido.

---

## 3. Taxonomia de Ações

### 3.1 Delta em relação ao ADR-0029

| Ação                                  | `action.name`                | Impact       | ADR-0029? |
|:--------------------------------------|:-----------------------------|:-------------|:----------|
| Envio de mensagem ao vendor (qualquer)| `llm_vendor_send`            | Irreversible | ❌ novo   |
| Recepção e exibição de resposta       | `llm_vendor_response_display`| Destructive  | ❌ novo   |
| Aprovação de vendor para workspace    | `vendor_approve`             | Irreversible | ❌ novo   |
| Revogação de vendor para workspace    | `vendor_revoke`              | Irreversible | ❌ novo   |
| Chunk RAG `RESTRICTED` em prompt      | `rag_chunk_inject_restricted`| Irreversible | ⚠️ mais restritivo |
| Deploy de LoRA                        | *(não aplicável)*            | —            | ✅ removido |
| Início de ciclo de treinamento        | *(não aplicável)*            | —            | ✅ removido |

### 3.2 Tabela completa (ações herdadas do ADR-0029)

| Ação                                  | `action.name`                | Impact       | Gate? |
|:--------------------------------------|:-----------------------------|:-------------|:------|
| **Chat e mensagens**                  |                              |              |       |
| Mensagem qualquer ao vendor externo   | `llm_vendor_send`            | Irreversible | ✅    |
| Resposta do vendor ao usuário         | `llm_vendor_response_display`| Destructive  | ✅    |
| Export de conversa (PDF/MD)           | `chat_export`                | Irreversible | ✅    |
| Exclusão de conversa                  | `chat_delete`                | Destructive  | ✅    |
| **Documentos e RAG**                  |                              |              |       |
| Upload doc `PUBLIC`/`INTERNAL`        | `document_upload`            | Safe         | ❌    |
| Upload doc `CONFIDENTIAL`             | `document_upload_conf`       | Destructive  | ✅    |
| Upload doc `RESTRICTED`              | `document_upload_restr`      | Irreversible | ✅    |
| Chunk `SAFE`/`INTERNAL` no prompt     | `rag_chunk_inject`           | Destructive  | ✅    |
| Chunk `CONFIDENTIAL` no prompt        | `rag_chunk_inject_conf`      | Irreversible | ✅    |
| Chunk `RESTRICTED` no prompt          | `rag_chunk_inject_restricted`| Irreversible | ✅ BLOCK sempre |
| **Vendor e sessão**                   |                              |              |       |
| Aprovação de vendor                   | `vendor_approve`             | Irreversible | ✅    |
| Revogação de vendor                   | `vendor_revoke`              | Irreversible | ✅    |
| **Admin (herdado do ADR-0029)**       |                              |              |       |
| Suspensão de usuário                  | `user_suspend`               | Destructive  | ✅    |
| Alteração de role/permissão           | `user_role_change`           | Destructive  | ✅    |
| Revogação de API key                  | `api_key_revoke`             | Irreversible | ✅    |
| Exclusão em massa                     | `bulk_delete`                | Irreversible | ✅    |
| Alteração de política de dados        | `data_policy_change`         | Irreversible | ✅    |
| Geração de relatório LGPD             | `lgpd_report_generate`       | Destructive  | ✅    |

---

## 4. Contrato de Comunicação — Delta

### 4.1 agent_id canônico

```
agent_id = "chatbot-external-" + BLAKE3(workspace_id + vendor_id + version)[..16]
```

O `vendor_id` integra o `agent_id` para que o DurableLedger do BTV
distinga evidências por empresa **e** por vendor utilizado.

### 4.2 profile_id e sector_id

```json
"profile_id": "external-chatbot",
"sector_id": "<finance|health|legal|hr|general>"
```

### 4.3 agent_metadata — campos adicionais (delta do ADR-0029)

```json
"agent_metadata": {
  "workspace_id": "<uuid>",
  "vendor_id": "openai|anthropic|google|azure_openai|cohere",
  "vendor_model": "gpt-4o|claude-3-5-sonnet|gemini-2.0-flash",
  "data_classification": "PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED",
  "pii_detected": true,
  "pii_types": ["CPF", "EMAIL"],
  "sanitized_before_send": true,
  "sanitize_evidence_id": "<evidence_id do /v1/sanitize>",
  "eligible_for_training": false,
  "rag_context": false,
  "data_residency_required": "BR",
  "vendor_data_retention_days": 0,
  "action_subtype": "llm_vendor_send|vendor_response|vendor_approve"
}
```

Campos novos em relação ao ADR-0029:
- `vendor_id`: identifica qual vendor receberá o dado.
- `vendor_model`: modelo específico em uso.
- `sanitized_before_send`: **obrigatório `true`** para `llm_vendor_send`.
  Se `false`, o BTV bloqueia independentemente de outras condições.
- `sanitize_evidence_id`: `evidence_id` gerado pelo `/v1/sanitize`
  imediatamente anterior. O BTV valida a consistência temporal
  (sanitização deve ocorrer ≤ 5 s antes da transmissão).
- `data_residency_required`: `"BR"` para workspaces com requisito LGPD.
- `vendor_data_retention_days`: dias que o vendor retém o dado conforme
  seu DPA. `0` = zero retention (ex.: OpenAI Enterprise com ZDR ativo).

---

## 5. Gates Detalhados

### Gate 1 — Transmissão ao Vendor (o gate mais crítico)

**Fluxo obrigatório — ordem não negociável:**

```
Mensagem do usuário
        │
        ▼
1. DataFilterService (Angular) — detecção de PII
        │
        ▼
2. POST /v1/sanitize ──► evidence_id_sanitize
   (SEMPRE, independente de classificação)
        │
        ▼
3. POST /v1/validate (llm_vendor_send, Irreversible)
   ├─ agent_metadata.sanitized_before_send = true
   └─ agent_metadata.sanitize_evidence_id = evidence_id_sanitize
        │
   ┌────┴──────────────────┐
ALLOW/EDUCATE            BLOCK
   │                       │
   ▼                       ▼
Vendor API           Feedback ao usuário
(com dado sanitizado)  + opção de contestação
   │
   ▼
4. Recebe resposta do vendor
        │
        ▼
5. POST /v1/sanitize (resposta) ──► evidence_id_response
        │
        ▼
6. Exibe resposta sanitizada ao usuário
```

**Diferença crítica do ADR-0029:**
No ADR-0029, `/v1/sanitize` era chamado apenas quando `pii_detected=true`.
Aqui, **é chamado em toda mensagem antes de qualquer envio ao vendor**,
independentemente de classificação. A evidência da sanitização é um
pré-requisito do veredicto de transmissão.

**Rust — `crates/btv-client/src/gates/vendor_send.rs`:**

```rust
use crate::{BtvClient, AgentDecisionRequest, ActionImpact, BtvError};
use crate::evidence::EvidenceId;
use crate::models::{VendorMessage, WorkspaceContext, VendorConfig};
use std::time::{Duration, SystemTime};

pub struct VendorSendGateResult {
    pub sanitized_content: String,
    pub sanitize_evidence_id: EvidenceId,
    pub send_evidence_id: EvidenceId,
}

/// Gate 1: sanitiza + valida transmissão ao vendor.
/// Ordem obrigatória: sanitize → validate → send.
/// Qualquer falha = não envia ao vendor (fail-secure).
pub async fn gate_vendor_send(
    message: &VendorMessage,
    btv: &dyn BtvClient,
    ctx: &WorkspaceContext,
    vendor: &VendorConfig,
) -> Result<VendorSendGateResult, BtvError> {
    let send_start = SystemTime::now();

    // Passo 1: sanitização obrigatória (sempre, não só com PII)
    let sanitized = btv.sanitize_output(&message.content).await
        .map_err(|_| BtvError::Unavailable)?;

    // Valida consistência temporal: sanitização deve ser recente
    let elapsed = send_start.elapsed().unwrap_or(Duration::MAX);
    if elapsed > Duration::from_secs(5) {
        return Err(BtvError::SanitizeStaleness);
    }

    // Passo 2: validação da transmissão (Irreversible)
    let req = AgentDecisionRequest {
        schema_version: "1.0".into(),
        request_id: uuid::Uuid::new_v4().to_string(),
        agent_id: derive_agent_id_external(
            &ctx.workspace_id,
            &vendor.vendor_id,
            env!("CARGO_PKG_VERSION")
        ),
        session_id: ctx.session_id.clone(),
        action: Action {
            name: "llm_vendor_send".into(),
            impact: ActionImpact::Irreversible, // sempre Irreversible
            capabilities: vec![
                "external_data_transfer".into(),
                format!("llm_vendor_{}", vendor.vendor_id),
            ],
        },
        // Hash do conteúdo JÁ sanitizado
        parameters_hash: blake3_hex(sanitized.content.as_bytes()),
        parameters_preview: serde_json::json!({
            "message_length": sanitized.content.len(),
            "classification": message.classification,
            "pii_types_found": sanitized.pii_types,
            "vendor_id": vendor.vendor_id,
            "vendor_model": vendor.model,
        }),
        context: Context {
            profile_id: "external-chatbot".into(),
            sector_id: ctx.sector_id.clone(),
            session_trust_score: ctx.trust_score,
            agent_metadata: serde_json::json!({
                "workspace_id": ctx.workspace_id,
                "vendor_id": vendor.vendor_id,
                "vendor_model": vendor.model,
                "data_classification": message.classification,
                "pii_detected": message.pii_detected,
                "pii_types": message.pii_types,
                "sanitized_before_send": true,     // sempre true aqui
                "sanitize_evidence_id": sanitized.evidence_id,
                "eligible_for_training": false,    // dado saiu do perímetro
                "rag_context": false,
                "data_residency_required": ctx.data_residency,
                "vendor_data_retention_days": vendor.data_retention_days,
                "action_subtype": "llm_vendor_send"
            }),
        },
        timestamp_utc: Utc::now().to_rfc3339(),
    };

    let envelope = btv.request_decision(&req).await
        .map_err(|_| BtvError::Unavailable)?;

    btv.verify_hmac(&envelope)?; // HMAC inválido = BtvError = não envia

    match envelope.verdict.as_str() {
        "ALLOW" | "EDUCATE" => Ok(VendorSendGateResult {
            sanitized_content: sanitized.content,
            sanitize_evidence_id: sanitized.evidence_id,
            send_evidence_id: envelope.evidence_id,
        }),
        "BLOCK" => Err(BtvError::Blocked {
            reason: envelope.explain_decision,
            evidence_id: envelope.evidence_id,
            contestable: envelope.contestable,
        }),
        _ => Err(BtvError::UnexpectedVerdict),
    }
}
```

---

### Gate 2 — Resposta do Vendor (gate novo, sem equivalente no ADR-0029)

A resposta do vendor pode conter dados exfiltrados via prompt injection
realizada no conteúdo de documentos RAG. Sanitizar a resposta antes de
exibi-la ao usuário é uma defesa de profundidade.

```rust
/// Gate 2: sanitiza resposta recebida do vendor antes de exibir ao usuário.
/// Protege contra exfiltração via prompt injection no modelo externo.
pub async fn gate_vendor_response(
    raw_response: &str,
    btv: &dyn BtvClient,
    ctx: &WorkspaceContext,
    send_evidence_id: &EvidenceId,
) -> Result<String, BtvError> {
    // Sanitização da resposta
    let sanitized = btv.sanitize_output(raw_response).await
        .map_err(|_| BtvError::Unavailable)?;

    // Validação do display (Destructive — resposta já no perímetro)
    let req = build_response_display_request(
        &sanitized,
        ctx,
        send_evidence_id
    );

    let envelope = btv.request_decision(&req).await
        .map_err(|_| BtvError::Unavailable)?;

    btv.verify_hmac(&envelope)?;

    match envelope.verdict.as_str() {
        "ALLOW" | "EDUCATE" => Ok(sanitized.content),
        "BLOCK" => {
            // Exibe mensagem genérica; evidence_id disponível para auditoria
            tracing::warn!(
                evidence_id = %envelope.evidence_id,
                "Resposta do vendor bloqueada: {}",
                envelope.explain_decision
            );
            Err(BtvError::Blocked {
                reason: envelope.explain_decision,
                evidence_id: envelope.evidence_id,
                contestable: false, // resposta bloqueada não é contestável pelo usuário
            })
        }
        _ => Err(BtvError::UnexpectedVerdict),
    }
}
```

---

### Gate 3 — Aprovação de Vendor por Workspace

Este gate é executado uma vez por sessão (ou quando o vendor muda),
não a cada mensagem. Resultado cacheável com TTL de 60 s.

```rust
/// Gate 3: valida se o vendor está aprovado para o sector_id do workspace.
/// Cacheável (TTL 60s) — não é Irreversible por mensagem, mas por sessão.
/// Resultado BLOCK = vendor proibido para este setor; não inicia sessão.
pub async fn gate_vendor_approval(
    vendor: &VendorConfig,
    btv: &dyn BtvClient,
    ctx: &WorkspaceContext,
) -> Result<EvidenceId, BtvError> {
    let req = AgentDecisionRequest {
        action: Action {
            name: "vendor_approve".into(),
            impact: ActionImpact::Irreversible,
            capabilities: vec![
                "vendor_session_start".into(),
                format!("llm_vendor_{}", vendor.vendor_id),
            ],
        },
        parameters_preview: serde_json::json!({
            "vendor_id": vendor.vendor_id,
            "vendor_model": vendor.model,
            "data_residency": vendor.data_residency,
            "data_retention_days": vendor.data_retention_days,
            "has_dpa": vendor.has_dpa,
            "has_zero_data_retention": vendor.has_zero_data_retention,
        }),
        context: Context {
            profile_id: "external-chatbot".into(),
            sector_id: ctx.sector_id.clone(),
            agent_metadata: serde_json::json!({
                "workspace_id": ctx.workspace_id,
                "action_subtype": "vendor_approve",
                "vendor_id": vendor.vendor_id,
            }),
            ..default_context(ctx)
        },
        ..base_request(ctx)
    };

    let envelope = btv.request_decision(&req).await?;
    btv.verify_hmac(&envelope)?;

    match envelope.verdict.as_str() {
        "ALLOW" => Ok(envelope.evidence_id),
        "BLOCK" => Err(BtvError::Blocked {
            reason: envelope.explain_decision,
            evidence_id: envelope.evidence_id,
            contestable: envelope.contestable,
        }),
        _ => Err(BtvError::UnexpectedVerdict),
    }
}
```

---

### Gate 4 — RAG com dado CONFIDENTIAL/RESTRICTED para vendor

```rust
/// Gate 4 (delta do ADR-0029 Gate 3):
/// Chunks RESTRICTED são SEMPRE bloqueados para vendors externos.
/// Chunks CONFIDENTIAL passam por gate adicional (Irreversible, não Destructive).
pub async fn gate_rag_chunks_external(
    chunks: Vec<RagChunk>,
    btv: &dyn BtvClient,
    ctx: &WorkspaceContext,
) -> Vec<RagChunk> {
    let futures: Vec<_> = chunks
        .iter()
        .map(|chunk| gate_rag_chunk_external(chunk, btv, ctx))
        .collect();

    let results = join_all(futures).await;

    chunks
        .into_iter()
        .zip(results)
        .filter_map(|(chunk, result)| match result {
            Ok(true)  => Some(chunk),
            Ok(false) => {
                tracing::warn!(
                    chunk_id = %chunk.id,
                    classification = %chunk.classification,
                    "Chunk RAG bloqueado para vendor externo"
                );
                None
            }
            Err(e) => {
                tracing::error!(error = %e, "Gate RAG falhou — chunk excluído");
                None
            }
        })
        .collect()
}

async fn gate_rag_chunk_external(
    chunk: &RagChunk,
    btv: &dyn BtvClient,
    ctx: &WorkspaceContext,
) -> Result<bool, BtvError> {
    // RESTRICTED: bloqueio incondicional — não consulta BTV
    if chunk.classification == Classification::Restricted {
        tracing::warn!(
            chunk_id = %chunk.id,
            "Chunk RESTRICTED bloqueado sem consulta BTV — dado nunca sai do perímetro"
        );
        return Ok(false);
    }

    // CONFIDENTIAL ou menor: consulta BTV (Irreversible para CONFIDENTIAL)
    let impact = if chunk.classification == Classification::Confidential {
        ActionImpact::Irreversible
    } else {
        ActionImpact::Destructive
    };

    let req = build_rag_external_request(chunk, impact, ctx);
    let envelope = btv.request_decision(&req).await?;
    btv.verify_hmac(&envelope)?;
    Ok(matches!(envelope.verdict.as_str(), "ALLOW" | "EDUCATE"))
}
```

---

## 6. Políticas YAML

### 6.1 Aprovação de Vendors por Sector

```yaml
# data/policies/chatbot-vendor-approval.yaml
id: chatbot-vendor-approval-v1
description: "Quais vendors são aprovados por sector_id."
applies_to:
  profile_id: "external-chatbot"
  action_names: ["vendor_approve"]

rules:
  # Setor saúde: apenas vendors com zero data retention e DPA válido
  - name: block_health_no_zdr
    conditions:
      sector_id: "health"
      agent_metadata.has_zero_data_retention: false
    verdict: BLOCK
    explain: >
      Setor saúde exige Zero Data Retention (ZDR) ativo no vendor.
      Configure ZDR no contrato Enterprise antes de habilitar este vendor.

  # Setor jurídico: bloqueia vendors sem DPA e com retenção > 0 dias
  - name: block_legal_no_dpa
    conditions:
      sector_id: "legal"
      agent_metadata.has_dpa: false
    verdict: BLOCK
    explain: >
      Setor jurídico exige Data Processing Agreement (DPA) assinado
      com o vendor. Consulte o departamento jurídico para assinar o DPA.

  # Setor financeiro: bloqueia vendors fora do Brasil sem DPA
  - name: block_finance_foreign_no_dpa
    conditions:
      sector_id: "finance"
      agent_metadata.data_residency: { not_in: ["BR", "EU"] }
      agent_metadata.has_dpa: false
    verdict: BLOCK
    explain: >
      Setor financeiro: vendor fora do Brasil/UE sem DPA viola requisitos
      de transferência internacional (LGPD Art. 33).

  # Setor RH: bloqueia retenção de dados > 30 dias
  - name: block_hr_long_retention
    conditions:
      sector_id: "hr"
      agent_metadata.vendor_data_retention_days: { gt: 30 }
    verdict: BLOCK
    explain: >
      Setor RH: vendor retém dados por mais de 30 dias. Dados de RH
      com PII não devem ser retidos além do necessário (LGPD Art. 5, X).

  # Geral: aprovado se tem DPA
  - name: allow_with_dpa
    conditions:
      agent_metadata.has_dpa: true
    verdict: ALLOW
    explain: "Vendor aprovado: DPA presente e condições atendidas."

  # Geral sem DPA: EDUCATE — aprovado mas com aviso
  - name: educate_no_dpa
    conditions:
      default: true
    verdict: EDUCATE
    explain: >
      Vendor sem DPA formal. Uso aprovado para dados não-sensíveis.
      Recomenda-se assinar DPA para uso com dados INTERNAL ou acima.
```

### 6.2 Transmissão de Mensagens ao Vendor

```yaml
# data/policies/chatbot-vendor-send.yaml
id: chatbot-vendor-send-v1
applies_to:
  profile_id: "external-chatbot"
  action_names: ["llm_vendor_send"]

rules:
  # Regra hard: sem sanitização = BLOCK absoluto
  - name: block_unsanitized
    conditions:
      agent_metadata.sanitized_before_send: false
    verdict: BLOCK
    explain: >
      Transmissão bloqueada: evidência de sanitização ausente.
      O dado deve passar por /v1/sanitize antes de qualquer envio externo.

  # Regra hard: dado RESTRICTED nunca sai do perímetro
  - name: block_restricted_data
    conditions:
      agent_metadata.data_classification: "RESTRICTED"
    verdict: BLOCK
    explain: >
      Dados RESTRICTED não são transmitidos a vendors externos.
      Reclassifique o dado ou utilize LLM self-hosted para este caso.

  # Setor saúde: bloqueia se ZDR não está ativo
  - name: block_health_no_zdr
    conditions:
      sector_id: "health"
      agent_metadata.vendor_data_retention_days: { gt: 0 }
    verdict: BLOCK
    explain: >
      Setor saúde: vendor não está com Zero Data Retention ativo.
      Dados de saúde não devem ser retidos pelo vendor.

  # CONFIDENTIAL com DPA: EDUCATE
  - name: educate_confidential_with_dpa
    conditions:
      agent_metadata.data_classification: "CONFIDENTIAL"
      agent_metadata.sanitized_before_send: true
    verdict: EDUCATE
    explain: >
      Dado CONFIDENTIAL sendo enviado a vendor externo com sanitização.
      Verifique se a sanitização removeu todos os identificadores
      antes de prosseguir.

  # Caso geral aprovado
  - name: allow_sanitized
    conditions:
      agent_metadata.sanitized_before_send: true
      agent_metadata.data_classification: { in: ["PUBLIC", "INTERNAL"] }
    verdict: ALLOW
    explain: "Transmissão autorizada: dado sanitizado e classificação adequada."
```

### 6.3 Resposta do Vendor

```yaml
# data/policies/chatbot-vendor-response.yaml
id: chatbot-vendor-response-v1
applies_to:
  profile_id: "external-chatbot"
  action_names: ["llm_vendor_response_display"]

rules:
  # Bloqueia respostas que parecem conter dados exfiltrados
  - name: block_exfiltration_patterns
    conditions:
      content_patterns:
        - "CPF:"
        - "CNPJ:"
        - "senha:"
        - "password:"
        - "token:"
        - "Bearer "
        - "sk-"         # prefixo de chave OpenAI
        - "-----BEGIN"  # chave PEM
    verdict: BLOCK
    explain: >
      Resposta do vendor contém padrões suspeitos de exfiltração de dados.
      Exibição bloqueada. Registre um ticket de segurança.

  - name: allow_clean_response
    conditions:
      default: true
    verdict: ALLOW
```

### 6.4 RAG para Vendor Externo

```yaml
# data/policies/chatbot-rag-external.yaml
id: chatbot-rag-external-v1
applies_to:
  profile_id: "external-chatbot"
  action_names:
    - "rag_chunk_inject"
    - "rag_chunk_inject_conf"

rules:
  # Prompt injection patterns (herdado do ADR-0029)
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

  # CONFIDENTIAL para vendor externo: EDUCATE (mais restritivo que interno)
  - name: educate_confidential_external
    conditions:
      action.name: "rag_chunk_inject_conf"
    verdict: EDUCATE
    explain: >
      Chunk CONFIDENTIAL sendo injetado em prompt para vendor externo.
      Verifique se o conteúdo foi sanitizado adequadamente.

  - name: allow_safe_chunk
    conditions:
      default: true
    verdict: ALLOW
```

---

## 7. Angular — BtvGateService (delta do ADR-0029)

```typescript
// core/services/btv-gate.service.ts — adições para LLM externa

@Injectable({ providedIn: 'root' })
export class BtvGateService {

  /**
   * Gate 1 + 2 combinados para LLM externa.
   * Ordem obrigatória: sanitize → validate → send → sanitize_response.
   * Qualquer falha = não envia ao vendor.
   */
  async validateVendorSend(
    filtered: FilteredMessage,
    vendor: VendorConfig
  ): Promise<VendorSendResult> {
    // Passo 1: sanitização obrigatória (sempre)
    const sanitized = await this.sanitizeMessage(filtered.content);

    // Passo 2: validação de transmissão (Irreversible)
    const request = this.buildVendorSendRequest(
      sanitized,
      vendor,
      filtered
    );

    const verdict = await firstValueFrom(
      this.http.post<VerdictEnvelope>('/api/btv/validate', request)
    );

    if (verdict.verdict === 'BLOCK') {
      throw new VendorSendBlockedError(
        verdict.explain_decision,
        verdict.evidence_id,
        verdict.contestable
      );
    }

    return {
      sanitizedContent: sanitized.content,
      sanitizeEvidenceId: sanitized.evidence_id,
      sendEvidenceId: verdict.evidence_id,
      educateWarning: verdict.verdict === 'EDUCATE'
        ? verdict.explain_decision
        : null
    };
  }

  /**
   * Gate 2: sanitiza resposta do vendor antes de exibir.
   */
  async sanitizeVendorResponse(
    rawResponse: string,
    sendEvidenceId: string
  ): Promise<string> {
    const sanitized = await this.sanitizeMessage(rawResponse);

    const request = this.buildResponseDisplayRequest(
      sanitized,
      sendEvidenceId
    );

    const verdict = await firstValueFrom(
      this.http.post<VerdictEnvelope>('/api/btv/validate', request)
    );

    if (verdict.verdict === 'BLOCK') {
      throw new VendorResponseBlockedError(verdict.explain_decision);
    }

    return sanitized.content;
  }

  private buildVendorSendRequest(
    sanitized: SanitizeResult,
    vendor: VendorConfig,
    filtered: FilteredMessage
  ): AgentDecisionRequest {
    const workspace = this.ctx.current();
    return {
      schema_version: '1.0',
      request_id: crypto.randomUUID(),
      agent_id: `chatbot-external-${workspace.btvAgentHash}`,
      session_id: workspace.sessionId,
      action: {
        name: 'llm_vendor_send',
        impact: 'Irreversible',
        capabilities: ['external_data_transfer', `llm_vendor_${vendor.id}`]
      },
      parameters_hash: sanitized.contentHash,
      parameters_preview: {
        message_length: sanitized.content.length,
        classification: filtered.classification,
        pii_types: sanitized.piiTypes,
        vendor_id: vendor.id,
        vendor_model: vendor.model
      },
      context: {
        profile_id: 'external-chatbot',
        sector_id: workspace.sectorId,
        session_trust_score: workspace.trustScore,
        agent_metadata: {
          workspace_id: workspace.workspaceId,
          vendor_id: vendor.id,
          vendor_model: vendor.model,
          data_classification: filtered.classification,
          pii_detected: filtered.piiDetected,
          pii_types: filtered.piiTypes,
          sanitized_before_send: true,
          sanitize_evidence_id: sanitized.evidence_id,
          eligible_for_training: false,
          rag_context: false,
          data_residency_required: workspace.dataResidency,
          vendor_data_retention_days: vendor.dataRetentionDays,
          action_subtype: 'llm_vendor_send'
        }
      },
      timestamp_utc: new Date().toISOString()
    };
  }
}
```

**Integração no `chat-container.component.ts` (delta):**

```typescript
async sendMessage(rawText: string): Promise<void> {
  const filtered = this.dataFilter.processMessage(rawText, this.workspace);

  try {
    // Gate unificado: sanitize + validate + obter resultado
    const gateResult = await this.btvGate.validateVendorSend(
      filtered,
      this.workspace.vendorConfig
    );

    if (gateResult.educateWarning) {
      this.showEducateWarning(gateResult.educateWarning);
    }

    // Envia ao vendor APENAS o conteúdo sanitizado
    const rawResponse = await this.vendorService.send(
      gateResult.sanitizedContent,
      gateResult.sendEvidenceId  // correlação no log
    );

    // Gate de resposta: sanitiza antes de exibir
    const safeResponse = await this.btvGate.sanitizeVendorResponse(
      rawResponse,
      gateResult.sendEvidenceId
    );

    this.displayMessage(safeResponse);

  } catch (e) {
    if (e instanceof VendorSendBlockedError) {
      this.showBlockFeedback(e.reason, e.evidenceId, e.contestable);
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

## 8. Evidência LGPD Art. 33 — Transferência Internacional

O Art. 33 da LGPD exige que transferências internacionais de dados
pessoais sejam baseadas em: DPA adequado, cláusulas contratuais padrão,
ou outros mecanismos aprovados pela ANPD.

O BTV provê os artefatos forenses que documentam cada transferência:

```
Para cada mensagem enviada a vendor externo, o DurableLedger contém:

  evidence_id_sanitize:
    - Prova que /v1/sanitize foi executado
    - Quais tipos de PII foram encontrados e removidos
    - Timestamp e HMAC da sanitização

  evidence_id_send:
    - Prova que a transmissão foi autorizada
    - policy_version_applied (qual política YAML estava ativa)
    - vendor_id e vendor_model
    - sector_id e data_classification
    - sanitize_evidence_id (referência cruzada)
    - HMAC-SHA256 da decisão

Rastreabilidade completa:
  mensagem → sanitização → autorização → envio ao vendor
  tudo com hash BLAKE3, assinado, imutável, contestável.
```

**Relatório LGPD — seção nova (transferências internacionais):**

```typescript
// Adição ao ComplianceReportComponent
internationalTransfers: {
  total: number;              // total de mensagens enviadas a vendors
  byVendor: {
    vendorId: string;
    vendorName: string;
    dataResidency: string;
    hasDpa: boolean;
    transferCount: number;
    evidenceIds: string[];    // amostra de evidence_ids BTV
  }[];
  lgpdArt33Compliant: boolean;
  nonCompliantInstances: {    // transmissões sem DPA (EDUCATE no ledger)
    evidenceId: string;
    timestamp: string;
    reason: string;
  }[];
}
```

---

## 9. Comparação Direta: ADR-0029 vs ADR-0030

| Aspecto | ADR-0029 (LLM interna) | ADR-0030 (LLM externa) |
|:--------|:-----------------------|:-----------------------|
| **Gate mais crítico** | `lora_deploy` (1x/semana) | `llm_vendor_send` (cada mensagem) |
| **ActionImpact da mensagem** | Destructive (se PII) | Irreversible (sempre) |
| **`/v1/sanitize`** | Se `pii_detected=true` | Toda mensagem, sem exceção |
| **Gate de resposta** | Não existe | Obrigatório (Gate 2) |
| **Pipeline de treinamento** | Gates 4 e 5 (críticos) | Não aplicável |
| **Aprovação de vendor** | Não aplicável | Gate 3 (por sessão) |
| **Chunk `RESTRICTED` no RAG** | Gate Irreversible | BLOCK incondicional |
| **LGPD** | Processamento interno | Art. 33 (transferência internacional) |
| **`eligible_for_training`** | Condicional (sem PII) | Sempre `false` (dado saiu) |
| **Cache de veredicto** | TTL 5s para Destructive | TTL zero para `llm_vendor_send` |
| **Relatório LGPD** | Sanitização interna | + Seção de transferências internacionais |

---

## 10. Invariantes desta ADR

1. **Sanitização antes de qualquer envio.** `llm_vendor_send` sem
   `sanitize_evidence_id` válido → BLOCK incondicional pelo BTV.
2. **`RESTRICTED` nunca sai do perímetro.** Bloqueio local antes do gate,
   sem consulta ao BTV (fail-safe adicional).
3. **Cache zero para transmissões.** Veredicto de `llm_vendor_send`
   nunca é cacheado — cada mensagem exige novo gate.
4. **`eligible_for_training: false` absoluto.** Todo dado que passou
   por um vendor externo é marcado como não elegível para treinamento
   — registrado no Evidence.
5. **Gate de resposta obrigatório.** Resposta do vendor sem sanitização
   e validação BTV não é exibida ao usuário.
6. **Fail-secure em toda falha.** BTV indisponível = mensagem não enviada
   ao vendor. Nunca permitir por omissão.
7. **Vendor não aprovado = sessão não iniciada.** Gate de aprovação de
   vendor bloqueado = nenhuma mensagem da sessão é enviada, mesmo que
   individualmente passassem nos outros gates.

---

## 11. Critérios de Aceitação

- [ ] Gate 1: mensagem sem `sanitize_evidence_id` → BTV retorna BLOCK.
- [ ] Gate 1: mensagem `RESTRICTED` → bloqueio local antes de chegar ao BTV.
- [ ] Gate 1: BTV indisponível → mensagem não enviada ao vendor.
- [ ] Gate 2: resposta do vendor sanitizada antes de exibição em 100% dos casos.
- [ ] Gate 3: vendor não aprovado para `sector_id: health` sem ZDR → BLOCK.
- [ ] Gate 4: chunk `RESTRICTED` nunca aparece em prompt enviado ao vendor.
- [ ] Teste: setor `health` + vendor sem ZDR → BLOCK no gate de aprovação.
- [ ] Teste: setor `legal` + vendor sem DPA → BLOCK no gate de aprovação.
- [ ] Teste: resposta do vendor com `sk-` → BLOCK no gate de resposta.
- [ ] Relatório LGPD inclui seção de transferências internacionais com `evidence_id`s.
- [ ] `evidence_id_sanitize` e `evidence_id_send` correlacionados em 100% dos registros.
- [ ] Métricas `btv_chatbot_vendor_*` visíveis no dashboard.
- [ ] `docs/integrations/chatbot-external-llm.md` criado.
- [ ] ADR registrado no `0000-adr-index.md`.

---

## 12. Referências Cruzadas

- BTV ADR-0028 (External Agent PDP — contrato canônico)
- BTV ADR-0029 (Chatbot LLM interna — base deste ADR)
- BTV ADR-0004 (Immutable Ledger — DurableLedger BLAKE3)
- BTV ADR-0005 (Evidence Protocol v2.1 — 9596 bytes)
- BTV ADR-0006 (Policy-as-Code — YAML)
- BTV ADR-0008 (Timing Mitigation — constant-time HMAC)
- BTV ADR-0010 (BiasDeclaration Mandate)
- BTV ADR-0017 (ContestabilityLoop SLA 24h)
- `docs/integrations/chatbot-external-llm.md` (perfil deste ADR)
- LGPD Art. 33 (transferência internacional de dados pessoais)
- EU AI Act Art. 5 (práticas proibidas de IA — em vigor)
```
