# ADR-0029 — Integração de Agentes Externos como Consumidores do BTV (PDP)

| Campo         | Valor                                            |
|:--------------|:-------------------------------------------------|
| **ID**        | 0029                                             |
| **Status**    | 🔒 Proposto                                      |
| **Alvo**      | BTV v2.0+                                        |
| **Autores**   | Arquiteta BTV                                    |
| **Data**      | 2026-02-23                                       |
| **Revisores** | Reviewer (Opus) — conformidade ADR + invariantes |

---

## 1. Contexto

O BTV é um Sovereign Trust OS: avalia intenções, emite veredictos éticos
assinados, mantém trilha forense imutável e oferece contestabilidade com
SLA de 24h. Até v1.9, o BTV é consumido diretamente via scripts de teste
ou por humanos via dashboard Streamlit.

A partir de v2.0, agentes de IA autônomos (executores de ferramentas,
orquestradores de tarefas, bots conversacionais) precisam de um padrão
formal para consumir o BTV como **Policy Decision Point (PDP) externo**.
Sem esse padrão:

- Cada integração reinventa contratos incompatíveis.
- Invariantes críticos (fail-secure, HMAC, contestabilidade) podem ser
  implementados de forma incorreta ou omitidos.
- O BTV não consegue escalar para múltiplos agentes com governança
  centralizada e uniforme.

Esta ADR define o **contrato canônico** que qualquer agente externo deve
seguir para consumir o BTV como PDP, independente de linguagem,
plataforma ou domínio de aplicação.

---

## 2. Decisão

O BTV expõe um **perfil de integração de agentes** baseado nos endpoints
já existentes (`/v1/validate`, `/v1/sanitize`, `/v1/decide`, `/v1/appeals`,
`/v1/trust/{id}`). Qualquer agente que implemente o contrato definido
nesta ADR é considerado um **BTV-compatible agent**.

O padrão é composto por três elementos:

1. **Taxonomia de impacto** — classificação obrigatória de cada ação do
   agente antes de solicitar veredicto.
2. **Contrato de comunicação** — schema canônico de `AgentDecisionRequest`
   e `AgentDecisionResponse`.
3. **Protocolo de resiliência** — regras de fallback, circuit breaker e
   comportamento obrigatório em falha.

Agentes não-conformes (que não verificam HMAC, que fazem bypass em timeout,
ou que omitem `tool_impact`) NÃO são BTV-compatible e não devem ser
registrados como integrações suportadas.

---

## 3. Taxonomia de Impacto de Ações (Padrão BTV)

Todo agente DEVE classificar cada ação antes de enviá-la ao BTV.
A ausência de classificação é tratada como `Irreversible`.

```rust
/// Padrão BTV para classificação de impacto de ações de agentes.
/// Implementado em cada agente na linguagem de sua plataforma.
pub enum ActionImpact {
    /// Leitura pura; sem efeito colateral externo observável.
    Safe,
    /// Modifica estado local; reversão possível (ex.: write com backup).
    Destructive,
    /// Efeito externo permanente ou escalação de privilégio.
    Irreversible,
}
```

**Regra:** Gate BTV obrigatório para `Destructive` e `Irreversible`.
`Safe` executa diretamente, mas DEVE ser logado localmente de forma
assíncrona para correlação futura.

---

## 4. Contrato de Comunicação

### 4.1 AgentDecisionRequest

```json
{
  "schema_version": "1.0",
  "request_id": "<UUIDv4>",
  "agent_id": "<identificador único e estável do agente>",
  "session_id": "<identificador da sessão corrente>",
  "action": {
    "name": "<nome da ação ou ferramenta>",
    "impact": "Safe | Destructive | Irreversible",
    "capabilities": ["<capability_1>", "<capability_2>"]
  },
  "parameters_hash": "<BLAKE3-hex dos parâmetros completos serializados>",
  "parameters_preview": {
    "<campo_não_sensível>": "<valor>"
  },
  "context": {
    "profile_id": "<perfil de política do agente>",
    "sector_id": "<setor de aplicação: finance|health|legal|general>",
    "session_trust_score": 0.0,
    "agent_metadata": {
      "<chave_livre>": "<valor>"
    }
  },
  "timestamp_utc": "<ISO8601>"
}
```

**Regras obrigatórias:**
- `parameters_preview` NUNCA contém segredos, tokens ou chaves.
  Dados sensíveis aparecem apenas em `parameters_hash`.
- `agent_id` DEVE ser estável (mesmo hash entre reinicializações);
  recomendado: `BLAKE3(config_canônica_do_agente)`.
- `session_trust_score` é obtido via `GET /v1/trust/{session_id}` com
  TTL de cache máximo de 60 s.
- `profile_id` e `sector_id` ativam ProfileManager e SectorLoader do BTV;
  omiti-los resulta em perfil `default`.
- Campos em `agent_metadata` são livres; o BTV os registra no Evidence
  sem processar.

### 4.2 AgentDecisionResponse

```json
{
  "request_id": "<mesmo UUIDv4 do request>",
  "verdict": "ALLOW | EDUCATE | BLOCK",
  "verdict_code": 200,
  "explain_decision": "<justificativa em linguagem natural — obrigatório>",
  "bias_declaration": {
    "false_positive_rate_pct": 0,
    "false_negative_rate_pct": 0,
    "calibration_date": "YYYYMMDD",
    "known_limitations": "<string livre>"
  },
  "contestable": true,
  "appeal_deadline_utc": "<ISO8601>",
  "policy_version_applied": "<versão da política YAML ativa>",
  "evidence_id": "<identificador da TechnicalEvidence gerada>",
  "hmac_sha256": "<hex64 — HMAC do payload canônico>",
  "timestamp_utc": "<ISO8601>"
}
```

**Tabela de vereditos:**

| `verdict`   | `verdict_code` | Ação obrigatória no agente                               |
|:------------|:---------------|:---------------------------------------------------------|
| `ALLOW`     | 200            | Executar; registrar `evidence_id` no log local.          |
| `EDUCATE`   | 202            | Executar; logar `explain_decision` completo com WARNING. |
| `BLOCK`     | 403            | Abortar; oferecer caminho de apelação ao operador.       |
| *(ausente)* | 5xx / timeout  | Fail-secure → tratar como `BLOCK`.                       |

### 4.3 Verificação HMAC (obrigatória em todo agente)

```
expected = HMAC-SHA256(btv_shared_key, canonical_bytes(response))
assert constant_time_eq(expected, response.hmac_sha256)
```

- `canonical_bytes`: serialização determinística do response (excluindo
  o próprio campo `hmac_sha256`), UTF-8, campos em ordem alfabética.
- Comparação DEVE ser constant-time para evitar timing attacks
  (alinhado com BTV ADR-0008).
- HMAC key DEVE ser zerada da memória após uso (`zeroize`).
- Veredicto com HMAC inválido → BLOCK imediato + alerta de segurança.

---

## 5. Protocolo de Resiliência (obrigatório para BTV-compatible agents)

| Cenário                       | Comportamento obrigatório                          |
|:------------------------------|:---------------------------------------------------|
| Resposta em < timeout         | Fluxo normal.                                      |
| Timeout (padrão: 5 s)         | BLOCK local + log estruturado `btv.timeout`.       |
| HTTP 5xx                      | 1 retry (100 ms backoff) → BLOCK se falhar.        |
| Circuit aberto (≥3 falhas/30s)| BLOCK todas `Destructive`/`Irreversible` + alerta. |
| HMAC inválido                 | BLOCK + evento `btv.hmac_mismatch` + alerta.       |
| `policy_version` diverge      | Log de aviso; não bloqueia (auditoria apenas).     |
| Auth inválida (401/403 BTV)   | BLOCK + log `btv.auth_failure`; não retry.         |

**Regra universal:** qualquer erro de rede, parsing, autenticação ou
verificação criptográfica é equivalente a BLOCK. **Nunca permitir por
omissão.**

---

## 6. Fluxo de Contestação (padrão BTV)

Quando o agente recebe `BLOCK` e o operador humano deseja contestar:

```
POST /v1/appeals
{
  "evidence_id": "<ev_hex32>",
  "justification": "<texto livre do operador>",
  "requested_by": "<identificador do operador>",
  "timestamp_utc": "<ISO8601>"
}

→ resposta: { "appeal_id": "<id>", "status": "pending" }
```

O agente deve:
1. Apresentar ao operador o `explain_decision` do veredicto BLOCK.
2. Registrar localmente o `appeal_id` correlacionado ao `evidence_id`.
3. Nunca executar a ação bloqueada enquanto o recurso estiver `pending`.
4. Consultar `GET /v1/appeals/{id}` para verificar resolução.

---

## 7. Autenticação

Todas as chamadas ao BTV incluem `X-API-Key: <chave>` no header.
- Chave gerada e rotacionada via mecanismo de key management do BTV.
- Ausência ou invalidade da chave → 401/403 → BLOCK no agente.
- Cada agente tem sua própria API key para rastreabilidade no ledger.

---

## 8. Registro de Agente (Perfil de Integração)

Todo agente BTV-compatible DEVE ter um **Perfil de Integração**
documentado em `docs/integrations/<nome-do-agente>.md` com:

- `agent_id` canônico e como é derivado.
- Mapeamento da taxonomia de ações do agente para `ActionImpact`.
- `profile_id` e `sector_id` usados por padrão.
- Campos em `agent_metadata` específicos do agente.
- Notas de implementação do protocolo de resiliência.
- Referência cruzada ao ADR do lado do agente.

O BTV não centraliza código de integração — apenas o padrão e os perfis.

---

## 9. Invariantes desta ADR

1. **Sem veredicto verificado → sem execução.** Ação `Destructive` ou
   `Irreversible` sem HMAC válido → BLOCK.
2. **Fail-secure absoluto.** Qualquer erro → BLOCK. Jamais permitir
   por omissão ou por silêncio da exceção.
3. **TTL zero para `Irreversible`.** Cache de veredicto PROIBIDO para
   ações irreversíveis.
4. **`evidence_id` obrigatório.** Todo `ALLOW`/`EDUCATE` registra
   `evidence_id` no log local do agente.
5. **API key por agente.** Chaves compartilhadas entre agentes são
   anti-padrão; prejudicam rastreabilidade no ledger.
6. **`explain_decision` não é opcional.** O agente DEVE logar o campo
   em todo veredicto, não apenas em BLOCK.

---

## 10. Consequências

**Positivas:**
- Qualquer agente (qualquer linguagem, qualquer domínio) pode consumir
  o BTV com garantias uniformes de segurança e auditabilidade.
- Ledger centralizado correlaciona ações de múltiplos agentes com
  evidências forenses padronizadas.
- Contestabilidade e BiasDeclaration ficam disponíveis para todo ecossistema,
  não apenas para um agente específico.
- Base para certificação BTV-compatible como selo de governança.

**Negativas:**
- Latência adicional por chamada HTTP (~10–15 ms em fluxo normal).
  Mitigada por cache TTL (Destructive) e circuit breaker.
- Custo operacional de manter BTV disponível como serviço.
  Mitigada por modo sidecar (dev) e alta disponibilidade (prod).

---

## 11. Critérios de Aceitação

- [ ] Schema `AgentDecisionRequest` / `AgentDecisionResponse` publicado
      em `spec/agent-pdp-v1.json` (JSON Schema Draft-07).
- [ ] Endpoint `/v1/validate` aceita e valida o novo schema.
- [ ] Documentação de exemplo em `docs/integrations/example-agent.md`.
- [ ] Pelo menos 1 perfil de integração real registrado em
      `docs/integrations/` (primeiro: OpenClaw).
- [ ] ADR registrado no `0000-adr-index.md`.

---

## 12. Referências Cruzadas

- BTV ADR-0001 (Hybrid Architecture)
- BTV ADR-0004 (Immutable Ledger)
- BTV ADR-0005 (Evidence Protocol v2.1 — 9596 bytes)
- BTV ADR-0006 (Policy-as-Code — YAML + Rawls)
- BTV ADR-0008 (Timing Mitigation — constant-time)
- BTV ADR-0010 (BiasDeclaration Mandate)
- BTV ADR-0017 (ContestabilityLoop SLA 24h)
- `docs/integrations/agentRust.md` (primeiro perfil de referência)
```
