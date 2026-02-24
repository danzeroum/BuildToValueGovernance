```markdown
# Perfil de Integração BTV: AgentRust Next Gen

| Campo              | Valor                                        |
|:-------------------|:---------------------------------------------|
| **Padrão**         | BTV ADR-0028 (External Agent PDP)            |
| **Versão agente**  | AgentRust v1.0-next (Rust)                    |
| **Versão BTV**     | v2.0+                                        |
| **ADR lado agente**| AgentRust ADR-024 (a ser criado no repo OC)   |
| **Mantenedor**     | Equipe AgentRust                              |
| **Data**           | 2026-02-23                                   |

---

## 1. O que é o AgentRust

Agente de IA conversacional em Rust com ferramentas de alto impacto:
execução de shell (`exec`, `process`), manipulação de arquivos (`write`,
`apply_patch`), acesso web (`web_fetch`, `browser`), subagentes autônomos
(`sessions_spawn`), agendamento (`cron`) e controle de nós remotos
(`nodes`). Opera com modelo de atores (tokio mpsc), cancelamento
determinístico (CancellationToken) e sandbox Wasm para plugins.

---

## 2. agent_id canônico

```
agent_id = "AgentRust-" + BLAKE3(config.instance_id + config.version)[..16]
```

Derivado no startup; estável entre reinicializações da mesma instância.

---

## 3. Mapeamento de Ferramentas → ActionImpact

| Ferramenta AgentRust       | ActionImpact   | Capabilities declaradas              |
|:--------------------------|:---------------|:-------------------------------------|
| `read`, `memory_search`   | Safe           | `["filesystem_read"]`                |
| `write`, `edit`           | Destructive    | `["filesystem_write"]`               |
| `apply_patch`             | Destructive    | `["filesystem_write","patch_apply"]` |
| `exec` (sem escalação)    | Destructive    | `["process_exec"]`                   |
| `exec` (com escalação)    | Irreversible   | `["process_exec","privilege_esc"]`   |
| `process` (kill/signal)   | Irreversible   | `["process_signal"]`                 |
| `web_fetch`               | Destructive    | `["network_fetch"]`                  |
| `browser` (write/click)   | Irreversible   | `["browser_interact"]`               |
| `sessions_spawn`          | Irreversible   | `["subagent_spawn"]`                 |
| `cron` (register)         | Destructive    | `["scheduler_write"]`                |
| `nodes` (remote exec)     | Irreversible   | `["remote_exec"]`                    |
| `tts`, `canvas` (read-UI) | Safe           | `["ui_read"]`                        |

---

## 4. Campos específicos do AgentRust no contrato

### 4.1 agent_metadata obrigatório

```json
"agent_metadata": {
  "subagent_depth": 0,
  "session_type": "interactive | background | spawned",
  "parent_session_id": "<id ou null>",
  "cancellation_token_active": true
}
```

- `subagent_depth`: 0 = sessão principal; ≥1 = subagente criado via
  `sessions_spawn`. O BTV pode aplicar política mais restritiva para
  profundidades maiores.
- `parent_session_id`: presente quando `subagent_depth > 0`; permite
  correlação no ledger.
- `cancellation_token_active`: indica se o CancellationToken da sessão
  está ativo (o BTV registra, mas não processa — para auditoria).

### 4.2 profile_id e sector_id padrão

```json
"profile_id": "autonomous-agent",
"sector_id": "general"
```

Configuráveis por instância via `config.yaml` do AgentRust. Agentes
implantados em domínios específicos (ex.: saúde) devem sobrescrever
`sector_id` na inicialização.

---

## 5. Implementação do protocolo de resiliência

O AgentRust implementa ADR-0028 §5 via `BTVClientActor` (tokio mpsc):

- Timeout HTTP: 5 s (configurável via `BTV_TIMEOUT_MS`).
- Circuit breaker: 3 falhas → circuito aberto por 30 s → BLOCK local
  com evento `btv.circuit_open` no ring buffer do kernel.
- Cache: `DashMap<CacheKey, CachedVerdict>` com TTL de 5 s para
  `Destructive`; TTL=0 (proibido) para `Irreversible`.
- Fallback: `BTVError::*` de qualquer tipo → `ToolOutcome::Blocked`.

---

## 6. Fluxo de contestação no AgentRust

Quando o agente recebe `BLOCK`, o `SessionActor` apresenta ao operador:

```
[BTV] Ação bloqueada: exec "rm -rf /tmp/build"
Motivo: Comando destrutivo em path não permitido pela política v1.2
Contestar? [s/n]: _
```

Se `s`:
- AgentRust faz POST `/v1/appeals` com `evidence_id` e justificativa.
- Registra `appeal_id` no log local correlacionado ao `evidence_id`.
- A ação NÃO é executada enquanto status for `pending`.
- Operador acompanha via `GET /v1/appeals/{id}` ou dashboard BTV.

---

## 7. Referências cruzadas

- BTV ADR-0028 (contrato canônico — este perfil é instância dele)
- AgentRust ADR-016 a ADR-023 (Security ADRs)
- AgentRust ADR-024 (a ser escrito: "Uso do BTV como PDP")
- BTV ADR-0006 (Policy-as-Code — YAMLs que governam as decisões)
- BTV ADR-0017 (ContestabilityLoop — fluxo de apelação)

