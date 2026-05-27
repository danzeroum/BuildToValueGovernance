[BuildToValue](../../README.md) › [Documentation](../README.md) › [Engineer Track](../for-engineers.md) › [Integrations](./index.md) › **Agent Rust**

![Engineer](https://img.shields.io/badge/Track-Engineer-1f6feb)

<!-- audience: engineer -->

---

```markdown
# BTV Integration Profile: AgentRust Next Gen

| Field              | Value                                        |
|:-------------------|:---------------------------------------------|
| **Standard**       | BTV ADR-0028 (External Agent PDP)            |
| **Agent version**  | AgentRust v1.0-next (Rust)                    |
| **BTV version**    | v2.0+                                        |
| **Agent-side ADR** | AgentRust ADR-024 (to be created in the OC repo) |
| **Maintainer**     | AgentRust Team                                |
| **Date**           | 2026-02-23                                   |

---

## 1. What AgentRust is

A conversational AI agent in Rust with high-impact tools: shell execution
(`exec`, `process`), file manipulation (`write`, `apply_patch`), web access
(`web_fetch`, `browser`), autonomous subagents (`sessions_spawn`), scheduling
(`cron`) and remote-node control (`nodes`). It runs on an actor model
(tokio mpsc), deterministic cancellation (CancellationToken) and a Wasm
sandbox for plugins.

---

## 2. Canonical agent_id

```
agent_id = "AgentRust-" + BLAKE3(config.instance_id + config.version)[..16]
```

Derived at startup; stable across restarts of the same instance.

---

## 3. Tools → ActionImpact mapping

| AgentRust tool            | ActionImpact   | Declared capabilities                |
|:--------------------------|:---------------|:-------------------------------------|
| `read`, `memory_search`   | Safe           | `["filesystem_read"]`                |
| `write`, `edit`           | Destructive    | `["filesystem_write"]`               |
| `apply_patch`             | Destructive    | `["filesystem_write","patch_apply"]` |
| `exec` (no escalation)    | Destructive    | `["process_exec"]`                   |
| `exec` (with escalation)  | Irreversible   | `["process_exec","privilege_esc"]`   |
| `process` (kill/signal)   | Irreversible   | `["process_signal"]`                 |
| `web_fetch`               | Destructive    | `["network_fetch"]`                  |
| `browser` (write/click)   | Irreversible   | `["browser_interact"]`               |
| `sessions_spawn`          | Irreversible   | `["subagent_spawn"]`                 |
| `cron` (register)         | Destructive    | `["scheduler_write"]`                |
| `nodes` (remote exec)     | Irreversible   | `["remote_exec"]`                    |
| `tts`, `canvas` (read-UI) | Safe           | `["ui_read"]`                        |

---

## 4. AgentRust-specific fields in the contract

### 4.1 Required agent_metadata

```json
"agent_metadata": {
  "subagent_depth": 0,
  "session_type": "interactive | background | spawned",
  "parent_session_id": "<id or null>",
  "cancellation_token_active": true
}
```

- `subagent_depth`: 0 = main session; ≥1 = subagent spawned via
  `sessions_spawn`. BTV may apply a stricter policy at greater depths.
- `parent_session_id`: present when `subagent_depth > 0`; enables ledger
  correlation.
- `cancellation_token_active`: indicates whether the session's
  CancellationToken is active (BTV records it but does not process it — for
  audit only).

### 4.2 Default profile_id and sector_id

```json
"profile_id": "autonomous-agent",
"sector_id": "general"
```

Configurable per instance via AgentRust's `config.yaml`. Agents deployed in
specific domains (e.g. healthcare) must override `sector_id` at startup.

---

## 5. Implementation of the resilience protocol

AgentRust implements ADR-0028 §5 via `BTVClientActor` (tokio mpsc):

- HTTP timeout: 5 s (configurable via `BTV_TIMEOUT_MS`).
- Circuit breaker: 3 failures → circuit open for 30 s → local BLOCK with
  `btv.circuit_open` event in the kernel ring buffer.
- Cache: `DashMap<CacheKey, CachedVerdict>` with a 5 s TTL for
  `Destructive`; TTL=0 (forbidden) for `Irreversible`.
- Fallback: any `BTVError::*` → `ToolOutcome::Blocked`.

---

## 6. Contestation flow inside AgentRust

When the agent receives `BLOCK`, the `SessionActor` surfaces to the operator:

```
[BTV] Action blocked: exec "rm -rf /tmp/build"
Reason: Destructive command in a path not allowed by policy v1.2
Contest? [y/n]: _
```

If `y`:
- AgentRust POSTs to `/v1/appeals` with the `evidence_id` and rationale.
- Records the `appeal_id` in the local log, correlated with `evidence_id`.
- The action is NOT executed while status is `pending`.
- The operator tracks it via `GET /v1/appeals/{id}` or the BTV dashboard.

---

## 7. Cross-references

- BTV ADR-0028 (canonical contract — this profile is an instance of it)
- AgentRust ADR-016 through ADR-023 (Security ADRs)
- AgentRust ADR-024 (to be written: "Using BTV as PDP")
- BTV ADR-0006 (Policy-as-Code — YAMLs that govern decisions)
- BTV ADR-0017 (ContestabilityLoop — appeal flow)

```

---

### Next steps / Related

- [Integrations — overview](./index.md)
- [API Reference](../api-reference.md)
- [Concepts](../concepts.md)

---

<sub>[↑ Hub](../README.md) · [Engineer Track](../for-engineers.md) · [DPO/CISO Track](../for-dpo-ciso.md) · [Reference Links](../reference-links.md)</sub>
