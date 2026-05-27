---
title: Mapa Operacional de YAMLs — DPO/CISO
---

# Mapa Operacional de YAMLs

Referência técnica de **cada arquivo YAML em `data/policies/`** que um DPO ou
CISO precisa entender para operar o BTV — com snippets representativos e a
chamada Rust/Python correspondente que o lê.

Esta página é o **par técnico** da [Trilha DPO / CISO](../../for-dpo-ciso.md):
ela serve para engenheiros que precisam dar suporte ao DPO/CISO sem reabrir
o código.

!!! tip "Regra de ouro"
    Toda mudança em `data/policies/` segue **Policy-as-Code** ([ADR-006](../../adr/0006-policy-as-code.md)):
    `validate_policy_schema.py` → `policy_signer.py` (Ed25519 — [ADR-064](../../adr/0064-policy-reload-ed25519.md))
    → PR → CI (`alignment_regression.yml` + `policy-blind-test.yml`) → merge manual → reload assinado.
    O kernel **nunca** aceita YAML sem assinatura verificada.

## `data/policies/default.yaml` — Comportamento base

```yaml
version: "1.0"
schema_type: "policy-rules"
governance:
  report_threshold: 0.65          # ≥ : REPORT (audita mas permite)
  report_threshold_min: 0.50      # floor de segurança
  report_threshold_max: 0.85
  report_sla_hours: 24            # SLA ADR-017
policies:
  - id: "block-valid-cpf"
    action: "BLOCK"
    ...
```

**Lido por:** `python/buildtovalue/compliance/compliance_evaluator.py`
(`load_default_policy`) e pelo kernel Rust em `rust/kernel/src/policy/loader.rs`.

**Norma:** LGPD art. 6º (finalidade, necessidade).

## `data/policies/sectors/<setor>.yaml` — Thresholds por setor

Cada arquivo é um **override** sobre `default.yaml`. Exemplos: `healthcare.yaml`,
`fintech.yaml`, `aerospace.yaml`, `government.yaml`, `education.yaml`,
`infrastructure.yaml`, `logistics.yaml`, `cold_chain.yaml`, `employment.yaml`,
`financial_hft.yaml`. O `_index.yaml` lista os perfis ativos.

```yaml
profile: "healthcare"
inherits: "default"
thresholds:
  pii_block: 0.45                 # mais estrito que default (0.55)
  hard_block_terms:
    - "exposure of patient data"
```

**Lido por:** `compliance_evaluator.load_sector_policy(sector_id)`.

**Norma:** EU AI Act Annex III (sistemas de alto risco).

## `data/policies/compliance/<norma>.yaml` — Plugin por regulação

Sete arquivos: `lgpd.yaml`, `gdpr.yaml`, `eu_ai_act.yaml`, `hipaa.yaml`,
`iso_42001.yaml`, `nist_ai_rmf.yaml`, `pci_dss.yaml`. Cada um habilita o plugin
correspondente em `python/buildtovalue/compliance/`.

```yaml
plugin: "lgpd"
jurisdiction: "BR"
articles:
  - article: 18
    behavior: "right_to_review"
  - article: 20
    behavior: "automated_decision_appeal"
```

**Lido por:** `frameworks.list_active()` →
`python/buildtovalue/compliance/{lgpd,gdpr,eu_ai_act,hipaa,iso_42001,nist_ai_rmf,pci_dss}_plugin.py`.

## `data/policies/frameworks/*_base.yaml` — Texto canônico da norma

Versão estrutural da norma para auditoria. Não muda exceto em PR
constitucional (CAP).

```yaml
framework: "GDPR"
version: "2016/679"
articles:
  - id: 5
    title: "Principles relating to processing of personal data"
    invariants: ["lawfulness", "fairness", "transparency"]
```

**Lido por:** `frameworks.canonical(framework_id)`.

## `data/policies/penalties.yaml` — Consequências regulatórias

```yaml
penalties:
  lgpd_art_52:
    severity: "fine"
    cap_brl: 50_000_000
  gdpr_art_83:
    severity: "fine"
    cap_eur_percent_of_revenue: 4
```

**Lido por:** `compliance_evaluator.estimate_penalty(violation)`.

## `data/policies/skill_revocation.yaml` — Revogação de habilidades

```yaml
revocations:
  - skill_id: "agent_send_email"
    revoked_at: "2026-05-01T00:00:00Z"
    reason: "ADR-052: unverified Merkle root"
```

**Lido por:** Rust `kernel/src/skill_registry.rs` no startup.

**Norma:** EU AI Act art. 14 (supervisão humana).

## `data/policies/chatbot-vendor-approval.yaml` — Aprovação de LLMs externos

```yaml
vendors:
  - id: "openai-gpt-4o"
    approved: true
    approval_date: "2026-04-12"
    dpia_link: "data/dpia/gpt-4o-2026-04-12.md"
  - id: "anthropic-claude-3.5-sonnet"
    approved: true
```

**Lido por:** gateway no carregamento; bloqueia chamadas a modelos não aprovados.

**Norma:** EU AI Act art. 28 (responsabilidade do fornecedor).

## `data/policies/model_registry.yaml` — Registro de modelos

```yaml
models:
  - id: "gpt-4o-2024-08-06"
    family: "gpt-4o"
    integrity_baseline: "hash-blake3:..."
    last_probed: "2026-05-26T10:00:00Z"
```

**Lido por:** ADR-051 model-integrity probes. Mudanças aqui disparam
`alignment_regression.yml` (golden suite PROP-035).

## `data/policies/webhooks.yaml` — Alertas SOC/SIEM

```yaml
webhooks:
  - id: "soc-pagerduty"
    url: "https://events.pagerduty.com/integration/abc/enqueue"
    on_event: ["sla_breach", "hard_block", "gilligan_S5"]
```

**Lido por:** `python/buildtovalue/governance/webhook_dispatcher.py`. O evento
`gilligan_S5` vem do algoritmo S1–S6 definido em [ADR-072](../../adr/0072-gilligan-sla-mercy-algorithm.md).

**Norma:** ISO 27035 (gestão de incidentes).

## `data/policies/governance_v1.yaml` — Governança geral

```yaml
governance_team:
  ethics_committee_quorum: 3
  cap_objection_window_days: 7
```

**Norma:** LGPD art. 50 (governança).

## `data/policies/evo_guard.yaml` — Guardrail evolucionário

```yaml
evo_guard:
  prompt_injection_threshold: 0.85
  jailbreak_patterns_file: "security/patterns_jailbreak.yaml"
```

**Lido por:** `python/buildtovalue/governance/agent_pdp.py` antes de qualquer
chamada de LLM. Ver também ADR-028 (heuristic prompt injection detector).

## `data/policies/security/*.yaml` — PII e segurança

Contém `patterns_jailbreak.yaml`, regras de redação, padrões de PII. Pertence
ao perímetro **CISO**.

**Norma:** LGPD art. 46 (segurança); HIPAA §164.312.

## `data/policies/agents/<agent>.yaml` — Agentes específicos

Exemplos: `medical-agent.yaml`, `pa_p2p_oracle.yaml`, `pa_privacy_geo.yaml`.
Cada arquivo define `profile_id`, `sector_id` e capabilities autorizadas.

**Norma:** EU AI Act art. 13–14 (transparência e supervisão).

## Anti-padrões a evitar

1. **Editar YAML sem assinar.** O kernel rejeita reload sem `.sig` Ed25519
   válido (ADR-064).
2. **Reduzir threshold abaixo do floor** (`report_threshold_min`). Bloqueado
   pelo `policy-blind-test.yml`.
3. **Adicionar `webhooks` para `gilligan_S5` sem rota de retorno ao
   `ContestabilityLoop`** — quebra a separação de poderes (ADR-017).
4. **Bypass do `bias_declaration`** — `validate_policy_schema.py
   --require-constitutional` falha; Painel 1 da Console força esse campo.

## Referências

- [ADR-006 — Policy-as-Code](../../adr/0006-policy-as-code.md)
- [ADR-064 — Policy Reload Ed25519](../../adr/0064-policy-reload-ed25519.md)
- [ADR-072 — Gilligan SLA Mercy Algorithm](../../adr/0072-gilligan-sla-mercy-algorithm.md)
- `scripts/validate_policy_schema.py`, `scripts/policy_signer.py`
- `.github/workflows/alignment_regression.yml`, `.github/workflows/policy-blind-test.yml`
