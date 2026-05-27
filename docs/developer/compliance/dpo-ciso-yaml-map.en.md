---
title: Operational YAML Map — DPO/CISO
---

# Operational YAML Map

Technical reference for **every YAML file in `data/policies/`** a DPO or
CISO needs to understand to operate BTV — with representative snippets and
the Rust/Python entry point that reads them.

This page is the **technical pair** of the [DPO / CISO Track](../../for-dpo-ciso.md):
it serves engineers supporting the DPO/CISO without reopening the code.

!!! tip "Golden rule"
    Every change in `data/policies/` follows **Policy-as-Code** ([ADR-006](../../adr/0006-policy-as-code.md)):
    `validate_policy_schema.py` → `policy_signer.py` (Ed25519 — [ADR-064](../../adr/0064-policy-reload-ed25519.md))
    → PR → CI (`alignment_regression.yml` + `policy-blind-test.yml`) → manual merge → signed reload.
    The kernel **never** accepts YAML without a verified signature.

## `data/policies/default.yaml` — Base behavior

```yaml
version: "1.0"
schema_type: "policy-rules"
governance:
  report_threshold: 0.65          # ≥ : REPORT (audits but allows)
  report_threshold_min: 0.50      # safety floor
  report_threshold_max: 0.85
  report_sla_hours: 24            # ADR-017 SLA
policies:
  - id: "block-valid-cpf"
    action: "BLOCK"
    ...
```

**Read by:** `python/buildtovalue/compliance/compliance_evaluator.py`
(`load_default_policy`) and the Rust kernel in `rust/kernel/src/policy/loader.rs`.

**Regulation:** LGPD art. 6 (purpose and necessity).

## `data/policies/sectors/<sector>.yaml` — Per-sector thresholds

Each file is an **override** on top of `default.yaml`. Examples:
`healthcare.yaml`, `fintech.yaml`, `aerospace.yaml`, `government.yaml`,
`education.yaml`, `infrastructure.yaml`, `logistics.yaml`, `cold_chain.yaml`,
`employment.yaml`, `financial_hft.yaml`. `_index.yaml` lists the active profiles.

```yaml
profile: "healthcare"
inherits: "default"
thresholds:
  pii_block: 0.45                 # stricter than default (0.55)
  hard_block_terms:
    - "exposure of patient data"
```

**Read by:** `compliance_evaluator.load_sector_policy(sector_id)`.

**Regulation:** EU AI Act Annex III (high-risk systems).

## `data/policies/compliance/<regulation>.yaml` — Plugin per regulation

Seven files: `lgpd.yaml`, `gdpr.yaml`, `eu_ai_act.yaml`, `hipaa.yaml`,
`iso_42001.yaml`, `nist_ai_rmf.yaml`, `pci_dss.yaml`. Each enables the
matching plugin under `python/buildtovalue/compliance/`.

```yaml
plugin: "lgpd"
jurisdiction: "BR"
articles:
  - article: 18
    behavior: "right_to_review"
  - article: 20
    behavior: "automated_decision_appeal"
```

**Read by:** `frameworks.list_active()` →
`python/buildtovalue/compliance/{lgpd,gdpr,eu_ai_act,hipaa,iso_42001,nist_ai_rmf,pci_dss}_plugin.py`.

## `data/policies/frameworks/*_base.yaml` — Canonical text of the regulation

A structural form of the regulation for audit. Does not change except in a
constitutional PR (CAP).

```yaml
framework: "GDPR"
version: "2016/679"
articles:
  - id: 5
    title: "Principles relating to processing of personal data"
    invariants: ["lawfulness", "fairness", "transparency"]
```

**Read by:** `frameworks.canonical(framework_id)`.

## `data/policies/penalties.yaml` — Regulatory penalties

```yaml
penalties:
  lgpd_art_52:
    severity: "fine"
    cap_brl: 50_000_000
  gdpr_art_83:
    severity: "fine"
    cap_eur_percent_of_revenue: 4
```

**Read by:** `compliance_evaluator.estimate_penalty(violation)`.

## `data/policies/skill_revocation.yaml` — Skill revocation

```yaml
revocations:
  - skill_id: "agent_send_email"
    revoked_at: "2026-05-01T00:00:00Z"
    reason: "ADR-052: unverified Merkle root"
```

**Read by:** Rust `kernel/src/skill_registry.rs` at startup.

**Regulation:** EU AI Act art. 14 (human oversight).

## `data/policies/chatbot-vendor-approval.yaml` — External LLM approval

```yaml
vendors:
  - id: "openai-gpt-4o"
    approved: true
    approval_date: "2026-04-12"
    dpia_link: "data/dpia/gpt-4o-2026-04-12.md"
  - id: "anthropic-claude-3.5-sonnet"
    approved: true
```

**Read by:** the gateway at load time; blocks calls to unapproved models.

**Regulation:** EU AI Act art. 28 (vendor responsibility).

## `data/policies/model_registry.yaml` — Model registry

```yaml
models:
  - id: "gpt-4o-2024-08-06"
    family: "gpt-4o"
    integrity_baseline: "hash-blake3:..."
    last_probed: "2026-05-26T10:00:00Z"
```

**Read by:** ADR-051 model-integrity probes. Changes here trigger
`alignment_regression.yml` (PROP-035 golden suite).

## `data/policies/webhooks.yaml` — SOC/SIEM alerts

```yaml
webhooks:
  - id: "soc-pagerduty"
    url: "https://events.pagerduty.com/integration/abc/enqueue"
    on_event: ["sla_breach", "hard_block", "gilligan_S5"]
```

**Read by:** `python/buildtovalue/governance/webhook_dispatcher.py`. The
`gilligan_S5` event comes from the S1–S6 algorithm defined in
[ADR-072](../../adr/0072-gilligan-sla-mercy-algorithm.md).

**Regulation:** ISO 27035 (incident management).

## `data/policies/governance_v1.yaml` — General governance

```yaml
governance_team:
  ethics_committee_quorum: 3
  cap_objection_window_days: 7
```

**Regulation:** LGPD art. 50 (governance).

## `data/policies/evo_guard.yaml` — Evolutionary guardrail

```yaml
evo_guard:
  prompt_injection_threshold: 0.85
  jailbreak_patterns_file: "security/patterns_jailbreak.yaml"
```

**Read by:** `python/buildtovalue/governance/agent_pdp.py` before any LLM
call. See also ADR-028 (heuristic prompt injection detector).

## `data/policies/security/*.yaml` — PII and security

Contains `patterns_jailbreak.yaml`, redaction rules, PII patterns. Falls
under the **CISO** perimeter.

**Regulation:** LGPD art. 46 (security); HIPAA §164.312.

## `data/policies/agents/<agent>.yaml` — Specific agents

Examples: `medical-agent.yaml`, `pa_p2p_oracle.yaml`, `pa_privacy_geo.yaml`.
Each file defines `profile_id`, `sector_id` and authorized capabilities.

**Regulation:** EU AI Act art. 13–14 (transparency and oversight).

## Anti-patterns to avoid

1. **Editing YAML without signing.** The kernel rejects reload without a
   valid Ed25519 `.sig` (ADR-064).
2. **Lowering threshold below the floor** (`report_threshold_min`). Blocked
   by `policy-blind-test.yml`.
3. **Adding `webhooks` for `gilligan_S5` without a return path to the
   `ContestabilityLoop`** — breaks the separation of powers (ADR-017).
4. **Bypassing `bias_declaration`** — `validate_policy_schema.py
   --require-constitutional` fails; Console Panel 1 enforces this field.

## References

- [ADR-006 — Policy-as-Code](../../adr/0006-policy-as-code.md)
- [ADR-064 — Policy Reload Ed25519](../../adr/0064-policy-reload-ed25519.md)
- [ADR-072 — Gilligan SLA Mercy Algorithm](../../adr/0072-gilligan-sla-mercy-algorithm.md)
- `scripts/validate_policy_schema.py`, `scripts/policy_signer.py`
- `.github/workflows/alignment_regression.yml`, `.github/workflows/policy-blind-test.yml`
