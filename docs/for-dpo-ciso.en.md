[BuildToValue](../README.md) › [Documentation](./README.md) › **DPO / CISO Track**

![DPO / CISO](https://img.shields.io/badge/Track-DPO%20%2F%20CISO-8957e5)

<!-- audience: dpo-ciso -->

---

# DPO / CISO Track

For Data Protection Officers, CISOs and legal teams. BTV turns every AI-agent
decision into immutable forensic evidence — auditable retroactively and
contestable within the SLA.

## Start here

1. **[Compliance](./compliance.md)** — how BTV maps to LGPD, EU AI Act and HIPAA.
2. **[Concepts](./concepts.md)** — the ethical reasoning behind every verdict (the bridge to the Engineering track).
3. **[Policy YAML Map](./developer/compliance/dpo-ciso-yaml-map.md)** — where each business rule lives in `data/policies/`.
4. **[Reference Links](./reference-links.md)** — official regulatory texts and external sources.

## Where to change what — quick map

BTV is **Policy-as-Code** ([ADR-006](./adr/0006-policy-as-code.md)). You do not
edit Rust or Python code to change behavior: you edit YAML in
`data/policies/`. Every change flows through:

1. Schema validation (`scripts/validate_policy_schema.py`).
2. Ed25519 signature by the Ethics Committee ([ADR-064](./adr/0064-policy-reload-ed25519.md))
   via `scripts/policy_signer.py`.
3. PR against `data/policies/` with required CI:
   `alignment_regression.yml` + `policy-blind-test.yml`.
4. Manual merge + signed reload by the kernel.

| Intent | Where to change | Regulation |
|---|---|---|
| General allow/block | [`data/policies/default.yaml`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/data/policies/default.yaml) | LGPD art. 6 |
| Threshold per sector | [`data/policies/sectors/<sector>.yaml`](https://github.com/danzeroum/BuildToValueGovernance/tree/main/data/policies/sectors) | EU AI Act Annex III |
| Compliance per regulation | [`data/policies/compliance/{lgpd,gdpr,eu_ai_act,hipaa,iso_42001,nist_ai_rmf,pci_dss}.yaml`](https://github.com/danzeroum/BuildToValueGovernance/tree/main/data/policies/compliance) | Corresponding regulation |
| Base frameworks | [`data/policies/frameworks/*_base.yaml`](https://github.com/danzeroum/BuildToValueGovernance/tree/main/data/policies/frameworks) | Canonical text |
| Regulatory penalties | [`data/policies/penalties.yaml`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/data/policies/penalties.yaml) | LGPD art. 52; GDPR art. 83 |
| Skill revocation | [`data/policies/skill_revocation.yaml`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/data/policies/skill_revocation.yaml) | EU AI Act art. 14 |
| External LLM approval | [`data/policies/chatbot-vendor-approval.yaml`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/data/policies/chatbot-vendor-approval.yaml) | EU AI Act art. 28 |
| Model registry | [`data/policies/model_registry.yaml`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/data/policies/model_registry.yaml) | EU AI Act art. 51 |
| SOC/SIEM alerts | [`data/policies/webhooks.yaml`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/data/policies/webhooks.yaml) | ISO 27035 |
| General governance | [`data/policies/governance_v1.yaml`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/data/policies/governance_v1.yaml) | LGPD art. 50 |
| Evolutionary guardrail | [`data/policies/evo_guard.yaml`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/data/policies/evo_guard.yaml) | EU AI Act art. 9 |
| PII and security | [`data/policies/security/`](https://github.com/danzeroum/BuildToValueGovernance/tree/main/data/policies/security) | LGPD art. 46; HIPAA §164.312 |
| Specific agents | [`data/policies/agents/`](https://github.com/danzeroum/BuildToValueGovernance/tree/main/data/policies/agents) | EU AI Act art. 13–14 |

> For the technical detail of **each YAML field** and **what the Rust kernel
> does with it**, see the [Operational YAML Map](./developer/compliance/dpo-ciso-yaml-map.md).

## Governance Console (demo)

The DPO/CISO console ([`demo/dpo-ciso/`](https://github.com/danzeroum/BuildToValueGovernance/tree/main/demo/dpo-ciso))
surfaces three panels on top of the same `data/policies/`:

1. **Compliance Dashboard** — live read of evidence; appeal SLA shown via
   Gilligan S1–S6 scenarios ([ADR-072](./adr/0072-gilligan-sla-mercy-algorithm.md)).
2. **Audit Trail** — lists decisions with `explain_decision` in natural
   language; exports a forensic PDF with BLAKE3 + HMAC verifiable via
   `btv-cli verify`.
3. **Policy Editor** — visual form that **never writes to runtime**; it
   generates YAML → signs (`policy_signer.py`) → opens a PR in
   `data/policies/`.

## What to assess

| Topic | Where |
|---|---|
| Contestability (right to appeal) | [Compliance](./compliance.md) — human-review SLA |
| Immutable cryptographic evidence | [Concepts](./concepts.md) — BLAKE3 + HMAC-SHA256 |
| Mercy algorithm S1–S6 | [ADR-072](./adr/0072-gilligan-sla-mercy-algorithm.md) |
| Billing model and plans | [Pricing](../PRICING.md) |
| Legal texts (LGPD, EU AI Act, GDPR) | [Reference Links](./reference-links.md) |

> **Note:** this documentation does not constitute legal advice. Consult your
> DPO or legal team about applicability to your regulatory context.

---

### Next steps / Related

- [Operational YAML Map](./developer/compliance/dpo-ciso-yaml-map.md) — technical reference
- [Compliance](./compliance.md) — regulatory compliance FAQ
- [Engineer Track](./for-engineers.md) — how the product is integrated technically

---

<sub>[↑ Hub](./README.md) · [Engineer Track](./for-engineers.md) · [DPO/CISO Track](./for-dpo-ciso.md) · [Reference Links](./reference-links.md)</sub>
