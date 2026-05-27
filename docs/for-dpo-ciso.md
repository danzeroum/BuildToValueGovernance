[BuildToValue](../README.md) › [Documentação](./README.md) › **Trilha DPO / CISO**

![DPO / CISO](https://img.shields.io/badge/Trilha-DPO%20%2F%20CISO-8957e5)

<!-- audience: dpo-ciso -->

---

# Trilha DPO / CISO

Para Data Protection Officers, CISOs e equipes jurídicas. O BTV transforma cada
decisão de um agente de IA em evidência forense imutável — auditável
retroativamente e contestável dentro do SLA.

## Comece por aqui

1. **[Compliance](./compliance.md)** — como o BTV se mapeia a LGPD, EU AI Act e HIPAA.
2. **[Conceitos](./concepts.md)** — o raciocínio ético por trás de cada veredicto (a ponte para a trilha de Engenharia).
3. **[Mapa de Políticas YAML](./developer/compliance/dpo-ciso-yaml-map.md)** — onde está cada regra de negócio em `data/policies/`.
4. **[Links de Referência](./reference-links.md)** — textos regulatórios oficiais e fontes externas.

## Onde alterar o quê — mapa rápido

O BTV é **Policy-as-Code** ([ADR-006](./adr/0006-policy-as-code.md)). Você não
edita código Rust nem Python para mudar comportamento: edita YAML em
`data/policies/`. Toda mudança passa por:

1. Validação de schema (`scripts/validate_policy_schema.py`).
2. Assinatura Ed25519 da Ethics Committee ([ADR-064](./adr/0064-policy-reload-ed25519.md))
   via `scripts/policy_signer.py`.
3. PR em `data/policies/` com CI obrigatório:
   `alignment_regression.yml` + `policy-blind-test.yml`.
4. Merge manual + reload assinado no kernel.

| Intenção | Onde alterar | Norma vinculada |
|---|---|---|
| Bloqueio/permissão geral | [`data/policies/default.yaml`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/data/policies/default.yaml) | LGPD art. 6º |
| Threshold por setor | [`data/policies/sectors/<setor>.yaml`](https://github.com/danzeroum/BuildToValueGovernance/tree/main/data/policies/sectors) | EU AI Act Annex III |
| Conformidade por norma | [`data/policies/compliance/{lgpd,gdpr,eu_ai_act,hipaa,iso_42001,nist_ai_rmf,pci_dss}.yaml`](https://github.com/danzeroum/BuildToValueGovernance/tree/main/data/policies/compliance) | Norma correspondente |
| Frameworks base | [`data/policies/frameworks/*_base.yaml`](https://github.com/danzeroum/BuildToValueGovernance/tree/main/data/policies/frameworks) | Texto canônico |
| Penalidades regulatórias | [`data/policies/penalties.yaml`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/data/policies/penalties.yaml) | LGPD art. 52; GDPR art. 83 |
| Revogação de skills | [`data/policies/skill_revocation.yaml`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/data/policies/skill_revocation.yaml) | EU AI Act art. 14 |
| Aprovação de LLM externo | [`data/policies/chatbot-vendor-approval.yaml`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/data/policies/chatbot-vendor-approval.yaml) | EU AI Act art. 28 |
| Registro de modelos | [`data/policies/model_registry.yaml`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/data/policies/model_registry.yaml) | EU AI Act art. 51 |
| Alertas SOC/SIEM | [`data/policies/webhooks.yaml`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/data/policies/webhooks.yaml) | ISO 27035 |
| Governança geral | [`data/policies/governance_v1.yaml`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/data/policies/governance_v1.yaml) | LGPD art. 50 |
| Guardrail evolucionário | [`data/policies/evo_guard.yaml`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/data/policies/evo_guard.yaml) | EU AI Act art. 9 |
| PII e segurança | [`data/policies/security/`](https://github.com/danzeroum/BuildToValueGovernance/tree/main/data/policies/security) | LGPD art. 46; HIPAA §164.312 |
| Agentes específicos | [`data/policies/agents/`](https://github.com/danzeroum/BuildToValueGovernance/tree/main/data/policies/agents) | EU AI Act art. 13–14 |

> Para o detalhe técnico de **cada campo YAML** e **o que o kernel Rust executa
> a partir dele**, abra o [Mapa Operacional de YAMLs](./developer/compliance/dpo-ciso-yaml-map.md).

## Governance Console (demo)

A console DPO/CISO ([`demo/dpo-ciso/`](https://github.com/danzeroum/BuildToValueGovernance/tree/main/demo/dpo-ciso))
expõe três painéis sobre o mesmo `data/policies/`:

1. **Compliance Dashboard** — leitura ao vivo de evidências; SLA de
   contestação com cenários Gilligan S1–S6 ([ADR-072](./adr/0072-gilligan-sla-mercy-algorithm.md)).
2. **Audit Trail** — lista decisões com `explain_decision` em linguagem natural;
   exporta PDF forense com BLAKE3 + HMAC verificável via `btv-cli verify`.
3. **Policy Editor** — formulário visual que **nunca grava runtime**; gera
   YAML → assina (`policy_signer.py`) → abre PR em `data/policies/`.

## O que avaliar

| Tema | Onde |
|---|---|
| Contestabilidade (direito de apelar) | [Compliance](./compliance.md) — SLA de revisão humana |
| Evidência criptográfica imutável | [Conceitos](./concepts.md) — BLAKE3 + HMAC-SHA256 |
| Algoritmo de misericórdia S1–S6 | [ADR-072](./adr/0072-gilligan-sla-mercy-algorithm.md) |
| Modelo de billing e planos | [Pricing](../PRICING.md) |
| Textos legais (LGPD, EU AI Act, GDPR) | [Links de Referência](./reference-links.md) |

> **Nota:** esta documentação não constitui aconselhamento jurídico. Consulte seu
> DPO ou equipe jurídica para aplicabilidade ao seu contexto regulatório.

---

### Próximos passos / Relacionados

- [Mapa Operacional de YAMLs](./developer/compliance/dpo-ciso-yaml-map.md) — referência técnica
- [Compliance](./compliance.md) — FAQ de conformidade regulatória
- [Trilha Engenheiro](./for-engineers.md) — como o produto é integrado tecnicamente

---

<sub>[↑ Hub](./README.md) · [Trilha Engenheiro](./for-engineers.md) · [Trilha DPO/CISO](./for-dpo-ciso.md) · [Links de Referência](./reference-links.md)</sub>
