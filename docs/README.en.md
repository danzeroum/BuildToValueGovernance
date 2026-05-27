[BuildToValue](../README.md) › **Documentation**

![Engineer](https://img.shields.io/badge/Track-Engineer-1f6feb) ![DPO / CISO](https://img.shields.io/badge/Track-DPO%20%2F%20CISO-8957e5)

<!-- audience: both -->

---

# BuildToValue Documentation

Governance gateway for AI agents — cryptographic evidence, LGPD / GDPR /
EU AI Act compliance, contestable decisions.

This documentation is organized into **two tracks**. Pick yours:

|  |  |
|---|---|
| 🛠️ **[Engineer Track →](./for-engineers.md)** | Quickstart, API, integrations, architecture, ADRs. For CTOs, Heads of AI Platform, developers. |
| 🛡️ **[DPO / CISO Track →](./for-dpo-ciso.md)** | Compliance, contestability, regulatory references, pricing. For DPOs, CISOs, legal. |

> The **[Concepts](./concepts.md)** page is the bridge between both tracks —
> recommended for both audiences.

---

## Documentation map

```mermaid
graph TD
  HUB([Documentation])

  HUB --> ENG[Engineer Track]
  HUB --> DPO[DPO / CISO Track]
  HUB --> CONC[Concepts]
  HUB --> INT2[Contributors / Internal]

  ENG --> QS[Quickstart]
  ENG --> API[API Reference]
  ENG --> INT[Integrations]
  ENG --> ARCH[Architecture]
  ENG --> ADR[ADRs]

  DPO --> COMP[Compliance]
  DPO --> REF[Reference Links]
  DPO --> PRICE[Pricing]

  QS --> API
  API --> CONC
  INT --> API
  ARCH --> ADR
  ADR --> CONC
  COMP --> CONC
  COMP --> REF
  CONC --> COMP
  PRICE --> QS

  click ENG "https://github.com/danzeroum/BuildToValueGovernance/blob/main/docs/for-engineers.md" "Engineer Track"
  click DPO "https://github.com/danzeroum/BuildToValueGovernance/blob/main/docs/for-dpo-ciso.md" "DPO / CISO Track"
  click CONC "https://github.com/danzeroum/BuildToValueGovernance/blob/main/docs/concepts.md" "Concepts"
  click INT2 "https://github.com/danzeroum/BuildToValueGovernance/blob/main/docs/PROJECT_CONTEXT.md" "Contributors / Internal"
  click QS "https://github.com/danzeroum/BuildToValueGovernance/blob/main/docs/quickstart.md" "Quickstart"
  click API "https://github.com/danzeroum/BuildToValueGovernance/blob/main/docs/api-reference.md" "API Reference"
  click INT "https://github.com/danzeroum/BuildToValueGovernance/blob/main/docs/integrations/index.md" "Integrations"
  click ARCH "https://github.com/danzeroum/BuildToValueGovernance/blob/main/docs/ARCHITECTURE_ATLAS.md" "Architecture (Atlas)"
  click ADR "https://github.com/danzeroum/BuildToValueGovernance/blob/main/docs/adr/0000-adr-index.md" "ADR Index"
  click COMP "https://github.com/danzeroum/BuildToValueGovernance/blob/main/docs/compliance.md" "Compliance"
  click REF "https://github.com/danzeroum/BuildToValueGovernance/blob/main/docs/reference-links.md" "Reference Links"
  click PRICE "https://github.com/danzeroum/BuildToValueGovernance/blob/main/PRICING.md" "Pricing"
```

Click any box of the graph to open the corresponding document. The index
below is the text alternative, with descriptions. **Concepts** is the bridge
node: reachable from `API Reference` and from `Compliance`.

---

## Full index

### 🛠️ Engineer Track

| Document | Description |
|---|---|
| [Quickstart](./quickstart.md) | Install and make the first governed call. |
| [API Reference](./api-reference.md) | All gateway endpoints. |
| [Integrations](./integrations/index.md) | LangChain, LlamaIndex, CrewAI, AutoGen, MCP, SDKs. |
| [Architecture (Atlas)](./ARCHITECTURE_ATLAS.md) | Architecture view and v1.0 → v3.0 roadmap. |
| [ADR Index](./adr/0000-adr-index.md) | Every recorded architecture decision. |

### 🛡️ DPO / CISO Track

| Document | Description |
|---|---|
| [Compliance](./compliance.md) | LGPD, EU AI Act, HIPAA — compliance FAQ. |
| [Reference Links](./reference-links.md) | Internal links and official regulatory texts. |
| [Pricing](../PRICING.md) | Plans and billing model. |

### 🔗 Shared (both audiences)

| Document | Description |
|---|---|
| [Concepts](./concepts.md) | The Algorithmic Republic — how BTV decides. |
| [Changelog](./changelog.md) | Release notes. |
| [Project overview](../README.md) | Root README of the repository. |

### 🔒 Contributors / Internal

Documents aimed at the development squad — technical jargon, not part of the
public tracks.

| Document | Description |
|---|---|
| [Project Context](./PROJECT_CONTEXT.md) | Technical context for the development squad. |
| [Handoff Templates](./HANDOFF_TEMPLATES.md) | Architect → dev handoff templates. |
| [Release Gates](./RELEASE_GATES.md) | Release-gate checklist. |
| [Research Gaps v3](./RESEARCH_GAPS_v3.md) | Literature review and research gaps. |
| [File structure](./estruturaArquivos/data.md) | Map of the repository file tree. |
| [Reserved metadata layout](./adr/reserved_metadata_layout.md) | Reserved metadata layout — **not** the ADR set (see `docs/adr/`). |
| `roadmap.html` | Visual roadmap (HTML file, opens as raw). |

---

## Why BTV is different

|  | BTV | Generic guardrails | Manual filtering |
|---|---|---|---|
| **PII detection (LGPD)** | ✅ Native | ⚠️ Partial | ❌ You implement it |
| **Ethical reasoning** | ✅ Rawls / Levinas / Jonas / Gilligan | ❌ | ❌ |
| **Contestability** | ✅ LGPD Art. 20 + EU AI Act Art. 14 | ❌ | ❌ |
| **Per-session trust score** | ✅ Multi-factor | ❌ | ❌ |
| **HMAC-signed verdict** | ✅ Immutable | ❌ | ❌ |
| **Setup** | 5 min | Days | Weeks |

---

<sub>[🛠️ Engineer Track](./for-engineers.md) · [🛡️ DPO/CISO Track](./for-dpo-ciso.md) · [🔗 Reference Links](./reference-links.md) · [Concepts](./concepts.md)</sub>
