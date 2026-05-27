[BuildToValue](../README.md) › [Documentation](./README.md) › **Changelog**

![Engineer](https://img.shields.io/badge/Track-Engineer-1f6feb) ![DPO / CISO](https://img.shields.io/badge/Track-DPO%20%2F%20CISO-8957e5)

<!-- audience: both -->

---

# Changelog

## v2.0.0 — 2026-03-20

### SDK and Developer Experience (Phase 1)

- **Python SDK** (`pip install buildtovalue`) — BTVClient, AsyncBTVClient, Pydantic v2 models, exponential retry, BTVSession
- **TypeScript SDK** (`npm install @buildtovalue/sdk`) — zero dependencies, native fetch, Node 18+/Deno/Bun
- **MCP Server** (`pip install btv-mcp-server`) — 5 tools for Claude Desktop and MCP-compatible agents
- **LangChain** (`pip install btv-langchain`) — BTVGuardrailCallback with on_llm_start + on_llm_end
- **LlamaIndex** (`pip install btv-llamaindex`) — BTVQueryEngineGuard for query engines and RAG
- **CrewAI** (`pip install btv-crewai`) — BTVCrewGuard with @guard.protect decorator
- **AutoGen** (`pip install btv-autogen`) — BTVAutoGenGuard compatible with register_reply()
- **OpenAPI spec** — spec/openapi.yaml (OpenAPI 3.0.3) covering every endpoint
- **Playground** — containerized Streamlit app (port 8502, Docker profile `playground`)
- **Documentation** — docs/ powered by MkDocs Material: quickstart, concepts, integrations, compliance FAQ

### Gateway (Rust Kernel)

- Verdicts signed with HMAC-SHA256 (`VRD-{ULID}`)
- Jurisdiction bitmask via `X-BTV-Jurisdiction` header
- Fail-secure mode when the Python judiciary is unavailable
- `hard_block_term` added to ValidateResponse

### Judiciary (Python)

- Full Rawls→Levinas→Jonas→Gilligan pipeline
- Multi-factor trust score (5 components)
- Appeals system with 24h SLA and AI mediator
- SLA metrics: `/v1/appeals/metrics`

---

## v1.x — (historical)

Earlier gateway releases without a public SDK. See the ADRs under `docs/adr/`
for the history of architecture decisions.

---

### Next steps / Related

- [Architecture (Atlas)](./ARCHITECTURE_ATLAS.md)
- [API Reference](./api-reference.md)
- [ADR Index](./adr/0000-adr-index.md)

---

<sub>[↑ Hub](./README.md) · [Engineer Track](./for-engineers.md) · [DPO/CISO Track](./for-dpo-ciso.md) · [Reference Links](./reference-links.md)</sub>
