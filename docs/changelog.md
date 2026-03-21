# Changelog

## v2.0.0 — 2026-03-20

### SDK e Developer Experience (Fase 1)

- **Python SDK** (`pip install buildtovalue`) — BTVClient, AsyncBTVClient, Pydantic v2 models, retry exponencial, BTVSession
- **TypeScript SDK** (`npm install @buildtovalue/sdk`) — zero dependências, native fetch, Node 18+/Deno/Bun
- **MCP Server** (`pip install btv-mcp-server`) — 5 ferramentas para Claude Desktop e agentes MCP
- **LangChain** (`pip install btv-langchain`) — BTVGuardrailCallback com on_llm_start + on_llm_end
- **LlamaIndex** (`pip install btv-llamaindex`) — BTVQueryEngineGuard para query engines e RAG
- **CrewAI** (`pip install btv-crewai`) — BTVCrewGuard com decorador @guard.protect
- **AutoGen** (`pip install btv-autogen`) — BTVAutoGenGuard compatível com register_reply()
- **OpenAPI spec** — spec/openapi.yaml (OpenAPI 3.0.3) com todos os endpoints
- **Playground** — Streamlit app containerizado (porta 8502, perfil Docker `playground`)
- **Documentação** — docs/ com MkDocs Material: quickstart, conceitos, integrações, compliance FAQ

### Gateway (Rust Kernel)

- Veredictos assinados com HMAC-SHA256 (`VRD-{ULID}`)
- Bitmask de jurisdições via header `X-BTV-Jurisdiction`
- Modo fail-secure quando Python judiciary indisponível
- `hard_block_term` no ValidateResponse

### Judiciário (Python)

- Pipeline Rawls→Levinas→Jonas→Gilligan completo
- Trust score multi-fatorial (5 componentes)
- Sistema de appeals com SLA 24h e mediador IA
- Métricas de SLA: `/v1/appeals/metrics`

---

## v1.x — (histórico)

Versões anteriores do gateway sem SDK público. Consulte os ADRs em `docs/adr/` para histórico de decisões de arquitetura.
