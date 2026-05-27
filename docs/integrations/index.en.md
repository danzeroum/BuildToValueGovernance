[BuildToValue](../../README.md) › [Documentation](../README.md) › [Engineer Track](../for-engineers.md) › **Integrations**

![Engineer](https://img.shields.io/badge/Track-Engineer-1f6feb)

<!-- audience: engineer -->

---

# Integrations

BTV ships plug-and-play integrations for the major AI frameworks. Each one is
installable in one line and configurable in two.

## Pick your integration

| Framework | Package | Use case |
|---|---|---|
| [Python SDK](python-sdk.md) | `pip install buildtovalue` | Direct integration in any Python app |
| [TypeScript SDK](typescript-sdk.md) | `npm install @buildtovalue/sdk` | Node.js, Deno, Bun apps |
| [LangChain](langchain.md) | `pip install btv-langchain` | Chains, agents, LLMChain |
| [LlamaIndex](llamaindex.md) | `pip install btv-llamaindex` | Query engines, RAG pipelines |
| [CrewAI](crewai.md) | `pip install btv-crewai` | Autonomous agents in a crew |
| [AutoGen](autogen.md) | `pip install btv-autogen` | Multi-agent conversations |
| [MCP Server](mcp.md) | `pip install btv-mcp-server` | Claude Desktop, any MCP agent |

## Common pattern

All integrations follow the same pattern:

```python
from buildtovalue import BTVClient  # or AsyncBTVClient

btv = BTVClient(api_key="...", gateway_url="http://localhost:8080")
```

The client is then passed to the framework-specific guard/callback. No
integration makes HTTP calls directly — everything goes through the SDK.

---

### Next steps / Related

- [Quickstart](../quickstart.md)
- [Python SDK](./python-sdk.md)
- [API Reference](../api-reference.md)

---

<sub>[↑ Hub](../README.md) · [Engineer Track](../for-engineers.md) · [DPO/CISO Track](../for-dpo-ciso.md) · [Reference Links](../reference-links.md)</sub>
