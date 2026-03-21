# Integrações

O BTV oferece integrações plug-and-play para os principais frameworks de IA. Cada uma é instalável com uma linha e configurável com duas.

## Escolha sua integração

| Framework | Pacote | Caso de uso |
|---|---|---|
| [Python SDK](python-sdk.md) | `pip install buildtovalue` | Integração direta em qualquer app Python |
| [TypeScript SDK](typescript-sdk.md) | `npm install @buildtovalue/sdk` | Apps Node.js, Deno, Bun |
| [LangChain](langchain.md) | `pip install btv-langchain` | Chains, agents, LLMChain |
| [LlamaIndex](llamaindex.md) | `pip install btv-llamaindex` | Query engines, RAG pipelines |
| [CrewAI](crewai.md) | `pip install btv-crewai` | Agentes autônomos em equipe |
| [AutoGen](autogen.md) | `pip install btv-autogen` | Conversas multi-agente |
| [MCP Server](mcp.md) | `pip install btv-mcp-server` | Claude Desktop, qualquer agente MCP |

## Padrão comum

Todas as integrações seguem o mesmo padrão:

```python
from buildtovalue import BTVClient  # ou AsyncBTVClient

btv = BTVClient(api_key="...", gateway_url="http://localhost:8080")
```

O cliente é depois passado para o guard/callback específico do framework. Nenhuma integração faz chamadas HTTP diretamente — tudo passa pelo SDK.
