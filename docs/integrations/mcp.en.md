[BuildToValue](../../README.md) › [Documentation](../README.md) › [Engineer Track](../for-engineers.md) › [Integrations](./index.md) › **MCP Server**

![Engineer](https://img.shields.io/badge/Track-Engineer-1f6feb)

<!-- audience: engineer -->

---

# MCP Server — Governance for any agent

```bash
pip install btv-mcp-server
```

BTV exposes an MCP Server (Model Context Protocol) that lets Claude Desktop,
GPT, Gemini and any MCP-compatible open-source agent use BTV as a native tool.

---

## Tools exposed

| Tool | Description |
|---|---|
| `validate_input` | Quick scan for PII, injections, and policies (Rust only) |
| `decide` | Full ethical pipeline (Rawls→Levinas→Jonas→Gilligan) |
| `submit_appeal` | Appeal a blocked verdict |
| `get_trust_score` | Trust score of the session |
| `check_compliance` | LGPD / EU AI Act compliance status |

---

## Configure in Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "buildtovalue": {
      "command": "btv-mcp",
      "env": {
        "BTV_API_KEY": "your-key-here",
        "BTV_GATEWAY_URL": "http://localhost:8080"
      }
    }
  }
}
```

Restart Claude Desktop. The BTV tools will appear automatically.

---

## Use via uv (recommended)

```json
{
  "mcpServers": {
    "buildtovalue": {
      "command": "uvx",
      "args": ["btv-mcp-server"],
      "env": {
        "BTV_API_KEY": "your-key",
        "BTV_GATEWAY_URL": "http://localhost:8080"
      }
    }
  }
}
```

---

## Usage examples in Claude

Once configured, Claude can call the tools directly:

```
User: Validate this text for me: "My CPF is 123.456.789-09"

Claude: [uses validate_input]
**Verdict**: BLOCK
**Verdict ID**: VRD-01ARZ3NDEK...
**Findings**: 1 (1 critical)
**Risk Score**: 0.88
**Hard Blocked**: False
**Contestable**: True
**Message**: CPF detected (LGPD Art. 6)
**Matched Policies**: lgpd_cpf
```

```
User: What is the trust score of session sess-user-001?

Claude: [uses get_trust_score]
**Trust Score**: 0.820 (high)
**Session**: sess-user-001
**Total Requests**: 47
**Offenses**: 1
```

---

## Run the server manually

```bash
# Via environment variables
export BTV_API_KEY=your-key
export BTV_GATEWAY_URL=http://localhost:8080
btv-mcp

# Via stdin/stdout (for integration with other MCP clients)
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | btv-mcp
```

---

## Compatibility

The server speaks JSON-RPC 2.0 over stdio — the standard MCP protocol.
Compatible with:

- Claude Desktop (Anthropic)
- Continue.dev
- Cursor
- Any open-source MCP client
- Direct subprocess integration in Python/TypeScript

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `BTV_API_KEY` | *(required)* | Gateway API key |
| `BTV_GATEWAY_URL` | `http://localhost:8080` | BTV gateway URL |

---

### Next steps / Related

- [Integrations — overview](./index.md)
- [API Reference](../api-reference.md)
- [Concepts](../concepts.md)

---

<sub>[↑ Hub](../README.md) · [Engineer Track](../for-engineers.md) · [DPO/CISO Track](../for-dpo-ciso.md) · [Reference Links](../reference-links.md)</sub>
