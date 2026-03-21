# MCP Server — Governança para qualquer agente

```bash
pip install btv-mcp-server
```

O BTV expõe um MCP Server (Model Context Protocol) que permite que Claude Desktop, GPT, Gemini e qualquer agente open-source MCP-compatível use o BTV como ferramenta nativa.

---

## Ferramentas expostas

| Ferramenta | Descrição |
|---|---|
| `validate_input` | Scan rápido de PII, injections, e políticas (Rust only) |
| `decide` | Pipeline ético completo (Rawls→Levinas→Jonas→Gilligan) |
| `submit_appeal` | Contestar um verdict bloqueado |
| `get_trust_score` | Trust score da sessão |
| `check_compliance` | Status de conformidade LGPD/EU AI Act |

---

## Configurar no Claude Desktop

Adicione ao `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) ou `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "buildtovalue": {
      "command": "btv-mcp",
      "env": {
        "BTV_API_KEY": "sua-chave-aqui",
        "BTV_GATEWAY_URL": "http://localhost:8080"
      }
    }
  }
}
```

Reinicie o Claude Desktop. As ferramentas BTV aparecerão automaticamente.

---

## Usar via uv (recomendado)

```json
{
  "mcpServers": {
    "buildtovalue": {
      "command": "uvx",
      "args": ["btv-mcp-server"],
      "env": {
        "BTV_API_KEY": "sua-chave",
        "BTV_GATEWAY_URL": "http://localhost:8080"
      }
    }
  }
}
```

---

## Exemplos de uso no Claude

Uma vez configurado, o Claude pode usar as ferramentas diretamente:

```
Usuário: Valide este texto para mim: "Meu CPF é 123.456.789-09"

Claude: [usa validate_input]
**Verdict**: BLOCK
**Verdict ID**: VRD-01ARZ3NDEK...
**Findings**: 1 (1 critical)
**Risk Score**: 0.88
**Hard Blocked**: False
**Contestable**: True
**Message**: CPF detectado (LGPD Art. 6)
**Matched Policies**: lgpd_cpf
```

```
Usuário: Qual é o trust score da sessão sess-user-001?

Claude: [usa get_trust_score]
**Trust Score**: 0.820 (high)
**Session**: sess-user-001
**Total Requests**: 47
**Offenses**: 1
```

---

## Rodar o servidor manualmente

```bash
# Via variáveis de ambiente
export BTV_API_KEY=sua-chave
export BTV_GATEWAY_URL=http://localhost:8080
btv-mcp

# Via stdin/stdout (para integração com outros clientes MCP)
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | btv-mcp
```

---

## Compatibilidade

O servidor usa JSON-RPC 2.0 sobre stdio — o protocolo padrão MCP. Compatível com:

- Claude Desktop (Anthropic)
- Continue.dev
- Cursor
- Qualquer cliente MCP open-source
- Integração direta via subprocess em Python/TypeScript

---

## Variáveis de ambiente

| Variável | Padrão | Descrição |
|---|---|---|
| `BTV_API_KEY` | *(obrigatório)* | Chave de API do gateway |
| `BTV_GATEWAY_URL` | `http://localhost:8080` | URL do gateway BTV |
