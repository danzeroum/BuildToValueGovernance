"""
BTV MCP Server — exposes BuildToValue governance as MCP tools.

Usage in claude_desktop_config.json:
    {
      "mcpServers": {
        "buildtovalue": {
          "command": "python",
          "args": ["-m", "btv_mcp"],
          "env": {
            "BTV_API_KEY": "your-api-key",
            "BTV_GATEWAY_URL": "http://localhost:8080"
          }
        }
      }
    }

Available tools:
  - validate_input: Fast Rust scan (PII, injection, policy)
  - decide: Full ethical governance pipeline
  - submit_appeal: Challenge a governance verdict
  - get_trust_score: Session trust score
  - check_compliance: Compliance status for text
"""
