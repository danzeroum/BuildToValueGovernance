# Quickstart — 5 minutos

## 1. Suba o gateway

```bash
git clone https://github.com/buildtovalue/buildtovalue
cd buildtovalue/ops

# Sobe gateway (Rust) + governança (Python)
docker compose up --build
```

O gateway estará em `http://localhost:8080`. Verifique:

```bash
curl http://localhost:8080/health
# {"status":"ok","uptime_seconds":3.2}
```

## 2. Instale o SDK

=== "Python"

    ```bash
    pip install buildtovalue
    ```

=== "TypeScript / Node"

    ```bash
    npm install @buildtovalue/sdk
    ```

=== "MCP (Claude Desktop)"

    ```bash
    pip install btv-mcp-server
    ```

## 3. Faça sua primeira chamada

=== "Python"

    ```python
    from buildtovalue import BTVClient

    btv = BTVClient(
        api_key="dev-key",  # (1)
        gateway_url="http://localhost:8080",
    )

    verdict = btv.decide(
        "Meu CPF é 123.456.789-09",
        session_id="sess-user-001",   # (2)
        profile="healthcare",          # (3)
    )

    print(verdict.action)         # EDUCATE
    print(verdict.composite_risk) # 0.71
    print(verdict.contestable)    # True
    ```

    1. Configure `BTV_API_KEYS=dev-key` no gateway (já vem configurado no docker-compose local).
    2. Use um identificador opaco de sessão — nunca o ID real do usuário (LGPD Art. 5).
    3. Perfis disponíveis: `general`, `healthcare`, `finance`, `legal`, `research`, `education`.

=== "TypeScript"

    ```typescript
    import { BTVClient } from "@buildtovalue/sdk";

    const btv = new BTVClient({
      apiKey: "dev-key",
      gatewayUrl: "http://localhost:8080",
    });

    const verdict = await btv.decide("Meu CPF é 123.456.789-09", {
      sessionId: "sess-user-001",
      profile: "healthcare",
    });

    console.log(verdict.action);         // "EDUCATE"
    console.log(verdict.composite_risk); // 0.71
    console.log(verdict.contestable);    // true
    ```

=== "curl"

    ```bash
    curl -s -X POST http://localhost:8080/v1/decide \
      -H "X-API-Key: dev-key" \
      -H "Content-Type: application/json" \
      -d '{
        "input": "Meu CPF é 123.456.789-09",
        "session_id": "sess-user-001",
        "profile": "healthcare"
      }' | jq .action
    # "EDUCATE"
    ```

## 4. Entenda o verdict

```python
verdict = btv.decide("SELECT * FROM users WHERE 1=1")

verdict.action           # "BLOCK" — ação a tomar
verdict.original_action  # "BLOCK" — antes da misericórdia
verdict.mercy_applied    # False — sem misericórdia aqui
verdict.composite_risk   # 0.94 — risco agregado [0-1]
verdict.finding_count    # 2 — evidências encontradas
verdict.critical_count   # 1 — evidências críticas
verdict.hard_blocked     # True — não contestável
verdict.contestable      # False
verdict.verdict_id       # "VRD-01ARZ3NDEK..." — ID imutável para auditoria

# Rationale filosófico (só em /v1/decide, não em /v1/validate)
verdict.explain.summary           # "SQL injection detectado. Risco crítico."
verdict.explain.rawls_rationale   # "Viola política sob o véu da ignorância."
verdict.explain.levinas_rationale # "Exposição de dados de terceiros."
verdict.explain.trust_score       # 0.85
```

## 5. Lidar com um BLOCK

```python
verdict = btv.decide(input_text, session_id=session_id)

if verdict.action == "BLOCK":
    if verdict.hard_blocked:
        # Sem saída — violação absoluta (ex: termos de hard-block)
        return {"error": "Conteúdo não permitido."}

    if verdict.contestable:
        # Usuário pode contestar (LGPD Art. 20)
        appeal = btv.appeal(
            verdict.verdict_id,
            reason="Este CPF é de um dataset de teste ABNT, não é PII real.",
            grounds=["technical_error", "false_positive"],
        )
        return {
            "blocked": True,
            "appeal_id": appeal.appeal_id,
            "message": verdict.rationale,
        }
```

## 6. Context manager para sessões

Use `BTVSession` para não repetir `session_id` em cada chamada:

```python
with btv.session("sess-user-001") as session:
    v1 = session.decide("Olá, como posso ajudar?")
    v2 = session.validate("Meu email é user@example.com")
    ts = session.trust_score()  # Score atual da sessão
    print(ts.trust_score)       # 0.82
    print(ts.level)             # "high"
```

---

## Próximos passos

- [→ Conceitos: o que é a República Algorítmica?](concepts.md)
- [→ Integrar com LangChain](integrations/langchain.md)
- [→ Configurar MCP para Claude Desktop](integrations/mcp.md)
- [→ Referência completa da API](api-reference.md)
