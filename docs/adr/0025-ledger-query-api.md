# ADR-024: Ledger Query API

**Status:** ✅ Ativo
**Data:** Fevereiro 2026
**Versão:** v2.1
**Grupo:** D — API & Observability

## Contexto

O Rust gateway grava decisões em `data/ledger/decisions.jsonl` (append-only).
Auditores (LGPD Art. 20, EU AI Act Art. 13) precisam consultar essas decisões
por sessão, período, action, ou verdict_id. Hoje não existe API para isso.

## Decisão

Implementar `LedgerReader` como módulo Python que lê o JSONL existente e expor
via `GET /v1/ledger/query` com filtros e paginação.

### Schema do JSONL (fonte: rust/gateway/src/routes/validate.rs)
```json
{
  "ts": 1739812345678,
  "session": "12345",
  "profile": "default",
  "policy_action": "BLOCK",
  "final_action": "EDUCATE",
  "mercy": true,
  "risk": 0.7500,
  "findings": 2,
  "critical": 1,
  "hard_blocked": false,
  "verdict_id": "verd_abc123",
  "latency_ms": 12.34
}
```

### Filtros suportados

| Parâmetro   | Tipo   | Descrição                    |
|:------------|:-------|:-----------------------------|
| session_id  | str    | Filtro exato por sessão      |
| verdict_id  | str    | Filtro exato por verdict     |
| action      | str    | ALLOW, EDUCATE, BLOCK, etc.  |
| start_ts    | int    | Timestamp mínimo (ms epoch)  |
| end_ts      | int    | Timestamp máximo (ms epoch)  |
| page        | int    | Página (default 1)           |
| page_size   | int    | Itens por página (10-1000)   |

### Invariantes

- Ledger é READ-ONLY para esta API (imutabilidade preservada)
- Sem índices em memória (scan linear, aceitável até ~1M linhas)
- Fail-secure: arquivo inexistente → resposta vazia, não erro 500

## Fundamento Filosófico

**Jonas (1984):** Responsabilidade exige rastreabilidade. Sem query, o ledger
é registro sem accountability — arquivo que ninguém consulta não é auditoria.

## Referências

- ADR-015 (Ledger Imutável)
- `rust/gateway/src/routes/validate.rs` (formato JSONL)