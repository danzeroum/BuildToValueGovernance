# Runbooks Operacionais — BuildToValue (BTV)

Este diretório contém os runbooks operacionais do ecossistema BTV v4.0, estruturados sob as premissas de rigor operacional da República Algorítmica.

## Índice de Runbooks

| ID | Título | Escopo | Status |
|---|---|---|---|
| **BTV-RUN-008** | Retenção, Custódia e Cripto-Shredding | Kernel Rust + Adaptadores JVM | ✅ Ativo v1.0.0 |
| **BTV-RUN-009** | _(reservado — a publicar)_ | — | 🔲 Pendente |
| **BTV-RUN-010** | Resposta a Incidentes E120 (Poluição Cross-Tenant) | Fronteira FFI + Isolamento Multi-Tenant | ✅ Ativo v1.0.0 |

## Convenções

- **Nomenclatura:** `BTV-RUN-NNN.md` onde NNN é sequencial a partir de 008.
- **Classificação:** Todos os runbooks são `Confidencial / Restrito` por padrão.
- **Accountability:** O DPO é o Accountable (A) em todos os procedimentos de governança regulatória.
- **Rollback:** Cada procedimento deve declarar explicitamente se possui rollback e qual é o critério.
- **Encerramento:** Todo incidente deve ter critérios de encerramento mensuráveis e assinatura do DPO para prestação de contas à ANPD.

## Relacionamentos com ADRs

```
BTV-RUN-008 ← ADR-0004 (Ledger Imutável)
             ← ADR-0005 (Evidence Protocol v2, 9596 bytes)
             ← ADR-0064 (Policy Reload Ed25519)

BTV-RUN-010 ← ADR-0009 (Modular Monolith)
             ← ADR-0017 (Contestability Loop, SLA 24h)
             ← ADR-0042 (Policy-as-Code v2)
             → BTV-RUN-008 (Procedimento B: TEK rotation)
```

_Mantido pelo AI Squad (Arquiteta) — última atualização: 2026-05-27_
