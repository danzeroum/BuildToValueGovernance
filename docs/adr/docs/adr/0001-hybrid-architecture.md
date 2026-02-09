# ADR-001: Hybrid Architecture (Rust + Python)

**Status**: ✅ APROVADO — EMENDADO v3.0  
**Data Original**: Outubro 2025 (fundação do projeto)  
**Emenda v3.0**: 08 fev 2026  
**Autores**: Daniel Camargo  
**Revisores**: Ethical Committee

## Contexto

Nenhuma linguagem satisfaz ambos os requisitos simultaneamente: validação determinística de alta performance e julgamento ético contextual. C++ oferece velocidade mas não segurança de memória. Python oferece flexibilidade semântica mas não previsibilidade de latência.

## Decisão

Separar responsabilidades em dois hemisférios linguísticos:

- **Rust (Executor de Fatos)**: Validators, evidence generation, hashing, ledger WAL. Determinístico, zero-heap no hot path, fail-secure.
- **Python (Juiz de Valores)**: EthicalContextEngine, MercyCalculator, ProfileManager, TrustScore. Contextual, adaptativo, explicável.

## Fundamento Filosófico

- **Rawls**: Fatos (Rust) são objetivos e cegos a contexto — Véu da Ignorância. Julgamentos (Python) interpretam fatos com equidade.
- **Gilligan**: Python permite ética do cuidado — mesmo CPF pode ser permitido ou bloqueado dependendo de quem, por quê e quando.

## Emenda v3.0 — IPC Strategy

A comunicação entre hemisférios mudou de gRPC/Protobuf para chamadas in-process:

| Aspecto | v1.0–v2.2 | v3.0 |
|---------|-----------|------|
| Bridge | FFI C + Protobuf batch | PyO3 0.28 `Python::attach()` |
| Latência inter-módulo | 2–5ms (serialização + rede) | < 0.1ms (memória compartilhada) |
| Tipo de deployment | Processos separados | Processo único (monolito modular) |
| Vetor de ataque | Superfície de rede interna | Eliminada — sem porta interna |

O princípio da separação de responsabilidades permanece intacto. Rust continua não sabendo o que é "Artigo 5 do EU AI Act"; ele só produz `TechnicalEvidence`. Python continua não alocando memória no hot path; ele só interpreta evidências.

## Consequências

- Latência end-to-end: < 50ms p99 (Rust < 30ms + Python < 10ms)
- Dois build systems (Cargo + pip/poetry) no mesmo workspace
- Requer PyO3 para bridge (dependency crítica)

## Métricas de Validação

- Rust hot path: 5.8ms p99 (benchmarks Criterion)
- Python governance: 3.2ms p99 (pytest-benchmark)
- Separação de código: 0 imports Python em Rust, 0 unsafe em Python

---
