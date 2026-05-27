---
title: Registro de Riscos do Portal
---

# Registro de Riscos do Portal do Desenvolvedor

Revisão trimestral. Responsável: mantenedores do repositório.

| # | Risco | Prob. | Impacto | Status | Mitigação atual |
| --- | --- | --- | --- | --- | --- |
| R1 | Divergência de bytes entre código e doc | Média | Alto | **Mitigado** | `scripts/autogen_reference.py` fail-secure; `validate_invariants.py` no CI |
| R2 | `--feature test-env` / `/debug/time-drift` inexistentes | Alta | Médio | **Aberto** | Playground usa mock client-side com badge `[SIMULAÇÃO DIDÁTICA]`; implementação no kernel pendente |
| R3 | Duplicação `docs/adr/` vs `docs/adrs/` | Confirmada | Baixo | **Mitigado** | Consolidado na Fase 0; `docs/adrs/README.md` é redirect |
| R4 | Sincronia emulador Docker ↔ kernel | Média | Alto | **Parcial** | Dockerfile usa `Cargo.lock`; tag = git SHA via `make emulator-up` |
| R5 | Drift visual entre playground e `demo/` | Baixa | Médio | **Mitigado** | `demo/playground/` reusa `demo/css/btv.css` |
| R6 | Resistência de contribuidores às trilhas | Baixa | Médio | **Mitigado** | `CONTRIBUTING.md` único, três trilhas explícitas |
| R7 | Riscos emergentes (IA, privacidade) | Média | Médio | **Aberto** | Revisão trimestral neste registro |
| R8 | Ambiguidade ADR-0047/0067 | Confirmada | Médio | **Aberto** | Mapeamento canônico em [`concepts/contestability-loop.md`](concepts/contestability-loop.md); issue #150 |
| R9 | `autogen_reference.py` como vetor de injeção | Baixa | Crítico | **Mitigado** | Workflow `.github/workflows/docs.yml` com permissions mínimas; sem credenciais HMAC/Ledger |
| R10 | Mock `time-drift` induz falsa percepção | Alta | Médio | **Mitigado** | Badge inamovível no playground |
| R11 | `reference/index.md` gerado em `main` | Média | Baixo | **Mitigado** | `docs/developer/reference/.gitignore` |

## Procedimento de revisão

A cada trimestre:

1. Reabrir cada linha **Aberto** ou **Parcial** e atualizar status.
2. Verificar se há novos riscos emergentes (cibersegurança, IA, sustentabilidade).
3. Registrar mudanças via PR — toda alteração no registro de riscos é uma
   decisão constitucional (segue o [Protocolo CAP](cap-protocol.md)).
