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
| R12 | `policy_signer.py` inexistente bloqueia Painel 1 | Alta | Alto | **Mitigado** | `scripts/policy_signer.py` criado (Fase 0 do Governance Console) |
| R13 | `alignment_regression.yml` cobre só `model_registry.yaml` | Confirmada | Alto | **Mitigado** | `paths` expandido para `data/policies/**` + step `validate_policy_schema.py` |
| R14 | Algoritmo Gilligan S1–S6 sem ADR | Confirmada | Médio | **Mitigado** | `docs/adr/0072-gilligan-sla-mercy-algorithm.md` (+ `.en.md`) |
| R15 | UI gravar runtime sem assinatura | Baixa | Crítico | **Mitigado** | Policy Editor não tem rota para `POST /reload`; fluxo obrigatório → PR + CI + reload Ed25519 |
| R16 | Páginas EN ausentes quebram `/en/` | Média | Médio | **Mitigado** | `validate_invariants.py` agora verifica cada `.md` do nav contra par `.en.md` |
| R17 | Duplicação com `python/buildtovalue/{compliance,governance}` | Média | Médio | **Em uso** | YAML map referencia `compliance_evaluator`, `frameworks`, plugins LGPD/EU AI Act; Audit Trail referencia `document_exporter.py` |
| R18 | `data/policies/compliance/gdpr.yaml` com erro de YAML na linha ~248 | Confirmada | Médio | **Aberto** | Detectado por `validate_policy_schema.py` (Fase 0); abrir issue para corrigir antes do próximo deploy. Não bloqueia a console, mas bloqueia merges que tocam `gdpr.yaml` |

## Procedimento de revisão

A cada trimestre:

1. Reabrir cada linha **Aberto** ou **Parcial** e atualizar status.
2. Verificar se há novos riscos emergentes (cibersegurança, IA, sustentabilidade).
3. Registrar mudanças via PR — toda alteração no registro de riscos é uma
   decisão constitucional (segue o [Protocolo CAP](cap-protocol.md)).
