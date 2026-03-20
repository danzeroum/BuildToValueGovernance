# ADR-046: ML Layer para Prompt Injection Detection

**Status:** ACCEPTED
**Date:** 2026-03-20
**Deciders:** Arquitetura BTV

## Context

O detector heuristico de prompt injection (ADR-028) tem FNR de 18%.
Ataques semanticos sem keywords (ex: parafrasear instrucoes, manipulacao
contextual) passam pelo heuristico com confidence Medium (60-85%) e nao
sao encaminhados ao SLM (ADR-027), que so aciona na zona de ambiguidade
(0 findings ou <=2 non-critical).

NeMo Guardrails e Lakera usam modelos fine-tuned para cobrir este gap.

## Decision

Estender o pipeline para acionar o SLM (Phi-4 Mini) tambem quando o
heuristico retorna **Medium confidence** — a "zona cinzenta" onde o
heuristico detectou sinais mas sem certeza suficiente.

### Mudancas:

1. **SLMClassifier**: Novo metodo `classify_medium_zone(text)` com prompt
   especializado para ataques semanticos (evasion, paraphrasing, context
   manipulation). Novo `IntentLabel.EVASION_ATTEMPT`.

2. **PayloadInspector**: `_run_slm()` recebe `max_severity` do Rust e
   aciona SLM quando `max_severity == "Medium"`.

3. **Training Pipeline**: Dataset loader para OWASP LLM Top 10 + Tensor
   Trust + red-team BTV. Script de fine-tuning QLoRA. Benchmark FNR/FPR.

4. **FFI Bridge**: `PyTechnicalEvidence` expoe `max_severity` para Python.

### Principios:

- **Jonas**: Dados nunca saem do perimetro (SLM local).
- **Levinas**: SLM output e Finding, nao Verdict — humano contesta.
- **Fail-open**: SLM falha -> sistema continua sem finding SLM.
- **ADR-010**: BiasDeclaration obrigatoria com FPR/FNR medidos.

## Target Metrics

| Metric | Before | After |
|--------|--------|-------|
| FNR    | 18%    | <5%   |
| FPR    | 8%     | <10%  |
| Latency (SLM) | <50ms | <100ms |

## Consequences

- SLM sera acionado com mais frequencia (Medium zone + ambiguity zone).
- Consumo de CPU aumenta marginalmente (~2-4 cores adicionais em pico).
- Necessidade de datasets curados e pipeline de avaliacao continua.
