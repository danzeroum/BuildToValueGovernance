---
title: Guia de Dimensionamento Econômico
---

# Guia de Dimensionamento Econômico

Quando vale a pena adotar o BuildToValue? Esta página é honesta sobre custos,
benefícios e **débitos técnicos ativos**.

## Quando o BTV é justificável

- Fluxos com **exposição regulatória** (LGPD, HIPAA, GDPR) onde uma única
  violação custa mais que o overhead de evidência.
- Domínios onde **rastreabilidade da decisão de IA** é exigida (financeiro,
  saúde, RH).
- Operações onde **contestação do usuário final** precisa de SLA garantido.

## Quando não é justificável (ainda)

- Fluxos puramente cosméticos (ex.: sugestão de emojis).
- Cargas onde a latência adicional do ledger é proibitiva e não há
  exposição regulatória.

## Débitos Técnicos Ativos

!!! danger "Transparência radical"
    Listamos aqui as falhas conhecidas **antes** que você decida adotar. Um
    desenvolvedor que dimensiona sua integração com base em benchmarks deve
    saber dos comportamentos inesperados nos fluxos abaixo.

| ID | Área | Status | Impacto |
| --- | --- | --- | --- |
| **DT-004** | Fluxos de Mercy e Compliance | 4 falhas E2E ativas | Cenários de borda no `MercyAlgorithm` ([ADR-0003](../../adr/0003-mercy-algorithm.md)) e no pipeline de compliance podem retornar `INDETERMINATE` quando o esperado seria `ALLOW`/`BLOCK`. Não há perda de auditabilidade; há perda de determinismo. |
| **#150** | ADRs | Conflito de numeração | `ADR-0047` aponta para dois documentos distintos; mirror `ADR-0067` aguarda decisão. Mapeamento canônico: ver [contestability-loop](../concepts/contestability-loop.md). |

## Métricas de referência

A coleta de métricas vive em
[`benchmarks/`](https://github.com/danzeroum/BuildToValueGovernance/tree/main/benchmarks).
Para reproduzir: `make benchmark`.

## Mapa regulatório

Ver [`regulatory-map.md`](regulatory-map.md).
