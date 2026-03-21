# ADR-048: Compliance-as-Code (Documentos Reais do Ledger)

**Status:** ACCEPTED
**Date:** 2026-03-20
**Deciders:** Arquitetura BTV

## Context

Os plugins LGPD e EU AI Act fazem self-assessment sem dados reais do ledger.
O FRIA generator usa parametros estaticos. Nao existe ROPA/RAT (Registro de
Atividades de Tratamento, LGPD Art. 37). Documentos sao apenas JSON.

Compliance officers gastam semanas preenchendo ROPA, FRIA e logs de decisoes
automatizadas manualmente. O BTV tem todos os dados no ledger — basta agregar.

## Decision

1. **LedgerAnalytics**: Agrega dados do ledger para compliance (contagens,
   distribuicao de risco, tipos de PII, periodos).

2. **ROPAGenerator**: Gera Registro de Atividades de Tratamento (LGPD Art. 37)
   preenchido com dados reais do ledger.

3. **Art20ReportGenerator**: Log de decisoes automatizadas (LGPD Art. 20)
   com verdict_id, rationale, e status de contestacao.

4. **FRIA Enhancement**: FRIAGenerator aceita LedgerAnalytics para preencher
   secoes com dados reais (risk scores, violations, PII stats).

5. **DocumentExporter**: Converte JSON para PDF via weasyprint + Jinja2.

### Principios:

- Dados nunca saem do perimetro (Jonas)
- Documentos sao deterministicos e reproduziveis
- Ledger e read-only — analytics nunca modifica
- PDF assinavel para compliance officers

## Consequences

- Compliance officers recebem documentos pre-preenchidos
- Dependencias opcionais: weasyprint, Jinja2
- LedgerReader existente e reutilizado sem modificacao
