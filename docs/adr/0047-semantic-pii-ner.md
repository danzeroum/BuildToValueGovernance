# ADR-047: Semantic PII Detection via NER (SLM-based)

**Status:** ACCEPTED
**Date:** 2026-03-20
**Deciders:** Arquitetura BTV

## Context

Os validadores de PII atuais (CPF/Mod11, CreditCard/Luhn, Email/regex, etc.)
sao puramente deterministicos. Nao detectam PII em linguagem natural:
- "moro na Rua Augusta 1200, apartamento 42, Sao Paulo"
- "meu cartao termina em 4532 e vence em 12/27"
- "me chamo Joao da Silva e meu CPF comeca com 123"

## Decision

Usar o SLM local (Phi-4 Mini, ADR-027) com prompt NER especializado
para extrair entidades PII semanticas. Zero dependencia nova — reutiliza
a mesma infra llama-cpp-python.

### Alternativas Consideradas

1. **spaCy (pt_core_news_sm)**: 5ms latencia, 15MB, boa precisao em NER
   padrao. Requer dependencia nova. Entity boundaries mais precisos.
2. **SLM com prompt NER** (escolhido): 30-50ms, zero dep nova, flexivel
   para tipos customizados (PARTIAL_CARD, HEALTH_INFO). Trade-off:
   entity boundaries menos precisos.
3. **Transformer fine-tuned**: Melhor precisao, mas requer GPU e
   pipeline de treino dedicado. Complexidade desproporcional.

### Decisao: SLM

- Reutiliza infra existente (Jonas: soberania, sem vendor dependency)
- Flexibilidade para novos entity types via prompt engineering
- Paralelo com Rust scan (nao bloqueia hot path)
- Fail-open: SLM indisponivel -> retorna lista vazia

## Entity Types

PERSON_NAME, ADDRESS, PARTIAL_CARD, PARTIAL_DOC, PHONE_NATURAL,
DATE_OF_BIRTH, HEALTH_INFO, FINANCIAL_INFO

## Consequences

- SLM faz dupla funcao: classificacao de intent + NER
- Latencia NER (~40ms) roda em paralelo com Rust (<2ms)
- Few-shot examples PT-BR sao criticos para precisao
- BiasDeclaration obrigatoria (ADR-010)
