# ADR-0050 — Multi-Run Consensus Validator

**Status:** Aceito  
**Data:** 2026-03-04  
**Refs:** PROP-032, paper 235 (ReasoningCollapse), paper 88 (BJudge)

## Problema

O EthicalContextEngine decide com base em uma única inferencia. Paper 235
demonstra reasoning collapse em LLMs: MI(X;Z) cai quando o raciocinio deriva
para templates genericos desacoplados da entrada X. Em decisoes irreversiveis
isso e inaceitavel — um collapse nao detectado pode gerar ALLOW onde BLOCK era
correto.

## Decisao

Para decisoes com  e , executar
N=3 inferencias paralelas via . Consenso exige >= 2 votos iguais.

**Regras de resultado:**
1. >= 2 votos BLOCK → BLOCK (majoritario ou unanime)
2. Divergencia (sem maioria) → ESCALATE_HUMAN (SLA 24h, Rawls)
3. Timeout 40ms → ESCALATE_HUMAN (fail-secure, Jonas)
4. Unanimidade nao-BLOCK → retorna aquela acao
5. Fast path: REVERSIBLE ou confidence >= 0.75 → juiz unico (<10ms)

## Invariantes

- N=3 fixo — nao configuravel em runtime
- Hard-cap 40ms via 
- Timeout → ESCALATE_HUMAN (nunca ALLOW)
- explain_decision obrigatorio com todos os rollouts (Levinas)
- HMAC-SHA256 na ConsensusDecision (Jonas)
- Aplicavel exclusivamente ao path Irreversible

## Filosofia

- **Rawls (Veu da Ignorancia):** decisao irreversivel exige processo robusto
  independente de quem e afetado.
- **Jonas (Responsabilidade):** impacto irreversivel exige proporcionalidade
  — N=3 e o minimo verificavel sem explosao de latencia.
- **Levinas (Alteridade):** cada rollout visivel no explain_decision.

## Consequencias

- Latencia adicional: apenas no path Irreversible/low-confidence (~5% das decisoes)
- Nova acao:  adicionada em types.py
- Nova metrica: , 
- Dependencia: asyncio (ja presente via FastAPI)

## Rejeicoes

- N configuravel: rejeitado — cria superfice de ataque e dificulta auditoria
- RAFT/quorum de nos: fora de escopo (PROP-032 e sobre inferencias, nao replicacao)
- Fallback ALLOW em timeout: rejeitado — viola fail-secure (ADR-0001)
