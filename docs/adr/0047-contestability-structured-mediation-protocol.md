# ADR-047 — Contestability: Structured Mediation Protocol

**Status:** ACCEPTED  
**Data:** 2026-03-04  
**Autor:** AI Squad (Arquiteta Opus)  
**Versão BTV alvo:** v1.6.0  
**Origem:** GT-HarmBench (ICLR 2026, arquivo 53) — game-theoretic safety benchmark  
**Relacionados:** ADR-021 (ContestabilityLoop), ADR-039 (TrustScoreCalculator)

---

## Contexto

O paper GT-HarmBench testa 5 mecanismos de design em 2.009 cenários
game-teóricos (Prisoner's Dilemma, Stag Hunt, Chicken) com 15 modelos frontier.
Resultado: apenas **62% de ações socialmente ótimas** sem intervenção.

Ganhos por mecanismo (∆ utilitarian accuracy vs baseline):

| Mecanismo | Ganho | Trade-off Nash |
|-----------|-------|----------------|
| Trusted Mediator | +18% | -6% Nash acc |
| Contracts + Penalties | +17% | -4% |
| Side Payments | +16% | -6% |
| Pre-play Communication | +14% | neutro |
| Commitment Devices | +13% | neutro |

**Achado crítico para BTV:** O mecanismo **Trusted Mediator** é o mais eficaz,
mas tem trade-off — reduz Nash accuracy (ações individualmente ótimas) para
aumentar utilitarian accuracy (ações melhores para o sistema). Isso mapeia
exatamente para o que o `MercyCalculator` já faz: recomendar `EDUCATE` em vez
de `BLOCK` quando o welfare coletivo justifica.

### Estado atual do ContestabilityLoop

`python/buildtovalue/governance/contestability_loop.py`:

```python
@dataclass
class AppealRequest:
    decision_id: str
    agent_id: str
    reason: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
```

O `AppealEngine.resolve()` aceita `status: accepted | rejected` e `resolution_notes`.

O que falta: o mediador (Reviewer Opus) não tem acesso estruturado ao
`bias_declaration_hash` original da decisão nem aos `contestation_grounds`
filosóficos — as bases formais da contestação. Sem isso, a resolução é binária
(aceitar/rejeitar) sem protocolo de mediação.

---

## Decisão

Estender `AppealRequest` com 3 campos que habilitam mediação estruturada:
`evidence_hash`, `grounds` e `mediator_recommendation`. Sem breaking changes
— campos opcionais com defaults.

---

## Implementação

### 1. Extensão do `AppealRequest`

```python
# python/buildtovalue/governance/contestability_loop.py — EXTENSÃO

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

# Grounds filosóficos permitidos (vocabulário controlado)
# Baseado nos fundamentos BTV: Rawls, Levinas, Gilligan, Jonas
VALID_GROUNDS = frozenset({
    "rawls_equity",           # decisão não passaria pelo véu de ignorância
    "levinas_protection",     # decisão falha em proteger o vulnerável
    "gilligan_mercy",         # aplicação rígida sem considerar contexto de cuidado
    "jonas_responsibility",   # decisão não considera impacto de longo prazo
    "technical_error",        # evidência forense incorreta (BLAKE3 hash)
    "scope_mismatch",         # policy aplicada fora do trust_boundary declarado
    "false_positive",         # validator disparou incorretamente
})

@dataclass
class AppealRequest:
    decision_id: str
    agent_id: str
    reason: str
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # ADR-047: Structured Mediation fields (opcionais, retrocompatível)
    evidence_hash: Optional[str] = None
    # BLAKE3 hash do TechnicalEvidence original — permite ao mediador
    # verificar que a evidência não foi alterada desde a decisão

    grounds: List[str] = field(default_factory=list)
    # Vocabulário controlado (VALID_GROUNDS).
    # Grounds inválidos são ignorados (não rejeitam o appeal).
    # Múltiplos grounds permitidos.

    mediator_recommendation: Optional[str] = None
    # Preenchido pelo Reviewer Opus durante análise, antes de resolve().
    # Valores: "accept_appeal" | "reject_appeal" | "escalate" | "educate"
    # Alimenta o MercyCalculator para decisões futuras da mesma sessão.

    def validated_grounds(self) -> List[str]:
        """Retorna apenas grounds do vocabulário controlado."""
        return [g for g in self.grounds if g in VALID_GROUNDS]
```

### 2. Extensão do `AppealEngine.resolve()`

```python
def resolve(
    self,
    appeal_id: str,
    status: str,              # "accepted" | "rejected"
    resolution_notes: str,
    mediator_recommendation: Optional[str] = None,
) -> AppealResolution:
    appeal = self._get_appeal(appeal_id)

    # Se mediator_recommendation presente, alimentar TrustScoreCalculator
    if mediator_recommendation and appeal.agent_id:
        if mediator_recommendation == "accept_appeal":
            self._trust_calculator.adjust(appeal.agent_id, delta=+0.05)
        elif mediator_recommendation == "educate":
            # Não penaliza — Gilligan: mercy sobre punição
            self._trust_calculator.adjust(appeal.agent_id, delta=0.0)
        elif mediator_recommendation == "reject_appeal":
            self._trust_calculator.adjust(appeal.agent_id, delta=-0.02)

    resolution = AppealResolution(
        appeal_id=appeal_id,
        status=status,
        resolution_notes=resolution_notes,
        mediator_recommendation=mediator_recommendation,
        validated_grounds=appeal.validated_grounds(),
        resolved_at=datetime.utcnow(),
    )
    self._ledger.record(resolution)  # imutável
    return resolution
```

### 3. Extensão do `AppealResolution`

```python
@dataclass
class AppealResolution:
    appeal_id: str
    status: str
    resolution_notes: str
    resolved_at: datetime
    mediator_recommendation: Optional[str] = None
    validated_grounds: List[str] = field(default_factory=list)
```

### 4. API — endpoint de appeal (sem breaking changes)

```python
# /v1/appeals/submit — campos novos opcionais
class AppealSubmitRequest(BaseModel):
    decision_id: str
    reason: str
    evidence_hash: Optional[str] = None  # ADR-047
    grounds: List[str] = []              # ADR-047
```

---

## Mapeamento GT-HarmBench → BTV

| Mecanismo (paper) | Implementação BTV | Status |
|-------------------|-------------------|--------|
| Trusted Mediator | Reviewer Opus com `mediator_recommendation` | ✅ este ADR |
| Commitment Devices | HMAC-SHA256 em decisões irreversíveis | ✅ existente |
| Information Asymmetry Reduction | `explain_decision()` obrigatório | ✅ existente |
| Reputation Mechanisms | `DurableLedger` imutável | ✅ existente |
| Pre-play Communication | Handoff templates AI Squad | ✅ existente |

**Nash↔Utilitarian trade-off documentado:** O mediador (Reviewer Opus) pode
recomendar `educate` em vez de `block` mesmo quando a policy diz BLOCK, se
`grounds` incluir `gilligan_mercy` e o trust_score do agente for alto.
Isso é uma redução de Nash accuracy intencional para maior welfare coletivo —
exatamente o que o MercyCalculator já faz, agora com grounds documentados.

---

## Retrocompatibilidade

- `AppealRequest` sem os 3 novos campos: funciona identicamente
- `grounds` vazio: `validated_grounds()` retorna `[]` — sem impacto
- `evidence_hash = None`: mediador trabalha sem verificação de integridade
  (menos informação, não erro)
- `mediator_recommendation = None`: `resolve()` não altera trust score

---

## Arquivos Alterados

| Arquivo | Mudança |
|---------|---------|
| `python/buildtovalue/governance/contestability_loop.py` | 3 campos em `AppealRequest` + `validated_grounds()` + `VALID_GROUNDS` |
| `python/buildtovalue/governance/contestability_loop.py` | Extensão de `AppealResolution` + `AppealEngine.resolve()` |
| `python/buildtovalue/api/app.py` | Modelo `AppealSubmitRequest` com campos opcionais |
| `python/tests/unit/governance/test_contestability.py` | 5 novos testes |

## Testes Obrigatórios

```
test_appeal_without_new_fields_backward_compat  → retrocompatibilidade
test_invalid_grounds_filtered                   → grounds fora do vocab ignorados
test_evidence_hash_stored                       → hash preservado na resolução
test_mediator_accept_adjusts_trust_score        → +0.05 ao trust
test_mediator_educate_no_penalty                → delta=0.0 (Gilligan)
```

## Estimativa

| Etapa | Tempo |
|-------|-------|
| Python (dataclasses + resolve()) | ~1.5h |
| API model update | ~20min |
| Testes | ~45min |
| Review | ~45min |

---

## Checklist de Review (Reviewer Opus)

- [ ] `VALID_GROUNDS` definido como `frozenset` (imutável)
- [ ] `validated_grounds()` não lança exceção para grounds inválidos
- [ ] `mediator_recommendation` persiste no `DurableLedger` via `AppealResolution`
- [ ] `evidence_hash` não é verificado pelo código — apenas armazenado (verificação é responsabilidade do Reviewer humano/Opus)
- [ ] `resolve()` sem `mediator_recommendation` funciona identicamente ao atual
- [ ] `adjust(delta=0.0)` não altera trust score (caso `educate`)
- [ ] Nenhum `.unwrap()` equivalente (`Optional` tratado com `if`)
- [ ] Funções ≤ 50 linhas

## O Que Está Bem Feito
*(preenchido pelo Reviewer após implementação)*

---

## Referências

- GT-HarmBench (ICLR 2026, arquivo 53): Trusted Mediator +18% welfare
- ADR-021: ContestabilityLoop original
- ADR-039: TrustScoreCalculator
- Paper 33 (AI Organizations): org_alignment_check no handoff (complementar)

---

*Fundamento filosófico (Gilligan): O protocolo de mediação estruturada é um ato
de cuidado — não basta abrir uma janela de contestação, é necessário que o
mediador tenha os instrumentos para recomendar misericórdia quando o contexto
justifica. `grounds: ["gilligan_mercy"]` não é metáfora — é um argumento
formal auditável.*
```
