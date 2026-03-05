# ADR-0049 — CoT Opacity Controlled (PROP-037)

**Status:** APROVADO
**Data:** 2026-03-04
**Autores:** Arquiteta (design), Dev Python (implementação)
**Desbloqueio:** PROP-037 PersuasionGuard
**Refs:** paper 209 (Persuasion_Attacks, ICLR 2026), ADR-0027 (Local SLM Strategy)
**ADRs relacionados:** ADR-0010 (BiasDeclaration), ADR-0038 (EthicalContextEngine v4)

---

## Contexto

O `EthicalContextEngine` acessa o Chain-of-Thought (CoT) do agente para julgamento —
exatamente o vetor de ataque demonstrado no paper 209. O princípio de **Transparência
Radical** do BTV (explain_decision obrigatório, CoT auditável) é, sem proteção adicional,
uma superfície de ataque estrutural explorável por adversários sofisticados.

**Evidência empírica (paper 209 — Persuasion_Attacks):**
- Acesso ao CoT: aprovação de ações maliciosas +9.5% vs. apenas justificativa
- Fact-checking com modelo de **família arquitetural diferente**: reduz aprovação
  maliciosa em até 45%
- Fact-checking com **mesmo modelo** do monitor: apenas -8% — família diferente é
  **requisito arquitetural**, não otimização

**Paradoxo a resolver:**
Transparência Radical é um invariante filosófico do BTV (Levinas). Reduzir transparência
para aumentar segurança violaria o contrato com o usuário. Este ADR resolve o paradoxo:
separando **CoT auditável** (preservado no Ledger) de **CoT como vetor de julgamento**
(anotado antes do uso pelo EthicalContextEngine).

---

## Decisões

### D1 — Definição formal de "família arquitetural diferente"

**Decisão:** Dois modelos são de famílias arquiteturais diferentes se e somente se
possuem `model_family` distintos em `BiasDeclaration`. Validação: comparação
case-insensitive do prefixo normalizado até o primeiro hífen ou ponto.

```python
# python/buildtovalue/core/bias_declaration.py
@dataclass(frozen=True)
class BiasDeclaration:
    model_id:             str   # identificador do modelo agente
    model_family:         str   # ex: "llama3", "mistral", "qwen2"
    checker_model_id:     str   # identificador do checker
    checker_model_family: str   # DEVE diferir de model_family
    declared_at_iso:      str
    # campos existentes preservados
```

**Exemplos:**
- agente: `"llama3"`, checker: `"qwen2"`   → ✅ famílias diferentes
- agente: `"mistral"`, checker: `"mistral-v2"` → ❌ mesmo prefixo normalizado

**Justificativa:** Paper 209: mesmo modelo com versão diferente partilha vieses de
treinamento — eficácia da defesa cai para apenas -8%. Família distinta é o mínimo
com suporte empírico.

### D2 — Validação obrigatória em startup

**Decisão:** `EthicalContextEngine` valida `checker_model_family != model_family` na
inicialização. Startup falha com erro explícito se a condição não for satisfeita.

```python
class EthicalContextEngine:
    def __init__(self, signing_key: bytes, bias_declaration: BiasDeclaration) -> None:
        if not bias_declaration.checker_model_family:
            raise ValueError("checker_model_family obrigatório (ADR-0049)")
        if _normalize_family(bias_declaration.checker_model_family) == \
           _normalize_family(bias_declaration.model_family):
            raise ValueError(
                "checker_model_family deve diferir de model_family "
                "(paper 209: mesma família = apenas -8% de eficácia)"
            )
```

**Justificativa (Jonas):** Sistema que não pode garantir a invariante não deve operar.
Startup é o momento correto — falha tardia já comprometeu decisões anteriores.

### D3 — Checker ausente: BLOCK (não ESCALATE_HUMAN)

**Decisão:** Se `PersuasionGuard` não estiver disponível em runtime, o
`EthicalContextEngine` retorna `BLOCK` com `explain_decision` indicando
indisponibilidade. Contestável via SLA 24h (Rawls preservado).

**Justificativa:** ESCALATE_HUMAN cria pressão operacional sistemática que incentiva
desativar o checker permanentemente. BLOCK é mais restritivo mas preserva o invariante:
sem checker validado, julgamento de CoT não pode ser considerado confiável.

**Alternativa rejeitada:** WARN + continuar sem anotação — equivale a desativar a
defesa silenciosamente. Incompatível com fail-secure.

### D4 — Invariante de separação: CoT original no Ledger, AnnotatedCoT no julgamento

**Decisão:** CoT original gravado no Ledger sem modificação. Julgamento usa
exclusivamente `AnnotatedCoT` com flags de claims não-verificados.

```
CoT original ──→ Ledger (imutável, HMAC-SHA256)   [auditável, contestável]
     │
     └──→ PersuasionGuard.annotate_cot()
               │
               └──→ AnnotatedCoT ──→ EthicalContextEngine   [seguro]
```

**Justificativa:** Transparência Radical preservada — o CoT completo está no Ledger,
disponível para auditoria e contestação. O julgamento usa versão anotada que expõe
claims não-verificados como flags explícitos, reduzindo poder persuasivo de raciocínio
adversarialmente construído.

`explain_decision` obrigatório inclui flags do `AnnotatedCoT` que influenciaram a
decisão (Levinas: visibilidade total do processo de julgamento).

### D5 — Checker implementado sobre SLMClassifier (ADR-0027)

**Decisão:** `PersuasionGuard._fact_checker` é implementado sobre `SLMClassifier`
(v1.8.0, 25/25 testes) com `model_id` e `model_family` distintos do agente principal.

**Justificativa:** ADR-0027 provê infraestrutura SLM local validada:
- API canônica `_llm.create_chat_completion()` testada
- Separação semântica erro-de-estrutura vs. erro-de-runtime estabelecida
- Disponível offline (invariante de privacidade)

Configurar `SLMClassifier` com `model_path` de família distinta satisfaz D1 sem
infraestrutura adicional.

```python
# Configuração válida (D1 satisfeito):
bias = BiasDeclaration(
    model_family         = "llama3",
    checker_model_family = "qwen2",      # família diferente
    checker_model_id     = "qwen2-1.5b-instruct",
)
```

---

## Consequências

### Positivas
- Transparência Radical preservada: CoT original no Ledger, inalterado
- Superfície de ataque via CoT eliminada sem reduzir auditabilidade
- Checker sobre infraestrutura existente (SLMClassifier ADR-0027)
- Startup validation: problema detectado antes de qualquer decisão comprometida

### Negativas / Trade-offs
- Latência adicional: anotação CoT ~5–15ms dependendo do SLM
- Requer dois modelos de famílias diferentes disponíveis
- Semantic reframing (<1% dos ataques, paper 209) fora de escopo → v3.0+

### Checklist de implementação (PROP-037)
- [ ] `checker_model_family != model_family`: validação em startup
- [ ] `AnnotatedCoT` registrada no Ledger junto com CoT original
- [ ] `EthicalContextEngine` recusa CoT sem `PersuasionGuard` ativo → BLOCK
- [ ] `explain_decision` inclui flags de anotação do `AnnotatedCoT`
- [ ] `_fact_checker` usa `model_id` distinto (SLMClassifier v1.8.0 base)
- [ ] `BiasDeclaration` extendida: +`checker_model_id`, +`checker_model_family`
- [ ] Normalização `model_family`: case-insensitive, prefixo até hífen/ponto

---

## Mapeamento de arquivos

```
python/buildtovalue/governance/persuasion_guard.py       — novo módulo
python/buildtovalue/governance/ethical_context_engine.py — pré-processador CoT
python/buildtovalue/core/bias_declaration.py             — +checker_model_family
data/policies/checker_model_registry.yaml                — modelos checker aprovados
```
