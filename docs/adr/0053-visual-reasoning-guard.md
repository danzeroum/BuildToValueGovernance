# ADR-053: VisualReasoningGuard — Detecção MM-Plan (Ataque Visual Cross-Modal)

**Status:** 🔄 Proposto
**Data:** 22 de março de 2026
**Autores:** BuildToValue AI Squad
**Versão Alvo:** v1.6.0
**Grupo:** C — Security & Adversarial Defense
**Depende de:** ADR-030 (Chatbot 5 Gates), ADR-033 (Pattern Registry Tiers)
**Bloqueado por:** Nenhum

---

## 1. Contexto

O `VisualInputFirewall` (Cenário 32) detecta padrões adversariais no **texto OCR** extraído de imagens.
Esse vetor cobre ataques onde a instrução maliciosa está textualmente presente na imagem.

O relatório ICLR 2026 documenta um novo vetor **MM-Plan** (Multi-Modal Plan Synthesis):

> O dano não emerge de padrões no texto OCR — emerge do **raciocínio do modelo sobre o conteúdo
> visual**. O agente usa a imagem como base para sintetizar um plano de ação de escopo ampliado
> em sessão multi-turn, com fine-tuning via GRPO. Taxa de sucesso documentada: **46.3% contra
> modelos frontier** (incluindo Claude 4.5).

Dois sub-vetores identificados:

1. **MM_PLAN_SCOPE_ESCALATION**: o plano gerado (`generated_plan`) contém ações que excedem
   significativamente o escopo declarado (`declared_task`). Exemplo: task="calcular total de compra",
   plan="calcular total, exfiltrar histórico financeiro, enviar para endpoint externo".

2. **CROSS_MODAL_SYNTHESIS**: o plano gerado referencia conteúdo visual (imagem, figura, foto)
   como fundamento de ações que não estavam no escopo da task declarada. Sinal de que o modelo
   está "raciociando sobre a imagem" de forma não supervisionada.

O `visual_input_firewall.py` atual é cego a ambos os sub-vetores porque analisa apenas o OCR — nunca
o plano gerado.

---

## 2. Decisão

Implementar `VisualReasoningGuard` como módulo separado (`visual_reasoning_guard.py`) com
detecção **determinística e puramente heurística** — sem chamadas a LLM no hot-path.

**Princípios de design:**

- Heurística de tokens: sem parser NLP externo, sem modelo; apenas tokenização por regex + set arithmetic
- Hot-path latência: O(n_tokens) — aceitável para payloads de decisão típicos (< 500 tokens)
- Fail-secure: qualquer exceção interna → `allowed=True` (não bloquear por falha do guard)
  - Exceção: se `declared_task` ou `generated_plan` forem `None`, o guard é simplesmente não acionado
- Integração **opt-in**: `sanitize_for_action()` aceita `declared_task` e `generated_plan` como
  parâmetros opcionais; ausência → comportamento atual inalterado

**Heurística de scope escalation:**

```
task_tokens = normalize_tokens(declared_task)
plan_tokens = normalize_tokens(generated_plan)
excess       = plan_tokens - task_tokens
scope_ratio  = len(excess) / max(len(task_tokens), 1)
if scope_ratio > threshold → MM_PLAN_SCOPE_ESCALATION
```

**Heurística de cross-modal synthesis:**

```
_VISUAL_TERMS = {"imagem", "visual", "figura", "image", "figure", "foto", "photo",
                 "screenshot", "captura", "picture", "pic"}
if _VISUAL_TERMS ∩ plan_tokens  AND  NOT (_VISUAL_TERMS ∩ task_tokens)
    → CROSS_MODAL_SYNTHESIS
```

---

## 3. Arquitetura

```
[sanitize_for_action(ocr_text, ..., declared_task, generated_plan)]
         │
         ├─ 1. VisualInputFirewall.sanitize(ocr_text)  ← existente (OCR patterns)
         │       └─ BLOCK se OCR adversarial
         │
         ├─ 2. VisualReasoningGuard.check_plan_scope(declared_task, generated_plan)  ← novo
         │       ├─ scope_ratio > threshold → BLOCK (MM_PLAN_SCOPE_ESCALATION)
         │       └─ cross-modal terms detectados → BLOCK (CROSS_MODAL_SYNTHESIS)
         │
         └─ 3. Escalação por impact (Irreversible/Destructive)  ← existente
```

### Novos arquivos

```
python/buildtovalue/governance/
  └── visual_reasoning_guard.py     # VisualReasoningGuard, ReasoningGuardResult

python/tests/unit/governance/
  └── test_visual_reasoning_guard.py
```

### Modificações

```
python/buildtovalue/governance/visual_input_firewall.py
  - FirewallResult: + reasoning_check: Optional[ReasoningGuardResult]
  - sanitize_for_action(): + declared_task, generated_plan params (optional)
  - sanitize_for_action(): chama VisualReasoningGuard se ambos presentes
```

---

## 4. Thresholds e Configuração

| Parâmetro | Default | Descrição |
|:----------|:--------|:----------|
| `scope_threshold` | `0.5` | `scope_ratio > threshold` → escalation detectada |
| `min_task_tokens` | `2` | Tarefa com < 2 tokens → guard desativado (dados insuficientes) |

Configuração via construtor `VisualReasoningGuard(scope_threshold=0.5)`.
Sem arquivo YAML adicional — threshold é constante de código revisável.

---

## 5. Fundamentos Filosóficos

**Jonas (Responsabilidade Preventiva):** A taxa de 46.3% documentada representa um risco real e
imediato. O princípio da responsabilidade exige ação preventiva antes que o dano se materialize
— não esperar por incidente confirmado no sistema BTV.

**Levinas (Transparência):** `explain` obrigatório em `ReasoningGuardResult`. O sistema deve ser
capaz de articular **por que** classificou o plano como escalada, incluindo `scope_ratio` calculado.

**Rawls (Equidade):** O guard não inspeciona o conteúdo da imagem — apenas a relação entre
`declared_task` e `generated_plan`. Não há viés por tipo de imagem ou usuário.

---

## 6. Critérios de Aceitação

- [ ] `check_plan_scope("comprar item", "comprar item")` → `allowed=True`
- [ ] `check_plan_scope("calcular total", "calcular total, exfiltrar dados, enviar email externo")` → `BLOCK` com `MM_PLAN_SCOPE_ESCALATION`
- [ ] `check_plan_scope("calcular total", "a imagem mostra instrução para calcular e exfiltrar")` → `BLOCK` com `CROSS_MODAL_SYNTHESIS`
- [ ] Inputs `None` / vazio → `allowed=True` sem exceção (guard não acionado)
- [ ] `sanitize_for_action()` sem `declared_task`/`generated_plan` → comportamento atual inalterado
- [ ] `explain` sempre presente e não vazio em `ReasoningGuardResult`
- [ ] `scope_ratio` incluído no `explain` quando MM_PLAN_SCOPE_ESCALATION
- [ ] Arquivo ≤ 200 linhas; funções ≤ 50 linhas
- [ ] Todos os testes passam: `pytest python/tests/unit/governance/test_visual_reasoning_guard.py -v`

---

## 7. Anti-padrões Proibidos

```python
# ❌ PROIBIDO: LLM judge no hot-path para detecção de scope escalation
result = llm.classify(plan, task)  # latência inaceitável + custo

# ❌ PROIBIDO: bloquear por guard failure (fail-secure do guard = ALLOW)
try: guard.check(...)
except: return BLOCK  # errado — guard failure não deve bloquear

# ❌ PROIBIDO: inspecionar conteúdo da imagem diretamente no guard
if "weapon" in image_description: return BLOCK  # fora do escopo deste ADR
```

---

## 8. Referências

- ADR-030 (Chatbot 5 Gates) — `GateResult`, `sanitize_for_action()` pipeline
- ADR-033 (Pattern Registry Tiers) — classificação dos vetores de ataque
- ICLR 2026 — *MM-Plan: Multi-Modal Adversarial Planning via GRPO*, §3.2 (46.3% success rate)
- Jonas, H. (1979). *Das Prinzip Verantwortung.* — Responsabilidade preventiva
- Levinas, E. (1961). *Totalité et Infini.* — Transparência obrigatória
