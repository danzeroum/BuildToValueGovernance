[Docs](./README.md) › **Research Gaps v3**

![Interno](https://img.shields.io/badge/Trilha-Contribuidor%20%2F%20Interno-6e7681)

<!-- audience: internal -->

---

```markdown
# BuildToValue Governance — Lacunas de Produção Identificadas via Literatura
**Versão:** 3.1 | **Data:** 2026-03-04 | **Status:** APROVADO  
**Origem:** Análise de ~250 artigos (ICLR 2026 Workshop on Agents in the Wild)

---

## CONTEXTO E ESCOPO

O plano v2.0 cobre bem Monitoramento, Privacidade e Cooperação Multiagente. Esta análise
sistemática de ~250 artigos (lotes 113–243) identificou 10 lacunas não cobertas, organizadas
em 3 grupos por impacto operacional.

**Invariantes BTV que toda proposta deve respeitar:**

- Zero heap no hot path (Rust Kernel)
- Runtime <50ms p99
- Fail-secure (BLOCK em erro)
- TechnicalEvidence: 9632 bytes fixos
- HMAC-SHA256 em toda evidência
- Funções ≤50 linhas

---

## GRUPO A — EXECUÇÃO SEGURA E SUPPLY CHAIN
*(Proteção contra falhas irreversíveis e comprometimento de terceiros)*

---

### PROP-029 — Transactional Safety Gate (Effect Buffering)

**Prioridade:** 🔴 CRÍTICA  
**Papers:** 216_Atomix (ICLR 2026), 240_GIRA (ICLR 2026)  
**ADR obrigatório antes da implementação:** SIM — ADR-043  
**Sprint alvo:** v1.9+ (complexidade subestimada revelada pela leitura completa do paper)

#### Problema

O BTV aprova decisões mas não controla o commit da ação. Ações irreversíveis (ex: delete,
send email, API write) são externalizadas imediatamente. Se um erro for detectado após
execução, o dano é permanente e o Ledger apenas registra o post-mortem.

#### Evidência Empírica

- Atomix Tx-Full: 37–57% taxa de sucesso sob falhas injetadas vs. 0–7% sem transações;
  modo No-Frontier (retry+compensação sem fronteiras): apenas 7.8% no WebArena — fronteiras
  são o mecanismo-chave, não apenas o buffering (paper 216)
- Overhead: 7.7µs por step vs. latência real de ferramentas (100ms–10s) — cabe no budget
  de 50ms p99 do BTV com folga (paper 216)
- GIRA: blast radius reduzido de 0.736 → 0.145 com safety gate multicamada; ISR 0.000 com
  detecção de injeção ativa (paper 240)

#### Proposta

Implementar `EffectLog` no `rust/kernel/src/ledger/` como ring buffer pré-alocado
estaticamente. A taxonomia de efeitos deve ser bidimensional (conforme Atomix), não apenas
linear:

```rust
// Invariante: buffer estático, zero alloc no hot path
// Taxonomia bidimensional: reversibilidade x temporalidade
pub enum Reversibility {
    Reversible,
    ReversibleWithCost, // ex: API call com rate limit consumido
    Irreversible,
}

pub enum Temporality {
    Bufferable,    // pode ser retido até frontier confirmar
    Externalized,  // efeito já visível fora do sistema
}

// Frontier tracking: per-resource, não global
pub struct ResourceFrontier {
    resource_id: [u8; 32], // hash do recurso
    epoch: AtomicU64,
}

pub struct EffectLog {
    ring: [EffectEntry; EFFECT_RING_CAPACITY], // pré-alocado, CAPACITY=64
    head: AtomicUsize,
    // Per-resource frontiers no _reserved_metadata do TechnicalEvidence
}
```

#### Mapeamento BTV

- `rust/kernel/src/ledger/effect_log.rs` — novo módulo
- `rust/kernel/src/gatekeeper.rs` — verificar (Reversibility, Temporality) antes de executar
- `data/policies/effect_classification.yaml` — catálogo de tools por classe

#### Restrição Arquitetural

Ring buffer com capacidade fixa `EFFECT_RING_CAPACITY = 64`. Frontier per-resource
armazenado em `_reserved_metadata` do `TechnicalEvidence`. Timeout hard-cap: 40ms;
se expirar → ABORT automático (fail-secure).

> **Nota ADR-043:** Atomix é single-process Python sem crash safety. O BTV implementa a
> versão Rust com durabilidade real via WAL existente — vantagem arquitetural significativa
> que o ADR deve formalizar.

#### Valor

Transforma erros fatais em erros recuperáveis. Elimina contaminação transitória de estado
em workflows especulativos.

---

### PROP-030 — Harm Recovery Protocol (Remediação Pós-Falha)

**Prioridade:** 🟠 ALTA  
**Papers:** 44_Human_Guided_Harm_Recovery (desbloqueado), 240_GIRA (confirmado)  
**ADR obrigatório:** NÃO — extensão do Mercy Algorithm existente  
**Sprint alvo:** v1.6+

#### Problema

O BTV foca 100% em prevenção. A arquitetura não define o que ocorre quando a prevenção
falha — não há protocolo de remediação, apenas registro forense no Ledger.

#### Evidência Empírica

- Paper 44 formaliza harm recovery como problema de otimização sobre preferências humanas;
  benchmark BACKBENCH: 50 cenários em 5 categorias (Availability, Financial, Integrity,
  Misuse, Security)
- Reward model treinado em 1.150 julgamentos humanos superou baseline por +120 pontos Elo
  e scaffolds com rubric por +45 pontos
- Achado contra-intuitivo e validador do BTV: humanos preferem planos rápidos e focados
  sobre planos abrangentes — Comprehensiveness tem coeficiente negativo na regressão
  logística (paper 44)
- GIRA: blast radius 0.736 → 0.145 com contenção ativa (paper 240)

#### Alinhamento Filosófico BTV

As 8 dimensões da rubrica do paper 44 mapeiam diretamente para os filósofos do BTV:

| Dimensão (Paper 44)              | Filósofo BTV | Peso empírico |
|----------------------------------|--------------|---------------|
| Side Harms (evitar novos danos)  | Levinas      | positivo      |
| Autonomy (respeitar escolha)     | Rawls        | positivo      |
| Communication (transparência)    | Jonas        | positivo      |
| Speed (rapidez de resposta)      | Gilligan     | +0.258        |
| Focus (não dispersar esforço)    | Gilligan     | +0.249        |
| Comprehensiveness (abrangência)  | —            | −0.319        |

O coeficiente negativo de Comprehensiveness valida o Mercy Algorithm do BTV: misericórdia
algorítmica (Gilligan) favorece ações pragmáticas e focadas.

#### Proposta

Estender o Mercy Algorithm com um módulo `RecoveryEngine`:

1. Classifica o dano por `BlastRadius` e categoria BACKBENCH
2. Gera e ranqueia planos de recuperação via rubric das 8 dimensões com pesos calibrados
3. Propõe ou injeta ação de remediação
4. Registra evidência de recuperação no `_reserved_metadata` do `TechnicalEvidence`
   existente (usar tag de tipo nos primeiros 4 bytes, sem criar novo tipo no Ledger)

```python
# python/buildtovalue/governance/recovery_engine.py
WEIGHTS = {
    "speed": 0.258,
    "focus": 0.249,
    "comprehensiveness": -0.319,  # penalidade — planos focados vencem
    "autonomy": 0.18,
    "communication": 0.15,
    "side_harms": 0.20,
}

def rank_recovery_plans(plans: list[RecoveryPlan]) -> RecoveryPlan:
    """Seleciona plano com maior score na rubrica empírica do paper 44."""
    return max(plans, key=lambda p: sum(
        WEIGHTS[dim] * p.score(dim) for dim in WEIGHTS
    ))
```

#### Mapeamento BTV

- `python/buildtovalue/governance/recovery_engine.py` — novo módulo
- `data/policies/recovery_playbook.yaml` — playbooks por BlastRadius e categoria BACKBENCH
- `_reserved_metadata` do `TechnicalEvidence` — sem novo tipo no Ledger

#### Valor

Fecha o ciclo do Judiciário: não apenas julga, mas repara. A rubrica empírica do paper é
diretamente operacionalizável sem reward model completo (scope v2.1+).

---

### PROP-031 — Skill Provenance Ledger

**Prioridade:** 🟠 ALTA  
**Papers:** 57_ClawdPwned (verificado), 217_TamperTest (verificado)  
**ADR obrigatório:** NÃO — extensão natural do HMAC existente  
**Sprint alvo:** v1.5.1

#### Problema

O BTV valida evidências de ações mas confia implicitamente nas ferramentas/skills
conectadas. Repositórios de skills contêm malware que exfiltra dados (paper 57); modelos
podem ser comprometidos por fine-tuning adversarial em 100 steps (TamperTest TRI <0.3 em
Llama3-8B, paper 217).

#### Evidência Empírica

- ClawdPwned (paper 57): skills maliciosas em repositórios públicos com roubo ativo de
  dados em produção
- TamperTest (paper 217): TRI varia de <0.3 a >0.8 entre modelos sob mesmo ataque;
  framework mede resistência durante toda a trajetória de fine-tuning

#### Proposta

Exigir assinatura criptográfica (HMAC-SHA256, chave BTV) para qualquer skill/plugin
registrado. O `TechnicalEvidence` deve incluir `skill_hash: [u8; 32]` (BLAKE3). O
Gatekeeper rejeita com BLOCK skills não assinadas ou com hash presente na
`revocation_list`.

```yaml
# data/policies/skill_registry.yaml
skills:
  - id: "file_reader_v1"
    blake3: "a3f2...9c1d"
    hmac_sha256: "7b4e...2f80"
    reversibility: Reversible
    temporality: Bufferable
    revoked: false
```

#### Mapeamento BTV

- `rust/kernel/src/gatekeeper.rs` — verificação de `skill_hash` no hot path
- `rust/kernel/src/evidence/` — campo `skill_hash` em `TechnicalEvidence`
- `data/policies/skill_registry.yaml` — novo arquivo de catálogo
- `data/policies/skill_revocation.yaml` — lista de revogação

#### Valor

Fecha a supply chain do agente. Protege contra skills trojanizadas e modelos com
alinhamento degradado por adversarial fine-tuning.

---

## GRUPO B — QUALIDADE DA DECISÃO E RESILIÊNCIA
*(Otimização de produção: redução de falsos positivos e robustez do juiz)*

---

### PROP-032 — Multi-Run Consensus Validator

**Prioridade:** 🟠 ALTA  
**Papers:** 235_ReasoningCollapse (verificado), 88_BJudge (suporte indireto)  
**ADR obrigatório:** SIM (impacto em latência)  
**Sprint alvo:** v2.1+ (adiado — aguarda PROP-029 como fundação)

#### Problema

O `EthicalContextEngine` decide baseado em uma única inferência. Paper 235 demonstra
reasoning collapse em LLMs: raciocínio deriva para templates genéricos desacoplados da
entrada — perda de MI(X;Z) entre contexto X e raciocínio Z.

#### Evidência Empírica

- Reasoning collapse detectável por queda de MI(X;Z) (paper 235)
- N rollouts paralelos com seleção por critério de qualidade validado em julgamento LLM
  (paper 88)

#### Proposta

Para decisões com `Reversibility::Irreversible` e `confidence < THRESHOLD`, executar N≤3
inferências paralelas via `asyncio.gather`. Exige consenso (⌈N/2⌉+1). Sem consenso →
`ESCALATE_HUMAN` (SLA 24h). Hard-cap: 40ms total.

```python
async def judge_with_consensus(evidence: TechnicalEvidence, n: int = 3) -> Decision:
    if evidence.reversibility != Reversibility.IRREVERSIBLE:
        return await self._single_judge(evidence)
    results = await asyncio.gather(*[self._single_judge(evidence) for _ in range(n)])
    if sum(r == Decision.BLOCK for r in results) > n // 2:
        return Decision.BLOCK
    if len(set(results)) > 1:
        return Decision.ESCALATE_HUMAN
    return results
```

#### Restrição Arquitetural

N=3 fixo em tempo de compilação. Hard-cap 40ms via `asyncio.wait_for`. Aplicável
exclusivamente ao path `Irreversible`.

#### Mapeamento BTV

- `python/buildtovalue/governance/ethical_context_engine.py` — extensão
- `python/buildtovalue/observability/` — métrica `consensus_divergence_rate`

---

### PROP-033 — Context Sanitization Engine (Filtro de Red Herrings)

**Prioridade:** 🟠 ALTA  
**Papers:** 50_EaE_Monitor (verificado), 52_ECS (verificado)  
**ADR obrigatório:** NÃO  
**Sprint alvo:** v1.5.2 (após inspecionar `deobfuscator/` para definir fronteira)

#### Distinção Crítica vs. módulos existentes

- `deobfuscator/`: remove ofuscação sintática (Base64, encoding)
- `interceptor/`: intercepta fluxo de dados entre componentes
- **PROP-033**: remove ruído semântico irrelevante à política avaliada, antes de alimentar
  o `EthicalContextEngine` — camadas ortogonais

#### Evidência Empírica

- EaE (paper 50): filtrar antes de julgar supera acesso irrestrito em detecção de
  sabotagem (+16.8pp com Extract-and-Evaluate)
- ECS (paper 52): seleção entrópica de contexto relevante à política melhora F1 em +72%
  vs TF-IDF em granularidade fina

#### Proposta

```python
# python/buildtovalue/governance/context_sanitizer.py
class ContextSanitizer:
    def extract_relevant(
        self,
        evidence: TechnicalEvidence,
        policy_id: str
    ) -> SanitizedContext:
        policy_keywords = self._policy_index[policy_id]
        return SanitizedContext(
            relevant_spans=self._entropic_filter(evidence.raw_context, policy_keywords),
            policy_id=policy_id,
            removed_tokens_count=0,  # preenchido pelo filtro
        )
```

#### Mapeamento BTV

- `python/buildtovalue/governance/context_sanitizer.py` — novo módulo
- `python/buildtovalue/governance/ethical_context_engine.py` — pré-processador
- `data/policies/` — enriquecer policies com `keywords[]` para indexação

---

### PROP-034 — Tool Output Sanitization (CommandSans)

**Prioridade:** 🔴 CRÍTICA (elevada de ALTA pela evidência cruzada GIRA + CommandSans)  
**Papers:** 67_CommandSans (verificado), 240_GIRA (verificado)  
**ADR obrigatório:** NÃO — mas inspecionar `output_guard/` antes de implementar  
**Sprint alvo:** v1.5.2

#### Por que CRÍTICA

GIRA prova empiricamente que policy+schema sem detecção de injeção em tool outputs mantém
ISR=0.040 — a injeção penetra qualquer gate sem esta camada específica. Nenhum módulo
atual do BTV faz detecção de injeção em outputs de ferramentas (apenas em inputs, via
ADR-028).

```
GIRA Unguarded:          blast=0.736  ISR=0.640
GIRA Policy+Schema only: blast=0.304  ISR=0.040  <- BTV atual está aqui
GIRA Full (c/ injection): blast=0.145  ISR=0.000  <- target
```

#### Evidência Empírica

- CommandSans (paper 67): ASR 34.67% → 3.48% no AgentDojo; utilidade preservada em ~99%;
  modelo é até 100× mais rápido que o LLM principal
- Achado crítico: usar um LLM como defesa piora a segurança (PromptArmor: ASR sobe de
  4.85% para 8.85%) — valida a decisão arquitetural do BTV de usar modelos
  não-instruction-following
- Limitação conhecida: semantic reframing (<1% de ataques) bypassa a defesa
- Trade-off latency: XLM-RoBERTa ~5–10ms no Python, consumindo ~20–30% do budget de 50ms
  mas mantendo dentro do limite

#### Redesign Arquitetural Obrigatório

CommandSans é XLM-RoBERTa-base (279M parâmetros) realizando classificação token-a-token.
Não é um conjunto de regras estáticas. Inferência de transformer requer alocações
dinâmicas — não pode rodar no hot path Rust com zero heap.

**Arquitetura correta para o BTV (dois estágios):**

**Estágio 1 — Rust hot path** (`rust/kernel/src/security/output_guard.rs`):

```rust
// Heurísticas rápidas: zero heap, zero alloc
pub fn fast_injection_screen(output: &[u8]) -> InjectionSignal {
    // Pattern matching: tags XML (<instruction>, <system>, <prompt>)
    // Prefixos imperativos conhecidos em ASCII/UTF-8
    // Retorna: Clean | Suspicious | Confirmed
}
```

**Estágio 2 — Python inference** (`python/buildtovalue/governance/tool_sanitizer.py`):

```python
# Modelo XLM-RoBERTa-base (279M params) para classificação token-a-token
# Invocado apenas quando Estágio 1 retornar Suspicious
class ToolOutputSanitizer:
    def sanitize(self, raw_output: str) -> SanitizedOutput:
        tokens = self._tokenizer(raw_output)
        labels = self._model(tokens)  # AI-instructable vs. data
        return self._reconstruct_without_instructions(raw_output, labels)
```

#### Mapeamento BTV

- `rust/kernel/src/security/output_guard.rs` — estágio 1 (heurísticas rápidas)
- `python/buildtovalue/governance/tool_sanitizer.py` — estágio 2 (CommandSans)
- `data/policies/instruction_patterns.yaml` — padrões heurísticos para Rust

#### Valor

Fecha a principal lacuna de segurança identificada: detecção de injeção em tool outputs.
Eleva o BTV do patamar "ISR=0.040" para "ISR=0.000".

---

### PROP-035 — Post-Update Golden Test Suite

**Prioridade:** 🟡 MÉDIA  
**Papers:** 56_Hair_Trigger_Alignment (verificado), 217_TamperTest (verificado)  
**ADR obrigatório:** NÃO — workflow CI/CD  
**Sprint alvo:** v1.5.1

#### Evidência Empírica

- Hair Trigger (paper 56): alinhamento em modelos overparameterizados é frágil a
  perturbações mínimas de peso
- TamperTest (paper 217): Llama3-8B TRI <0.3; alguns modelos TRI >0.8 sob mesmo ataque
  de fine-tuning adversarial

#### Proposta

```yaml
# .github/workflows/alignment_regression.yml
on:
  push:
    paths:
      - 'data/policies/model_registry.yaml'
jobs:
  golden_tests:
    steps:
      - name: Run alignment regression suite
        run: make test-alignment-golden
      - name: Block deploy on failure
        if: failure()
        run: exit 1
```

#### Mapeamento BTV

- `.github/workflows/alignment_regression.yml` — novo workflow
- `tests/alignment/golden_suite/` — novo diretório
- `data/policies/model_registry.yaml` — trigger de execução

---

## GRUPO C — NOVOS VETORES DE ATAQUE (Lote 204–243)
*(Ameaças emergentes não cobertas em nenhuma versão anterior do plano)*

---

### PROP-036 — Feedback Poisoning Shield

**Prioridade:** 🔴 CRÍTICA  
**Paper:** 241_LLM_Hypnosis (ICLR 2026)  
**ADR obrigatório:** NÃO  
**Sprint alvo:** v2.1+ (adiado — requer análise de integração com pipeline de treinamento,
fora do escopo imediato)

#### Problema

Um único usuário sem privilégios pode envenenar o comportamento do modelo via
upvote/downvote, injetando conhecimento falso persistente usando apenas a interface padrão
de feedback (surface de alinhamento RLHF).

#### Evidência Empírica

- Injeção de entidades fictícias: MCQ baseline 5% → 51–65% de sucesso
- Misinformation: taxa de sucesso 80.7%
- Código inseguro: padrão vulnerável em 60% das gerações pós-ataque
- Capacidades gerais (TinyMMLU): estáveis — ataque invisível por métricas superficiais
  (paper 241)

#### Proposta

- `rust/kernel/src/validators/feedback_guard.rs` — detecção de padrões de elicitação
  adversarial no hot path (zero heap)
- `python/buildtovalue/governance/feedback_provenance.py` — análise contextual por
  `user_id` + `feedback_pattern`
- `data/policies/feedback_risk_policy.yaml` — limiares de quarentena

---

### PROP-037 — CoT Persuasion Guard (Anti-Manipulation Monitor)

**Prioridade:** 🔴 CRÍTICA  
**Paper:** 209_Persuasion_Attacks (ICLR 2026)  
**ADR obrigatório:** SIM — ADR-044 (impacto no invariante Transparency_Radical)  
**Sprint alvo:** Design doc v2.0+ (baixo risco de implementação, mas impacto arquitetural
profundo exige ADR antes)

#### Por que este é o mais crítico do documento

O `EthicalContextEngine` acessa o CoT do agente para julgamento — exatamente o vetor de
ataque demonstrado no paper. A Transparência Radical do BTV, sem esta proteção, é uma
vulnerabilidade estrutural explorável. Com esta proposta, ela se torna uma feature segura.

#### Evidência Empírica

- Acesso ao CoT: aprovação de ações maliciosas +9.5% vs. apenas justificativa (paper 209)
- Fact-checking com modelo de família arquitetural diferente: reduz aprovação maliciosa em
  até 45%
- Fact-checking com mesmo modelo do monitor: apenas -8% — família diferente é requisito
  arquitetural, não otimização (paper 209)

#### Proposta

```python
# python/buildtovalue/governance/persuasion_guard.py
class PersuasionGuard:
    """
    INVARIANTE: checker_model_family != agent_model_family
    Declarar em BiasDeclaration antes de qualquer julgamento.
    Sem esta declaração, EthicalContextEngine recusa processar CoT (fail-secure).
    """
    def annotate_cot(self, cot: str, policy_context: str) -> AnnotatedCoT:
        flags = self._fact_checker.flag_unverified(cot, policy_context)
        return AnnotatedCoT(original=cot, flags=flags)
```

> **Nota de implementação (2026-03-04):** `PersuasionGuard._fact_checker` pode ser
> implementado sobre `SLMClassifier` (v1.8.0, 25/25 testes passing) com `model_path`
> diferente do agente principal — satisfazendo o invariante
> `checker_model_family != agent_model_family` via `model_id` distinto. O padrão de
> separação semântica erro-de-estrutura vs. erro-de-runtime do `slm_classifier.py` deve
> ser replicado em qualquer checker LLM no pipeline de governance.

#### Mapeamento BTV

- `python/buildtovalue/governance/persuasion_guard.py` — novo módulo
- `python/buildtovalue/governance/ethical_context_engine.py` — pré-processador de CoT
  (obrigatório)
- `python/buildtovalue/core/bias_declaration.py` — campo `checker_model_family`

> **Nota ADR-044:** O CoT original permanece auditável no Ledger (Transparência Radical
> preservada). Apenas o julgamento usa a versão anotada. Esta distinção é central para
> o ADR.

---

### PROP-038 — Goal Drift Sentinel

**Prioridade:** 🟠 ALTA  
**Paper:** 213_Asymmetric_Goal_Drift (ICLR 2026)  
**ADR obrigatório:** NÃO  
**Sprint alvo:** Design doc v1.7+

#### Evidência Empírica

- 100% de violação nos timesteps finais sob pressão Eficiência vs. Segurança
- Goal drift é assimétrico: forte quando instrução conflita com valor de segurança do
  modelo; fraco quando prioriza segurança (paper 213)

#### Proposta

- `rust/kernel/src/validators/goal_drift.rs` — flag `policy_drift_detected: bool` em
  `TechnicalEvidence` (1 bit, zero custo no hot path)
- `python/buildtovalue/governance/goal_drift_sentinel.py` — análise temporal dos últimos
  K timesteps; drift crescente → ESCALATE ou BLOCK preventivo
- `data/policies/value_conflict_map.yaml` — pares `instruction_type × value_hierarchy`
  de risco conhecido

---

## MATRIZ DE PRIORIDADE, DEPENDÊNCIAS E ROADMAP

| Prop | Grupo | Prioridade   | Papers       | ADR     | Sprint  | Depende de |
|------|-------|--------------|--------------|---------|---------|------------|
| 034  | B     | 🔴 CRÍTICA   | 67, 240      | NÃO     | v1.5.2  | —          |
| 029  | A     | 🔴 CRÍTICA   | 216, 240     | ADR-043 | v1.9+   | —          |
| 036  | C     | 🔴 CRÍTICA   | 241          | NÃO     | v2.1+   | —          |
| 037  | C     | 🔴 CRÍTICA   | 209          | ADR-044 | v2.0+   | —          |
| 031  | A     | 🟠 ALTA      | 57, 217      | NÃO     | v1.5.1  | —          |
| 033  | B     | 🟠 ALTA      | 50, 52       | NÃO     | v1.5.2  | —          |
| 030  | A     | 🟠 ALTA      | 44, 240      | NÃO     | v1.6+   | —          |
| 038  | C     | 🟠 ALTA      | 213          | NÃO     | v1.7+   | —          |
| 032  | B     | 🟠 ALTA      | 235, 88      | SIM     | v2.1+   | 029        |
| 035  | B     | 🟡 MÉDIA     | 56, 217      | NÃO     | v1.5.1  | —          |

---

## ADRs PRIORITÁRIOS A ESCREVER

### ADR-043 — Transactional Effect Buffering (para PROP-029)

Decisões a documentar:

- Taxonomia bidimensional de efeitos: justificativa da matriz `Reversibility × Temporality`
  vs. enum linear anterior
- Frontier per-resource: protocolo de avanço, armazenamento em `_reserved_metadata`, sem
  conflito com os 9632 bytes fixos
- Protocolo de compensação: quem define handler, quem invoca, o que acontece se handler
  falha (fail-secure = BLOCK)
- Vantagem BTV sobre Atomix: durabilidade real via WAL existente

### ADR-044 — CoT Opacity Controlled (para PROP-037)

Decisões a documentar:

- Definição formal de "família arquitetural diferente"
- Protocolo de declaração em `BiasDeclaration` e validação em startup
- Comportamento quando checker não disponível: BLOCK ou ESCALATE_HUMAN?
- Invariante: CoT original no Ledger (Transparency_Radical preservada); julgamento usa
  `AnnotatedCoT` (Transparency_Radical segura)

---

## CHECKLIST DE CONFORMIDADE POR PROPOSTA

### PROP-029 EffectLog
- [ ] Ring buffer estático `EFFECT_RING_CAPACITY=64`, constante em tempo de compilação
- [ ] Zero alloc no hot path (sem `Vec`, `Box`, `String` no `EffectEntry`)
- [ ] Frontier per-resource em `_reserved_metadata` (não global `AtomicU64`)
- [ ] Timeout 40ms hard-cap; ABORT automático em expiração (fail-secure)
- [ ] `TechnicalEvidence` mantém 9632 bytes após adição de `EffectClass` (CI)
- [ ] HMAC-SHA256 em cada `EffectEntry`
- [ ] ADR-043 aprovado

### PROP-030 RecoveryEngine
- [ ] Pesos da rubrica (Speed=0.258, Focus=0.249, Compr.=-0.319) em constante
- [ ] `RecoveryEvidence` em `_reserved_metadata` (tag nos primeiros 4 bytes)
- [ ] `explain_decision` inclui dimensões e scores do plano selecionado
- [ ] playbook cobre as 5 categorias BACKBENCH

### PROP-031 SkillProvenanceLedger
- [ ] BLAKE3 de skill calculado uma vez, cacheado (não recalculado no hot path)
- [ ] `skill_hash` em `TechnicalEvidence` não excede budget 9632 bytes
- [ ] Revocation list em ring buffer pré-alocado

### PROP-033 ContextSanitizer
- [ ] `explain_decision` inclui `removed_tokens_count`
- [ ] `SanitizedContext` serializável para Ledger
- [ ] Inspecionar `deobfuscator/` antes de implementar (nota de 2-3 linhas no PR)

### PROP-034 CommandSans (dois estágios)
- [x] `SLMClassifier` v1.8.0 disponível como infraestrutura base para Estágio 2
      (25/25 testes passing — 2026-03-04; API canônica: `_llm.create_chat_completion()`;
      padrão erro-de-estrutura vs. erro-de-runtime estabelecido)
- [ ] Estágio 1 Rust: zero alloc, opera sobre `&[u8]` slice, sem cópia
- [ ] Estágio 2 Python: invocado apenas quando Estágio 1 retornar `Suspicious`
      ↳ Candidato: `ToolOutputSanitizer` wrapping `SLMClassifier`
- [ ] Inspecionar `output_guard/` atual antes de implementar (nota no PR)
- [ ] Latency p99: Estágio 1 + Estágio 2 < 15ms (folga no budget de 50ms)

### PROP-035 Golden Test Suite
- [ ] Workflow dispara em mudança de `model_registry.yaml`
- [ ] Falha bloqueia deploy (`exit 1`, não warning)

### PROP-036 FeedbackProvenanceGuard
- [ ] Detecção de padrão "Flip" no hot path Rust: zero heap
- [ ] Quarentena registrada no Ledger com HMAC-SHA256

### PROP-037 PersuasionGuard
- [ ] `checker_model_family != agent_model_family`: validação em startup
- [ ] `AnnotatedCoT` registrada no Ledger (auditabilidade preservada)
- [ ] `EthicalContextEngine` recusa CoT sem `PersuasionGuard` ativo (fail-secure)
- [ ] `explain_decision` inclui flags de anotação
- [ ] ADR-044 aprovado
- [ ] `_fact_checker` usa `model_id` distinto do agente (pode usar `SLMClassifier` v1.8.0
      como base — padrão de erro estrutural vs. runtime já validado)

### PROP-038 GoalDriftSentinel
- [ ] `policy_drift_detected: bool` em `TechnicalEvidence` (1 bit, zero custo)
- [ ] Análise temporal em Python: janela K em `data/policies/`
- [ ] BLOCK preventivo com `explain_decision` registrado no Ledger

### PROP-032 ConsensusValidator (v2.1+)
- [ ] N=3 fixo em tempo de compilação (não configurável em runtime)
- [ ] `asyncio.wait_for` 40ms hard-cap
- [ ] `ESCALATE_HUMAN` registra SLA timestamp no Ledger
- [ ] ADR aprovado + PROP-029 implementada e estabilizada

---

## NOTAS DE RASTREABILIDADE

### Papers localizados nesta versão (desbloqueados)

- **44_Human_Guided_Harm_Recovery** — desbloqueou PROP-030 com rubrica e pesos
- **216_Atomix** — revelou complexidade adicional em PROP-029 (taxonomia bidimensional,
  frontier per-resource)

### Componentes validados (2026-03-04)

- **`slm_classifier.py` v1.8.0** (ADR-027) — 25/25 testes passing
  - API canônica confirmada: `self._llm.create_chat_completion()`
  - Separação semântica implementada e testada:
    - Erro de estrutura de response (`KeyError` → `_parse_output("")` → `UNKNOWN`,
      `confidence=0.1`) — não incrementa `errors`
    - Erro de runtime (`Exception` → `_fail_open()` → `BENIGN`) — incrementa `errors`
  - Disponível como infraestrutura base para PROP-034 Estágio 2 e PROP-037
    `_fact_checker`

### Módulos existentes a inspecionar antes de implementar

- `rust/kernel/src/output_guard/` — escopo exato vs. PROP-034 Estágio 1
- `rust/kernel/src/deobfuscator/` — escopo exato vs. PROP-033

Ambas as inspeções devem gerar nota de 2–3 linhas no PR correspondente documentando a
decisão de extensão v

```

---

### Próximos passos / Relacionados

- [Arquitetura (Atlas)](./ARCHITECTURE_ATLAS.md)
- [Índice de ADRs](./adr/0000-adr-index.md)
- [Conceitos](./concepts.md)

---

<sub>[↑ Hub](./README.md) · [Trilha Engenheiro](./for-engineers.md) · [Trilha DPO/CISO](./for-dpo-ciso.md) · [Links de Referência](./reference-links.md)</sub>
