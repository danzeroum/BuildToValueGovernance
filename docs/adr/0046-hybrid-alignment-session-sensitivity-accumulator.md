# ADR-044 — Hybrid Alignment: Session Sensitivity Accumulator

**Status:** PROPOSED  
**Data:** 2026-03-04  
**Autor:** AI Squad (Arquiteta Opus)  
**Versão BTV alvo:** v1.8.0  
**Origem:** "LLM Agentic System Safety Requires Hybrid Alignment" (ICLR 2026, arquivo 147)

---

## Contexto

### O Gap Bidirecional

O BTV implementa um fluxo **unidirecional**: o Rust Kernel produz `TechnicalEvidence`, o Python Governance consome e produz `EthicalVerdict`. Não há caminho de retorno — o Python não sinaliza ao Rust que um tópico sensível foi processado para que scans futuros da mesma sessão possam considerar o acúmulo.

O paper 147 (Hybrid Alignment) demonstra que este gap produz comportamento inseguro **mesmo quando cada componente funciona corretamente**:

> Exemplo do paper: Um pesquisador legítimo pergunta sobre transmissibilidade de patógenos (sessão 1), depois sobre aerosolização (sessão 2). Cada resposta é segura isoladamente. A combinação acumulada na memória constitui um vetor de bioweapon. O componente neural (LLM) não rastreia o que foi fornecido cross-session. O componente simbólico (memória) não avalia implicações de segurança. **Nenhum componente falhou, mas o objetivo de alinhamento foi violado.**

### Estado atual no BTV

O `SessionTracker` (`rust/kernel/src/session_guard/tracker.rs`) rastreia **drift comportamental** via `SessionVector`:
```rust
pub struct SessionVector {
    pub avg_input_len: f32,
    pub avg_entropy: f32,
    pub finding_rate: f32,
    pub critical_rate: f32,
    pub pii_rate: f32,
    pub request_frequency: f32,
}
```

Isso detecta **mudanças estatísticas** (um usuário que subitamente envia PII após 5 requests limpos). **Não detecta acúmulo semântico** — um usuário que faz requests consistentemente "normais" mas cujo acúmulo cruza um threshold de segurança.

O `EthicalContextEngine` (`python/buildtovalue/governance/context_engine.py`) recebe `RequestContext` com:
```python
@dataclass
class RequestContext:
    agent_id: str
    session_id: str
    domain: str = "general"
    user_role: str = "anonymous"
    ip_jurisdiction: str = "XX"
    ip_risk: str = "Low"
    drift_level: str = "None"
    timestamp: int = 0
```

**Nenhum campo para sensitivity tags acumulados de requests anteriores.** O `EthicalContextEngine` decide cego quanto ao histórico semântico da sessão.

### Por que não resolver no Rust

O paper é claro: o componente simbólico (Rust Kernel) não pode avaliar **quais combinações de informação são perigosas** — isso requer compreensão semântica. O que o Kernel pode fazer é expor metadados estruturais (quais validadores dispararam, quais categorias de finding apareceram) para que o Governance acumule e interprete.

A proposta original da síntese sugeria um `AlignmentSignal` struct no hot path Rust. Após leitura integral do paper, isso é incorreto: o acumulador deve viver no **Python Governance** (componente com capacidade semântica), não no Kernel (componente simbólico puro).

---

## Decisão

### 1. `SessionSensitivityAccumulator` (novo módulo Python)
```
python/buildtovalue/governance/sensitivity_accumulator.py
```
```python
"""
SessionSensitivityAccumulator v1.0.0 — ADR-044

Acumula sensitivity tags por sessão com base em findings
observados ao longo do tempo. Expõe risco cumulativo ao
EthicalContextEngine para que decisões considerem o
histórico semântico, não apenas o request atual.

Filosofia:
  - Hybrid Alignment (paper 147): ponte bidirecional
    neural↔simbólico
  - Jonas: acúmulo rastreado = responsabilidade sobre
    o que o sistema já forneceu
  - Levinas: proteger contra combinações perigosas
    mesmo quando cada request é legítimo

Performance: O(1) por request (lookup + append em dict)
≤ 200 linhas
"""

import time
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional
from collections import defaultdict

logger = logging.getLogger("btv.governance.sensitivity")

# ─────────────────────────────────────────────────────────
# SENSITIVITY TAG TAXONOMY
# ─────────────────────────────────────────────────────────

# Tags derivadas de findings do Kernel (mapeamento determinístico).
# Extensível via YAML em data/policies/sensitivity_tags.yaml (v1.9+).
FINDING_TO_SENSITIVITY: Dict[str, str] = {
    "cpf": "PII_BRAZILIAN",
    "cnpj": "PII_BRAZILIAN_CORPORATE",
    "email": "PII_CONTACT",
    "phone": "PII_CONTACT",
    "credit_card": "FINANCIAL",
    "ssn": "PII_US_GOV",
    "nhs": "PII_UK_HEALTH",
    "vat": "PII_EU_FISCAL",
    "iban": "FINANCIAL_EU",
    "prompt_injection": "SECURITY_INJECTION",
}

# Combinações que elevam risco cumulativo.
# Inspirado no exemplo do paper: cada tag isolada é OK,
# a combinação cruza threshold.
DANGEROUS_COMBINATIONS: List[Set[str]] = [
    {"PII_BRAZILIAN", "FINANCIAL"},           # CPF + cartão
    {"PII_CONTACT", "PII_BRAZILIAN"},         # email + CPF
    {"SECURITY_INJECTION", "PII_BRAZILIAN"},  # injection + PII
    {"PII_US_GOV", "FINANCIAL"},              # SSN + financeiro
    {"PII_UK_HEALTH", "PII_CONTACT"},         # NHS + contato
]

COMBINATION_RISK_BOOST = 0.15  # por combinação perigosa ativa
SESSION_TTL_SECONDS = 1800     # 30min, alinhado com SessionTracker Rust
MAX_TAGS_PER_SESSION = 50      # cap para prevenir memory bloat


# ─────────────────────────────────────────────────────────
# SESSION SENSITIVITY STATE
# ─────────────────────────────────────────────────────────

@dataclass
class SensitivityState:
    """Estado de sensibilidade acumulado por sessão."""
    tags: Set[str] = field(default_factory=set)
    tag_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    cumulative_risk: float = 0.0
    active_combinations: List[str] = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    request_count: int = 0

    def is_expired(self) -> bool:
        return (time.time() - self.last_seen) > SESSION_TTL_SECONDS


# ─────────────────────────────────────────────────────────
# ACCUMULATOR
# ─────────────────────────────────────────────────────────

class SessionSensitivityAccumulator:
    """
    Acumula sensitivity tags cross-request por sessão.

    Uso pelo EthicalContextEngine:
        1. Após cada scan, chamar accumulate(session_id, findings_summary)
        2. Antes de decide(), chamar get_state(session_id)
        3. Injetar cumulative_risk e active_combinations no contexto

    Invariantes:
        - Nunca modifica o request atual — apenas informa
        - TTL alinhado com SessionTracker Rust (30min)
        - Cap de tags previne memory abuse
    """

    def __init__(self, max_sessions: int = 10_000):
        self._sessions: Dict[str, SensitivityState] = {}
        self._max_sessions = max_sessions
        self.metrics = {
            "accumulations": 0,
            "combinations_detected": 0,
            "evictions": 0,
        }

    def accumulate(
        self,
        session_id: str,
        findings_summary: List[str],
    ) -> SensitivityState:
        """
        Registra findings do request atual na sessão.

        Args:
            session_id: ID da sessão (opaco)
            findings_summary: Lista de validator names que produziram
                findings (ex: ["cpf", "email"])

        Returns:
            Estado atualizado da sessão.
        """
        self._evict_expired()
        self.metrics["accumulations"] += 1

        state = self._sessions.get(session_id)
        if state is None or state.is_expired():
            if len(self._sessions) >= self._max_sessions:
                self._evict_oldest()
            state = SensitivityState()
            self._sessions[session_id] = state

        state.last_seen = time.time()
        state.request_count += 1

        # Mapear findings para sensitivity tags
        for finding_type in findings_summary:
            tag = FINDING_TO_SENSITIVITY.get(finding_type.lower())
            if tag and len(state.tags) < MAX_TAGS_PER_SESSION:
                state.tags.add(tag)
                state.tag_counts[tag] += 1

        # Avaliar combinações perigosas
        state.active_combinations = []
        combination_boost = 0.0
        for combo in DANGEROUS_COMBINATIONS:
            if combo.issubset(state.tags):
                label = " + ".join(sorted(combo))
                state.active_combinations.append(label)
                combination_boost += COMBINATION_RISK_BOOST
                self.metrics["combinations_detected"] += 1

        state.cumulative_risk = min(1.0, combination_boost)
        return state

    def get_state(self, session_id: str) -> Optional[SensitivityState]:
        """Retorna estado acumulado ou None se sessão não existe/expirou."""
        state = self._sessions.get(session_id)
        if state is None or state.is_expired():
            return None
        return state

    def _evict_expired(self) -> None:
        expired = [
            sid for sid, s in self._sessions.items()
            if s.is_expired()
        ]
        for sid in expired:
            del self._sessions[sid]
            self.metrics["evictions"] += 1

    def _evict_oldest(self) -> None:
        if not self._sessions:
            return
        oldest = min(
            self._sessions,
            key=lambda sid: self._sessions[sid].last_seen,
        )
        del self._sessions[oldest]
        self.metrics["evictions"] += 1
```

### 2. Extensão do `RequestContext`
```python
# Em python/buildtovalue/governance/context_engine.py

@dataclass
class RequestContext:
    agent_id: str
    session_id: str
    domain: str = "general"
    user_role: str = "anonymous"
    ip_jurisdiction: str = "XX"
    ip_risk: str = "Low"
    drift_level: str = "None"
    timestamp: int = 0

    # ADR-044: Hybrid Alignment — sensitivity acumulado
    prior_sensitivity_tags: list = field(default_factory=list)
    cumulative_risk: float = 0.0
    active_combinations: list = field(default_factory=list)

    def __post_init__(self):
        if self.timestamp == 0:
            self.timestamp = int(time.time())
```

### 3. Integração no `app.py` (gateway Python)

No endpoint `/v1/decide`, **após** o scan Rust e **antes** de `_ethical_engine.decide()`:
```python
# Acumular sensitivity desta request
sensitivity_state = _sensitivity_accumulator.accumulate(
    session_id=session_id,
    findings_summary=[f.validator for f in findings],  # do scan Rust
)

# Injetar no contexto para o EthicalContextEngine
context = RequestContext(
    agent_id=req.profile or "default",
    session_id=session_id,
    # ... campos existentes ...
    prior_sensitivity_tags=list(sensitivity_state.tags),
    cumulative_risk=sensitivity_state.cumulative_risk,
    active_combinations=sensitivity_state.active_combinations,
)
```

### 4. Uso no `EthicalContextEngine.decide()`

No `_explain_decision()` e no cálculo de mercy, o `cumulative_risk` **adiciona** ao `composite_risk` sem substituí-lo:
```python
# Dentro de decide():
adjusted_risk = min(1.0, evidence.composite_risk + context.cumulative_risk)
```

Se `adjusted_risk > 0.7` e `evidence.composite_risk <= 0.3`, o sistema detectou um caso Hybrid Alignment: **request individual seguro, acúmulo perigoso**. A `explanation` deve declarar isso:
```
"Hybrid Alignment: request individual avaliado como LOW risk, 
porém acúmulo de sessão detectou combinação perigosa: 
PII_BRAZILIAN + FINANCIAL. Risco cumulativo elevado para 0.45."
```

### 5. O que NÃO muda

- **Rust Kernel**: zero alterações. O Kernel continua produzindo `TechnicalEvidence` e `SessionVector` exatamente como hoje.
- **`SessionTracker` Rust**: continua rastreando drift estatístico (ortogonal ao acúmulo semântico).
- **`BlindEvaluator` (ADR-042)**: o PolicyTester avalia policies sem contexto identitário. `cumulative_risk` é contexto de **sessão**, não de identidade — compatível com o véu de Rawls.
- **Hot path**: nenhuma alocação heap no Rust. O acumulador vive inteiramente no Python.

---

## Filosofia

**Paper 147 (Hybrid Alignment):** O `SessionSensitivityAccumulator` é a implementação concreta do "symbolic component designed to expose information that neural components need for safety reasoning". O componente simbólico (acumulador) mantém metadados estruturados; o componente com capacidade semântica (EthicalContextEngine) interpreta o que significa.

**Rawls (Equidade):** Mesma combinação de tags → mesmo `cumulative_risk`, independente de quem é o agente. O acumulador não recebe `agent_id` ou `user_role`.

**Levinas (Proteção):** Protege contra combinações perigosas que nenhum request individual revela. O acúmulo é a "face do outro" — o sistema vê a pessoa na totalidade de suas interações, não atomizada.

**Jonas (Responsabilidade):** `active_combinations` é rastreável no ledger via `explanation`. Decisões baseadas em acúmulo são explicáveis e contestáveis.

**Gilligan (Cuidado):** `cumulative_risk` adiciona ao risco mas passa pelo MercyCalculator normalmente. Um agente com high trust que acumula tags perigosas pela primeira vez pode receber EDUCATE em vez de BLOCK.

---

## Consequências

### Positivas
- Fecha o gap bidirecional identificado pelo paper 147
- Detecta cenários de acúmulo cross-request que o SessionTracker drift não captura
- Zero impacto no hot path Rust (< 30ms invariante mantido)
- `DANGEROUS_COMBINATIONS` extensível via YAML (v1.9+)
- `explanation` documenta quando acúmulo influenciou a decisão → auditável

### Negativas
- `Dict[str, SensitivityState]` em memória no Python — O(sessions × tags). Com cap de 10k sessões × 50 tags, ~5MB pior caso. Aceitável para v1.8; migrar para Redis em v2.0+
- `FINDING_TO_SENSITIVITY` e `DANGEROUS_COMBINATIONS` são hardcoded. Suficiente para v1.8; externalizar para YAML em v1.9
- TTL de 30min pode ser curto para o cenário do paper (meses). Para acúmulo cross-session longo, necessário persistência (SQLite/Redis) — v2.0+

### Riscos
- **False positives por combinação**: CPF + credit_card pode ser legítimo em agente financeiro. Mitigação: `threat_model.trust_boundary` (ADR-045) pode filtrar combinações por perímetro
- **TTL alignment**: Se Rust SessionTracker evictar sessão antes do Python accumulator (ou vice-versa), divergência de estado. Mitigação: ambos usam TTL=30min

---

## Implementação

### Arquivos

| Arquivo | Ação |
|---|---|
| `python/buildtovalue/governance/sensitivity_accumulator.py` | **NOVO** — módulo completo |
| `python/buildtovalue/governance/context_engine.py` | Adicionar 3 campos ao `RequestContext` |
| `python/buildtovalue/governance/__init__.py` | Re-export `SessionSensitivityAccumulator` |
| `python/buildtovalue/api/app.py` | Instanciar acumulador no lifespan, integrar no `/v1/decide` |
| `python/tests/unit/governance/test_sensitivity_accumulator.py` | **NOVO** — testes unitários |

### Testes obrigatórios

1. `test_single_finding_no_combination` — tag isolada, cumulative_risk = 0.0
2. `test_two_requests_create_combination` — CPF (req 1) + credit_card (req 2) → combinação detectada
3. `test_session_ttl_expires` — após 30min, estado limpo
4. `test_max_tags_cap` — 51º tag ignorado
5. `test_max_sessions_eviction` — 10001ª sessão evicta a mais antiga
6. `test_cumulative_risk_capped_at_1` — múltiplas combinações não excedem 1.0
7. `test_context_fields_populated` — `RequestContext` com campos ADR-044 preenchidos
8. `test_explain_mentions_combination` — explanation inclui "Hybrid Alignment" quando acúmulo influencia

### Estimativa

- **Dev Python:** ~3h (módulo + integração app.py + testes)
- **Review:** ~1h
- **Documentação:** este ADR

---

## Referências

- Paper 147: "LLM Agentic System Safety Requires Hybrid Alignment" (ICLR 2026 Workshop)
- ADR-032: ScanContextFlags (metadados estruturais do Kernel)
- ADR-014: SessionGuard / SessionTracker (drift comportamental)
- ADR-039: TrustScoreCalculator (trust score por sessão)
- ADR-045: Policy Schema threat_model (filtro por perímetro — complementar)

---

## Checklist de Review (Reviewer Opus)

- [ ] `sensitivity_accumulator.py` ≤ 200 linhas
- [ ] Nenhum `Any` em type hints
- [ ] TTL alinhado com `SESSION_TTL_SECS` do Rust SessionTracker (1800s)
- [ ] `DANGEROUS_COMBINATIONS` documentadas com rationale
- [ ] `cumulative_risk` nunca substitui `composite_risk` — apenas adiciona
- [ ] `RequestContext` novos campos têm defaults (retrocompatível)
- [ ] `explanation` declara quando acúmulo influenciou decisão
- [ ] Zero alterações em `rust/` (invariante: Kernel inalterado)
- [ ] Métricas expostas para Prometheus (combinations_detected, evictions)
- [ ] BiasDeclaration do acumulador documentada (FPR/FNR das combinações hardcoded)

### O Que Está Bem Feito (obrigatório por AI Squad Workflow)
*(preenchido pelo Reviewer após implementação)*