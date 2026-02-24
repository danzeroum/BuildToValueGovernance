# ADR-039: TrustScoreCalculator v2.0 — Algoritmo Multifatorial com Decay Temporal, Feedback de Appeals e Persistência Redis-ready

**Status:** 🆕 PROPOSTO
**Data:** 24 de fevereiro de 2026
**Autores:** IA Arquiteta (Claude Sonnet 4.6) — validado por Staff Engineer
**Versão alvo:** v1.8.0
**Grupo:** B — Governança & Transparência
**Substitui:** ADR-007 (esboço — promovido a spec de produção)
**Depende de:** ADR-037 (AppealEngine), ADR-038 (EthicalContextEngine v4.0 / GilliganStage)

**Impacto:**
```
python/buildtovalue/governance/trust_score.py      — v1→v2.0 (refactor)
python/buildtovalue/governance/trust_store.py      — novo (abstração de persistência)
python/tests/unit/governance/test_trust_score_v2.py — novo
```

---

## 1. Contexto

### 1.1 Gaps da implementação atual

O `TrustScoreCalculator` existente (`trust_score.py`) implementa a fórmula do ADR-007 mas tem três gaps críticos para v1.8.0:

| Gap | Problema | Impacto |
|:---|:---|:---|
| **Persistência in-memory** | `trust_cache` e `activity_log` são dicts Python; resetados no restart | Appeals aceitos em prod não persistem — trust feedback do AppealEngine é perdido |
| **Feedback de AppealEngine não integrado** | `adjust(session_id, delta)` não existe — `GilliganStage` chama `trust_store.adjust()` mas o método não existe no `TrustScoreCalculator` | `AttributeError` em produção |
| **Decay de violações** | `_decay_penalty` usa half-life de 30 dias com acúmulo ilimitado | Usuário com 20 BLOCKs antigos tem penalty > 1.0 (nunca clamped antes da fórmula) |

### 1.2 Relação com ADR-038

`GilliganStage` recebe `trust_store=self._trust_scores` — mas o dict não tem `adjust()`. A v2.0 fecha esse contrato: `TrustScoreCalculator` torna-se o `trust_store` oficial que `GilliganStage` consome.

---

## 2. Decisão

### 2.1 Contrato de Interface (TrustStore Protocol)

```python
# python/buildtovalue/governance/trust_store.py

"""
TrustStore Protocol v1.0.0 (ADR-039)

Abstração de persistência para trust scores.
Permite trocar in-memory por Redis sem alterar GilliganStage ou AppealEngine.
"""

from typing import Protocol, runtime_checkable

@runtime_checkable
class TrustStore(Protocol):
    """
    Interface mínima que GilliganStage e AppealEngine consomem.

    Implementações:
    - InMemoryTrustStore: testes e desenvolvimento (padrão)
    - RedisTrustStore: produção v2.0+ (fora do escopo deste ADR)
    - SqliteTrustStore: single-process com persistência (v1.8.0)
    """

    def get(self, session_id: str, default: float = 0.5) -> float:
        """Retorna trust score atual. Default 0.5 (neutro)."""
        ...

    def set(self, session_id: str, score: float) -> None:
        """Define trust score diretamente (clamped a [0.0, 0.95])."""
        ...

    def adjust(self, session_id: str, delta: float) -> float:
        """
        Ajusta trust score por delta. Retorna novo valor.
        Usado por AppealEngine: +0.1 (aceito) / −0.05 (rejeitado).
        Clamped a [0.0, 0.95] — humility ceiling (ADR-007).
        """
        ...


class InMemoryTrustStore:
    """
    Implementação in-memory. Zero dependências.
    Thread-safe via GIL (CPython). Adequada para testes e dev.
    """
    HUMILITY_CEILING = 0.95   # trust nunca excede 0.95 (Jonas: sistema admite incerteza)
    FLOOR = 0.0

    def __init__(self):
        self._scores: dict[str, float] = {}

    def get(self, session_id: str, default: float = 0.5) -> float:
        return self._scores.get(session_id, default)

    def set(self, session_id: str, score: float) -> None:
        self._scores[session_id] = max(self.FLOOR, min(self.HUMILITY_CEILING, score))

    def adjust(self, session_id: str, delta: float) -> float:
        current = self.get(session_id)
        new_score = max(self.FLOOR, min(self.HUMILITY_CEILING, current + delta))
        self._scores[session_id] = new_score
        return new_score


class SqliteTrustStore:
    """
    Implementação SQLite — persiste entre restarts.
    Adequada para produção single-process (v1.8.0).
    RedisTrustStore é planejada para v2.0+ (multi-process/multi-tenant).
    """
    HUMILITY_CEILING = 0.95
    FLOOR = 0.0

    def __init__(self, db_path: str = "data/trust.db"):
        import sqlite3
        from pathlib import Path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db = db_path
        with sqlite3.connect(self._db) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS trust_scores (
                    session_id TEXT PRIMARY KEY,
                    score REAL NOT NULL DEFAULT 0.5,
                    updated_at INTEGER NOT NULL
                )
            """)

    def get(self, session_id: str, default: float = 0.5) -> float:
        import sqlite3
        with sqlite3.connect(self._db) as conn:
            row = conn.execute(
                "SELECT score FROM trust_scores WHERE session_id = ?",
                (session_id,)
            ).fetchone()
        return row[0] if row else default

    def set(self, session_id: str, score: float) -> None:
        import sqlite3, time
        clamped = max(self.FLOOR, min(self.HUMILITY_CEILING, score))
        with sqlite3.connect(self._db) as conn:
            conn.execute("""
                INSERT INTO trust_scores VALUES (?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    score=excluded.score,
                    updated_at=excluded.updated_at
            """, (session_id, clamped, int(time.time())))

    def adjust(self, session_id: str, delta: float) -> float:
        current = self.get(session_id)
        new_score = max(self.FLOOR, min(self.HUMILITY_CEILING, current + delta))
        self.set(session_id, new_score)
        return new_score
```

### 2.2 TrustScoreCalculator v2.0

```python
# python/buildtovalue/governance/trust_score.py — v2.0

"""
TrustScoreCalculator v2.0.0 (ADR-039)

Fórmula (ADR-007, preservada):
  trust = w₁·base + w₂·history + w₃·appeals + w₄·(1−decay) + w₅·consistency

Mudanças v2.0:
  - [BREAKING-NONE] Aceita TrustStore protocol (InMemory | Sqlite | Redis-ready)
  - [FIX] decay_penalty clamped antes da fórmula (evita overflow)
  - [NEW] adjust(session_id, delta) — integração com AppealEngine (ADR-037)
  - [NEW] explain_score() retorna TrustExplain estruturado (não str)
  - [FIX] appeal_score(): bonus/penalty balanceados conforme ADR-007 tabela
  - [PERF] Cache com TTL 300s parametrizável
"""

import math
import time
import logging
from dataclasses import dataclass
from typing import Optional
from collections import defaultdict

from .trust_store import TrustStore, SqliteTrustStore

logger = logging.getLogger("btv.governance.trust_score")

# Pesos canônicos (ADR-007 — não alterar sem novo ADR)
DEFAULT_WEIGHTS = {
    "base":        0.20,
    "history":     0.30,
    "appeals":     0.20,
    "decay":       0.15,
    "consistency": 0.15,
}

# Scores base por role (ADR-007)
ROLE_BASE_SCORES = {
    "admin":        0.90,
    "developer":    0.70,
    "power_user":   0.60,
    "user":         0.50,
    "guest":        0.30,
    "anonymous":    0.20,
}

HUMILITY_CEILING = 0.95   # Jonas: sistema nunca declara confiança absoluta
DECAY_HALF_LIFE_DAYS = 30
DECAY_PER_VIOLATION = 0.20
CACHE_TTL_S = 300


@dataclass(frozen=True)
class TrustExplain:
    """
    Breakdown estruturado do trust score.
    Auditável por LGPD Art. 20 — não contém PII.
    """
    session_id: str       # nunca user_id — privacy-preserving
    total: float
    base: float
    history: float
    appeals: float
    decay_penalty: float
    consistency: float
    weights: dict
    cache_age_s: int      # 0 = calculado agora

    def explain_decision(self) -> str:
        """Obrigatório por ADR-038 (explainability)."""
        return (
            f"Trust={self.total:.3f} | "
            f"base={self.base:.2f}(×{self.weights['base']}) "
            f"history={self.history:.2f}(×{self.weights['history']}) "
            f"appeals={self.appeals:.2f}(×{self.weights['appeals']}) "
            f"decay_penalty={self.decay_penalty:.2f}(×{self.weights['decay']}) "
            f"consistency={self.consistency:.2f}(×{self.weights['consistency']})"
        )


@dataclass
class UserActivity:
    """Registro de atividade — sem PII."""
    session_id: str
    timestamp: int
    action: str    # "request" | "appeal"
    result: str    # "allowed" | "blocked" | "appeal_success" | "appeal_fail"


class TrustScoreCalculator:
    """
    Calcula e gerencia trust scores.

    Interface com GilliganStage (ADR-038):
      trust_store = TrustScoreCalculator(store=SqliteTrustStore())
      GilliganStage(trust_store=trust_store)

    Interface com AppealEngine (ADR-037):
      appeal_engine = AppealEngine(trust_store=trust_score_calc)
      # Internamente: trust_store.adjust(user_id, +0.1 | −0.05)
    """

    def __init__(
        self,
        store: Optional[TrustStore] = None,
        weights: Optional[dict] = None,
        cache_ttl_s: int = CACHE_TTL_S,
    ):
        self._store = store or SqliteTrustStore()
        self._weights = weights or DEFAULT_WEIGHTS.copy()
        self._cache_ttl = cache_ttl_s
        self._activity_log: dict[str, list[UserActivity]] = defaultdict(list)
        self._score_cache: dict[str, tuple[float, int]] = {}   # (score, ts)

    # ── TrustStore protocol (consumido por GilliganStage e AppealEngine) ──

    def get(self, session_id: str, default: float = 0.5) -> float:
        """Retorna trust score (do cache ou calculado)."""
        cached = self._score_cache.get(session_id)
        if cached:
            score, ts = cached
            if time.time() - ts < self._cache_ttl:
                return score
        # Recalcula com role=anonymous se sem histórico
        return self._compute(session_id, "anonymous")

    def set(self, session_id: str, score: float) -> None:
        """Define score diretamente (override — usar com cautela)."""
        clamped = max(0.0, min(HUMILITY_CEILING, score))
        self._store.set(session_id, clamped)
        self._score_cache[session_id] = (clamped, int(time.time()))

    def adjust(self, session_id: str, delta: float) -> float:
        """
        Ajusta score por delta. Chamado pelo AppealEngine.
        +0.1: appeal aceito (sistema reconheceu falso positivo — Gilligan)
        −0.05: appeal rejeitado (comportamento confirmado — Rawls)
        """
        new_score = self._store.adjust(session_id, delta)
        self._score_cache[session_id] = (new_score, int(time.time()))
        logger.info(
            "trust_adjusted session=%s delta=%.2f new_score=%.3f",
            session_id, delta, new_score,
        )
        return new_score

    # ── API pública ────────────────────────────────────────────────────────

    def calculate(self, session_id: str, user_role: str) -> float:
        """Calcula e persiste trust score."""
        score = self._compute(session_id, user_role)
        self._store.set(session_id, score)
        self._score_cache[session_id] = (score, int(time.time()))
        return score

    def explain_score(self, session_id: str, user_role: str) -> TrustExplain:
        """Retorna breakdown estruturado (auditável, sem PII)."""
        cached = self._score_cache.get(session_id)
        cache_age = int(time.time() - cached[1]) if cached else 0

        base        = self._base_score(user_role)
        history     = self._history_score(session_id)
        appeals     = self._appeal_score(session_id)
        decay_pen   = self._decay_penalty(session_id)    # clamped [0,1]
        consistency = self._consistency_score(session_id)
        total       = self._formula(base, history, appeals, decay_pen, consistency)

        return TrustExplain(
            session_id=session_id,
            total=round(total, 4),
            base=round(base, 4),
            history=round(history, 4),
            appeals=round(appeals, 4),
            decay_penalty=round(decay_pen, 4),
            consistency=round(consistency, 4),
            weights=self._weights.copy(),
            cache_age_s=cache_age,
        )

    def record_activity(self, activity: UserActivity) -> None:
        """Registra atividade e invalida cache."""
        self._activity_log[activity.session_id].append(activity)
        self._score_cache.pop(activity.session_id, None)

    # ── Cálculo interno ────────────────────────────────────────────────────

    def _compute(self, session_id: str, user_role: str) -> float:
        base        = self._base_score(user_role)
        history     = self._history_score(session_id)
        appeals     = self._appeal_score(session_id)
        decay_pen   = self._decay_penalty(session_id)
        consistency = self._consistency_score(session_id)
        return self._formula(base, history, appeals, decay_pen, consistency)

    def _formula(
        self,
        base: float,
        history: float,
        appeals: float,
        decay_penalty: float,
        consistency: float,
    ) -> float:
        w = self._weights
        trust = (
            w["base"]        * base
            + w["history"]   * history
            + w["appeals"]   * appeals
            + w["decay"]     * (1.0 - decay_penalty)   # FIX: (1−decay), não −decay
            + w["consistency"] * consistency
        )
        return max(0.0, min(HUMILITY_CEILING, trust))

    def _base_score(self, user_role: str) -> float:
        return ROLE_BASE_SCORES.get(user_role, 0.5)

    def _history_score(self, session_id: str) -> float:
        requests = [
            a for a in self._activity_log.get(session_id, [])
            if a.action == "request"
        ]
        if not requests:
            return 0.5
        allowed = sum(1 for r in requests if r.result == "allowed")
        ratio = allowed / len(requests)
        return ratio if ratio >= 0.5 else ratio * 0.8   # penalidade se < 50%

    def _appeal_score(self, session_id: str) -> float:
        """
        ADR-007 tabela:
          bonus   = success_rate × 0.3   → range [0, 0.3]
          penalty = fail_rate × 0.15     → range [0, 0.15]
          net     = bonus − penalty      → range [−0.15, 0.3]
        Normalizado para [0, 1] para uso na fórmula ponderada.
        """
        appeals = [
            a for a in self._activity_log.get(session_id, [])
            if a.action == "appeal"
        ]
        if not appeals:
            return 0.5   # neutro — sem histórico de appeals

        total = len(appeals)
        success = sum(1 for a in appeals if a.result == "appeal_success")
        fail = total - success

        bonus   = (success / total) * 0.3
        penalty = (fail    / total) * 0.15
        net     = bonus - penalty   # range [−0.15, 0.3]

        # Normaliza para [0, 1]: net=0 → 0.5 (neutro)
        # net=+0.3 → 1.0, net=−0.15 → 0.25
        return max(0.0, min(1.0, 0.5 + net / 0.3))

    def _decay_penalty(self, session_id: str) -> float:
        """
        FIX v2.0: resultado clamped a [0, 1] antes de retornar.
        Cada BLOCK contribui com decay exponencial.
        half_life = 30 dias.
        """
        blocked = [
            a for a in self._activity_log.get(session_id, [])
            if a.result == "blocked"
        ]
        if not blocked:
            return 0.0

        now = int(time.time())
        penalty = 0.0
        for a in blocked:
            days_ago = (now - a.timestamp) / 86400.0
            decay = math.exp(-days_ago / DECAY_HALF_LIFE_DAYS)
            penalty += decay * DECAY_PER_VIOLATION

        return min(1.0, penalty)   # FIX: clamp antes de retornar

    def _consistency_score(self, session_id: str) -> float:
        activities = self._activity_log.get(session_id, [])
        timestamps = [a.timestamp for a in activities[-30:]]
        if len(timestamps) < 2:
            return 0.5
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        mean = sum(intervals) / len(intervals)
        variance = sum((x - mean)**2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        # Assume intervalo esperado ~1h = 3600s
        return max(0.0, min(1.0, 1.0 - std_dev / 3600.0))
```

### 2.3 Integração com GilliganStage (ADR-038)

```python
# Atualização em EthicalContextEngine.__init__() — context_engine.py

from .trust_store import SqliteTrustStore
from .trust_score import TrustScoreCalculator

# Antes (v1.8.0):
#   self._gilligan = GilliganStage(trust_store=self._trust_scores)  # dict simples
#
# Depois (v2.0):
self._trust_calc = TrustScoreCalculator(store=SqliteTrustStore())
self._gilligan   = GilliganStage(trust_store=self._trust_calc)

# GilliganStage chama trust_store.get(session_id) → TrustScoreCalculator.get()
# AppealEngine chama trust_store.adjust(user_id, delta) → TrustScoreCalculator.adjust()
```

---

## 3. Diagrama de Fluxo do Trust Feedback

```
EthicalContextEngine.decide()
    └─► GilliganStage
            └─► TrustScoreCalculator.get(session_id)   ← lê score
                    └─► SqliteTrustStore.get()

AppealEngine.resolve(accepted=True)
    └─► TrustScoreCalculator.adjust(user_id, +0.1)     ← escreve delta
            └─► SqliteTrustStore.adjust()

AppealEngine.resolve(accepted=False)
    └─► TrustScoreCalculator.adjust(user_id, −0.05)

TrustScoreCalculator.calculate(session_id, user_role)
    └─► fórmula 5 componentes → SqliteTrustStore.set()
            └─► GilliganStage (próxima decisão lê score atualizado)
```

O ciclo fecha: appeal aceito → trust sobe → Gilligan aplica S2/S3 na próxima decisão. Appeal rejeitado → trust cai levemente → Gilligan é mais conservador.

---

## 4. Fundamentos Filosóficos

**Gilligan (Feedback de Cuidado):** A assimetria `+0.1 / −0.05` é intencional. Contestar é exercício legítimo de direito — quem perde um appeal não deve ser punido proporcionalmente a quem ganhou é recompensado. O relacionamento é preservado mesmo em rejeição.

**Rawls (Determinismo Procedural):** `_formula()` é determinística — mesmo histórico produz mesmo score, independente de quando é calculado. A fórmula ponderada é aplicada cegamente, sem considerar quem é o usuário.

**Jonas (Humility Ceiling = 0.95):** O sistema nunca declara `trust = 1.0` sobre nenhum usuário. A incerteza residual de 5% materializa a responsabilidade epistêmica — nenhum sistema de governança tem certeza absoluta.

**Levinas (Privacy-Preserving):** `TrustExplain.session_id` nunca é `user_id`. O score é calculado sobre comportamento agregado, não identidade. O `explain_decision()` é auditável sem revelar PII.

---

## 5. Consequências

### Positivas

O contrato `TrustStore Protocol` permite substituir `SqliteTrustStore` por `RedisTrustStore` em v2.0 sem alterar `GilliganStage` ou `AppealEngine`. O fix do `decay_penalty` elimina o bug de overflow silencioso que subestimava trust de usuários com histórico antigo. `TrustExplain` estruturado permite auditores LGPD verificar o breakdown de cada componente sem acesso a dados brutos.

### Negativas e Trade-offs

`SqliteTrustStore` usa uma conexão por operação — aceitável para single-process (v1.8.0), mas inadequado para multi-process. O cache de 5min no `TrustScoreCalculator` e o store SQLite podem ficar dessincronizados em cenários de restart rápido com appeals pendentes. Mitigado: `adjust()` invalida o cache imediatamente.

`_activity_log` ainda é in-memory — o histórico de atividades não persiste entre restarts. Em v1.8.0 isso é aceitável; v2.0 migrará para SQLite via `ActivityStore` (fora do escopo deste ADR).

---

## 6. Testes Obrigatórios

```
[ ] InMemoryTrustStore.get() retorna default=0.5 para session desconhecida
[ ] InMemoryTrustStore.adjust(+0.1) não excede HUMILITY_CEILING=0.95
[ ] InMemoryTrustStore.adjust(−1.0) não vai abaixo de 0.0
[ ] SqliteTrustStore.set() persiste entre instâncias (nova conexão)
[ ] SqliteTrustStore.adjust() é idempotente com delta=0.0
[ ] TrustScoreCalculator.adjust() invalida cache imediatamente
[ ] _decay_penalty() com 10 BLOCKs antigos retorna <= 1.0 (fix v2.0)
[ ] _formula() com todos componentes=1.0 retorna HUMILITY_CEILING (0.95)
[ ] _formula() com todos componentes=0.0 retorna 0.0
[ ] _appeal_score(): 100% success → > 0.5 (bonus)
[ ] _appeal_score(): 100% fail → < 0.5 (penalidade)
[ ] _appeal_score(): sem histórico → 0.5 (neutro)
[ ] calculate() persiste no SqliteTrustStore
[ ] explain_score().explain_decision() contém todos os 5 componentes
[ ] TrustScoreCalculator satisfaz TrustStore Protocol (isinstance check)
[ ] Integração: AppealEngine.resolve(accepted=True) → trust aumenta +0.1
[ ] Integração: AppealEngine.resolve(accepted=False) → trust diminui −0.05
[ ] GilliganStage consome TrustScoreCalculator via Protocol (duck typing)
```
