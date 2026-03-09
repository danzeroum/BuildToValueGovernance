"""
SessionSensitivityAccumulator v1.3.0 — ADR-046

Acumula sensitivity tags por sessão com base em findings observados
ao longo do tempo. Expõe risco cumulativo ao EthicalContextEngine
para que decisões considerem o histórico semântico (Hybrid Alignment).

Filosofia:
  - Hybrid Alignment (ICLR 2026, paper 147): ponte neural↔simbólico
  - Jonas: acúmulo rastreado = responsabilidade sobre o que foi fornecido;
    frequência indica intenção, não acidente
  - Levinas: proteger contra combinações perigosas mesmo quando cada
    request individual é legítimo

Changelog:
  v1.1.0 (Sprint 1, Gaps 6, 7): tag_counts→cumulative_risk, metrics corretos
  v1.2.0 (Sprint 4, Gaps 8, 18): +6 DANGEROUS_COMBINATIONS ausentes
    - Corporativas: PII_BRAZILIAN_CORPORATE + FINANCIAL/PII_BRAZILIAN
    - Cross-jurisdicionais: PII_EU_FISCAL + FINANCIAL_EU
    - Injection expandido: SECURITY_INJECTION + PII_US_GOV/PII_UK_HEALTH/PII_EU_FISCAL
  v1.3.0 (Sprint 5, Gaps 5/17): SessionManager LRU+TTL unificado
    - Remove _evict_expired() O(n) scan completo
    - Remove _evict_oldest() O(n) min() scan
    - Substitui por SessionManager.touch() O(1) amortizado

Performance: O(1) por request (dict lookup + set operations + LRU amortizado)
Limite de linhas: ≤ 250
"""

import time
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from collections import defaultdict

from .session_manager import SessionManager

logger = logging.getLogger("btv.governance.sensitivity")

# ───────────────────────────────────────────────────────────────────────────────
# TAXONOMIA DE SENSITIVITY TAGS
# ───────────────────────────────────────────────────────────────────────────────

FINDING_TO_SENSITIVITY: Dict[str, str] = {
    "cpf":              "PII_BRAZILIAN",
    "cnpj":             "PII_BRAZILIAN_CORPORATE",
    "email":            "PII_CONTACT",
    "phone":            "PII_CONTACT",
    "credit_card":      "FINANCIAL",
    "ssn":              "PII_US_GOV",
    "nhs":              "PII_UK_HEALTH",
    "vat":              "PII_EU_FISCAL",
    "iban":             "FINANCIAL_EU",
    "prompt_injection": "SECURITY_INJECTION",
}

# ───────────────────────────────────────────────────────────────────────────────
# DANGEROUS_COMBINATIONS v1.2.0 (12 combinações)
# ───────────────────────────────────────────────────────────────────────────────
DANGEROUS_COMBINATIONS: List[frozenset] = [
    # ── Originais (v1.0) ────────────────────────────────────────────────────────────────
    frozenset({"PII_BRAZILIAN",             "FINANCIAL"}),
    frozenset({"PII_CONTACT",               "PII_BRAZILIAN"}),
    frozenset({"SECURITY_INJECTION",        "PII_BRAZILIAN"}),
    frozenset({"SECURITY_INJECTION",        "PII_CONTACT"}),
    frozenset({"PII_US_GOV",               "FINANCIAL"}),
    frozenset({"PII_UK_HEALTH",            "PII_CONTACT"}),
    # ── Gap 8: Corporativas (v1.2.0) ────────────────────────────────────────────────
    frozenset({"PII_BRAZILIAN_CORPORATE",   "FINANCIAL"}),
    frozenset({"PII_BRAZILIAN_CORPORATE",   "PII_BRAZILIAN"}),
    # ── Gap 8: Cross-jurisdicionais (v1.2.0) ─────────────────────────────────────────
    frozenset({"PII_EU_FISCAL",             "FINANCIAL_EU"}),
    # ── Gap 18: Injection expandido (v1.2.0) ──────────────────────────────────────
    frozenset({"SECURITY_INJECTION",        "PII_US_GOV"}),
    frozenset({"SECURITY_INJECTION",        "PII_UK_HEALTH"}),
    frozenset({"SECURITY_INJECTION",        "PII_EU_FISCAL"}),
]

COMBINATION_RISK_BOOST: float = 0.15
SESSION_TTL_SECONDS:    int   = 1800   # 30min — alinhado com SessionTracker Rust
MAX_TAGS_PER_SESSION:   int   = 50
MAX_SESSIONS:           int   = 10_000

FREQ_WEIGHT_PER_REPEAT: float = 0.02
FREQ_MAX_COUNT:         int   = 10
FREQ_HIGH_RISK_TAGS: frozenset = frozenset(
    tag for combo in DANGEROUS_COMBINATIONS for tag in combo
)


# ───────────────────────────────────────────────────────────────────────────────
# STATE
# ───────────────────────────────────────────────────────────────────────────────

@dataclass
class SensitivityState:
    """Estado de sensibilidade acumulado por sessão."""
    tags: Set[str] = field(default_factory=set)
    tag_counts: Dict[str, int] = field(
        default_factory=lambda: defaultdict(int)
    )
    cumulative_risk: float = 0.0
    active_combinations: List[str] = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    request_count: int = 0

    def is_expired(self) -> bool:
        """Belt-and-suspenders: verifica expiração baseada em last_seen do estado."""
        return (time.time() - self.last_seen) > SESSION_TTL_SECONDS


# ───────────────────────────────────────────────────────────────────────────────
# MODULE-LEVEL HELPERS
# ───────────────────────────────────────────────────────────────────────────────

def _frequency_boost(tag_counts: Dict[str, int]) -> float:
    """
    Gap 6: converte tag_counts em sinal de risco por probing persistente.
    Apenas tags em FREQ_HIGH_RISK_TAGS contribuem.
    Satura em FREQ_MAX_COUNT contra DoS por volume.
    """
    boost = 0.0
    for tag, count in tag_counts.items():
        if tag in FREQ_HIGH_RISK_TAGS and count > 1:
            boost += min(count - 1, FREQ_MAX_COUNT - 1) * FREQ_WEIGHT_PER_REPEAT
    return boost


# ───────────────────────────────────────────────────────────────────────────────
# ACCUMULATOR
# ───────────────────────────────────────────────────────────────────────────────

class SessionSensitivityAccumulator:
    """
    Acumula sensitivity tags cross-request por sessão.

    BiasDeclaration (ADR-046):
      - FPR das combinações: estimado ~5% (combinações legítimas em agentes
        financeiros) — mitigado por trust_boundary (ADR-045)
      - FNR: 0% para combinações em DANGEROUS_COMBINATIONS (determinístico)
      - Calibração: 2026-03-09 (v1.3.0)

    v1.3.0: _evict_expired() O(n) e _evict_oldest() O(n) removidos.
    SessionManager.touch() delega LRU+TTL com O(1) amortizado.
    """

    def __init__(self, max_sessions: int = MAX_SESSIONS) -> None:
        self._sessions: Dict[str, SensitivityState] = {}
        self._session_mgr = SessionManager(
            max_sessions=max_sessions,
            ttl_s=SESSION_TTL_SECONDS,
        )
        self.metrics: Dict[str, int] = {
            "accumulations":         0,
            "combinations_detected": 0,
            "evictions":             0,
        }

    def accumulate(
        self,
        session_id: str,
        findings_summary: List[str],
    ) -> SensitivityState:
        """
        Registra findings do request atual e retorna estado atualizado.

        Gap 5/17: SessionManager.touch() substitui _evict_expired() O(n)
        e _evict_oldest() O(n). Complexidade: O(1) amortizado.
        """
        self.metrics["accumulations"] += 1

        # Gap 5/17: touch retorna sessões evictadas (TTL amortizado + cap LRU)
        evicted = self._session_mgr.touch(session_id)
        for sid in evicted:
            self._sessions.pop(sid, None)
            self.metrics["evictions"] += 1

        # Belt-and-suspenders: estado expirado entre requests (edge case)
        state = self._sessions.get(session_id)
        if state is not None and state.is_expired():
            del self._sessions[session_id]
            state = None

        if state is None:
            state = SensitivityState()
            self._sessions[session_id] = state

        state.last_seen = time.time()
        state.request_count += 1

        for finding_type in findings_summary:
            tag = FINDING_TO_SENSITIVITY.get(finding_type.lower())
            if tag and len(state.tags) < MAX_TAGS_PER_SESSION:
                state.tags.add(tag)
                state.tag_counts[tag] += 1

        previous_combos: set = set(state.active_combinations)

        state.active_combinations = []
        combination_boost = 0.0
        for combo in DANGEROUS_COMBINATIONS:
            if combo.issubset(state.tags):
                label = " + ".join(sorted(combo))
                state.active_combinations.append(label)
                combination_boost += COMBINATION_RISK_BOOST
                if label not in previous_combos:
                    self.metrics["combinations_detected"] += 1

        freq_boost = _frequency_boost(state.tag_counts)
        state.cumulative_risk = min(1.0, combination_boost + freq_boost)
        return state

    def get_state(self, session_id: str) -> Optional[SensitivityState]:
        """Retorna estado atual da sessão, ou None se não existe / expirada."""
        state = self._sessions.get(session_id)
        if state is None or state.is_expired():
            return None
        return state
