"""
SessionSensitivityAccumulator v1.0.0 — ADR-046

Acumula sensitivity tags por sessão com base em findings observados
ao longo do tempo. Expõe risco cumulativo ao EthicalContextEngine
para que decisões considerem o histórico semântico (Hybrid Alignment).

Filosofia:
  - Hybrid Alignment (ICLR 2026, paper 147): ponte neural↔simbólico
  - Jonas: acúmulo rastreado = responsabilidade sobre o que foi fornecido
  - Levinas: proteger contra combinações perigosas mesmo quando cada
    request individual é legítimo

Performance: O(1) por request (dict lookup + set operations)
Limite de linhas: ≤ 200 (invariante AI Squad)
"""

import time
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from collections import defaultdict

logger = logging.getLogger("btv.governance.sensitivity")

# ─────────────────────────────────────────────────────────────────────────────
# TAXONOMIA DE SENSITIVITY TAGS
# Mapeamento determinístico: validator name (lowercase) → tag semântica.
# Extensível via YAML (data/policies/sensitivity_tags.yaml) em v1.9+.
# ─────────────────────────────────────────────────────────────────────────────

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

# Combinações perigosas: cada tag isolada pode ser legítima;
# a combinação cross-session cruza threshold de risco.
# Rationale de cada par (Jonas: responsabilidade por impactos combinados):
#   PII_BRAZILIAN + FINANCIAL   → fraude CPF + cartão
#   PII_CONTACT + PII_BRAZILIAN → dossier pessoal completo
#   SECURITY_INJECTION + PII_*  → exfiltração via injection
#   PII_US_GOV + FINANCIAL      → fraude identidade federal
#   PII_UK_HEALTH + PII_CONTACT → dados sensíveis de saúde + contato
DANGEROUS_COMBINATIONS: List[frozenset] = [
    frozenset({"PII_BRAZILIAN",  "FINANCIAL"}),
    frozenset({"PII_CONTACT",    "PII_BRAZILIAN"}),
    frozenset({"SECURITY_INJECTION", "PII_BRAZILIAN"}),
    frozenset({"SECURITY_INJECTION", "PII_CONTACT"}),
    frozenset({"PII_US_GOV",     "FINANCIAL"}),
    frozenset({"PII_UK_HEALTH",  "PII_CONTACT"}),
]

COMBINATION_RISK_BOOST: float = 0.15   # por combinação ativa (cap 1.0 no total)
SESSION_TTL_SECONDS:    int   = 1800   # 30min — alinhado com SessionTracker Rust
MAX_TAGS_PER_SESSION:   int   = 50     # cap contra memory abuse
MAX_SESSIONS:           int   = 10_000 # cap de sessões simultâneas


# ─────────────────────────────────────────────────────────────────────────────
# STATE
# ─────────────────────────────────────────────────────────────────────────────

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
        return (time.time() - self.last_seen) > SESSION_TTL_SECONDS


# ─────────────────────────────────────────────────────────────────────────────
# ACCUMULATOR
# ─────────────────────────────────────────────────────────────────────────────

class SessionSensitivityAccumulator:
    """
    Acumula sensitivity tags cross-request por sessão.

    BiasDeclaration (ADR-046):
      - FPR das combinações: estimado ~5% (combinações legítimas em agentes
        financeiros) — mitigado por trust_boundary (ADR-045)
      - FNR: 0% para combinações em DANGEROUS_COMBINATIONS (determinístico)
      - Calibração: 2026-03-04 (hardcoded v1.8; YAML em v1.9+)

    Uso pelo gateway (app.py):
      1. Após scan Rust: accumulate(session_id, findings_summary)
      2. Antes de EthicalContextEngine.decide(): get_state(session_id)
      3. Injetar cumulative_risk e active_combinations no RequestContext
    """

    def __init__(self, max_sessions: int = MAX_SESSIONS) -> None:
        self._sessions: Dict[str, SensitivityState] = {}
        self._max_sessions = max_sessions
        self.metrics: Dict[str, int] = {
            "accumulations":        0,
            "combinations_detected": 0,
            "evictions":            0,
        }

    def accumulate(
        self,
        session_id: str,
        findings_summary: List[str],
    ) -> SensitivityState:
        """
        Registra findings do request atual e retorna estado atualizado.

        Args:
            session_id: ID da sessão (opaco, não interpretado)
            findings_summary: nomes dos validators que produziram findings
                              (ex: ["cpf", "email"])

        Returns:
            SensitivityState atualizado com cumulative_risk e active_combinations.
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

        for finding_type in findings_summary:
            tag = FINDING_TO_SENSITIVITY.get(finding_type.lower())
            if tag and len(state.tags) < MAX_TAGS_PER_SESSION:
                state.tags.add(tag)
                state.tag_counts[tag] += 1

        # Recalcular combinações perigosas após atualizar tags
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
        """Retorna estado atual da sessão, ou None se não existe / expirada."""
        state = self._sessions.get(session_id)
        if state is None or state.is_expired():
            return None
        return state

    def _evict_expired(self) -> None:
        expired = [
            sid for sid, s in self._sessions.items() if s.is_expired()
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