"""Tipos puros do GoalDriftSentinel (ADR-0094) — zero lógica de detecção.

Constantes, enums e dataclasses imutáveis. Sem dependências internas do
subpacote (folha da árvore de imports): ``_types`` ← ``_scorer`` ← ``_detector``.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from enum import Enum

# ── Constantes ───────────────────────────────────────────────────────────────
DRIFT_WINDOW_K: int = 10
DRIFT_THRESHOLD_PCT: int = 60
DRIFT_SCORE: dict[str, int] = {
    "None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4,
}
EFFICIENCY_PRESSURE_ACTIONS = frozenset({"ALLOW", "LOG"})
SECURITY_PRESSURE_ACTIONS = frozenset(
    {"BLOCK", "REDACT", "EDUCATE", "ESCALATE_HUMAN", "REFUSE"}
)


class DriftAction(str, Enum):
    ALLOW = "ALLOW"
    ESCALATE_HUMAN = "ESCALATE_HUMAN"
    BLOCK = "BLOCK"


class DriftDirection(str, Enum):
    """Direção do drift de objetivo — Asymmetric Goal Drift (ICLR 2026).

    SECURITY_TO_CONVENIENCE: vetor crítico — agente pressionado a abrir mão
      de constraints de segurança em favor de eficiência/conveniência.
      Paper 213: 100% violação nos timesteps finais sob esta pressão.
    CONVENIENCE_TO_SECURITY: pressão inversa — ações de segurança impostas
      enquanto drift permanece baixo (menos crítico).
    NONE: sem padrão direcional detectável.
    """
    SECURITY_TO_CONVENIENCE = "SECURITY_TO_CONVENIENCE"
    CONVENIENCE_TO_SECURITY = "CONVENIENCE_TO_SECURITY"
    NONE = "NONE"


@dataclass(frozen=True)
class DriftReport:
    """Resultado imutável da análise de drift. explain_decision OBRIGATÓRIO."""
    session_id:              str
    policy_drift_detected:   bool
    drift_action:            DriftAction
    drift_score_sequence:    tuple[int, ...]
    trend_pct:               int
    asymmetric_pressure:     bool
    explain_decision:        str
    decided_at_iso:          str
    signature:               str
    # v1.4.0: Asymmetric Goal Drift direction + pressure accumulation (ICLR 2026)
    drift_direction:              DriftDirection = DriftDirection.NONE
    pressure_accumulation_score:  float          = 0.0   # [0.0, 1.0]

    def to_dict(self) -> dict[str, object]:
        return {
            "session_id":                 self.session_id,
            "policy_drift_detected":      self.policy_drift_detected,
            "drift_action":               self.drift_action.value,
            "trend_pct":                  self.trend_pct,
            "asymmetric_pressure":        self.asymmetric_pressure,
            "drift_direction":            self.drift_direction.value,
            "pressure_accumulation_score": round(self.pressure_accumulation_score, 4),
            "explain_decision":           self.explain_decision,
            "decided_at_iso":             self.decided_at_iso,
            "signature":                  self.signature,
        }


@dataclass
class _SessionWindow:
    scores:  "deque[int]"  # maxlen=DRIFT_WINDOW_K
    actions: "deque[str]"  # maxlen=DRIFT_WINDOW_K


@dataclass(frozen=True)
class ModelPerformanceReport:
    """Resultado imutável do monitoramento de performance de modelo (Cenário 19).

    Detecta degradação abrupta que pode indicar backdoor ativado.
    explain_decision OBRIGATÓRIO (Levinas). signature OBRIGATÓRIO (Jonas).
    """
    model_id:             str
    metric:               float
    baseline:             float
    degradation_pct:      float    # (baseline - metric) / baseline * 100
    degradation_detected: bool
    explain_decision:     str      # Mandatory (Levinas)
    measured_at_iso:      str
    signature:            str      # HMAC-SHA256 (Jonas: contestável)
