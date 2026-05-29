"""goal_drift — subpacote do GoalDriftSentinel (ADR-0094).

API pública reexportada aqui; ``goal_drift_sentinel.py`` é a facade de
compatibilidade retroativa. Funções de scoring "privadas" são reexportadas
para preservar imports de testes existentes.
"""
from ._detector import GoalDriftSentinel
from ._scorer import (
    _compute_drift_direction,
    _compute_pressure_accumulation,
    _compute_trend_pct,
    _detect_asymmetric_pressure,
    _is_burst,
)
from ._types import (
    DRIFT_SCORE,
    DRIFT_THRESHOLD_PCT,
    DRIFT_WINDOW_K,
    EFFICIENCY_PRESSURE_ACTIONS,
    SECURITY_PRESSURE_ACTIONS,
    DriftAction,
    DriftDirection,
    DriftReport,
    ModelPerformanceReport,
    _SessionWindow,
)

__all__ = [
    "GoalDriftSentinel",
    "DriftReport",
    "DriftAction",
    "DriftDirection",
    "ModelPerformanceReport",
    "DRIFT_SCORE",
    "DRIFT_WINDOW_K",
    "DRIFT_THRESHOLD_PCT",
    "EFFICIENCY_PRESSURE_ACTIONS",
    "SECURITY_PRESSURE_ACTIONS",
]
