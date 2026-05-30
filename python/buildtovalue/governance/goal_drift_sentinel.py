"""Facade de compatibilidade retroativa (ADR-0094).

NÃO adicionar lógica aqui — toda a implementação vive em ``goal_drift/``
(``_types.py``, ``_scorer.py``, ``_detector.py``). Este módulo apenas
reexporta a API pública (e os helpers de scoring usados por testes legados)
para que nenhum import existente quebre.
"""
from buildtovalue.governance.goal_drift import (  # noqa: F401
    DRIFT_SCORE,
    DRIFT_THRESHOLD_PCT,
    DRIFT_WINDOW_K,
    EFFICIENCY_PRESSURE_ACTIONS,
    SECURITY_PRESSURE_ACTIONS,
    DriftAction,
    DriftDirection,
    DriftReport,
    GoalDriftSentinel,
    ModelPerformanceReport,
    _compute_drift_direction,
    _compute_pressure_accumulation,
    _compute_trend_pct,
    _detect_asymmetric_pressure,
    _is_burst,
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
