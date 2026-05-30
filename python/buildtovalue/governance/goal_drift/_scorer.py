"""Scoring puro de drift (ADR-0094) — funções sem estado.

Thresholds, tendência ponderada, detecção de burst e direção assimétrica.
Depende apenas de ``_types`` (constantes + DriftDirection).
"""
from __future__ import annotations

from ._types import (
    EFFICIENCY_PRESSURE_ACTIONS,
    SECURITY_PRESSURE_ACTIONS,
    DriftDirection,
)


def _compute_trend_pct(scores: list[int]) -> int:
    """% ponderado de passos ascendentes — recência linear.

    Passo i (1-indexed dentro da janela) tem peso i. O passo mais recente
    (i=n-1) tem o maior peso.
    """
    n = len(scores)
    if n < 2:
        return 0
    total_weight = (n * (n - 1)) // 2
    ascending_weight = sum(
        i for i in range(1, n) if scores[i] > scores[i - 1]
    )
    return (ascending_weight * 100) // total_weight


def _is_burst(scores: list[int]) -> bool:
    """Detecta aceleração localizada: últimos 3 passos estritamente crescentes."""
    if len(scores) < 3:
        return False
    tail = scores[-3:]
    return tail[1] > tail[0] and tail[2] > tail[1]


def _detect_asymmetric_pressure(actions: list[str]) -> bool:
    """Pressão assimétrica: maioria das ações recentes ALLOW/LOG enquanto drift
    sobe — vetor crítico do paper 213.
    """
    if len(actions) < 3:
        return False
    recent = actions[-5:]
    eff_count = sum(1 for a in recent if a in EFFICIENCY_PRESSURE_ACTIONS)
    return eff_count > len(recent) // 2


def _compute_drift_direction(actions: list[str], asym: bool) -> "DriftDirection":
    """Direção do drift (ICLR 2026 — Asymmetric Goal Drift).

    SECURITY_TO_CONVENIENCE: asym=True — maioria ALLOW/LOG enquanto drift sobe.
    CONVENIENCE_TO_SECURITY: maioria BLOCK/ESCALATE sem pressão de eficiência.
    NONE: sem padrão direcional detectável.
    """
    if not actions or len(actions) < 2:
        return DriftDirection.NONE
    if asym:
        return DriftDirection.SECURITY_TO_CONVENIENCE
    recent = actions[-5:]
    sec_count = sum(1 for a in recent if a in SECURITY_PRESSURE_ACTIONS)
    if sec_count > len(recent) // 2:
        return DriftDirection.CONVENIENCE_TO_SECURITY
    return DriftDirection.NONE


def _compute_pressure_accumulation(trend_pct: int, asym: bool) -> float:
    """Score [0.0, 1.0] de acumulação de pressão ao longo da janela temporal.

    Pressão assimétrica SECURITY→CONVENIENCE recebe peso total (vetor crítico).
    Pressão sem assimetria recebe peso reduzido (0.5x) — risco menor.
    """
    base = trend_pct / 100.0
    return min(1.0, base if asym else base * 0.5)
