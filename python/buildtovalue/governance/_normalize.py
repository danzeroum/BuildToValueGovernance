"""
InputNormalizer — Sprint 0 (Gaps 2, 4, 15).

Fronteira gateway→governance: normaliza e valida enums de entrada antes
que cheguem aos módulos de governança.

Fail-secure (Jonas): incerteza tratada com a mesma seriedade que perigo
confirmado. Valor desconhecido → valor conservador, nunca silêncio.

ADR ref: ADR-044 (drift_level uppercase Rust), PROP-038 (policy_action).
"""
from __future__ import annotations

import logging

_log = logging.getLogger(__name__)

# Conjunto canônico do DRIFT_SCORE em goal_drift_sentinel.py
# (definido aqui para evitar import circular)
_VALID_DRIFT: frozenset[str] = frozenset({"None", "Low", "Medium", "High", "Critical"})

_VALID_ACTIONS: frozenset[str] = frozenset({
    "ALLOW", "LOG", "BLOCK", "REDACT", "EDUCATE", "ESCALATE_HUMAN",
})

# Aliases para upstream Rust uppercase (ADR-044)
_DRIFT_ALIASES: dict[str, str] = {
    "NONE":     "None",
    "LOW":      "Low",
    "MEDIUM":   "Medium",
    "HIGH":     "High",
    "CRITICAL": "Critical",
}


def normalize_drift_level(raw: str) -> str:
    """
    Retorna drift_level no formato canônico de DRIFT_SCORE.

    Aceita:
      - Title case ("Low", "Medium") — formato Python nativo
      - Uppercase ("LOW", "MEDIUM") — formato Rust upstream (ADR-044)

    Fail-secure: valor não reconhecido → "High" (score 3).
    Nunca retorna valor ausente de DRIFT_SCORE.
    """
    if not isinstance(raw, str):
        _log.warning(
            "normalize_drift_level: tipo inesperado %r → fail-secure High",
            type(raw).__name__,
        )
        return "High"

    stripped = raw.strip()

    if stripped in _VALID_DRIFT:
        return stripped

    aliased = _DRIFT_ALIASES.get(stripped.upper())
    if aliased is not None:
        return aliased

    _log.warning(
        "normalize_drift_level: valor não reconhecido %r → fail-secure 'High'",
        raw,
    )
    return "High"


def normalize_action(raw: str) -> str:
    """
    Retorna policy_action em uppercase canônico.

    Fail-secure: valor não reconhecido → "BLOCK".
    Nunca retorna valor ausente de EFFICIENCY_PRESSURE_ACTIONS ∪ SECURITY_PRESSURE_ACTIONS.
    """
    if not isinstance(raw, str):
        _log.warning(
            "normalize_action: tipo inesperado %r → fail-secure BLOCK",
            type(raw).__name__,
        )
        return "BLOCK"

    upper = raw.strip().upper()

    if upper in _VALID_ACTIONS:
        return upper

    _log.warning(
        "normalize_action: valor não reconhecido %r → fail-secure 'BLOCK'",
        raw,
    )
    return "BLOCK"
