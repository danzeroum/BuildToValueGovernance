"""
GoalDriftSentinel - PROP-038 (Python Governance).

Analise temporal de drift de objetivo por sessao.
Detecta pressao Eficiencia vs. Seguranca (paper 213: 100% violacao nos
timesteps finais sob pressao).

Invariantes:
- Ring buffer por sessao: deque maxlen=K
- explain_decision OBRIGATORIO (Levinas)
- HMAC-SHA256 em todo DriftReport (Jonas)
- Fail-secure: excecao -> ESCALATE assinado, nunca silencio
- Drift assimetrico: eficiencia > seguranca = vetor critico

Filosofia: Jonas (responsabilidade preventiva), Rawls (SLA 24h contestavel).
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

DRIFT_WINDOW_K: int = 10          # janela temporal (timesteps)
DRIFT_THRESHOLD_PCT: int = 60     # % de passos crescentes para drift
DRIFT_SCORE: dict[str, int] = {
    "None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4,
}
# Acoes que indicam pressao de eficiencia (vetor assimetrico do paper 213)
EFFICIENCY_PRESSURE_ACTIONS = frozenset({"ALLOW", "LOG"})
SECURITY_PRESSURE_ACTIONS   = frozenset({"BLOCK", "REDACT", "EDUCATE", "ESCALATE_HUMAN"})


# ─────────────────────────────────────────────────────────────────────────────
# TYPES
# ─────────────────────────────────────────────────────────────────────────────

class DriftAction(str, Enum):
    ALLOW           = "ALLOW"
    ESCALATE_HUMAN  = "ESCALATE_HUMAN"
    BLOCK           = "BLOCK"


@dataclass(frozen=True)
class DriftReport:
    """
    Resultado imutavel da analise de drift.
    explain_decision OBRIGATORIO.
    policy_drift_detected: espelha o flag que sera gravado no TechnicalEvidence.
    """
    session_id:              str
    policy_drift_detected:   bool
    drift_action:            DriftAction
    drift_score_sequence:    tuple
    trend_pct:               int      # % de passos crescentes na janela
    asymmetric_pressure:     bool     # pressao eficiencia > seguranca
    explain_decision:        str
    decided_at_iso:          str
    signature:               str

    def to_dict(self) -> dict:
        return {
            "session_id":            self.session_id,
            "policy_drift_detected": self.policy_drift_detected,
            "drift_action":          self.drift_action.value,
            "trend_pct":             self.trend_pct,
            "asymmetric_pressure":   self.asymmetric_pressure,
            "explain_decision":      self.explain_decision,
            "decided_at_iso":        self.decided_at_iso,
            "signature":             self.signature,
        }


# ─────────────────────────────────────────────────────────────────────────────
# SENTINEL
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _SessionWindow:
    scores:  deque  # deque[int], maxlen=DRIFT_WINDOW_K
    actions: deque  # deque[str], maxlen=DRIFT_WINDOW_K


class GoalDriftSentinel:
    """
    Analise temporal de drift por sessao.

    Mantém ring buffer de K timesteps por session_id.
    Fail-secure: excecao interna -> ESCALATE assinado.
    """

    def __init__(
        self,
        hmac_secret:     bytes,
        window_k:        int = DRIFT_WINDOW_K,
        threshold_pct:   int = DRIFT_THRESHOLD_PCT,
    ) -> None:
        if not hmac_secret:
            raise ValueError("hmac_secret nao pode ser vazio")
        self._secret       = hmac_secret
        self._window_k     = window_k
        self._threshold    = threshold_pct
        self._sessions: dict[str, _SessionWindow] = {}

    def record_and_analyze(
        self,
        session_id:   str,
        drift_level:  str,
        policy_action: str = "ALLOW",
    ) -> DriftReport:
        """Registra timestep e analisa drift. Fail-secure em erro."""
        try:
            return self._analyze(session_id, drift_level, policy_action)
        except Exception as exc:
            return self._fail_secure(session_id, str(exc))

    def reset_session(self, session_id: str) -> None:
        """Remove janela de sessao (ex: apos contestacao aprovada)."""
        self._sessions.pop(session_id, None)

    def window_snapshot(self, session_id: str) -> list[int]:
        """Retorna copia da janela atual (para auditoria)."""
        w = self._sessions.get(session_id)
        return list(w.scores) if w else []

    # ── Internal ─────────────────────────────────────────────────────────────

    def _analyze(
        self,
        session_id:    str,
        drift_level:   str,
        policy_action: str,
    ) -> DriftReport:
        score = DRIFT_SCORE.get(drift_level, 0)
        win   = self._get_or_create(session_id)
        win.scores.append(score)
        win.actions.append(policy_action)

        scores_list  = list(win.scores)
        trend_pct    = _compute_trend_pct(scores_list)
        asym         = _detect_asymmetric_pressure(list(win.actions))
        drift_det    = self._is_drift(scores_list, trend_pct, asym)
        action       = self._decide_action(drift_det, scores_list)
        explain      = self._build_explain(
            session_id, drift_level, scores_list, trend_pct, asym, drift_det, action,
        )
        now  = datetime.now(timezone.utc).isoformat()
        sig  = self._sign(session_id, drift_det, action, now)
        return DriftReport(
            session_id=session_id,
            policy_drift_detected=drift_det,
            drift_action=action,
            drift_score_sequence=tuple(scores_list),
            trend_pct=trend_pct,
            asymmetric_pressure=asym,
            explain_decision=explain,
            decided_at_iso=now,
            signature=sig,
        )

    def _get_or_create(self, session_id: str) -> _SessionWindow:
        if session_id not in self._sessions:
            self._sessions[session_id] = _SessionWindow(
                scores=deque(maxlen=self._window_k),
                actions=deque(maxlen=self._window_k),
            )
        return self._sessions[session_id]

    def _is_drift(
        self,
        scores:    list[int],
        trend_pct: int,
        asym:      bool,
    ) -> bool:
        last = scores[-1] if scores else 0
        # Critico imediato: score Critical(4) em qualquer ponto — sem minimo de janela
        if last >= DRIFT_SCORE["Critical"]:
            return True
        if len(scores) < 2:
            return False
        # Drift crescente + pressao assimetrica = drift confirmado
        if trend_pct >= self._threshold and asym:
            return True
        # Drift crescente acima do threshold sem pressao assimetrica
        if trend_pct >= self._threshold and last >= DRIFT_SCORE["High"]:
            return True
        return False

    def _decide_action(
        self, drift_detected: bool, scores: list[int]
    ) -> DriftAction:
        if not drift_detected:
            return DriftAction.ALLOW
        last = scores[-1] if scores else 0
        if last >= DRIFT_SCORE["Critical"]:
            return DriftAction.BLOCK
        return DriftAction.ESCALATE_HUMAN

    def _build_explain(
        self,
        session_id: str,
        drift_level: str,
        scores: list[int],
        trend_pct: int,
        asym: bool,
        detected: bool,
        action: DriftAction,
    ) -> str:
        parts = [
            f"[GoalDriftSentinel] session={session_id}  drift_detected={detected}",
            f"  drift_level={drift_level}  trend={trend_pct}%  "
            f"asymmetric_pressure={asym}",
            f"  window(K={self._window_k}): {scores}",
            f"  action={action.value}",
        ]
        if detected:
            parts.append(
                "  Diagnostico: pressao Eficiencia vs. Seguranca detectada "
                "(paper 213: 100% violacao em timesteps finais sob pressao)."
            )
        if action == DriftAction.ESCALATE_HUMAN:
            parts.append(
                "  Encaminhado para revisao humana (SLA 24h — Rawls: "
                "drift nao implica culpa, implica cautela)."
            )
        elif action == DriftAction.BLOCK:
            parts.append(
                "  BLOCK preventivo: drift Critical detectado. "
                "Jonas: responsabilidade exige intervencao antes do ponto de nao retorno."
            )
        parts.append("  Contestavel via /api/v1/contestation (SLA 24h).")
        return "\n".join(parts)

    def _fail_secure(self, session_id: str, error: str) -> DriftReport:
        now = datetime.now(timezone.utc).isoformat()
        sig = self._sign(session_id, True, DriftAction.ESCALATE_HUMAN, now)
        explain = (
            f"[GoalDriftSentinel] FAIL-SECURE ativado. session={session_id}\n"
            f"  erro interno: {error}\n"
            "  Acao: ESCALATE_HUMAN (Levinas: erro do sistema nao e culpa do usuario).\n"
            "  Contestavel via /api/v1/contestation (SLA 24h)."
        )
        return DriftReport(
            session_id=session_id,
            policy_drift_detected=True,
            drift_action=DriftAction.ESCALATE_HUMAN,
            drift_score_sequence=(),
            trend_pct=0,
            asymmetric_pressure=False,
            explain_decision=explain,
            decided_at_iso=now,
            signature=sig,
        )

    def _sign(
        self,
        session_id:  str,
        detected:    bool,
        action:      DriftAction,
        decided_at:  str,
    ) -> str:
        payload = json.dumps(
            {"action": action.value, "decided_at": decided_at,
             "detected": detected, "session_id": session_id},
            sort_keys=True, separators=(",", ":"),
        ).encode()
        return _hmac.new(self._secret, payload, hashlib.sha256).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# MODULE-LEVEL HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _compute_trend_pct(scores: list[int]) -> int:
    """% de passos estritamente crescentes na janela."""
    n = len(scores)
    if n < 2:
        return 0
    ascending = sum(1 for i in range(1, n) if scores[i] > scores[i - 1])
    return (ascending * 100) // (n - 1)


def _detect_asymmetric_pressure(actions: list[str]) -> bool:
    """
    Detecta pressao assimetrica: maioria das acoes recentes de ALLOW/LOG
    enquanto drift_level sobe — vetor critico do paper 213.
    """
    if len(actions) < 3:
        return False
    recent = actions[-5:]  # ultimos 5
    eff_count = sum(1 for a in recent if a in EFFICIENCY_PRESSURE_ACTIONS)
    return eff_count > len(recent) // 2
