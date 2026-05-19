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
- Inputs normalizados na fronteira (_normalize): nunca score 0 por case mismatch

Changelog:
  v1.1.0 (Sprint 0, Gaps 2/4/15): normalize_drift_level + normalize_action
  v1.2.0 (Sprint 3): _compute_trend_pct ponderado + _is_burst + burst condition
  v1.3.0 (Sprint 5, Gaps 1/9): SessionManager LRU+TTL — sessões expiradas
    são evictadas; ring buffer não polui com histórico obsoleto.
    max_sessions=10_000, ttl_s=1800 (alinhado com SessionTracker Rust).
  v1.4.0: DriftDirection enum + pressure_accumulation_score em DriftReport.
    Implementa detecção de direção assimétrica (ICLR 2026 — Asymmetric Goal
    Drift). Retrocompatível: novos campos têm defaults em DriftReport.

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
from typing import Callable, Optional

from ._normalize import normalize_drift_level, normalize_action
from .session_manager import SessionManager

# ───────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ───────────────────────────────────────────────────────────────────────────────

DRIFT_WINDOW_K: int = 10
DRIFT_THRESHOLD_PCT: int = 60
DRIFT_SCORE: dict[str, int] = {
    "None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4,
}
EFFICIENCY_PRESSURE_ACTIONS = frozenset({"ALLOW", "LOG"})
SECURITY_PRESSURE_ACTIONS   = frozenset({"BLOCK", "REDACT", "EDUCATE", "ESCALATE_HUMAN", "REFUSE"})


# ───────────────────────────────────────────────────────────────────────────────
# TYPES
# ───────────────────────────────────────────────────────────────────────────────

class DriftAction(str, Enum):
    ALLOW           = "ALLOW"
    ESCALATE_HUMAN  = "ESCALATE_HUMAN"
    BLOCK           = "BLOCK"


class DriftDirection(str, Enum):
    """
    Direção do drift de objetivo — Asymmetric Goal Drift (ICLR 2026).

    SECURITY_TO_CONVENIENCE: vetor crítico — agente pressionado a abrir mão
      de constraints de segurança em favor de eficiência/conveniência.
      Paper 213: 100% violação nos timesteps finais sob esta pressão.
    CONVENIENCE_TO_SECURITY: pressão inversa — ações de segurança impostas
      enquanto drift permanece baixo (menos crítico).
    NONE: sem padrão direcional detectável.
    """
    SECURITY_TO_CONVENIENCE = "SECURITY_TO_CONVENIENCE"
    CONVENIENCE_TO_SECURITY = "CONVENIENCE_TO_SECURITY"
    NONE                    = "NONE"


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
    trend_pct:               int
    asymmetric_pressure:     bool
    explain_decision:        str
    decided_at_iso:          str
    signature:               str
    # v1.4.0: Asymmetric Goal Drift direction + pressure accumulation (ICLR 2026)
    drift_direction:              DriftDirection = DriftDirection.NONE
    pressure_accumulation_score:  float          = 0.0   # [0.0, 1.0]

    def to_dict(self) -> dict:
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


# ───────────────────────────────────────────────────────────────────────────────
# SENTINEL
# ───────────────────────────────────────────────────────────────────────────────

@dataclass
class _SessionWindow:
    scores:  deque  # deque[int], maxlen=DRIFT_WINDOW_K
    actions: deque  # deque[str], maxlen=DRIFT_WINDOW_K


class GoalDriftSentinel:
    """
    Analise temporal de drift por sessao.

    Mantém ring buffer de K timesteps por session_id.
    Fail-secure: excecao interna -> ESCALATE assinado.
    SessionManager (v1.3.0): cap de sessoes e TTL — prevenção de DoS/leak.
    """

    def __init__(
        self,
        hmac_secret:     Optional[bytes] = None,
        window_k:        int = DRIFT_WINDOW_K,
        threshold_pct:   int = DRIFT_THRESHOLD_PCT,
        max_sessions:    int = 10_000,
        ttl_s:           int = 1800,
        hmac_secret_fn:  Optional[Callable[[], bytes]] = None,
    ) -> None:
        if hmac_secret_fn is not None:
            self._secret_fn: Callable[[], bytes] = hmac_secret_fn
        elif hmac_secret is not None:
            if not hmac_secret:
                raise ValueError("hmac_secret nao pode ser vazio")
            _captured = hmac_secret
            self._secret_fn = lambda: _captured
        else:
            raise ValueError("Provide hmac_secret or hmac_secret_fn")
        self._window_k     = window_k
        self._threshold    = threshold_pct
        self._sessions: dict[str, _SessionWindow] = {}
        # Gap 1/9: LRU+TTL — evicção automática, sem crescimento ilimitado
        self._session_mgr  = SessionManager(max_sessions=max_sessions, ttl_s=ttl_s)
        # C14: ring buffer de métricas por model_id (maxlen=30 observações)
        self._model_metrics: dict[str, deque] = {}

    def record_and_analyze(
        self,
        session_id:    str,
        drift_level:   str,
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
        self._session_mgr.evict(session_id)

    # ------------------------------------------------------------------ #
    # Cenário 28 — Drift Longitudinal Multi-Sessão                        #
    # ------------------------------------------------------------------ #

    def persist_checkpoint(
        self,
        agent_id: str,
        drift_level: str,
        ledger: "DurableLedger",
    ) -> None:
        """Persiste o DriftScore atual no DurableLedger ao fechar sessão.

        Chamado por SessionManager.close_session() para construir histórico
        longitudinal. Fail-secure: erro → loga e não silencia.
        """
        from .durable_ledger import DurableLedger  # importação local (evita circular)
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        score_int = DRIFT_SCORE.get(normalize_drift_level(drift_level), 0)
        ledger.append({
            "type": "drift_checkpoint",
            "agent_id": agent_id,
            "drift_level": drift_level,
            "drift_score": score_int,
            "recorded_at_iso": now_iso,
            "explain_decision": (
                f"Checkpoint de drift persistido ao encerrar sessão: "
                f"agent={agent_id} drift_level={drift_level} score={score_int}"
            ),
        })

    def compute_longitudinal_drift(
        self,
        agent_id: str,
        ledger: "DurableLedger",
        window_days: int = 30,
        threshold_pct: int = 60,
    ) -> bool:
        """Detecta drift longitudinal multi-sessão via série temporal do ledger.

        Lê checkpoints de `window_days` dias anteriores, aplica detect_drift()
        sobre a série temporal de DriftScores.

        Retorna True se drift longitudinal detectado (>threshold_pct ascendente).
        Fail-secure: erro → retorna True (conservativo — drift assumido).
        """
        from .durable_ledger import DurableLedger  # importação local
        from datetime import timedelta
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
            scores: list[int] = []
            for entry in ledger.entries():
                payload = entry.payload
                if (
                    payload.get("type") == "drift_checkpoint"
                    and payload.get("agent_id") == agent_id
                ):
                    iso = payload.get("recorded_at_iso", "")
                    try:
                        ts = datetime.fromisoformat(iso.replace("Z", "+00:00"))
                        if ts >= cutoff:
                            scores.append(int(payload.get("drift_score", 0)))
                    except (ValueError, TypeError):
                        continue

            if len(scores) < 3:
                return False  # histórico insuficiente

            from ._normalize import normalize_drift_level
            # Reutiliza lógica de detect_drift com scores da série temporal
            ascending = sum(
                1 for i in range(1, len(scores)) if scores[i] > scores[i - 1]
            )
            total_steps = len(scores) - 1
            pct = (ascending * 100) // total_steps if total_steps > 0 else 0
            return pct >= threshold_pct and max(scores) >= 2  # ≥ Medium
        except Exception as exc:
            import logging
            logging.getLogger("btv.governance.goal_drift_sentinel").error(
                "Erro em compute_longitudinal_drift: %s — retornando True (fail-secure)", exc
            )
            return True  # fail-secure: assume drift

    def window_snapshot(self, session_id: str) -> list[int]:
        """Retorna copia da janela atual (para auditoria)."""
        w = self._sessions.get(session_id)
        return list(w.scores) if w else []

    def monitor_model_performance(
        self,
        model_id: str,
        metric: float,
        threshold: float = 0.20,
    ) -> "ModelPerformanceReport":
        """Detecta degradação abrupta de modelo (C14 — Cenário 19: backdoor comportamental).

        Baseline = média dos primeiros 50% das amostras acumuladas.
        Fail-secure: exceção → report assinado com degradation_detected=True.
        """
        try:
            buf = self._model_metrics.setdefault(model_id, deque(maxlen=30))
            buf.append(metric)
            samples = list(buf)
            if len(samples) < 3:
                baseline, deg_pct, detected = metric, 0.0, False
            else:
                half = max(1, len(samples) // 2)
                baseline = sum(samples[:half]) / half
                deg_pct = ((baseline - metric) / baseline * 100) if baseline > 0 else 0.0
                detected = deg_pct > threshold * 100
            explain = (
                f"[ModelPerformanceSentinel] model={model_id} "
                f"metric={metric:.4f} baseline={baseline:.4f} "
                f"degradation={deg_pct:.1f}% threshold={threshold*100:.0f}% "
                f"detected={detected}"
            )
            if detected:
                explain += (
                    "\n  Degradação abrupta detectada — possível backdoor ativado. "
                    "Evidência forense gerada. Contestável via /api/v1/contestation."
                )
            now = datetime.now(timezone.utc).isoformat()
            action = DriftAction.BLOCK if detected else DriftAction.ALLOW
            sig = self._sign(model_id, detected, action, now)
            return ModelPerformanceReport(
                model_id=model_id, metric=metric, baseline=baseline,
                degradation_pct=deg_pct, degradation_detected=detected,
                explain_decision=explain, measured_at_iso=now, signature=sig,
            )
        except Exception as exc:
            now = datetime.now(timezone.utc).isoformat()
            sig = self._sign(model_id, True, DriftAction.ESCALATE_HUMAN, now)
            return ModelPerformanceReport(
                model_id=model_id, metric=metric, baseline=0.0, degradation_pct=0.0,
                degradation_detected=True,
                explain_decision=f"[ModelPerformanceSentinel] FAIL-SECURE: {exc}",
                measured_at_iso=now, signature=sig,
            )

    # ── Internal ───────────────────────────────────────────────────────────────────

    def _analyze(
        self,
        session_id:    str,
        drift_level:   str,
        policy_action: str,
    ) -> DriftReport:
        drift_level   = normalize_drift_level(drift_level)
        policy_action = normalize_action(policy_action)
        score = DRIFT_SCORE[drift_level]

        win = self._get_or_create(session_id)
        win.scores.append(score)
        win.actions.append(policy_action)

        scores_list  = list(win.scores)
        actions_list = list(win.actions)
        trend_pct    = _compute_trend_pct(scores_list)
        asym         = _detect_asymmetric_pressure(actions_list)
        direction    = _compute_drift_direction(actions_list, asym)
        pressure     = _compute_pressure_accumulation(trend_pct, asym)
        drift_det    = self._is_drift(scores_list, trend_pct, asym)
        action       = self._decide_action(drift_det, scores_list)
        explain      = self._build_explain(
            session_id, drift_level, scores_list, trend_pct, asym,
            drift_det, action, direction, pressure,
        )
        now = datetime.now(timezone.utc).isoformat()
        sig = self._sign(session_id, drift_det, action, now)
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
            drift_direction=direction,
            pressure_accumulation_score=pressure,
        )

    def _get_or_create(self, session_id: str) -> _SessionWindow:
        """
        Toca sessão no SessionManager (LRU+TTL).
        Limpa dados das sessões que foram evictadas.
        Cria nova janela se sessão não existe.
        """
        evicted = self._session_mgr.touch(session_id)
        for sid in evicted:
            self._sessions.pop(sid, None)

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
        if last >= DRIFT_SCORE["Critical"]:
            return True
        if len(scores) < 2:
            return False
        if trend_pct >= self._threshold and asym:
            return True
        if trend_pct >= self._threshold and last >= DRIFT_SCORE["High"]:
            return True
        # Sprint 3: burst tardio — 3 steps finais todos ascendentes + High + pressao
        if _is_burst(scores) and last >= DRIFT_SCORE["High"] and asym:
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
        session_id:  str,
        drift_level: str,
        scores:      list[int],
        trend_pct:   int,
        asym:        bool,
        detected:    bool,
        action:      DriftAction,
        direction:   "DriftDirection" = DriftDirection.NONE,
        pressure:    float = 0.0,
    ) -> str:
        burst = _is_burst(scores)
        parts = [
            f"[GoalDriftSentinel] session={session_id}  drift_detected={detected}",
            f"  drift_level={drift_level}  trend={trend_pct}%(ponderado)  "
            f"asymmetric_pressure={asym}  burst={burst}",
            f"  drift_direction={direction.value}  pressure_accumulation={pressure:.4f}",
            f"  window(K={self._window_k}): {scores}",
            f"  action={action.value}",
        ]
        if detected:
            parts.append(
                "  Diagnostico: pressao Eficiencia vs. Seguranca detectada "
                "(paper 213: 100% violacao em timesteps finais sob pressao)."
            )
        if burst and detected:
            parts.append(
                "  Burst tardio: ultimos 3 passos estritamente crescentes — "
                "aceleracao localizada detectada."
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
            drift_direction=DriftDirection.NONE,
            pressure_accumulation_score=0.0,
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
        return _hmac.new(self._secret_fn(), payload, hashlib.sha256).hexdigest()


# ───────────────────────────────────────────────────────────────────────────────
# MODULE-LEVEL HELPERS
# ───────────────────────────────────────────────────────────────────────────────

def _compute_trend_pct(scores: list[int]) -> int:
    """
    Sprint 3: % ponderado de passos ascendentes — recencia linear.

    Passo i (1-indexed dentro da janela) tem peso i.
    O passo mais recente (i=n-1) tem o maior peso.
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
    """
    Sprint 3: detecta aceleracao localizada nos 3 ultimos steps.
    Retorna True se os ultimos 3 passos sao estritamente crescentes.
    """
    if len(scores) < 3:
        return False
    tail = scores[-3:]
    return tail[1] > tail[0] and tail[2] > tail[1]


def _detect_asymmetric_pressure(actions: list[str]) -> bool:
    """
    Detecta pressao assimetrica: maioria das acoes recentes de ALLOW/LOG
    enquanto drift_level sobe — vetor critico do paper 213.
    """
    if len(actions) < 3:
        return False
    recent = actions[-5:]
    eff_count = sum(1 for a in recent if a in EFFICIENCY_PRESSURE_ACTIONS)
    return eff_count > len(recent) // 2


def _compute_drift_direction(actions: list[str], asym: bool) -> "DriftDirection":
    """
    Determina a direção do drift de objetivo (ICLR 2026 — Asymmetric Goal Drift).

    SECURITY_TO_CONVENIENCE: asym=True — maioria ALLOW/LOG enquanto drift sobe.
      Vetor crítico: paper 213 mostra 100% violação nos timesteps finais.
    CONVENIENCE_TO_SECURITY: maioria BLOCK/ESCALATE sem pressão eficiência.
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
    """
    Score [0.0, 1.0] de acumulação de pressão ao longo da janela temporal.

    Pressão assimétrica SECURITY→CONVENIENCE recebe peso total (vetor crítico).
    Pressão sem assimetria recebe peso reduzido (0.5x) — risco menor.
    """
    base = trend_pct / 100.0
    return min(1.0, base if asym else base * 0.5)


# ── C14: ModelPerformanceSentinel ─────────────────────────────────────────────


@dataclass(frozen=True)
class ModelPerformanceReport:
    """Resultado imutavel do monitoramento de performance de modelo (Cenário 19).

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
