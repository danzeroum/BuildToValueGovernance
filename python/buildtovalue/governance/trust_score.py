"""
Trust Score Calculator v1.2.0 — ADR-039.

Calculador de confianca multifatorial baseado em historico e comportamento.

Changelog:
  v1.1.0: adjust_post_penalty (Gap 14)
  v1.2.0 (Gap 12): SessionManager LRU+TTL + deque(maxlen=200) por sessao.
    - trust_cache sem cap -> substituido por evicao via SessionManager
    - activity_log list crescimento ilimitado -> deque(maxlen=200)
    - evict_session() limpa ambas as estruturas
"""
from __future__ import annotations

import math
import sqlite3
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .session_manager import SessionManager

MAX_SESSIONS:       int = 10_000
SESSION_TTL_S:      int = 1800   # 30 min — alinhado com SessionTracker Rust
ACTIVITY_MAX:       int = 200    # historico por sessao
TRUST_CACHE_TTL_S:  int = 300    # 5 min

# C9: Escrow DB path (same SQLite as app — overrideable via env)
import os as _os
ESCROW_DB_PATH: str = _os.environ.get("BTV_DB_PATH", "data/trust.db")


@dataclass
class UserActivity:
    """Atividade de usuario."""
    session_id: str
    timestamp:  int
    action:     str   # "request", "appeal", "feedback", "post_penalty_analysis"
    result:     str   # "allowed", "blocked", "appeal_success", "appeal_fail", ...
    context:    Optional[Dict[str, Any]] = None


class TrustScoreCalculator:
    """
    Calcula Trust Score multi-fatorial.

    Formula:
        trust = w1*base + w2*history + w3*appeals + w4*decay + w5*consistency

    Garantias:
    - Score em [0.0, 1.0]
    - Determinístico: mesmo historico = mesmo score
    - Nao-gaming: spam nao aumenta trust
    - Privacy-preserving: sem PII
    - Gap 12 (v1.2.0): SessionManager evita memory leak em prod.
      activity_log limitado a 200 entradas por sessao (deque).

    BiasDeclaration (ADR-039):
    - FPR de penalidade por decay: ~10% em usuarios com bloqueios por FP
      do sistema — mitigado por adjust_post_penalty() e appeals
    - Calibracao: 2026-03-09 (v1.2.0)
    """

    def __init__(self, max_sessions: int = MAX_SESSIONS) -> None:
        self.weights = {
            "base":        0.20,
            "history":     0.30,
            "appeals":     0.20,
            "decay":       0.15,
            "consistency": 0.15,
        }
        # Gap 12: LRU + TTL — previne crescimento ilimitado
        self._session_mgr = SessionManager(max_sessions=max_sessions, ttl_s=SESSION_TTL_S)
        # trust_cache: session_id -> (score: float, ts: int)
        self.trust_cache:  Dict[str, tuple[float, int]] = {}
        # activity_log: session_id -> deque[UserActivity] (cap: ACTIVITY_MAX)
        self.activity_log: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=ACTIVITY_MAX)
        )

    # ── Public API ─────────────────────────────────────────────────────────────

    def calculate(self, session_id: str, user_role: str) -> float:
        """Calcula trust score. Retorna float em [0.0, 1.0]."""
        evicted = self._session_mgr.touch(session_id)
        for sid in evicted:
            self.evict_session(sid)

        # Cache hit (5 min)
        cached = self.trust_cache.get(session_id)
        if cached is not None:
            score, ts = cached
            if time.time() - ts < TRUST_CACHE_TTL_S:
                return score

        trust = (
            self.weights["base"]        * self._base_score(user_role)
            + self.weights["history"]   * self._history_score(session_id)
            + self.weights["appeals"]   * self._appeal_score(session_id)
            + self.weights["decay"]     * (1.0 - self._decay_penalty(session_id))
            + self.weights["consistency"] * self._consistency_score(session_id)
        )
        trust = max(0.0, min(1.0, trust))
        self.trust_cache[session_id] = (trust, int(time.time()))
        return trust

    def record_activity(self, activity: UserActivity) -> None:
        """Registra atividade. deque(maxlen=200) descarta entradas antigas."""
        evicted = self._session_mgr.touch(activity.session_id)
        for sid in evicted:
            self.evict_session(sid)
        self.activity_log[activity.session_id].append(activity)
        self.trust_cache.pop(activity.session_id, None)  # invalida cache

    def evict_session(self, session_id: str) -> None:
        """Remove sessao de trust_cache e activity_log."""
        self.trust_cache.pop(session_id, None)
        self.activity_log.pop(session_id, None)

    def explain(self, session_id: str, user_role: str) -> str:
        """Gera explicacao human-readable do trust score."""
        trust       = self.calculate(session_id, user_role)
        base        = self._base_score(user_role)
        history     = self._history_score(session_id)
        appeals     = self._appeal_score(session_id)
        decay       = self._decay_penalty(session_id)
        consistency = self._consistency_score(session_id)
        lines = [
            f"Trust Score: {trust:.2f}",
            "",
            "Componentes:",
            f"  base (role={user_role}): {base:.2f}  peso={self.weights['base']:.0%}",
            f"  historico:               {history:.2f}  peso={self.weights['history']:.0%}",
            f"  appeals:                 {appeals:.2f}  peso={self.weights['appeals']:.0%}",
            f"  decay_penalty:           {decay:.2f}  peso={self.weights['decay']:.0%}",
            f"  consistencia:            {consistency:.2f}  peso={self.weights['consistency']:.0%}",
        ]
        return "\n".join(lines)

    def adjust(self, user_id: str, delta: float) -> float:
        """
        Ajusta trust score de user_id por delta (ADR-039).
        Usado por adjust_trust_after_appeal() do AppealEngine.
        Retorna novo score clampado em [0.0, 1.0].

        Fix D12: usa score cacheado (role correto) em vez de
        recalcular com role="anonymous" (que ignorava o role real).
        """
        cached    = self.trust_cache.get(user_id)
        current   = cached[0] if cached is not None else self.calculate(user_id, "anonymous")
        new_score = max(0.0, min(1.0, current + delta))
        activity  = UserActivity(
            session_id=user_id,
            timestamp=int(time.time()),
            action="appeal",
            result="appeal_success" if delta > 0 else "appeal_fail",
        )
        self.record_activity(activity)
        return new_score

    def adjust_post_penalty(
        self,
        session_id:        str,
        pre_block_entropy:  float,
        post_block_entropy: float,
        subsequent_action:  str,
    ) -> float:
        """
        Analisa comportamento apos BLOCK para refinar trust.

        Levinas: distinguir erro genuino de escalada adversarial.
        Jonas: registrar padrao para responsabilidade auditavel.

        Returns: delta aplicado (positivo=recuperacao, negativo=penalidade).
        """
        entropy_delta = post_block_entropy - pre_block_entropy

        if entropy_delta < -0.3 and subsequent_action == "ALLOW":
            delta  = +0.05
            result = "post_penalty_recovery"
        elif entropy_delta > 0.2:
            delta  = -0.10
            result = "post_penalty_escalation"
        else:
            return 0.0

        activity = UserActivity(
            session_id=session_id,
            timestamp=int(time.time()),
            action="post_penalty_analysis",
            result=result,
        )
        self.record_activity(activity)
        self.adjust(session_id, delta)
        return delta

    # ── Private score components ────────────────────────────────────────────────

    def _base_score(self, user_role: str) -> float:
        role_scores = {
            "admin":       0.9,
            "developer":   0.7,
            "power_user":  0.6,
            "user":        0.5,
            "guest":       0.3,
            "anonymous":   0.2,
        }
        return role_scores.get(user_role, 0.5)

    def _history_score(self, session_id: str) -> float:
        activities = self.activity_log.get(session_id, [])
        requests   = [a for a in activities if a.action == "request"]
        if not requests:
            return 0.5
        allowed = sum(1 for r in requests if r.result == "allowed")
        ratio   = allowed / len(requests)
        return ratio * 0.8 if ratio < 0.5 else ratio

    def _appeal_score(self, session_id: str) -> float:
        activities = self.activity_log.get(session_id, [])
        appeals    = [a for a in activities if a.action == "appeal"]
        if not appeals:
            return 0.5
        success_ratio = sum(
            1 for a in appeals if a.result == "appeal_success"
        ) / len(appeals)
        return 0.3 + (success_ratio * 0.7)

    def _decay_penalty(self, session_id: str) -> float:
        activities = self.activity_log.get(session_id, [])
        blocked    = [a for a in activities if a.result == "blocked"]
        if not blocked:
            return 0.0
        now     = int(time.time())
        penalty = 0.0
        for activity in blocked:
            days_ago = (now - activity.timestamp) / 86400
            penalty += math.exp(-days_ago / 30) * 0.2
        return min(1.0, penalty)

    def _consistency_score(self, session_id: str) -> float:
        activities = self.activity_log.get(session_id, [])
        if len(activities) < 5:
            return 0.5
        timestamps = [a.timestamp for a in list(activities)[-30:]]
        if len(timestamps) < 2:
            return 0.5
        intervals   = [
            timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)
        ]
        mean_iv  = sum(intervals) / len(intervals)
        variance = sum((x - mean_iv) ** 2 for x in intervals) / len(intervals)
        std_dev  = math.sqrt(variance)
        return 1.0 - min(1.0, std_dev / 3600)

    # ── C9: Reputation Escrow ───────────────────────────────────────────────────

    def _ensure_escrow_table(self) -> None:
        """Create escrow_ledger table if not exists."""
        conn = sqlite3.connect(ESCROW_DB_PATH)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS escrow_ledger (
                escrow_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                amount REAL NOT NULL,
                delegation_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'frozen',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        conn.commit()
        conn.close()

    def freeze_escrow(self, session_id: str, amount: float, delegation_id: str) -> str:
        """Freeze `amount` trust points linked to a delegation. Returns escrow_id."""
        self._ensure_escrow_table()
        escrow_id = str(uuid.uuid4())
        conn = sqlite3.connect(ESCROW_DB_PATH)
        conn.execute(
            "INSERT INTO escrow_ledger (escrow_id, session_id, amount, delegation_id, status) "
            "VALUES (?, ?, ?, ?, 'frozen')",
            (escrow_id, session_id, amount, delegation_id),
        )
        conn.commit()
        conn.close()
        return escrow_id

    def release_escrow(self, escrow_id: str) -> None:
        """Release frozen points (promise fulfilled)."""
        self._ensure_escrow_table()
        conn = sqlite3.connect(ESCROW_DB_PATH)
        conn.execute(
            "UPDATE escrow_ledger SET status='released' WHERE escrow_id=? AND status='frozen'",
            (escrow_id,),
        )
        conn.commit()
        conn.close()

    def forfeit_escrow(self, escrow_id: str) -> None:
        """Permanently deduct frozen points (promise violated)."""
        self._ensure_escrow_table()
        conn = sqlite3.connect(ESCROW_DB_PATH)
        row = conn.execute(
            "SELECT session_id, amount FROM escrow_ledger WHERE escrow_id=? AND status='frozen'",
            (escrow_id,),
        ).fetchone()
        if row:
            session_id, amount = row
            conn.execute(
                "UPDATE escrow_ledger SET status='forfeited' WHERE escrow_id=?",
                (escrow_id,),
            )
            # Apply penalty to session trust in sessions table
            conn.execute(
                "UPDATE sessions SET trust_score = MAX(0.0, trust_score - ?), "
                "offenses = offenses + 1 WHERE session_id = ?",
                (amount, session_id),
            )
        conn.commit()
        conn.close()
