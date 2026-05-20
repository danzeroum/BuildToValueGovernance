"""
PrivacyBudgetTracker — Cenários 26, 30, 3
Rastreamento de budget de dados sensíveis por agente/sessão/janela temporal.

Previne over-sharing gradual: um agente não pode acumular dados sensíveis
indefinidamente sem controle. Cada tipo de dado tem um orçamento configurável
por sessão, dia e semana.

Fundamentação normativa:
  - GPS_LOCATION: LGPD Art. 6, GDPR Art. 5(1)(c) — minimização de dados
  - HEALTH_DATA:  LGPD Art. 11, GDPR Art. 9(2)(h) — dados especiais de saúde
  - FINANCIAL:    LGPD Art. 11, LGPD Art. 20 — dados financeiros
  - BIOMETRIC:    LGPD Art. 11, GDPR Art. 9 — dados biométricos

Invariantes:
  - Fail-secure: exceção → BudgetCheckResult(EXHAUSTED, BLOCK)
  - explain_decision obrigatório em todo resultado
  - HMAC-SHA256 em todo BudgetCheckResult
  - SQLite para persistência entre reinícios
  - Isolamento garantido entre agentes/sessões distintas
  - Thread-safe: threading.Lock em operações SQLite
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import logging
import os
import sqlite3
from buildtovalue.security import sqlite_connect_wal
import threading
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Optional

logger = logging.getLogger("btv.governance.privacy_budget")

_DEFAULT_KEY = b"btv-privacy-budget-default-key-v1"

# ─── Constantes de threshold ───────────────────────────────────────────────────
_WARNING_PCT  = 70   # >= 70% → WARNING
_CRITICAL_PCT = 90   # >= 90% → CRITICAL
_EXHAUSTED_PCT = 100 # = 100% → EXHAUSTED


# ─── Enums ────────────────────────────────────────────────────────────────────

class SensitiveDataType(str, Enum):
    GPS_LOCATION  = "GPS_LOCATION"   # LGPD Art. 6, GDPR Art. 5(1)(c)
    HEALTH_DATA   = "HEALTH_DATA"    # LGPD Art. 11, GDPR Art. 9(2)(h)
    FINANCIAL     = "FINANCIAL_DATA" # LGPD Art. 11, LGPD Art. 20
    BIOMETRIC     = "BIOMETRIC"      # LGPD Art. 11, GDPR Art. 9


class BudgetWindow(str, Enum):
    SESSION = "session"
    DAILY   = "daily"
    WEEKLY  = "weekly"


class BudgetStatus(str, Enum):
    OK        = "OK"        # < 70% utilizado
    WARNING   = "WARNING"   # >= 70%
    CRITICAL  = "CRITICAL"  # >= 90%
    EXHAUSTED = "EXHAUSTED" # = 100% → BLOCK automático


# ─── Resultado imutável ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class BudgetCheckResult:
    """
    Resultado imutável da verificação de budget.
    explain_decision obrigatório (Levinas).
    signature HMAC-SHA256 obrigatório (Jonas: contestável).
    """
    status:           BudgetStatus
    data_type:        SensitiveDataType
    window:           BudgetWindow
    used:             int
    limit:            int
    explain_decision: str
    decided_at_iso:   str
    signature:        str

    @property
    def blocked(self) -> bool:
        return self.status == BudgetStatus.EXHAUSTED


# ─── Limites padrão por tipo e janela ─────────────────────────────────────────

_DEFAULT_LIMITS: dict[str, dict[str, int]] = {
    SensitiveDataType.GPS_LOCATION: {
        BudgetWindow.SESSION: 3,
        BudgetWindow.DAILY:   10,
        BudgetWindow.WEEKLY:  30,
    },
    SensitiveDataType.HEALTH_DATA: {
        BudgetWindow.SESSION: 1,
        BudgetWindow.DAILY:   5,
        BudgetWindow.WEEKLY:  15,
    },
    SensitiveDataType.FINANCIAL: {
        BudgetWindow.SESSION: 2,
        BudgetWindow.DAILY:   8,
        BudgetWindow.WEEKLY:  20,
    },
    SensitiveDataType.BIOMETRIC: {
        BudgetWindow.SESSION: 1,
        BudgetWindow.DAILY:   3,
        BudgetWindow.WEEKLY:  10,
    },
}


# ─── PrivacyBudgetTracker ─────────────────────────────────────────────────────

class PrivacyBudgetTracker:
    """
    Rastreia budget de dados sensíveis por agente/sessão e janela temporal.

    Usa SQLite para persistência durável (sobrevive a reinícios).
    Thread-safe via threading.Lock.

    Uso:
        tracker = PrivacyBudgetTracker()
        result = tracker.check_and_record(
            agent_id="agent-001",
            session_id="sess-abc",
            data_type=SensitiveDataType.GPS_LOCATION,
        )
        if result.blocked:
            raise PrivacyBudgetExhausted(result.explain_decision)
    """

    def __init__(
        self,
        hmac_key:  bytes = _DEFAULT_KEY,
        db_path:   Optional[str] = None,
        limits:    Optional[dict] = None,
    ) -> None:
        self._secret  = hmac_key
        self._db_path = db_path or os.environ.get(
            "BTV_PRIVACY_BUDGET_DB", "data/privacy_budget.db"
        )
        self._limits  = limits or _DEFAULT_LIMITS
        self._lock    = threading.Lock()
        self._init_db()

    # ── API pública ────────────────────────────────────────────────────────────

    def check_and_record(
        self,
        agent_id:   str,
        session_id: str,
        data_type:  SensitiveDataType,
    ) -> BudgetCheckResult:
        """
        Verifica budget e registra consumo se não exausto.

        Se exausto → BudgetCheckResult(EXHAUSTED) sem registrar.
        Fail-secure: exceção → BudgetCheckResult(EXHAUSTED, BLOCK).
        """
        try:
            return self._check_and_record_internal(agent_id, session_id, data_type)
        except Exception as exc:
            logger.error("[PrivacyBudgetTracker] FAIL-SECURE: %s", exc)
            return self._fail_secure(data_type, str(exc))

    def check_only(
        self,
        agent_id:   str,
        session_id: str,
        data_type:  SensitiveDataType,
    ) -> BudgetCheckResult:
        """Verifica budget sem registrar consumo (somente leitura)."""
        try:
            return self._check_internal(agent_id, session_id, data_type)
        except Exception as exc:
            logger.error("[PrivacyBudgetTracker] FAIL-SECURE check_only: %s", exc)
            return self._fail_secure(data_type, str(exc))

    # ── Internos ───────────────────────────────────────────────────────────────

    def _check_and_record_internal(
        self,
        agent_id:   str,
        session_id: str,
        data_type:  SensitiveDataType,
    ) -> BudgetCheckResult:
        with self._lock:
            conn = self._connect()
            try:
                now = datetime.now(timezone.utc)
                result = self._evaluate(conn, agent_id, session_id, data_type, now)
                if result.status != BudgetStatus.EXHAUSTED:
                    self._record_usage(conn, agent_id, session_id, data_type, now)
                    conn.commit()
                    # Re-avalia após registrar para refletir o novo contador
                    result = self._evaluate(conn, agent_id, session_id, data_type, now)
                conn.commit()
                return result
            finally:
                conn.close()

    def _check_internal(
        self,
        agent_id:   str,
        session_id: str,
        data_type:  SensitiveDataType,
    ) -> BudgetCheckResult:
        with self._lock:
            conn = self._connect()
            try:
                now = datetime.now(timezone.utc)
                return self._evaluate(conn, agent_id, session_id, data_type, now)
            finally:
                conn.close()

    def _evaluate(
        self,
        conn:       sqlite3.Connection,
        agent_id:   str,
        session_id: str,
        data_type:  SensitiveDataType,
        now:        datetime,
    ) -> BudgetCheckResult:
        """Avalia o pior status entre janelas session/daily/weekly."""
        status_order = {
            BudgetStatus.OK: 0,
            BudgetStatus.WARNING: 1,
            BudgetStatus.CRITICAL: 2,
            BudgetStatus.EXHAUSTED: 3,
        }
        worst_status = BudgetStatus.OK
        worst_window = BudgetWindow.SESSION
        worst_used   = 0
        worst_limit  = self._get_limit(data_type, BudgetWindow.SESSION)
        first        = True

        for window in BudgetWindow:
            used  = self._count_usage(conn, agent_id, session_id, data_type, window, now)
            limit = self._get_limit(data_type, window)
            status = self._compute_status(used, limit)

            # Primeiro sempre inicializa; depois atualiza apenas se pior
            if first or status_order[status] > status_order[worst_status]:
                worst_status = status
                worst_window = window
                worst_used   = used
                worst_limit  = limit
                first        = False

        now_iso = now.isoformat().replace("+00:00", "Z")
        explain = self._build_explain(
            agent_id, data_type, worst_window, worst_used, worst_limit, worst_status
        )
        sig = self._sign(agent_id, data_type, worst_status, now_iso)

        return BudgetCheckResult(
            status           = worst_status,
            data_type        = data_type,
            window           = worst_window,
            used             = worst_used,
            limit            = worst_limit,
            explain_decision = explain,
            decided_at_iso   = now_iso,
            signature        = sig,
        )

    def _count_usage(
        self,
        conn:       sqlite3.Connection,
        agent_id:   str,
        session_id: str,
        data_type:  SensitiveDataType,
        window:     BudgetWindow,
        now:        datetime,
    ) -> int:
        cutoff = self._window_cutoff(window, now, session_id)
        if window == BudgetWindow.SESSION:
            row = conn.execute(
                "SELECT COUNT(*) FROM privacy_usage "
                "WHERE agent_id=? AND session_id=? AND data_type=?",
                (agent_id, session_id, data_type.value),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT COUNT(*) FROM privacy_usage "
                "WHERE agent_id=? AND data_type=? AND recorded_at>=?",
                (agent_id, data_type.value, cutoff.isoformat()),
            ).fetchone()
        return row[0] if row else 0

    def _window_cutoff(
        self,
        window:     BudgetWindow,
        now:        datetime,
        session_id: str,
    ) -> datetime:
        if window == BudgetWindow.DAILY:
            return now - timedelta(days=1)
        if window == BudgetWindow.WEEKLY:
            return now - timedelta(weeks=1)
        return now  # SESSION: sem cutoff por tempo, filtra por session_id

    def _record_usage(
        self,
        conn:       sqlite3.Connection,
        agent_id:   str,
        session_id: str,
        data_type:  SensitiveDataType,
        now:        datetime,
    ) -> None:
        conn.execute(
            "INSERT INTO privacy_usage (agent_id, session_id, data_type, recorded_at) "
            "VALUES (?, ?, ?, ?)",
            (agent_id, session_id, data_type.value, now.isoformat()),
        )

    def _get_limit(self, data_type: SensitiveDataType, window: BudgetWindow) -> int:
        return self._limits.get(data_type, {}).get(window, 999)

    @staticmethod
    def _compute_status(used: int, limit: int) -> BudgetStatus:
        if limit <= 0:
            return BudgetStatus.EXHAUSTED
        pct = (used * 100) // limit
        if pct >= _EXHAUSTED_PCT:
            return BudgetStatus.EXHAUSTED
        if pct >= _CRITICAL_PCT:
            return BudgetStatus.CRITICAL
        if pct >= _WARNING_PCT:
            return BudgetStatus.WARNING
        return BudgetStatus.OK

    def _build_explain(
        self,
        agent_id:  str,
        data_type: SensitiveDataType,
        window:    BudgetWindow,
        used:      int,
        limit:     int,
        status:    BudgetStatus,
    ) -> str:
        pct = (used * 100) // limit if limit > 0 else 100
        lines = [
            f"[PrivacyBudgetTracker] agent={agent_id} data_type={data_type.value}",
            f"  window={window.value} used={used}/{limit} ({pct}%) status={status.value}",
        ]
        if status == BudgetStatus.EXHAUSTED:
            lines.append(
                f"  Budget EXAUSTO: BLOCK automático. LGPD Art. 11 / GDPR Art. 9 — "
                f"minimização de dados exige limite de {data_type.value}."
            )
        elif status == BudgetStatus.CRITICAL:
            lines.append(
                f"  ATENÇÃO CRÍTICA: budget >= 90%. Próxima solicitação pode ser bloqueada."
            )
        elif status == BudgetStatus.WARNING:
            lines.append(f"  AVISO: budget >= 70%. Monitoramento elevado ativado.")
        else:
            lines.append(f"  Budget OK.")
        lines.append("  Contestável via /api/v1/contestation (SLA 24h — LGPD Art. 20).")
        return "\n".join(lines)

    def _fail_secure(self, data_type: SensitiveDataType, error: str) -> BudgetCheckResult:
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        explain = (
            f"[PrivacyBudgetTracker] FAIL-SECURE ativado.\n"
            f"  erro interno: {error}\n"
            f"  Ação: BLOCK (Jonas: erro do sistema não é licença para vazar dados).\n"
            f"  Contestável via /api/v1/contestation (SLA 24h)."
        )
        sig = self._sign("FAIL-SECURE", data_type, BudgetStatus.EXHAUSTED, now_iso)
        return BudgetCheckResult(
            status           = BudgetStatus.EXHAUSTED,
            data_type        = data_type,
            window           = BudgetWindow.SESSION,
            used             = -1,
            limit            = -1,
            explain_decision = explain,
            decided_at_iso   = now_iso,
            signature        = sig,
        )

    def _sign(
        self,
        agent_id:  str,
        data_type: SensitiveDataType,
        status:    BudgetStatus,
        now_iso:   str,
    ) -> str:
        payload = json.dumps(
            {
                "agent_id":  agent_id,
                "data_type": data_type.value,
                "status":    status.value,
                "decided_at": now_iso,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return _hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

    # ── SQLite ─────────────────────────────────────────────────────────────────

    def _connect(self) -> sqlite3.Connection:
        parent = os.path.dirname(self._db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        return sqlite_connect_wal(self._db_path)

    def _init_db(self) -> None:
        """Inicializa o banco. Erros de I/O são registrados — operações futuras ativam fail-secure."""
        with self._lock:
            try:
                conn = self._connect()
                try:
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS privacy_usage (
                            id          INTEGER PRIMARY KEY AUTOINCREMENT,
                            agent_id    TEXT    NOT NULL,
                            session_id  TEXT    NOT NULL,
                            data_type   TEXT    NOT NULL,
                            recorded_at TEXT    NOT NULL
                        )
                    """)
                    conn.execute(
                        "CREATE INDEX IF NOT EXISTS idx_usage_agent_type_time "
                        "ON privacy_usage (agent_id, data_type, recorded_at)"
                    )
                    conn.commit()
                finally:
                    conn.close()
            except Exception as exc:
                logger.error("[PrivacyBudgetTracker] _init_db falhou: %s", exc)
                # Não propaga — fail-secure será ativado em cada operação
