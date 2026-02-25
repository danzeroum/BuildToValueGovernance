"""
Contestability Loop v3.0 - Human-in-the-Loop (Levinas)
T2.2: SQLite persistence — appeals survive restarts.

Responsabilidades:
- Aceita recursos de decisões (LGPD Art. 20)
- SLA 24h para resposta humana
- Persistência SQLite (durável)
- Feedback loop (melhoria contínua)
- Audit trail completo

Filosofia: Levinas (Dever de Cuidado) - Sempre dar direito de recurso

Mudanças v3.0:
- [BREAKING-NONE] SQLite backend (db_path param, default=data/appeals.db)
- [BREAKING-NONE] Cache em memória para hot path (<5ms)
- [BREAKING-NONE] Recovery automático no startup
- Interface pública idêntica à v2.0
"""

import os
import sqlite3
import time
import logging
from enum import Enum
from typing import Optional, List, Dict, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# APPEAL TYPES
# ═══════════════════════════════════════════════════════════════

class AppealStatus(Enum):
    """Status de recurso."""
    PENDING = "pending"
    UNDER_REVIEW = "under_review"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass
class Appeal:
    """Recurso de usuário."""
    appeal_id: str
    audit_trail_id: int
    user_id: str
    timestamp: int
    reason: str
    evidence_provided: Optional[str] = None

    # Review
    status: AppealStatus = AppealStatus.PENDING
    reviewer_notes: Optional[str] = None
    resolution_timestamp: Optional[int] = None

    # SLA
    sla_deadline: int = 0

    def __post_init__(self):
        if self.sla_deadline == 0:
            self.sla_deadline = self.timestamp + (24 * 3600)

    def is_overdue(self) -> bool:
        return (
            int(time.time()) > self.sla_deadline
            and self.status == AppealStatus.PENDING
        )


# ═══════════════════════════════════════════════════════════════
# CONTESTABILITY LOOP v3.0
# ═══════════════════════════════════════════════════════════════

class ContestabilityLoop:
    """
    Contestability Loop v3.0 - SQLite-backed.

    Architecture:
    - SQLite = source of truth (durável)
    - Dict cache = hot path (<5ms reads)
    - Writes: cache + SQLite (sync)
    - Startup: load pending from SQLite

    Philosophy: Levinas (Dever de Cuidado)
    """

    def __init__(
        self,
        sla_hours: int = 24,
        db_path: Optional[str] = None,
    ):
        self.sla_seconds = sla_hours * 3600
        self.appeals: Dict[str, Appeal] = {}

        # SQLite
        self._db_path = db_path or os.environ.get(
            "BTV_APPEALS_DB", "data/appeals.db"
        )
        self._init_db()
        self._load_from_db()

        # Metrics (recalculados do DB no startup)
        self.metrics = {
            'appeals_submitted': 0,
            'appeals_accepted': 0,
            'appeals_rejected': 0,
            'sla_violations': 0,
        }
        self._recalculate_metrics()

    # ── DATABASE ──────────────────────────────────────────────

    def _init_db(self) -> None:
        """Create appeals table if not exists."""
        os.makedirs(os.path.dirname(self._db_path) or ".", exist_ok=True)
        conn = sqlite3.connect(self._db_path)
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS appeals (
                    appeal_id       TEXT PRIMARY KEY,
                    audit_trail_id  INTEGER NOT NULL,
                    user_id         TEXT NOT NULL,
                    timestamp       INTEGER NOT NULL,
                    reason          TEXT NOT NULL,
                    evidence        TEXT,
                    status          TEXT NOT NULL DEFAULT 'pending',
                    reviewer_notes  TEXT,
                    resolution_ts   INTEGER,
                    sla_deadline    INTEGER NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_appeals_status
                ON appeals(status)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_appeals_user
                ON appeals(user_id)
            """)
            conn.commit()
        finally:
            conn.close()

    def _load_from_db(self) -> None:
        """Load all appeals from SQLite into cache."""
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT * FROM appeals ORDER BY timestamp"
            ).fetchall()
            for row in rows:
                appeal = self._row_to_appeal(row)
                self.appeals[appeal.appeal_id] = appeal
            if rows:
                logger.info("Loaded %d appeals from SQLite", len(rows))
        finally:
            conn.close()

    def _save_appeal(self, appeal: Appeal) -> None:
        """Persist appeal to SQLite."""
        conn = sqlite3.connect(self._db_path)
        try:
            conn.execute("""
                INSERT OR REPLACE INTO appeals
                (appeal_id, audit_trail_id, user_id, timestamp,
                 reason, evidence, status, reviewer_notes,
                 resolution_ts, sla_deadline)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                appeal.appeal_id,
                appeal.audit_trail_id,
                appeal.user_id,
                appeal.timestamp,
                appeal.reason,
                appeal.evidence_provided,
                appeal.status.value,
                appeal.reviewer_notes,
                appeal.resolution_timestamp,
                appeal.sla_deadline,
            ))
            conn.commit()
        finally:
            conn.close()

    def _recalculate_metrics(self) -> None:
        """Rebuild metrics from cache (after DB load)."""
        submitted = 0
        accepted = 0
        rejected = 0
        sla_violations = 0

        for appeal in self.appeals.values():
            submitted += 1
            if appeal.status == AppealStatus.ACCEPTED:
                accepted += 1
            elif appeal.status == AppealStatus.REJECTED:
                rejected += 1
            elif appeal.status == AppealStatus.EXPIRED:
                sla_violations += 1

        self.metrics = {
            'appeals_submitted': submitted,
            'appeals_accepted': accepted,
            'appeals_rejected': rejected,
            'sla_violations': sla_violations,
        }

    @staticmethod
    def _row_to_appeal(row: sqlite3.Row) -> Appeal:
        """Convert DB row to Appeal dataclass."""
        return Appeal(
            appeal_id=row["appeal_id"],
            audit_trail_id=row["audit_trail_id"],
            user_id=row["user_id"],
            timestamp=row["timestamp"],
            reason=row["reason"],
            evidence_provided=row["evidence"],
            status=AppealStatus(row["status"]),
            reviewer_notes=row["reviewer_notes"],
            resolution_timestamp=row["resolution_ts"],
            sla_deadline=row["sla_deadline"],
        )

    # ── PUBLIC API (interface idêntica v2.0) ──────────────────

    def submit_appeal(
        self,
        audit_trail_id: int,
        user_id: str,
        reason: str,
        evidence: Optional[str] = None,
    ) -> Appeal:
        """Submete recurso (LGPD Art. 20)."""
        if len(reason) < 20:
            raise ValueError("Reason must be at least 20 characters")

        appeal_id = f"APL-{audit_trail_id}-{int(time.time())}"
        appeal = Appeal(
            appeal_id=appeal_id,
            audit_trail_id=audit_trail_id,
            user_id=user_id,
            timestamp=int(time.time()),
            reason=reason,
            evidence_provided=evidence,
            status=AppealStatus.PENDING,
        )

        # Cache + SQLite (sync)
        self.appeals[appeal_id] = appeal
        self._save_appeal(appeal)
        self.metrics['appeals_submitted'] += 1

        logger.info(
            "Appeal submitted: %s by %s for decision %d",
            appeal_id, user_id, audit_trail_id,
        )
        self._notify_review_team(appeal)
        return appeal

    def resolve_appeal(
        self,
        appeal_id: str,
        accepted: bool,
        reviewer_notes: str,
        reviewer_id: str,
    ) -> Appeal:
        """Resolve recurso (decisão humana)."""
        if appeal_id not in self.appeals:
            raise ValueError(f"Appeal not found: {appeal_id}")

        appeal = self.appeals[appeal_id]
        appeal.status = (
            AppealStatus.ACCEPTED if accepted else AppealStatus.REJECTED
        )
        appeal.reviewer_notes = reviewer_notes
        appeal.resolution_timestamp = int(time.time())

        # Persist
        self._save_appeal(appeal)

        if accepted:
            self.metrics['appeals_accepted'] += 1
        else:
            self.metrics['appeals_rejected'] += 1

        resolution_time = appeal.resolution_timestamp - appeal.timestamp
        logger.info(
            "Appeal resolved: %s %s by %s (%.1fh)",
            appeal_id,
            "ACCEPTED" if accepted else "REJECTED",
            reviewer_id,
            resolution_time / 3600,
        )

        self._notify_user_decision(appeal)
        if accepted:
            self._update_false_positive_metrics(appeal.audit_trail_id)

        return appeal

    def get_appeal(self, appeal_id: str) -> Optional[Appeal]:
        return self.appeals.get(appeal_id)

    def list_pending_appeals(self) -> List[Appeal]:
        return [
            a for a in self.appeals.values()
            if a.status == AppealStatus.PENDING
        ]

    def list_expired_appeals(self) -> List[Appeal]:
        """Marca e retorna appeals que excederam SLA."""
        now = int(time.time())
        expired = []

        for appeal in self.appeals.values():
            if appeal.status == AppealStatus.PENDING:
                if now - appeal.timestamp > self.sla_seconds:
                    appeal.status = AppealStatus.EXPIRED
                    self._save_appeal(appeal)
                    self.metrics['sla_violations'] += 1
                    expired.append(appeal)
                    logger.warning(
                        "Appeal expired (SLA breach): %s (%.1fh)",
                        appeal.appeal_id,
                        (now - appeal.timestamp) / 3600,
                    )

        return expired

    def get_sla_compliance_rate(self) -> float:
        resolved = [
            a for a in self.appeals.values()
            if a.status in (AppealStatus.ACCEPTED, AppealStatus.REJECTED)
        ]
        if not resolved:
            return 1.0

        within_sla = sum(
            1 for a in resolved
            if (a.resolution_timestamp - a.timestamp) <= self.sla_seconds
        )
        return within_sla / len(resolved)

    def get_appeal_success_rate(self) -> float:
        total = self.metrics['appeals_accepted'] + self.metrics['appeals_rejected']
        if total == 0:
            return 0.0
        return self.metrics['appeals_accepted'] / total

    def get_metrics(self) -> Dict[str, Any]:
        pending = len(self.list_pending_appeals())
        return {
            **self.metrics,
            'pending_appeals': pending,
            'sla_compliance_rate': self.get_sla_compliance_rate(),
            'appeal_success_rate': self.get_appeal_success_rate(),
        }

    # ── STUBS (notificação) ───────────────────────────────────

    def expire_overdue(self) -> int:
        """Expira appeals além do SLA. Retorna quantidade expirada."""
        now = int(time.time())
        expired = 0
        for appeal in list(self.appeals.values()):
            sla_seconds = self.sla_seconds
            overdue = int(time.time()) > (appeal.timestamp + sla_seconds)
            if appeal.status == AppealStatus.PENDING and overdue:
                appeal.status = AppealStatus.EXPIRED
                appeal.resolution_timestamp = now
                self._save_appeal(appeal)
                expired += 1
                logger.info("Appeal %s expired (SLA breach)", appeal.appeal_id)
        if expired:
            self._recalculate_metrics()
        return expired

    def adjust_trust_after_appeal(self, appeal_id: str, trust_store: object) -> bool:
        """
        Ajusta trust score quando appeal é aceito (Gilligan: cuidado contínuo).
        trust_store deve implementar adjust(user_id, delta).
        Retorna True se ajuste foi aplicado.
        """
        appeal = self.get_appeal(appeal_id)
        if not appeal or appeal.status != AppealStatus.ACCEPTED:
            return False
        try:
            trust_store.adjust(appeal.user_id, delta=+0.1)
            logger.info("Trust adjusted for %s after accepted appeal %s",
                        appeal.user_id, appeal_id)
            return True
        except Exception as exc:
            logger.warning("Trust adjustment failed: %s", exc)
            return False

    def _notify_review_team(self, appeal: Appeal) -> None:
        logger.info("NOTIFY review team: %s", appeal.appeal_id)

    def _notify_user_decision(self, appeal: Appeal) -> None:
        status = "aceito" if appeal.status == AppealStatus.ACCEPTED else "rejeitado"
        logger.info("NOTIFY user %s: appeal %s %s", appeal.user_id, appeal.appeal_id, status)

    def _update_false_positive_metrics(self, audit_trail_id: int) -> None:
        logger.info("FP metric update for decision %d", audit_trail_id)