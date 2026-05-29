"""ContestabilityLoop — orquestração de recursos humanos (ADR-0095).

A classe permanece coesa (estado: appeals em memória + SQLite + métricas).
A lógica de SLA é inseparável do loop: o predicado de prazo vive em
``Appeal.is_overdue`` (``_types``) e a varredura/expiração são métodos aqui.
"""
from __future__ import annotations

import logging
import sqlite3  # noqa: F401 — kept for sqlite3.Row / sqlite3.Connection type refs
import time
from typing import Dict, List, Optional, Protocol

from buildtovalue.security import sqlite_connect_wal

from ._types import VALID_MEDIATOR_RECOMMENDATIONS, Appeal, AppealStatus

logger = logging.getLogger(__name__)


class _TrustStore(Protocol):
    """Contrato mínimo do trust store consumido por adjust_trust_after_appeal."""
    def adjust(self, user_id: str, delta: float) -> object: ...


class ContestabilityLoop:
    """Contestability Loop v3.1.0 — SQLite-backed + Structured Mediation.

    Interface pública idêntica à v3.0 (zero breaking changes).
    resolve_appeal() aceita mediator_recommendation como parâmetro opcional.
    """

    def __init__(
        self,
        sla_hours: int = 24,
        db_path: Optional[str] = None,
    ) -> None:
        self.sla_hours = sla_hours
        import os as _os
        self.db_path = db_path or _os.environ.get("BTV_APPEALS_DB", "data/appeals.db")
        self.appeals: Dict[str, Appeal] = {}
        self.metrics: Dict[str, int] = {
            'appeals_submitted': 0,
            'appeals_accepted': 0,
            'appeals_rejected': 0,
            'appeals_expired': 0,
            'false_positives_confirmed': 0,
        }
        self._init_db()
        self._load_from_db()

    # ── INIT ──────────────────────────────────────────────────────────────────

    def _init_db(self) -> None:
        # sqlite_connect_wal applies journal_mode=WAL + synchronous=NORMAL +
        # busy_timeout uniformly (PR-2 / S-04); preserves ADR-047 semantics.
        with sqlite_connect_wal(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
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
                    sla_deadline    INTEGER NOT NULL,
                    evidence_hash   TEXT,
                    grounds         TEXT,
                    mediator_rec    TEXT,
                    hash_algorithm  TEXT DEFAULT 'blake3'
                )
            """)
            # Migração segura: adicionar colunas ADR-047/ADR-063 se db existente não as tiver
            existing = {
                row[1] for row in conn.execute("PRAGMA table_info(appeals)")
            }
            for col, typedef in [
                ("evidence_hash",  "TEXT"),
                ("grounds",        "TEXT"),
                ("mediator_rec",   "TEXT"),
                ("hash_algorithm", "TEXT DEFAULT 'blake3'"),
            ]:
                if col not in existing:
                    conn.execute(
                        f"ALTER TABLE appeals ADD COLUMN {col} {typedef}"
                    )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_user ON appeals(user_id)"
            )
            conn.commit()

    def _load_from_db(self) -> None:
        """Recupera appeals do SQLite na inicialização (recovery após restart)."""
        with sqlite_connect_wal(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            for row in conn.execute("SELECT * FROM appeals"):
                appeal = self._row_to_appeal(row)
                self.appeals[appeal.appeal_id] = appeal
                status = appeal.status
                if status == AppealStatus.ACCEPTED:
                    self.metrics['appeals_accepted'] += 1
                elif status == AppealStatus.REJECTED:
                    self.metrics['appeals_rejected'] += 1
                elif status == AppealStatus.EXPIRED:
                    self.metrics['appeals_expired'] += 1
                self.metrics['appeals_submitted'] += 1

    @staticmethod
    def _row_to_appeal(row: sqlite3.Row) -> Appeal:
        import json as _json
        grounds_raw = row["grounds"]
        grounds = _json.loads(grounds_raw) if grounds_raw else []
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
            evidence_hash=row["evidence_hash"],
            grounds=grounds,
            mediator_recommendation=row["mediator_rec"],
        )

    # ── PUBLIC API ────────────────────────────────────────────────────────────

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
        mediator_recommendation: Optional[str] = None,  # ADR-047
    ) -> Appeal:
        """Resolve recurso (decisão humana).

        ADR-047: mediator_recommendation opcional — quando fornecido,
        é persistido no registro para auditoria e altera o ajuste de
        trust de forma proporcional (Gilligan: educate não penaliza).
        """
        if appeal_id not in self.appeals:
            raise ValueError(f"Appeal not found: {appeal_id}")

        appeal = self.appeals[appeal_id]
        appeal.status = (
            AppealStatus.ACCEPTED if accepted else AppealStatus.REJECTED
        )
        appeal.reviewer_notes = reviewer_notes
        appeal.resolution_timestamp = int(time.time())

        # ADR-047: persistir recomendação do mediador
        if mediator_recommendation is not None:
            if mediator_recommendation in VALID_MEDIATOR_RECOMMENDATIONS:
                appeal.mediator_recommendation = mediator_recommendation
            else:
                logger.warning(
                    "mediator_recommendation '%s' não reconhecido — ignorado",
                    mediator_recommendation,
                )

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
        """Marca e retorna appeals que excederam SLA (Jonas: ativo)."""
        expired = []
        for appeal in self.appeals.values():
            if appeal.is_overdue():
                appeal.status = AppealStatus.EXPIRED
                self._save_appeal(appeal)
                self.metrics['appeals_expired'] += 1
                logger.info("Appeal %s expired (SLA breach)", appeal.appeal_id)
                expired.append(appeal)
        return expired

    def expire_overdue(self) -> int:
        """Expira appeals vencidos. Retorna quantidade expirada."""
        return len(self.list_expired_appeals())

    def adjust_trust_after_appeal(
        self, appeal_id: str, trust_store: _TrustStore
    ) -> bool:
        """Ajusta trust score após resolução de appeal.

        ADR-047: se mediator_recommendation presente, usa delta diferenciado:
          accept_appeal → +0.10 (reforço positivo)
          educate       → +0.00 (Gilligan: não penaliza)
          reject_appeal → -0.05 (penalização leve)
          escalate      → +0.00 (aguarda decisão superior)
          sem rec.      → +0.10 se ACCEPTED (comportamento original)

        trust_store deve implementar adjust(user_id, delta).
        """
        appeal = self.get_appeal(appeal_id)
        if not appeal or appeal.status not in (
            AppealStatus.ACCEPTED, AppealStatus.REJECTED
        ):
            return False

        rec = appeal.mediator_recommendation
        if rec == "accept_appeal" or (rec is None and appeal.status == AppealStatus.ACCEPTED):
            delta = +0.10
        elif rec == "educate" or rec == "escalate":
            delta = 0.0
        elif rec == "reject_appeal":
            delta = -0.05
        else:
            # REJECTED sem mediator_recommendation
            delta = 0.0

        trust_store.adjust(appeal.user_id, delta=delta)
        logger.info(
            "Trust adjusted: user=%s appeal=%s delta=%.2f rec=%s",
            appeal.user_id, appeal_id, delta, rec,
        )
        return True

    # ── METRICS ───────────────────────────────────────────────────────────────

    def get_sla_compliance_rate(self) -> float:
        total = self.metrics['appeals_submitted']
        expired = self.metrics['appeals_expired']
        if total == 0:
            return 1.0
        return max(0.0, (total - expired) / total)

    def get_appeal_success_rate(self) -> float:
        accepted = self.metrics['appeals_accepted']
        rejected = self.metrics['appeals_rejected']
        total = accepted + rejected
        if total == 0:
            return 0.0
        return accepted / total

    def get_metrics(self) -> Dict[str, object]:
        return {
            'appeals_submitted':  self.metrics.get('appeals_submitted', 0),
            'appeals_accepted':   self.metrics.get('appeals_accepted', 0),
            'appeals_rejected':   self.metrics.get('appeals_rejected', 0),
            'sla_violations':     self.metrics.get('sla_violations', 0),
            'pending_appeals':    len(self.list_pending_appeals()),
            'sla_compliance_rate': self.get_sla_compliance_rate(),
            'appeal_success_rate': self.get_appeal_success_rate(),
        }

    # ── PERSISTENCE ───────────────────────────────────────────────────────────

    def _save_appeal(self, appeal: Appeal) -> None:
        import json as _json
        grounds_json = _json.dumps(appeal.grounds) if appeal.grounds else None
        with sqlite_connect_wal(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO appeals
                (appeal_id, audit_trail_id, user_id, timestamp, reason,
                 evidence, status, reviewer_notes, resolution_ts,
                 sla_deadline, evidence_hash, grounds, mediator_rec)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
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
                appeal.evidence_hash,
                grounds_json,
                appeal.mediator_recommendation,
            ))
            conn.commit()

    # ── NOTIFICATIONS (hooks) ─────────────────────────────────────────────────

    def _notify_review_team(self, appeal: Appeal) -> None:
        logger.info("NOTIFY review team: %s", appeal.appeal_id)

    def _notify_user_decision(self, appeal: Appeal) -> None:
        logger.info(
            "NOTIFY user %s: appeal %s %s",
            appeal.user_id, appeal.appeal_id, appeal.status.value,
        )

    def _update_false_positive_metrics(self, audit_trail_id: int) -> None:
        self.metrics['false_positives_confirmed'] += 1
        logger.info("FP metric update for decision %d", audit_trail_id)
