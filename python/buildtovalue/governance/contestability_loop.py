"""
Contestability Loop v2.0 - Human-in-the-Loop (Levinas)

Responsabilidades:
- Aceita recursos de decisões (LGPD Art. 20)
- SLA 24h para resposta humana
- Feedback loop (melhoria contínua)
- Audit trail completo

Filosofia: Levinas (Dever de Cuidado) - Sempre dar direito de recurso
Gate: Week 4 - Day 18
"""

import time
import logging
from enum import Enum
from typing import Optional, List, Dict, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# APPEAL TYPES
# ═══════════════════════════════════════════════════════════════════════════

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
    sla_deadline: int = 0  # 24h após timestamp

    def __post_init__(self):
        """Calcula deadline SLA."""
        if self.sla_deadline == 0:
            self.sla_deadline = self.timestamp + (24 * 3600)  # 24 horas

    def is_overdue(self) -> bool:
        """Verifica se SLA foi violado."""
        return int(time.time()) > self.sla_deadline and self.status == AppealStatus.PENDING


# ═══════════════════════════════════════════════════════════════════════════
# CONTESTABILITY LOOP
# ═══════════════════════════════════════════════════════════════════════════

class ContestabilityLoop:
    """
    Contestability Loop v2.0 - Human-in-the-Loop.

    Features:
    - Submit appeals (user requests)
    - SLA 24h tracking
    - Human review workflow
    - Feedback loop (learn from mistakes)
    - Metrics (appeal success rate)

    Philosophy: Levinas (Dever de Cuidado)
    - Sempre permitir contestação
    - Resposta em tempo razoável (24h)
    - Transparência na justificativa

    Performance: <5ms to submit appeal
    """

    def __init__(self, sla_hours: int = 24):
        """
        Inicializa loop.

        Args:
            sla_hours: SLA em horas para resposta (padrão: 24h)
        """
        self.sla_seconds = sla_hours * 3600
        self.appeals: Dict[str, Appeal] = {}  # Em prod: DB

        # Metrics
        self.metrics = {
            'appeals_submitted': 0,
            'appeals_accepted': 0,
            'appeals_rejected': 0,
            'sla_violations': 0,
        }

    def submit_appeal(
            self,
            audit_trail_id: int,
            user_id: str,
            reason: str,
            evidence: Optional[str] = None,
    ) -> Appeal:
        """
        Submete recurso.

        Args:
            audit_trail_id: ID da decisão contestada
            user_id: ID do usuário
            reason: Justificativa (min 20 chars)
            evidence: Evidências adicionais (opcional)

        Returns:
            Appeal criado

        Raises:
            ValueError: Se reason muito curto
        """
        # Valida reason
        if len(reason) < 20:
            raise ValueError("Reason must be at least 20 characters")

        # Cria appeal
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
        self.metrics['appeals_submitted'] += 1

        logger.info(f"Appeal submitted: {appeal_id} by {user_id} for decision {audit_trail_id}")

        # Notifica equipe de revisão (em prod: email/Slack)
        self._notify_review_team(appeal)

        return appeal

    def resolve_appeal(
            self,
            appeal_id: str,
            accepted: bool,
            reviewer_notes: str,
            reviewer_id: str,
    ) -> Appeal:
        """
        Resolve recurso (decisão humana).

        Args:
            appeal_id: ID do appeal
            accepted: True se aceito, False se rejeitado
            reviewer_notes: Notas do revisor
            reviewer_id: ID do revisor

        Returns:
            Appeal atualizado

        Raises:
            ValueError: Se appeal não encontrado
        """
        if appeal_id not in self.appeals:
            raise ValueError(f"Appeal not found: {appeal_id}")

        appeal = self.appeals[appeal_id]

        # Atualiza status
        appeal.status = AppealStatus.ACCEPTED if accepted else AppealStatus.REJECTED
        appeal.reviewer_notes = reviewer_notes
        appeal.resolution_timestamp = int(time.time())

        # Metrics
        if accepted:
            self.metrics['appeals_accepted'] += 1
        else:
            self.metrics['appeals_rejected'] += 1

        # Resolution time
        resolution_time = appeal.resolution_timestamp - appeal.timestamp

        logger.info(
            f"Appeal resolved: {appeal_id} "
            f"{'ACCEPTED' if accepted else 'REJECTED'} "
            f"by {reviewer_id} "
            f"(resolution time: {resolution_time / 3600:.1f}h)"
        )

        # Notifica usuário
        self._notify_user_decision(appeal)

        # Se aceito, atualiza métricas de false positives
        if accepted:
            self._update_false_positive_metrics(appeal.audit_trail_id)

        return appeal

    def get_appeal(self, appeal_id: str) -> Optional[Appeal]:
        """Recupera appeal por ID."""
        return self.appeals.get(appeal_id)

    def list_pending_appeals(self) -> List[Appeal]:
        """Lista appeals pendentes."""
        return [a for a in self.appeals.values() if a.status == AppealStatus.PENDING]

    def list_expired_appeals(self) -> List[Appeal]:
        """Lista appeals que excederam SLA."""
        now = int(time.time())
        expired = []

        for appeal in self.appeals.values():
            if appeal.status == AppealStatus.PENDING:
                elapsed = now - appeal.timestamp
                if elapsed > self.sla_seconds:
                    appeal.status = AppealStatus.EXPIRED
                    self.metrics['sla_violations'] += 1
                    expired.append(appeal)
                    logger.warning(f"Appeal expired (SLA breach): {appeal.appeal_id} (elapsed: {elapsed / 3600:.1f}h)")

        return expired

    def get_sla_compliance_rate(self) -> float:
        """
        Calcula taxa de conformidade com SLA.

        Returns:
            Taxa de appeals resolvidos dentro do SLA (0.0-1.0)
        """
        resolved = [
            a for a in self.appeals.values()
            if a.status in [AppealStatus.ACCEPTED, AppealStatus.REJECTED]
        ]

        if not resolved:
            return 1.0  # Sem appeals = 100% compliance

        within_sla = 0
        for appeal in resolved:
            resolution_time = appeal.resolution_timestamp - appeal.timestamp
            if resolution_time <= self.sla_seconds:
                within_sla += 1

        return within_sla / len(resolved)

    def get_appeal_success_rate(self) -> float:
        """
        Calcula taxa de sucesso de appeals.

        Returns:
            Taxa de appeals aceitos (0.0-1.0)
        """
        total = self.metrics['appeals_accepted'] + self.metrics['appeals_rejected']
        if total == 0:
            return 0.0

        return self.metrics['appeals_accepted'] / total

    def _notify_review_team(self, appeal: Appeal):
        """Notifica equipe de revisão (stub - em prod: email/Slack)."""
        logger.info(f"NOTIFICATION: New appeal for review: {appeal.appeal_id}")
        logger.info(f"  User: {appeal.user_id}")
        logger.info(f"  Reason: {appeal.reason[:100]}...")
        logger.info(f"  SLA: {self.sla_seconds / 3600}h")

    def _notify_user_decision(self, appeal: Appeal):
        """Notifica usuário sobre decisão (stub - em prod: email)."""
        status = "aceito" if appeal.status == AppealStatus.ACCEPTED else "rejeitado"
        logger.info(f"NOTIFICATION: Appeal decision to user {appeal.user_id}")
        logger.info(f"  Appeal: {appeal.appeal_id}")
        logger.info(f"  Status: {status}")
        logger.info(f"  Notes: {appeal.reviewer_notes}")

    def _update_false_positive_metrics(self, audit_trail_id: int):
        """
        Atualiza métricas de falsos positivos.

        Appeals aceitos indicam que o sistema cometeu erro.
        Importante para calibração futura.
        """
        logger.info(f"False positive detected (audit_trail_id={audit_trail_id}). Updating model calibration metrics.")
        # Em prod: incrementar contador em Prometheus, atualizar BiasDeclaration

    def get_metrics(self) -> Dict[str, Any]:
        """Retorna métricas."""
        return {
            **self.metrics,
            'pending_appeals': len(self.list_pending_appeals()),
            'sla_compliance_rate': self.get_sla_compliance_rate(),
            'appeal_success_rate': self.get_appeal_success_rate(),
        }
