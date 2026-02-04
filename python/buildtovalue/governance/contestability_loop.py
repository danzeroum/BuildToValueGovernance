"""
Contestability Loop - Loop de contestação (Levinas).
Implementa direito de recurso humano em 24h (LGPD Art. 20).
"""
import logging
import time
from dataclasses import dataclass
from typing import Optional, List
from enum import Enum

from .explanation_store import ExplanationStore, FullExplanation

logger = logging.getLogger(__name__)


class AppealStatus(Enum):
    """Status de recurso."""
    PENDING = "PENDING"
    UNDER_REVIEW = "UNDER_REVIEW"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


@dataclass
class Appeal:
    """Recurso de usuário."""
    appeal_id: str
    audit_trail_id: int
    user_id: str
    timestamp: int
    reason: str
    evidence_provided: Optional[str] = None
    status: AppealStatus = AppealStatus.PENDING
    reviewer_notes: Optional[str] = None
    resolution_timestamp: Optional[int] = None


class ContestabilityLoop:
    """
    Implementa loop de contestabilidade.

    Garante:
    - SLA 24h para revisão humana
    - Transparência total (FullExplanation)
    - Notificação ao usuário
    - Audit trail de decisões
    """

    def __init__(
            self,
            explanation_store: ExplanationStore,
            sla_hours: int = 24
    ):
        """
        Inicializa loop.

        Args:
            explanation_store: Store de explicações
            sla_hours: SLA em horas para revisão (padrão: 24h)
        """
        self.explanation_store = explanation_store
        self.sla_seconds = sla_hours * 3600

        # Storage de appeals (em prod: usar DB)
        self.appeals: List[Appeal] = []

        # Config de notificações (em prod: configurar SMTP real)
        self.email_config = {
            'smtp_server': 'smtp.buildtovalue.com',
            'smtp_port': 587,
            'smtp_user': 'appeals@buildtovalue.com',
            'smtp_password': '***',  # Usar env var em prod
            'from_email': 'appeals@buildtovalue.com'
        }

    def submit_appeal(
            self,
            audit_trail_id: int,
            user_id: str,
            reason: str,
            evidence: Optional[str] = None
    ) -> Appeal:
        """
        Submete recurso de usuário.

        Args:
            audit_trail_id: ID da decisão contestada
            user_id: ID do usuário
            reason: Justificativa do recurso
            evidence: Evidências adicionais (opcional)

        Returns:
            Appeal criado

        Raises:
            ValueError: Se decisão não encontrada
        """
        # Verifica se decisão existe
        explanation = self.explanation_store.get(audit_trail_id)
        if not explanation:
            raise ValueError(f"Decision not found: {audit_trail_id}")

        # Cria appeal
        appeal = Appeal(
            appeal_id=f"APL-{audit_trail_id}-{int(time.time())}",
            audit_trail_id=audit_trail_id,
            user_id=user_id,
            timestamp=int(time.time()),
            reason=reason,
            evidence_provided=evidence,
            status=AppealStatus.PENDING
        )

        self.appeals.append(appeal)

        # Log
        logger.info(
            f"Appeal submitted: {appeal.appeal_id} by {user_id} "
            f"for decision {audit_trail_id}"
        )

        # Notifica equipe de revisão
        self._notify_review_team(appeal, explanation)

        return appeal

    def get_appeal(self, appeal_id: str) -> Optional[Appeal]:
        """Recupera appeal por ID."""
        for appeal in self.appeals:
            if appeal.appeal_id == appeal_id:
                return appeal
        return None

    def list_pending_appeals(self) -> List[Appeal]:
        """Lista appeals pendentes."""
        return [a for a in self.appeals if a.status == AppealStatus.PENDING]

    def list_expired_appeals(self) -> List[Appeal]:
        """Lista appeals que excederam SLA."""
        now = int(time.time())
        expired = []

        for appeal in self.appeals:
            if appeal.status == AppealStatus.PENDING:
                elapsed = now - appeal.timestamp
                if elapsed > self.sla_seconds:
                    appeal.status = AppealStatus.EXPIRED
                    expired.append(appeal)
                    logger.warning(
                        f"Appeal expired (SLA breach): {appeal.appeal_id} "
                        f"(elapsed: {elapsed / 3600:.1f}h)"
                    )

        return expired

    def resolve_appeal(
            self,
            appeal_id: str,
            accepted: bool,
            reviewer_notes: str,
            reviewer_id: str
    ):
        """
        Resolve appeal (decisão humana).

        Args:
            appeal_id: ID do appeal
            accepted: True se aceito, False se rejeitado
            reviewer_notes: Notas do revisor
            reviewer_id: ID do revisor humano
        """
        appeal = self.get_appeal(appeal_id)
        if not appeal:
            raise ValueError(f"Appeal not found: {appeal_id}")

        # Atualiza status
        appeal.status = AppealStatus.ACCEPTED if accepted else AppealStatus.REJECTED
        appeal.reviewer_notes = reviewer_notes
        appeal.resolution_timestamp = int(time.time())

        # Calcula tempo de resolução
        resolution_time = appeal.resolution_timestamp - appeal.timestamp

        # Log
        logger.info(
            f"Appeal resolved: {appeal_id} → "
            f"{'ACCEPTED' if accepted else 'REJECTED'} "
            f"by {reviewer_id} "
            f"(resolution time: {resolution_time / 3600:.1f}h)"
        )

        # Notifica usuário
        self._notify_user_decision(appeal)

        # Se aceito, atualiza métricas de sistema
        if accepted:
            self._update_false_positive_metrics(appeal.audit_trail_id)

    def _notify_review_team(self, appeal: Appeal, explanation: FullExplanation):
        """
        Notifica equipe de revisão sobre novo appeal.

        Em prod: enviar email real + criar ticket no sistema.
        """
        logger.info(
            f"[NOTIFICATION] New appeal for review: {appeal.appeal_id}\n"
            f"  User: {appeal.user_id}\n"
            f"  Decision: {explanation.verdict['action']}\n"
            f"  Reason: {appeal.reason}\n"
            f"  SLA: {self.sla_seconds / 3600}h"
        )

        # TODO: Enviar email real
        # self._send_email(
        #     to='review-team@buildtovalue.com',
        #     subject=f'New Appeal: {appeal.appeal_id}',
        #     body=...
        # )

    def _notify_user_decision(self, appeal: Appeal):
        """
        Notifica usuário sobre decisão do appeal.

        Em prod: enviar email real.
        """
        status = "aceito" if appeal.status == AppealStatus.ACCEPTED else "rejeitado"

        logger.info(
            f"[NOTIFICATION] Appeal decision to user {appeal.user_id}:\n"
            f"  Appeal: {appeal.appeal_id}\n"
            f"  Status: {status}\n"
            f"  Notes: {appeal.reviewer_notes}"
        )

        # TODO: Obter email do usuário da explanation
        # user_email = self._get_user_email(appeal.user_id)
        # self._send_email(
        #     to=user_email,
        #     subject=f'Decisão sobre seu recurso: {appeal.appeal_id}',
        #     body=...
        # )

    def _update_false_positive_metrics(self, audit_trail_id: int):
        """
        Atualiza métricas de falsos positivos.

        Appeals aceitos indicam que o sistema cometeu erro.
        Importante para calibração futura.
        """
        logger.info(
            f"False positive detected: audit_trail_id={audit_trail_id}. "
            "Updating model calibration metrics."
        )

        # TODO: Atualizar métricas em sistema de observability
        # prometheus_counter('false_positives_total').inc()

    def get_sla_compliance_rate(self) -> float:
        """
        Calcula taxa de conformidade com SLA.

        Returns:
            Taxa de appeals resolvidos dentro do SLA (0.0-1.0)
        """
        resolved = [
            a for a in self.appeals
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
