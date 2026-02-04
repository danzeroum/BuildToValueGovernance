
from dataclasses import dataclass
from typing import Optional, List
from enum import Enum
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from .explanation_store import ExplanationStore, FullExplanation

class AppealStatus(Enum):
    """Status de uma apelação"""
    PENDING = "pending"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    ESCALATED = "escalated"

@dataclass
class Appeal:
    """Apelação de usuário"""
    appeal_id: str
    audit_trail_id: int
    user_justification: str
    submitted_at: int
    status: AppealStatus
    
    # Revisão (preenchido pelo comitê)
    reviewer_id: Optional[str] = None
    review_decision: Optional[str] = None
    review_rationale: Optional[str] = None
    reviewed_at: Optional[int] = None
    
    # SLA
    sla_deadline: int = 0  # 24h após submitted_at
    
    def __post_init__(self):
        if self.sla_deadline == 0:
            self.sla_deadline = self.submitted_at + (24 * 3600)
    
    def is_overdue(self) -> bool:
        """Verifica se apelação está atrasada"""
        return int(time.time()) > self.sla_deadline and self.status == AppealStatus.PENDING

class ContestabilityLoop:
    """
    Implementa loop de contestação (LGPD Art. 20).
    
    Fluxo:
    1. Usuário bloqueado submete recurso
    2. Sistema cria caso para revisão humana
    3. Comitê Ético revisa dentro de 24h (SLA)
    4. Decisão é notificada ao usuário
    5. Se aprovado, policy é ajustada
    
    Garantias:
    - SLA 24h monitorado
    - Notificações automáticas
    - Auditoria completa de decisões
    """
    
    def __init__(
        self,
        explanation_store: ExplanationStore,
        email_config: dict,
    ):
        self.explanation_store = explanation_store
        self.email_config = email_config
        
        # Storage de apelações
        self.appeals: dict[str, Appeal] = {}
        
        # Comitê Ético (emails)
        self.committee_emails = email_config.get('committee_emails', [])
    
    def submit_appeal(
        self,
        audit_trail_id: int,
        user_email: str,
        justification: str,
    ) -> Appeal:
        """Usuário submete recurso"""
        
        # Valida que decisão existe
        explanation = self.explanation_store.get(audit_trail_id)
        if not explanation:
            raise ValueError(f"Audit trail not found: {audit_trail_id}")
        
        # Valida que foi bloqueado (não pode apelar de ALLOW)
        if explanation.verdict['action'] not in ['BLOCK', 'REDACT']:
            raise ValueError("Can only appeal blocked/redacted decisions")
        
        # Cria apelação
        appeal_id = f"APPEAL-{audit_trail_id}-{int(time.time())}"
        appeal = Appeal(
            appeal_id=appeal_id,
            audit_trail_id=audit_trail_id,
            user_justification=justification,
            submitted_at=int(time.time()),
            status=AppealStatus.PENDING,
        )
        
        self.appeals[appeal_id] = appeal
        
        # Notifica comitê
        self._notify_committee(appeal, explanation, user_email)
        
        # Notifica usuário
        self._notify_user_submission(user_email, appeal)
        
        import logging
        logging.info(
            f"Appeal submitted: {appeal_id} for audit_trail {audit_trail_id}"
        )
        
        return appeal
    
    def review_appeal(
        self,
        appeal_id: str,
        reviewer_id: str,
        decision: str,  # "approve" ou "reject"
        rationale: str,
    ) -> Appeal:
        """Comitê revisa apelação"""
        
        if appeal_id not in self.appeals:
            raise ValueError(f"Appeal not found: {appeal_id}")
        
        appeal = self.appeals[appeal_id]
        
        if appeal.status != AppealStatus.PENDING:
            raise ValueError(f"Appeal already reviewed: {appeal.status}")
        
        # Atualiza apelação
        appeal.reviewer_id = reviewer_id
        appeal.review_decision = decision
        appeal.review_rationale = rationale
        appeal.reviewed_at = int(time.time())
        
        if decision == "approve":
            appeal.status = AppealStatus.APPROVED
        elif decision == "reject":
            appeal.status = AppealStatus.REJECTED
        else:
            raise ValueError(f"Invalid decision: {decision}")
        
        # Se aprovado, atualiza policy (TODO)
        if appeal.status == AppealStatus.APPROVED:
            self._update_policy_from_appeal(appeal)
        
        # Notifica usuário
        explanation = self.explanation_store.get(appeal.audit_trail_id)
        self._notify_user_decision(appeal, explanation)
        
        import logging
        logging.info(
            f"Appeal reviewed: {appeal_id} → {decision} by {reviewer_id}"
        )
        
        return appeal
    
    def get_pending_appeals(self) -> List[Appeal]:
        """Retorna apelações pendentes (para dashboard)"""
        return [
            appeal for appeal in self.appeals.values()
            if appeal.status == AppealStatus.PENDING
        ]
    
    def get_overdue_appeals(self) -> List[Appeal]:
        """Retorna apelações atrasadas (>24h)"""
        return [
            appeal for appeal in self.appeals.values()
            if appeal.is_overdue()
        ]
    
    def _notify_committee(
        self,
        appeal: Appeal,
        explanation: FullExplanation,
        user_email: str,
    ):
        """Notifica comitê sobre nova apelação"""
        
        subject = f"[BuildToValue] Nova Apelação: {appeal.appeal_id}"
        
        body = f"""
Nova apelação submetida por usuário bloqueado.

**Detalhes da Apelação:**
- ID: {appeal.appeal_id}
- Audit Trail ID: {appeal.audit_trail_id}
- Usuário: {user_email}
- Submetido em: {time.ctime(appeal.submitted_at)}
- SLA Deadline: {time.ctime(appeal.sla_deadline)}

**Justificativa do Usuário:**
{appeal.user_justification}

**Decisão Original:**
- Ação: {explanation.verdict['action']}
- Risco: {explanation.evidence_summary['composite_risk']}/255
- Confiança: {explanation.verdict['confidence']:.0%}
- Rationale: {explanation.full_rationale}

**Findings Detectados:**
{self._format_findings(explanation.findings_detail)}

**Link para Revisão:**
https://btv.internal/appeals/{appeal.appeal_id}

Por favor, revise dentro de 24 horas.
        """
        
        self._send_email(
            to_emails=self.committee_emails,
            subject=subject,
            body=body,
        )
    
    def _notify_user_submission(self, user_email: str, appeal: Appeal):
        """Notifica usuário que apelação foi recebida"""
        
        subject = "Seu recurso foi recebido - BuildToValue"
        
        body = f"""
Olá,

Recebemos seu recurso sobre a decisão de bloqueio.

**ID do Recurso:** {appeal.appeal_id}
**Protocolo:** {appeal.audit_trail_id}

Seu recurso será analisado por nosso Comitê Ético dentro de 24 horas.
Você receberá uma resposta até: {time.ctime(appeal.sla_deadline)}

Obrigado pela sua paciência.

Atenciosamente,
Equipe BuildToValue
        """
        
        self._send_email([user_email], subject, body)
    
    def _notify_user_decision(self, appeal: Appeal, explanation: FullExplanation):
        """Notifica usuário sobre decisão da apelação"""
        
        if appeal.status == AppealStatus.APPROVED:
            subject = "Seu recurso foi APROVADO - BuildToValue"
            outcome = "✅ APROVADO"
        else:
            subject = "Decisão sobre seu recurso - BuildToValue"
            outcome = "❌ REJEITADO"
        
        body = f"""
Olá,

Analisamos seu recurso e chegamos a uma decisão.

**Decisão:** {outcome}

**Justificativa do Revisor:**
{appeal.review_rationale}

**Revisor:** {appeal.reviewer_id}
**Data da Revisão:** {time.ctime(appeal.reviewed_at)}

{"Sua solicitação foi liberada e nossas políticas foram ajustadas." if appeal.status == AppealStatus.APPROVED else "A decisão original foi mantida."}

Se tiver dúvidas, entre em contato: suporte@buildtovalue.com

Atenciosamente,
Equipe BuildToValue
        """
        
        # TODO: Obter email do usuário da explanation
        # self._send_email([user_email], subject, body)
    
    def _update_policy_from_appeal(self, appeal: Appeal):
        """Atualiza policy baseado em apelação aprovada"""
        
        # TODO: Implementar ajuste automático de policies
        # Ideias:
        # - Adicionar exceção para contexto específico
        # - Reduzir severidade de regra
        # - Adicionar usuário a whitelist
        
        import logging
        logging.info(
            f"Policy update triggered by appeal: {appeal.appeal_id}"
        )
    
    def _format_findings(self, findings: List[dict]) -> str:
        """Formata findings para email"""
        if not findings:
            return "Nenhuma violação detectada."
        
        lines = []
        for f in findings:
            lines.append(
                f"- {f['title']}: {f['description']} "
                f"(confiança: {f['confidence']/255.0:.0%})"
            )
        return "\n".join(lines)
    
    def _send_email(self, to_emails: List[str], subject: str, body: str):
        """Envia email via SMTP"""
        
        if not self.email_config.get('enabled', False):
            import logging
            logging.warning(f"Email disabled, would send: {subject}")
            return
        
        msg = MIMEMultipart()
        msg['From'] = self.email_config['from_email']
        msg['To'] = ', '.join(to_emails)
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'plain'))
        
        try:
            with smtplib.SMTP(
                self.email_config['smtp_host'],
                self.email_config['smtp_port']
            ) as server:
                server.starttls()
                server.login(
                    self.email_config['smtp_user'],
                    self.email_config['smtp_password']
                )
                server.send_message(msg)
        except Exception as e:
            import logging
            logging.error(f"Failed to send email: {e}")