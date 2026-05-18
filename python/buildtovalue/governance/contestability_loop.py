"""
Contestability Loop v3.1.0 — Human-in-the-Loop (Levinas)
ADR-017 + ADR-047: SQLite persistence + Structured Mediation Protocol.

Responsabilidades:
- Aceita recursos de decisões (LGPD Art. 20 / EU AI Act Art. 86)
- SLA 24h para resposta humana (Jonas: responsabilidade ativa)
- Persistência SQLite (durável, sobrevive a restarts)
- Feedback loop (melhoria contínua)
- Audit trail completo
- ADR-047: grounds filosóficos + mediator_recommendation + evidence_hash

Mudanças v3.1 (ADR-047):
- [BREAKING-NONE] 3 campos opcionais em Appeal
- [BREAKING-NONE] VALID_GROUNDS frozenset (vocabulário controlado)
- [BREAKING-NONE] validated_grounds() em Appeal
- [BREAKING-NONE] mediator_recommendation param em resolve_appeal()
- Schema SQLite estendido com colunas opcionais (ALTER TABLE se db existente)
"""

import hashlib
import hmac
import os
import sqlite3
import time
import logging
from enum import Enum
from typing import Literal, Optional, List, Dict, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# ADR-047: VOCABULÁRIO CONTROLADO DE GROUNDS
# Frozenset garante imutabilidade em runtime.
# ─────────────────────────────────────────────────────────────────────────────

VALID_GROUNDS: frozenset = frozenset({
    "rawls_equity",         # decisão não passaria pelo véu de ignorância
    "levinas_protection",   # falha em proteger o vulnerável
    "gilligan_mercy",       # rigidez sem contexto de cuidado
    "jonas_responsibility", # impacto de longo prazo ignorado
    "technical_error",      # evidência forense incorreta (BLAKE3)
    "scope_mismatch",       # policy aplicada fora do trust_boundary (ADR-045)
    "false_positive",       # validator disparou incorretamente
})

# Valores permitidos para mediator_recommendation
VALID_MEDIATOR_RECOMMENDATIONS: frozenset = frozenset({
    "accept_appeal",
    "reject_appeal",
    "escalate",
    "educate",
})


# ─────────────────────────────────────────────────────────────────────────────
# ETHICAL VERDICT (ADR-0028 + ADR-0005)
# ─────────────────────────────────────────────────────────────────────────────

_HMAC_KEY: bytes = os.environb.get(b"BTV_HMAC_KEY", b"btv-verdict-hmac-v1")


@dataclass
class EthicalVerdict:
    """
    Verdict final do pipeline de governança.

    ADR-0028: explain_decision() obrigatório — toda decisão deve ser explicável.
    ADR-0005: hmac_signature garante integridade do veredicto.
    CONTEST: enfileira em appeals.db para revisão humana ≤24h SLA (Jonas).
    """
    decision: Literal["ALLOW", "BLOCK", "EDUCATE", "CONTEST"]
    explanation: str
    bias_declaration: str
    finding_count: int = 0
    critical_count: int = 0
    hmac_signature: bytes = field(default_factory=bytes)

    def __post_init__(self) -> None:
        if not self.hmac_signature:
            self.hmac_signature = self._compute_hmac()

    def _compute_hmac(self) -> bytes:
        payload = f"{self.decision}|{self.explanation}|{self.bias_declaration}".encode()
        return hmac.new(_HMAC_KEY, payload, hashlib.sha256).digest()

    def verify(self) -> bool:
        return hmac.compare_digest(self.hmac_signature, self._compute_hmac())

    def explain_decision(self) -> str:
        """Return human-readable explanation (ADR-0028 mandatory)."""
        return (
            f"Decision: {self.decision}\n"
            f"Findings: {self.finding_count} total, {self.critical_count} critical\n"
            f"Bias: {self.bias_declaration}\n"
            f"Reason: {self.explanation}"
        )


def _derive_decision(finding_count: int, critical_count: int) -> Literal["ALLOW", "BLOCK", "EDUCATE", "CONTEST"]:
    if critical_count > 0:
        return "BLOCK"
    if finding_count > 0:
        return "EDUCATE"
    return "ALLOW"


def _summarize_bias(fpr: float, fnr: float) -> str:
    return f"FPR={fpr:.1%} FNR={fnr:.1%}"


def _build_explanation(decision: str, finding_count: int, critical_count: int) -> str:
    if decision == "BLOCK":
        return f"Blocked: {critical_count} critical finding(s) detected"
    if decision == "EDUCATE":
        return f"Flagged: {finding_count} finding(s) requiring review"
    return "No policy violations detected"


def build_verdict(
    finding_count: int,
    critical_count: int,
    fpr: float = 0.0,
    fnr: float = 0.0,
) -> EthicalVerdict:
    """Build and sign an EthicalVerdict from scan results (ADR-0028/ADR-0005)."""
    decision = _derive_decision(finding_count, critical_count)
    explanation = _build_explanation(decision, finding_count, critical_count)
    bias_declaration = _summarize_bias(fpr, fnr)
    return EthicalVerdict(
        decision=decision,
        explanation=explanation,
        bias_declaration=bias_declaration,
        finding_count=finding_count,
        critical_count=critical_count,
    )


# ─────────────────────────────────────────────────────────────────────────────
# APPEAL TYPES
# ─────────────────────────────────────────────────────────────────────────────

class AppealStatus(Enum):
    """Status de recurso."""
    PENDING      = "pending"
    UNDER_REVIEW = "under_review"
    ACCEPTED     = "accepted"
    REJECTED     = "rejected"
    EXPIRED      = "expired"


@dataclass
class Appeal:
    """
    Recurso de usuário — imutável após criação exceto campos de resolução.

    Invariante: reason >= 20 chars (Levinas — contestação pressupõe
    articulação mínima).

    ADR-047: campos opcionais para mediação estruturada.
    """
    appeal_id: str
    audit_trail_id: int
    user_id: str
    timestamp: int
    reason: str
    evidence_provided: Optional[str] = None

    # Resolução
    status: AppealStatus = AppealStatus.PENDING
    reviewer_notes: Optional[str] = None
    resolution_timestamp: Optional[int] = None

    # SLA
    sla_deadline: int = 0

    # ADR-047: Structured Mediation fields (opcionais, retrocompatível)
    evidence_hash: Optional[str] = None
    # BLAKE3 hash do TechnicalEvidence original — permite ao mediador
    # verificar integridade da evidência sem modificar o código de validação.

    grounds: list = field(default_factory=list)
    # Vocabulário controlado (VALID_GROUNDS).
    # Grounds inválidos são silenciosamente ignorados via validated_grounds().

    mediator_recommendation: Optional[str] = None
    # Preenchido pelo Reviewer antes de resolve_appeal().
    # Valores: "accept_appeal" | "reject_appeal" | "escalate" | "educate"

    def __post_init__(self) -> None:
        if self.sla_deadline == 0:
            self.sla_deadline = self.timestamp + (24 * 3600)

    def is_overdue(self) -> bool:
        return (
            int(time.time()) > self.sla_deadline
            and self.status == AppealStatus.PENDING
        )

    def validated_grounds(self) -> list:
        """Retorna apenas grounds do vocabulário controlado (VALID_GROUNDS).
        Não lança exceção para grounds inválidos — os ignora silenciosamente.
        """
        return [g for g in self.grounds if g in VALID_GROUNDS]


# ─────────────────────────────────────────────────────────────────────────────
# CONTESTABILITY LOOP v3.1.0
# ─────────────────────────────────────────────────────────────────────────────

class ContestabilityLoop:
    """
    Contestability Loop v3.1.0 — SQLite-backed + Structured Mediation.

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
        self.metrics: Dict[str, Any] = {
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
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")  # ADR-047: durability + concurrent reads
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
                    mediator_rec    TEXT
                )
            """)
            # Migração segura: adicionar colunas ADR-047 se db existente não as tiver
            existing = {
                row[1] for row in conn.execute("PRAGMA table_info(appeals)")
            }
            for col, typedef in [
                ("evidence_hash", "TEXT"),
                ("grounds",       "TEXT"),
                ("mediator_rec",  "TEXT"),
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
        with sqlite3.connect(self.db_path) as conn:
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
        """
        Resolve recurso (decisão humana).

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
        self, appeal_id: str, trust_store: object
    ) -> bool:
        """
        Ajusta trust score após resolução de appeal.

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

    def get_metrics(self) -> Dict[str, Any]:
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
        with sqlite3.connect(self.db_path) as conn:
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