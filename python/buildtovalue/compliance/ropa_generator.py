"""
ROPA Generator v1.0 — Registro de Atividades de Tratamento (LGPD Art. 37, ADR-048).

Generates a legally compliant ROPA document from real ledger data.
The ROPA (Record of Processing Activities) is mandatory under LGPD for
controllers and processors that handle personal data.

Filosofia (Jonas): Data sovereignty — all data stays local.
Filosofia (Rawls): Equal documentation standard for all agents.
"""

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .ledger_analytics import LedgerAnalytics, LedgerAggregation

logger = logging.getLogger("btv.compliance.ropa")


@dataclass
class ROPAEntry:
    """Uma atividade de tratamento no ROPA (Art. 37)."""
    activity_name: str
    purpose: str
    legal_basis: str
    data_categories: List[str]
    data_subjects: str
    recipients: str
    retention_period: str
    security_measures: str
    cross_border_transfer: bool
    # From ledger:
    record_count: int = 0
    period_start: str = ""
    period_end: str = ""
    pii_types_detected: Dict[str, int] = field(default_factory=dict)
    risk_distribution: Dict[str, int] = field(default_factory=dict)
    block_count: int = 0
    mercy_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "activity_name": self.activity_name,
            "purpose": self.purpose,
            "legal_basis": self.legal_basis,
            "data_categories": self.data_categories,
            "data_subjects": self.data_subjects,
            "recipients": self.recipients,
            "retention_period": self.retention_period,
            "security_measures": self.security_measures,
            "cross_border_transfer": self.cross_border_transfer,
            "record_count": self.record_count,
            "period_start": self.period_start,
            "period_end": self.period_end,
            "pii_types_detected": self.pii_types_detected,
            "risk_distribution": self.risk_distribution,
            "block_count": self.block_count,
            "mercy_count": self.mercy_count,
        }


@dataclass
class ROPADocument:
    """Complete ROPA document (Art. 37)."""
    controller: str
    dpo_name: str
    dpo_contact: str
    entries: List[ROPAEntry]
    generated_at: str
    ledger_hash: str
    total_records_processed: int
    period_covered: str
    version: str = "1.0"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "document_type": "ROPA",
            "legal_basis": "LGPD Art. 37",
            "version": self.version,
            "controller": self.controller,
            "dpo_name": self.dpo_name,
            "dpo_contact": self.dpo_contact,
            "generated_at": self.generated_at,
            "ledger_hash": self.ledger_hash,
            "total_records_processed": self.total_records_processed,
            "period_covered": self.period_covered,
            "entries": [e.to_dict() for e in self.entries],
        }


class ROPAGenerator:
    """
    Generates ROPA (Registro de Atividades de Tratamento) from ledger data.

    Usage:
        analytics = LedgerAnalytics("data/ledger/decisions.jsonl")
        generator = ROPAGenerator(analytics)
        ropa = generator.generate(
            controller="Empresa XYZ",
            dpo_name="Maria Silva",
            dpo_contact="dpo@empresa.com",
        )
    """

    def __init__(self, analytics: LedgerAnalytics) -> None:
        self._analytics = analytics

    def generate(
        self,
        controller: str,
        dpo_name: str,
        dpo_contact: str,
        start_ts: Optional[int] = None,
        end_ts: Optional[int] = None,
    ) -> ROPADocument:
        """Generate ROPA document from ledger data."""
        agg = self._analytics.aggregate(start_ts=start_ts, end_ts=end_ts)

        entries = self._build_entries(agg)

        period = self._format_period(agg.period_start_ts, agg.period_end_ts)
        ledger_hash = self._compute_ledger_hash(agg)

        return ROPADocument(
            controller=controller,
            dpo_name=dpo_name,
            dpo_contact=dpo_contact,
            entries=entries,
            generated_at=datetime.now(timezone.utc).isoformat(),
            ledger_hash=ledger_hash,
            total_records_processed=agg.total_decisions,
            period_covered=period,
        )

    def _build_entries(self, agg: LedgerAggregation) -> List[ROPAEntry]:
        """Build ROPA entries from aggregated ledger data."""
        entries = []

        # Primary activity: AI Input Governance
        entries.append(ROPAEntry(
            activity_name="Governanca de Inputs de IA",
            purpose="Validacao de seguranca, deteccao de PII, e prevencao de injecao de prompt em inputs para sistemas de IA",
            legal_basis="Art. 7, IX — Interesse legitimo do controlador para protecao de seguranca",
            data_categories=self._infer_data_categories(agg),
            data_subjects="Usuarios de sistemas de IA operados pelo controlador",
            recipients="Nenhum — processamento local, dados nao sao compartilhados (Jonas: soberania de dados)",
            retention_period="Conforme politica de retencao do ledger (padrao: 90 dias para dados ativos, arquivo imutavel indefinido)",
            security_measures=(
                "HMAC-SHA256 para assinatura de verdicts; "
                "BLAKE3 para integridade do ledger; "
                "SLM local (zero exfiltracao de dados); "
                "Fail-secure design; "
                "Ledger imutavel (append-only)"
            ),
            cross_border_transfer=False,
            record_count=agg.total_decisions,
            period_start=self._format_ts(agg.period_start_ts),
            period_end=self._format_ts(agg.period_end_ts),
            pii_types_detected=agg.pii_types_detected,
            risk_distribution=agg.risk_distribution,
            block_count=agg.block_count,
            mercy_count=agg.mercy_count,
        ))

        # Secondary activity: Automated Decision-Making
        entries.append(ROPAEntry(
            activity_name="Tomada de Decisao Automatizada",
            purpose="Decisao automatica sobre permitir, bloquear, educar ou redigir inputs com base em risco calculado (Art. 20)",
            legal_basis="Art. 7, IX — Interesse legitimo; Art. 20 — Direito a revisao de decisoes automatizadas",
            data_categories=["Metadados de decisao", "Scores de risco", "Rationale de verdicts", "IDs de sessao"],
            data_subjects="Usuarios cujos inputs foram avaliados pelo sistema de governanca",
            recipients="Nenhum — decisoes armazenadas localmente no ledger imutavel",
            retention_period="Indefinido (ledger imutavel para auditoria e contestacao)",
            security_measures=(
                "Verdict IDs deterministicos (HMAC-SHA256); "
                "ContestabilityLoop com SLA 24h; "
                "Mercy algorithm (Gilligan) para mitigacao de dano"
            ),
            cross_border_transfer=False,
            record_count=agg.total_decisions,
            period_start=self._format_ts(agg.period_start_ts),
            period_end=self._format_ts(agg.period_end_ts),
            block_count=agg.block_count,
            mercy_count=agg.mercy_count,
        ))

        return entries

    def _infer_data_categories(self, agg: LedgerAggregation) -> List[str]:
        """Infer data categories from PII types detected in ledger."""
        categories = ["Texto de input (prompts/queries)"]
        pii = agg.pii_types_detected
        if pii.get("CPF", 0) > 0 or pii.get("CNPJ", 0) > 0:
            categories.append("Documentos de identificacao (CPF, CNPJ)")
        if pii.get("EMAIL", 0) > 0:
            categories.append("Dados de contato (email)")
        if pii.get("PHONE", 0) > 0:
            categories.append("Dados de contato (telefone)")
        if pii.get("CREDIT_CARD", 0) > 0:
            categories.append("Dados financeiros (cartao de credito)")
        if pii.get("SSN", 0) > 0:
            categories.append("Numero de seguridade social (SSN)")
        if pii.get("ADDRESS", 0) > 0:
            categories.append("Enderecos")
        if pii.get("PERSON_NAME", 0) > 0:
            categories.append("Nomes pessoais")
        if pii.get("HEALTH_INFO", 0) > 0:
            categories.append("Dados de saude (categoria especial)")
        if not pii:
            categories.append("Metadados de sessao e risco")
        return categories

    def _format_period(
        self, start_ts: Optional[int], end_ts: Optional[int],
    ) -> str:
        if start_ts and end_ts:
            start = datetime.fromtimestamp(start_ts / 1000, tz=timezone.utc).strftime("%Y-%m-%d")
            end = datetime.fromtimestamp(end_ts / 1000, tz=timezone.utc).strftime("%Y-%m-%d")
            return f"{start} a {end}"
        return "Periodo nao disponivel"

    def _format_ts(self, ts: Optional[int]) -> str:
        if ts:
            return datetime.fromtimestamp(ts / 1000, tz=timezone.utc).isoformat()
        return ""

    def _compute_ledger_hash(self, agg: LedgerAggregation) -> str:
        """Compute integrity hash of aggregation for ROPA provenance."""
        import json
        data = json.dumps(agg.to_dict(), sort_keys=True).encode()
        return hashlib.blake2b(data, digest_size=32).hexdigest()
