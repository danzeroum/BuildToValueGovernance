"""
LedgerAnalytics v1.0 — Aggregate ledger data for compliance reports (ADR-048).

Read-only analytics over the decisions.jsonl ledger.
Never modifies the ledger. Fail-secure: missing data returns empty aggregations.

Reutiliza LedgerReader (ADR-025) para acesso ao ledger.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from buildtovalue.api.ledger_reader import LedgerReader, LedgerQuery

logger = logging.getLogger("btv.compliance.analytics")


@dataclass
class LedgerAggregation:
    """Aggregated ledger statistics for a time period."""
    total_decisions: int = 0
    period_start_ts: Optional[int] = None
    period_end_ts: Optional[int] = None

    # Action distribution
    action_counts: Dict[str, int] = field(default_factory=dict)
    # e.g. {"ALLOW": 500, "BLOCK": 50, "EDUCATE": 30, "REDACT": 20}

    # Risk distribution
    risk_distribution: Dict[str, int] = field(default_factory=dict)
    # e.g. {"low": 400, "medium": 100, "high": 40, "critical": 10}

    # PII-related stats (from findings)
    pii_types_detected: Dict[str, int] = field(default_factory=dict)

    # Mercy stats
    mercy_count: int = 0
    block_count: int = 0
    hard_block_count: int = 0

    # Contestation stats
    contested_count: int = 0

    # Average risk
    total_risk_sum: float = 0.0

    @property
    def avg_risk(self) -> float:
        return self.total_risk_sum / self.total_decisions if self.total_decisions > 0 else 0.0

    @property
    def block_rate(self) -> float:
        return self.block_count / self.total_decisions if self.total_decisions > 0 else 0.0

    @property
    def mercy_rate(self) -> float:
        return self.mercy_count / self.total_decisions if self.total_decisions > 0 else 0.0

    def to_dict(self) -> dict:
        return {
            "total_decisions": self.total_decisions,
            "period_start_ts": self.period_start_ts,
            "period_end_ts": self.period_end_ts,
            "action_counts": self.action_counts,
            "risk_distribution": self.risk_distribution,
            "pii_types_detected": self.pii_types_detected,
            "mercy_count": self.mercy_count,
            "block_count": self.block_count,
            "hard_block_count": self.hard_block_count,
            "contested_count": self.contested_count,
            "avg_risk": round(self.avg_risk, 4),
            "block_rate": round(self.block_rate, 4),
            "mercy_rate": round(self.mercy_rate, 4),
        }


@dataclass
class DecisionRecord:
    """Single decision record for Art. 20 reports."""
    verdict_id: str
    timestamp: int
    action: str
    final_action: str
    risk: float
    findings: int
    critical: int
    mercy: bool
    hard_blocked: bool
    session: str
    profile: str
    latency_ms: float

    def to_dict(self) -> dict:
        return {
            "verdict_id": self.verdict_id,
            "timestamp": self.timestamp,
            "action": self.action,
            "final_action": self.final_action,
            "risk": self.risk,
            "findings": self.findings,
            "critical": self.critical,
            "mercy": self.mercy,
            "hard_blocked": self.hard_blocked,
            "session": self.session,
            "profile": self.profile,
            "latency_ms": self.latency_ms,
        }


class LedgerAnalytics:
    """
    Read-only analytics engine over the BTV ledger.

    Provides aggregations for compliance document generation:
    - ROPA (Art. 37): data categories, processing counts, retention
    - Art. 20: automated decision records with verdict details
    - FRIA: risk distribution, violation stats, PII coverage

    Never modifies the ledger (fail-secure).
    """

    def __init__(self, ledger_path: str = "data/ledger/decisions.jsonl") -> None:
        self._reader = LedgerReader(ledger_path)

    def aggregate(
        self,
        start_ts: Optional[int] = None,
        end_ts: Optional[int] = None,
    ) -> LedgerAggregation:
        """
        Aggregate all ledger entries in the given time range.

        Returns LedgerAggregation with counts, distributions, and averages.
        """
        agg = LedgerAggregation()

        query = LedgerQuery(
            start_ts=start_ts,
            end_ts=end_ts,
            page_size=1000,
        )

        # Paginate through all results
        page = 1
        while True:
            q = LedgerQuery(
                start_ts=start_ts,
                end_ts=end_ts,
                page=page,
                page_size=1000,
            )
            result = self._reader.query(q)

            for entry in result.entries:
                self._process_entry(entry, agg)

            if page >= result.total_pages or not result.entries:
                break
            page += 1

        return agg

    def get_decision_records(
        self,
        start_ts: Optional[int] = None,
        end_ts: Optional[int] = None,
        action_filter: Optional[str] = None,
        limit: int = 1000,
    ) -> List[DecisionRecord]:
        """
        Get individual decision records for Art. 20 reporting.

        Returns list of DecisionRecord ordered by timestamp.
        """
        records: List[DecisionRecord] = []

        page = 1
        while len(records) < limit:
            q = LedgerQuery(
                start_ts=start_ts,
                end_ts=end_ts,
                action=action_filter,
                page=page,
                page_size=min(1000, limit - len(records)),
            )
            result = self._reader.query(q)

            for entry in result.entries:
                records.append(DecisionRecord(
                    verdict_id=entry.get("verdict_id", ""),
                    timestamp=entry.get("ts", 0),
                    action=entry.get("policy_action", ""),
                    final_action=entry.get("final_action", ""),
                    risk=float(entry.get("risk", 0.0)),
                    findings=int(entry.get("findings", 0)),
                    critical=int(entry.get("critical", 0)),
                    mercy=bool(entry.get("mercy", False)),
                    hard_blocked=bool(entry.get("hard_blocked", False)),
                    session=entry.get("session", ""),
                    profile=entry.get("profile", ""),
                    latency_ms=float(entry.get("latency_ms", 0.0)),
                ))

            if page >= result.total_pages or not result.entries:
                break
            page += 1

        return records[:limit]

    def _process_entry(self, entry: dict, agg: LedgerAggregation) -> None:
        """Process a single ledger entry into aggregation."""
        agg.total_decisions += 1

        ts = entry.get("ts", 0)
        if agg.period_start_ts is None or ts < agg.period_start_ts:
            agg.period_start_ts = ts
        if agg.period_end_ts is None or ts > agg.period_end_ts:
            agg.period_end_ts = ts

        # Action counts
        action = entry.get("final_action", "UNKNOWN")
        agg.action_counts[action] = agg.action_counts.get(action, 0) + 1

        # Risk distribution
        risk = float(entry.get("risk", 0.0))
        agg.total_risk_sum += risk
        if risk < 0.25:
            bucket = "low"
        elif risk < 0.5:
            bucket = "medium"
        elif risk < 0.75:
            bucket = "high"
        else:
            bucket = "critical"
        agg.risk_distribution[bucket] = agg.risk_distribution.get(bucket, 0) + 1

        # Mercy/block
        if entry.get("mercy", False):
            agg.mercy_count += 1
        if action == "BLOCK":
            agg.block_count += 1
        if entry.get("hard_blocked", False):
            agg.hard_block_count += 1

    @property
    def ledger_exists(self) -> bool:
        return self._reader.exists()

    @property
    def entry_count(self) -> int:
        return self._reader.entry_count()
