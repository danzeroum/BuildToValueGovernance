"""PolicyEngine v1.0.0 — ADR-011 (Policy-as-Code / Legislativo)

Republica Algoritmica — ramo Legislativo.
Carrega politicas YAML (Rawls), avalia contexto etico, retorna
PolicyEvalResult contestavel com explain_decision() obrigatorio.

Invariantes:
- fail-secure: excecao -> BLOCK assinado (Jonas)
- explain_decision() em todos os caminhos (Levinas)
- HMAC-SHA256 sobre resultado (Jonas: responsabilidade assinada)
- funcoes <= 50 linhas, zero bare except, zero Any sem justificativa
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


class PolicyAction(Enum):
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    ESCALATE = "ESCALATE"
    BLOCK = "BLOCK"


class PolicySeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class PolicyRule:
    """Regra atomica carregada de YAML. Imutavel apos parse."""
    rule_id: str
    description: str
    action: PolicyAction
    severity: PolicySeverity
    condition_field: str          # "composite_risk" ou chave do context dict
    condition_operator: str       # gt | lt | gte | lte | eq | contains | in
    condition_value: Any          # Any justificado: valores YAML sao polimorficos
    adr_refs: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class PolicyEvalResult:
    """Resultado imutavel da avaliacao de politicas (Rawls: contrato auditavel)."""
    action: PolicyAction
    triggered_rules: List[str]
    policy_source: str
    composite_risk: float
    contestable: bool
    sla_deadline_iso: str
    hmac_tag: str
    explain: str

    def explain_decision(self) -> str:
        """Obrigatorio — ADR-016 Transparency Radical."""
        return self.explain


class PolicyEngine:
    """
    Motor de politicas runtime — ADR-011.

    Filosofia (Rawls): politicas sao o contrato social do sistema;
    toda decisao e tracavel ao YAML legislativo que a originou.
    Fail-secure (Jonas): excecao interna -> BLOCK, nunca silencio.
    """

    _HMAC_KEY: bytes = b"btv-policy-engine-v1-adr011"

    def __init__(self, policies_dir: Optional[Path] = None) -> None:
        self._rules: List[PolicyRule] = []
        self._policy_source: str = "none"
        _dir = policies_dir or (
            Path(__file__).parent.parent.parent.parent / "data" / "policies"
        )
        self._load_policies(_dir)

    def _load_policies(self, policies_dir: Path) -> None:
        """Carrega YAMLs de politicas. Fail-secure: parse error -> skip (nao BLOCK)."""
        if not policies_dir.exists():
            return
        for yaml_file in sorted(policies_dir.glob("*.yaml")):
            try:
                self._parse_policy_file(yaml_file)
            except Exception:
                pass  # policy malformada nao impede operacao

    def _parse_policy_file(self, yaml_file: Path) -> None:
        """Parse atomico de um arquivo YAML. Regras malformadas sao descartadas."""
        raw = yaml_file.read_text(encoding="utf-8")
        data = yaml.safe_load(raw)
        if not isinstance(data, dict):
            return
        for r in data.get("rules", []):
            try:
                rule = PolicyRule(
                    rule_id=r["rule_id"],
                    description=r.get("description", ""),
                    action=PolicyAction(r.get("action", "BLOCK").upper()),
                    severity=PolicySeverity(r.get("severity", "medium").lower()),
                    condition_field=r.get("condition_field", "composite_risk"),
                    condition_operator=r.get("condition_operator", "gt"),
                    condition_value=r.get("condition_value", 0.8),
                    adr_refs=r.get("adr_refs", []),
                )
                self._rules.append(rule)
                self._policy_source = yaml_file.name
            except (KeyError, ValueError):
                continue

    def evaluate(
        self,
        composite_risk: float,
        context: Dict[str, Any],
        audit_trail_id: str = "",
    ) -> PolicyEvalResult:
        """
        Avalia contexto contra todas as regras.
        Fail-secure: qualquer excecao -> BLOCK contestavel (Jonas).
        """
        try:
            return self._evaluate_rules(composite_risk, context, audit_trail_id)
        except Exception as exc:
            return self._fail_secure_result(str(exc), audit_trail_id)

    def _evaluate_rules(
        self,
        composite_risk: float,
        context: Dict[str, Any],
        audit_trail_id: str,
    ) -> PolicyEvalResult:
        triggered: List[str] = []
        worst = PolicyAction.ALLOW
        priority = {
            PolicyAction.ALLOW: 0,
            PolicyAction.REDACT: 1,
            PolicyAction.ESCALATE: 2,
            PolicyAction.BLOCK: 3,
        }
        for rule in self._rules:
            if self._matches(rule, composite_risk, context):
                triggered.append(rule.rule_id)
                if priority[rule.action] > priority[worst]:
                    worst = rule.action
        explain = self._build_explain(worst, triggered, composite_risk)
        hmac_tag = self._sign(worst, triggered, composite_risk, audit_trail_id)
        sla = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
        return PolicyEvalResult(
            action=worst,
            triggered_rules=triggered,
            policy_source=self._policy_source,
            composite_risk=composite_risk,
            contestable=True,
            sla_deadline_iso=sla,
            hmac_tag=hmac_tag,
            explain=explain,
        )

    def _matches(
        self,
        rule: PolicyRule,
        composite_risk: float,
        context: Dict[str, Any],
    ) -> bool:
        """Avalia uma regra. Any justificado: valores de campo sao polimorficos."""
        field_val: Any = (
            composite_risk if rule.condition_field == "composite_risk"
            else context.get(rule.condition_field)
        )
        if field_val is None:
            return False
        op, cv = rule.condition_operator, rule.condition_value
        try:
            if op == "gt":
                return float(field_val) > float(cv)
            if op == "lt":
                return float(field_val) < float(cv)
            if op == "gte":
                return float(field_val) >= float(cv)
            if op == "lte":
                return float(field_val) <= float(cv)
            if op == "eq":
                return str(field_val) == str(cv)
            if op == "contains":
                return str(cv).lower() in str(field_val).lower()
            if op == "in":
                return str(field_val) in (cv if isinstance(cv, list) else [cv])
        except (TypeError, ValueError):
            return False
        return False

    def _build_explain(
        self,
        action: PolicyAction,
        triggered: List[str],
        composite_risk: float,
    ) -> str:
        if not triggered:
            return (
                f"PolicyEngine: 0 regras ativadas. "
                f"composite_risk={composite_risk:.3f}. "
                f"Acao padrao: {action.value} (nenhuma restricao aplicavel)."
            )
        rules_str = ", ".join(triggered)
        return (
            f"PolicyEngine: {len(triggered)} regra(s) ativada(s): [{rules_str}]. "
            f"composite_risk={composite_risk:.3f}. "
            f"Acao determinada: {action.value} (pior caso — Rawls: maximin)."
        )

    def _sign(
        self,
        action: PolicyAction,
        triggered: List[str],
        composite_risk: float,
        audit_trail_id: str,
    ) -> str:
        payload = json.dumps(
            {
                "action": action.value,
                "triggered": sorted(triggered),
                "composite_risk": round(composite_risk, 6),
                "audit_trail_id": audit_trail_id,
            },
            sort_keys=True,
        ).encode()
        return hmac.new(self._HMAC_KEY, payload, hashlib.sha256).hexdigest()

    def _fail_secure_result(
        self, error: str, audit_trail_id: str
    ) -> PolicyEvalResult:
        sla = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
        explain = (
            f"PolicyEngine FAIL-SECURE: erro interno -> BLOCK (Jonas). "
            f"Motivo: {error[:120]}. "
            f"Contestavel: SLA 24h garantido (Rawls)."
        )
        return PolicyEvalResult(
            action=PolicyAction.BLOCK,
            triggered_rules=["FAIL_SECURE"],
            policy_source=self._policy_source,
            composite_risk=1.0,
            contestable=True,
            sla_deadline_iso=sla,
            hmac_tag=self._sign(PolicyAction.BLOCK, ["FAIL_SECURE"], 1.0, audit_trail_id),
            explain=explain,
        )

    @property
    def rule_count(self) -> int:
        return len(self._rules)
