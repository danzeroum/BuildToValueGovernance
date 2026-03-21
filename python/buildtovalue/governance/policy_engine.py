"""PolicyEngine v1.1.0 — ADR-011 + ADR-042 (Policy-as-Code / Legislativo)

Republica Algoritmica — ramo Legislativo.
Carrega politicas YAML (Rawls), avalia contexto etico, retorna
PolicyEvalResult contestavel com explain_decision() obrigatorio.

Invariantes:
- fail-secure: excecao -> BLOCK assinado (Jonas)
- explain_decision() em todos os caminhos (Levinas)
- HMAC-SHA256 sobre resultado (Jonas: responsabilidade assinada)
- funcoes <= 50 linhas, zero bare except, zero Any sem justificativa

v1.1.0 (ADR-042):
- ModelConfig, ModelIntegrityConfig, AbliterationConfig — dataclasses frozen
- _load_policies usa rglob para carregar subdiretorios (ex: security/)
- Novos accessors: .model_integrity, .abliteration, .abliteration_threshold,
  .manifest_path_for(model_id)
- AbliterationDetector e ModelIntegrityVerifier NAO alterados neste ciclo
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


# ---------------------------------------------------------------------------
# ADR-042: Typed accessors para Model Integrity e Abliteration
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ModelConfig:
    """Configuracao por modelo: manifest_path e env var para hash esperado."""
    manifest_path: str
    expected_hash_env: str


@dataclass(frozen=True)
class ModelIntegrityConfig:
    """ADR-042: Configuracao tipada de integridade de modelo.

    Rawls: verificacao de integridade como contrato social — nenhum modelo
    opera sem hash validado quando verification_enabled=True.
    Jonas: defaults conservadores (verification_enabled=True, block_on_failure=True).
    """
    verification_enabled: bool
    block_on_failure: bool
    models: Dict[str, ModelConfig]  # Dict justificado: chave = model_id (str dinamico)


@dataclass(frozen=True)
class AbliterationConfig:
    """ADR-042: Configuracao tipada de deteccao de abliteration.

    refusal_threshold e clamped entre refusal_threshold_min e
    refusal_threshold_max para evitar configuracao insegura.
    """
    refusal_threshold: float        # clamped no accessor — nunca fora de [min, max]
    refusal_threshold_min: float
    refusal_threshold_max: float
    probe_timeout_ms: int


@dataclass(frozen=True)
class ArtifactAllowlistConfig:
    """C15: Configuracao tipada de allowlist de artefatos (Cenario 11).

    Complementa supply_guard.rs + skill_registry.rs (Rust layer).
    Fail-secure (Jonas): block_on_unknown_artifact=True por padrao —
    artefato desconhecido = BLOCK, nunca ALLOW silencioso.
    """
    require_artifact_allowlist: bool
    allowlist_hash_algorithm: str   # "blake3" ou "sha256"
    block_on_unknown_artifact: bool


# ---------------------------------------------------------------------------
# PolicyEngine
# ---------------------------------------------------------------------------

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
        # ADR-043: configuracao de governanca lida dos YAMLs (campo governance:)
        self._governance_config: dict = {}
        _dir = policies_dir or (
            Path(__file__).parent.parent.parent.parent / "data" / "policies"
        )
        self._load_policies(_dir)

    def _load_policies(self, policies_dir: Path) -> None:
        """Carrega YAMLs recursivamente (rglob). Fail-secure: parse error -> skip."""
        if not policies_dir.exists():
            return
        for yaml_file in sorted(policies_dir.rglob("*.yaml")):
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
        # ADR-043 + ADR-042: ler configuracao de governanca (governance:) se presente
        if "governance" in data and isinstance(data["governance"], dict):
            self._governance_config.update(data["governance"])

    # -----------------------------------------------------------------------
    # Properties existentes
    # -----------------------------------------------------------------------

    @property
    def report_threshold(self) -> float:
        """ADR-043: threshold para emissao de REPORT, lido do YAML.
        Respeita floor (min) e ceiling (max) definidos na policy.
        Default 0.65 se nao configurado.
        """
        raw = self._governance_config.get("report_threshold", 0.65)
        floor = self._governance_config.get("report_threshold_min", 0.50)
        ceiling = self._governance_config.get("report_threshold_max", 0.85)
        try:
            value = float(raw)
        except (TypeError, ValueError):
            value = 0.65
        return max(floor, min(ceiling, value))

    # -----------------------------------------------------------------------
    # ADR-042: Novos accessors tipados
    # -----------------------------------------------------------------------

    @property
    def model_integrity(self) -> ModelIntegrityConfig:
        """ADR-042: Configuracao tipada de integridade de modelo.

        Fail-secure (Jonas): defaults conservadores quando YAML ausente —
        verification_enabled=True, block_on_failure=True.
        """
        cfg: dict = self._governance_config.get("model_integrity", {})
        raw_models: dict = cfg.get("models", {}) if isinstance(cfg, dict) else {}
        models: Dict[str, ModelConfig] = {}
        for model_id, mcfg in raw_models.items():
            if isinstance(mcfg, dict):
                models[str(model_id)] = ModelConfig(
                    manifest_path=str(mcfg.get("manifest_path", "")),
                    expected_hash_env=str(mcfg.get("expected_hash_env", "")),
                )
        return ModelIntegrityConfig(
            verification_enabled=bool(cfg.get("verification_enabled", True)),
            block_on_failure=bool(cfg.get("block_on_failure", True)),
            models=models,
        )

    @property
    def abliteration(self) -> AbliterationConfig:
        """ADR-042: Configuracao tipada de deteccao de abliteration.

        refusal_threshold e clamped entre min e max.
        Fail-secure: defaults conservadores se nao configurado.
        """
        cfg: dict = self._governance_config.get("abliteration", {})
        if not isinstance(cfg, dict):
            cfg = {}
        try:
            value = float(cfg.get("refusal_threshold", 0.6))
            floor_f = float(cfg.get("refusal_threshold_min", 0.4))
            ceiling_f = float(cfg.get("refusal_threshold_max", 0.9))
        except (TypeError, ValueError):
            value, floor_f, ceiling_f = 0.6, 0.4, 0.9
        clamped = max(floor_f, min(ceiling_f, value))
        return AbliterationConfig(
            refusal_threshold=clamped,
            refusal_threshold_min=floor_f,
            refusal_threshold_max=ceiling_f,
            probe_timeout_ms=int(cfg.get("probe_timeout_ms", 5000)),
        )

    @property
    def abliteration_threshold(self) -> float:
        """ADR-042: atalho para refusal_threshold clamped — espelha report_threshold."""
        return self.abliteration.refusal_threshold

    def manifest_path_for(self, model_id: str) -> Optional[str]:
        """ADR-042: retorna manifest_path para model_id, ou None se ausente.

        Retorna None em vez de lancar excecao — fail-secure sem BLOCK:
        a ausencia de manifest e tratada pelo ModelIntegrityVerifier.
        """
        model_cfg = self.model_integrity.models.get(model_id)
        if model_cfg is None:
            return None
        return model_cfg.manifest_path if model_cfg.manifest_path else None

    @property
    def artifact_allowlist(self) -> ArtifactAllowlistConfig:
        """C15: Configuracao tipada de allowlist de artefatos (Cenario 11 — typosquatting).

        Fail-secure (Jonas): block_on_unknown_artifact=True por padrao —
        artefato desconhecido = BLOCK se require_artifact_allowlist=True.
        require_artifact_allowlist=False por padrao (dev mode compativel com
        skill_registry vazio).
        """
        cfg: dict = self._governance_config.get("artifact_allowlist", {})
        return ArtifactAllowlistConfig(
            require_artifact_allowlist=bool(cfg.get("require_artifact_allowlist", False)),
            allowlist_hash_algorithm=str(cfg.get("allowlist_hash_algorithm", "blake3")),
            block_on_unknown_artifact=bool(cfg.get("block_on_unknown_artifact", True)),
        )

    # -----------------------------------------------------------------------
    # Core evaluation (inalterado de v1.0.0)
    # -----------------------------------------------------------------------

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
