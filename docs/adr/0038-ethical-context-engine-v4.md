# ADR-038: EthicalContextEngine v4.0 — Pipeline Filosófico Explícito + ExplainDecision Estruturado

**Status:** 🆕 PROPOSTO
**Data:** 24 de fevereiro de 2026
**Autores:** IA Arquiteta (Claude Sonnet 4.6) — validado por Staff Engineer
**Versão alvo:** v1.8.0
**Grupo:** B — Governança & Transparência
**Substitui:** ADR-016 (esboço promovido a spec completa)
**Depende de:** ADR-005 (Evidence v2.1), ADR-010 (BiasDeclaration), ADR-037 (AppealEngine)

**Impacto:**
```
python/buildtovalue/governance/context_engine.py      — refactor para v4.0
python/buildtovalue/governance/pipeline/              — novo subpacote
    rawls_stage.py
    levinas_stage.py
    jonas_stage.py
    gilligan_stage.py
python/buildtovalue/governance/explain_decision.py    — novo (estruturado)
python/tests/unit/governance/test_pipeline_v4.py      — novo
```

---

## 1. Contexto

### 1.1 O problema da filosofia implícita

O `EthicalContextEngine` v1.8.0 atual executa o pipeline em 7 steps não nomeados filosoficamente:

```python
# context_engine.py — atual
# Step 1: Trust score
# Step 2: First offense check
# Step 3: Mercy score
# Step 4: Mercy scenarios
# Step 5: IP/drift risk override
# Step 6: explain_decision()
# Step 7: HMAC signature
```

Rawls, Levinas, Jonas e Gilligan são **referenciados nos comentários** mas não são **estágios verificáveis**. Consequências:

- Um Reviewer não pode validar "o estágio de Rawls foi executado" — não existe como unidade testável.
- `explain_decision()` retorna uma string monolítica; auditores LGPD/EU AI Act precisam de campos estruturados.
- O `AppealEngine` (ADR-037) precisa verificar qual estágio produziu a decisão contestada — sem estrutura isso é impossível.

### 1.2 O que existe e o que muda

| Componente | Estado atual | Estado v4.0 |
|:---|:---|:---|
| Pipeline | 7 steps implícitos | 4 estágios nomeados + pre/pos |
| `explain_decision()` | `str` monolítica | `ExplainDecision` dataclass estruturada |
| Verificação filosófica | Comentários | Cada estágio retorna `StageResult` testável |
| Integração AppealEngine | Ausente | `EthicalVerdict.appeal_hint` gerado pelo estágio Levinas |
| Auditoria por estágio | Impossível | `EthicalVerdict.pipeline_trace` lista todos os estágios |

---

## 2. Decisão

### 2.1 Arquitetura do Pipeline v4.0

```
                    ┌────────────────────────────────────────────┐
                    │         EthicalContextEngine v4.0          │
                    │           decide(evidence, context)        │
                    └───────────────────┬────────────────────────┘
                                        │
                    ┌───────────────────▼────────────────────────┐
                    │  PRE: PolicyAction (do Rust/PolicyEngine)   │
                    │  Entrada: RustEvidence.policy_action        │
                    └───────────────────┬────────────────────────┘
                                        │
           ┌────────────────────────────▼───────────────────────────────┐
           │  ESTÁGIO 1 — RAWLS (Equidade Procedimental)                │
           │  RawlsStage.evaluate(evidence, context)                    │
           │  • Blind evaluation: mesma lógica para qualquer identidade │
           │  • Verifica se policy_action é consistente com YAML        │
           │  • Output: RawlsResult (policy_consistent, veil_passed)    │
           └────────────────────────────┬───────────────────────────────┘
                                        │
           ┌────────────────────────────▼───────────────────────────────┐
           │  ESTÁGIO 2 — LEVINAS (Cuidado com o Outro)                 │
           │  LevinasStage.evaluate(evidence, context, rawls_result)    │
           │  • Detecta vulnerabilidade do usuário (role, domain)       │
           │  • Avalia se BLOCK causa dano desproporcional              │
           │  • Define contestable + appeal_hint (liga ao AppealEngine) │
           │  • Output: LevinasResult (vulnerability, care_override)    │
           └────────────────────────────┬───────────────────────────────┘
                                        │
           ┌────────────────────────────▼───────────────────────────────┐
           │  ESTÁGIO 3 — JONAS (Responsabilidade Proporcional)         │
           │  JonasStage.evaluate(evidence, context, levinas_result)    │
           │  • Verifica BiasDeclaration (calibration_date válida?)     │
           │  • Pondera custo da ação vs severidade do risco            │
           │  • IP/drift risk override (responsabilidade pelo contexto) │
           │  • Output: JonasResult (proportional_action, bias_ok)      │
           └────────────────────────────┬───────────────────────────────┘
                                        │
           ┌────────────────────────────▼───────────────────────────────┐
           │  ESTÁGIO 4 — GILLIGAN (Misericórdia Contextual)            │
           │  GilliganStage.evaluate(evidence, context, jonas_result)   │
           │  • Trust score + violation history                         │
           │  • 6 mercy scenarios calibrados (S1–S6)                   │
           │  • Downgrade apenas se Jonas não escalou por risk          │
           │  • Output: GilliganResult (final_action, scenario_id)      │
           └────────────────────────────┬───────────────────────────────┘
                                        │
                    ┌───────────────────▼────────────────────────┐
                    │  POS: HMAC-SHA256 + ExplainDecision        │
                    │  Assinatura criptográfica + raciocínio     │
                    │  estruturado por estágio                   │
                    └───────────────────┬────────────────────────┘
                                        │
                    ┌───────────────────▼────────────────────────┐
                    │         EthicalVerdict v4.0                │
                    │  + pipeline_trace: list[StageResult]       │
                    │  + explain: ExplainDecision                │
                    └────────────────────────────────────────────┘
```

### 2.2 Tipos Base

```python
# python/buildtovalue/governance/pipeline/__init__.py

from dataclasses import dataclass, field
from typing import Optional, Any

@dataclass(frozen=True)
class StageResult:
    """
    Resultado imutável de um estágio filosófico.
    frozen=True: estágios não se modificam após execução (auditabilidade).
    """
    stage_name: str           # "rawls" | "levinas" | "jonas" | "gilligan"
    philosopher: str          # Nome completo para relatórios
    action_in: str            # Ação ao entrar no estágio
    action_out: str           # Ação ao sair (pode ser igual = sem alteração)
    modified: bool            # True se action_out != action_in
    rationale: str            # Justificativa deste estágio (para ExplainDecision)
    metadata: dict = field(default_factory=dict)  # dados extras por estágio
```

### 2.3 Estágio 1 — Rawls

```python
# python/buildtovalue/governance/pipeline/rawls_stage.py

"""
Rawls Stage v1.0.0 (ADR-038)

Princípio: Véu da Ignorância — a decisão deve ser a mesma independente
de quem é o usuário. Verifica consistência da policy_action com as regras
YAML que a produziram.

Função: gate de consistência, não de modificação.
Rawls raramente altera a ação — ele VALIDA que a ação é justa proceduralmente.
"""

from dataclasses import dataclass
from .base import StageResult
from ..context_engine import RustEvidence, RequestContext

@dataclass(frozen=True)
class RawlsResult(StageResult):
    policy_consistent: bool = True   # action está alinhada com policy YAML
    veil_passed: bool = True         # sem tratamento diferenciado por identidade
    anomaly_detected: bool = False   # policy_action inconsistente com evidence

class RawlsStage:
    """
    Verifica equidade procedimental.

    Rawls não modifica a ação — ele sinaliza anomalias.
    Uma anomalia (ALLOW com risco > 0.8) não reverte a ação automaticamente
    mas é registrada no pipeline_trace para auditoria.

    Filosofia: nenhuma identidade recebe tratamento especial.
    O Véu da Ignorância garante que se o avaliador não soubesse quem é o
    usuário, tomaria a mesma decisão.
    """

    # Limites que tornam uma policy_action suspeita
    _ANOMALY_RULES = [
        # (policy_action, condição, mensagem)
        ("ALLOW", lambda e: e.composite_risk > 0.8,
         "ALLOW com risco > 0.8 — possível inconsistência de policy"),
        ("ALLOW", lambda e: e.critical_count > 0,
         "ALLOW com findings críticos — requer auditoria"),
        ("BLOCK", lambda e: e.composite_risk < 0.1 and e.finding_count == 0,
         "BLOCK com risco mínimo e zero findings — possível policy bug"),
    ]

    def evaluate(
        self,
        evidence: RustEvidence,
        context: RequestContext,
    ) -> RawlsResult:
        action = evidence.policy_action
        anomalies = []

        for act, condition, msg in self._ANOMALY_RULES:
            if action == act and condition(evidence):
                anomalies.append(msg)

        # Rawls não altera action — apenas documenta
        consistent = len(anomalies) == 0
        rationale = (
            f"Rawls (equidade procedimental): policy_action={action} "
            + ("consistente com evidence." if consistent
               else f"anomalia detectada: {'; '.join(anomalies)}.")
        )

        return RawlsResult(
            stage_name="rawls",
            philosopher="John Rawls — A Theory of Justice (1971)",
            action_in=action,
            action_out=action,          # Rawls não altera
            modified=False,
            rationale=rationale,
            policy_consistent=consistent,
            veil_passed=True,           # sempre: sem info de identidade aqui
            anomaly_detected=not consistent,
            metadata={"anomalies": anomalies},
        )
```

### 2.4 Estágio 2 — Levinas

```python
# python/buildtovalue/governance/pipeline/levinas_stage.py

"""
Levinas Stage v1.0.0 (ADR-038)

Princípio: O dever de cuidado com o Outro.
- Usuário vulnerável (role=student, domain=medical, primeira ocorrência) merece
  proteção especial antes de punição.
- Todo BLOCK deve ser contestável — direito de recurso é incondicional.
- Fail-secure: erros protegem o usuário, não o sistema.

Função: define contestability + care_override (abrandamento por vulnerabilidade).
"""

from dataclasses import dataclass
from .base import StageResult
from ..context_engine import RustEvidence, RequestContext

# Papéis considerados vulneráveis (Levinas: atenção ao Outro concreto)
VULNERABLE_ROLES = frozenset({"student", "patient", "minor", "anonymous"})

# Domínios de cuidado especial
CARE_DOMAINS = frozenset({"medical", "mental_health", "legal_aid", "education"})

@dataclass(frozen=True)
class LevinasResult(StageResult):
    user_vulnerable: bool = False
    care_override: bool = False          # abrandamento por vulnerabilidade
    contestable: bool = True             # sempre True (invariante)
    appeal_hint: str = ""                # mensagem ao usuário sobre como contestar
    hard_block: bool = False             # se True: não contestável (SQL_INJECTION etc)

class LevinasStage:
    """
    Avalia o dever de cuidado e define contestabilidade.

    Levinas pode ABRANDAR (nunca endurecer):
    - Usuário vulnerável + BLOCK + primeira ocorrência → EDUCATE
    - Domínio de cuidado + BLOCK + sem críticos → REDACT

    Invariante: contestable=True em qualquer decisão não-hard-block.
    """

    HARD_BLOCK_MARKERS = frozenset({
        "SQL_INJECTION", "XSS_PAYLOAD", "CSAM", "CBRN_SYNTHESIS",
    })

    def evaluate(
        self,
        evidence: RustEvidence,
        context: RequestContext,
        rawls_result: "RawlsResult",
    ) -> LevinasResult:
        action = rawls_result.action_out
        is_hard = any(m in str(evidence.findings_summary) for m in self.HARD_BLOCK_MARKERS)
        vulnerable = context.user_role in VULNERABLE_ROLES
        care_domain = context.domain in CARE_DOMAINS

        # Care override: apenas se não-hard-block e não-crítico
        care_override = False
        new_action = action

        if (not is_hard
                and evidence.critical_count == 0
                and action == "BLOCK"):
            if vulnerable:
                new_action = "EDUCATE"
                care_override = True
            elif care_domain:
                new_action = "REDACT"
                care_override = True

        # Appeal hint — sempre presente em BLOCK/REDACT
        if new_action in ("BLOCK", "REDACT"):
            appeal_hint = (
                "Esta decisão pode ser contestada em até 24h via POST /v1/appeals. "
                "Direito garantido por LGPD Art. 20 e EU AI Act Art. 86."
            )
        else:
            appeal_hint = ""

        rationale = (
            f"Levinas (dever de cuidado): "
            + (f"usuário vulnerável (role={context.user_role}), BLOCK→EDUCATE. "
               if care_override and vulnerable else "")
            + (f"domínio de cuidado ({context.domain}), BLOCK→REDACT. "
               if care_override and care_domain and not vulnerable else "")
            + (f"sem override necessário (action={action}). "
               if not care_override else "")
            + f"contestable=True (direito incondicional de recurso)."
        )

        return LevinasResult(
            stage_name="levinas",
            philosopher="Emmanuel Levinas — Totalité et Infini (1961)",
            action_in=action,
            action_out=new_action,
            modified=care_override,
            rationale=rationale,
            user_vulnerable=vulnerable,
            care_override=care_override,
            contestable=not is_hard,
            appeal_hint=appeal_hint,
            hard_block=is_hard,
            metadata={
                "user_role": context.user_role,
                "domain": context.domain,
                "is_hard_block": is_hard,
            },
        )
```

### 2.5 Estágio 3 — Jonas

```python
# python/buildtovalue/governance/pipeline/jonas_stage.py

"""
Jonas Stage v1.0.0 (ADR-038)

Princípio: Responsabilidade Proporcional ao Poder de Causar Dano.
- BiasDeclaration expirada → declarar incerteza no rationale (não bloquear, mas avisar)
- IP/drift risk elevado → escalar ação (quem tem mais risco, mais responsabilidade)
- Custo da ação deve ser proporcional à certeza do risco

Função: verifica BiasDeclaration + aplica risk overrides.
"""

from dataclasses import dataclass
import time
from .base import StageResult
from ..context_engine import RustEvidence, RequestContext

# Mapeamento de ip_risk para escalada máxima
IP_RISK_ESCALATION = {
    "Critical": 2,   # Tor/VPN confirmado: +2 níveis de severidade
    "High": 1,
    "Medium": 0,
    "Low": 0,
}
DRIFT_ESCALATION = {
    "Critical": 2,
    "High": 1,
    "Medium": 0,
    "None": 0,
}

ACTION_SEVERITY = {
    "ALLOW": 0, "LOG": 1, "EDUCATE": 2, "REDACT": 3, "BLOCK": 4,
}
SEVERITY_ACTION = {v: k for k, v in ACTION_SEVERITY.items()}

@dataclass(frozen=True)
class JonasResult(StageResult):
    bias_calibration_ok: bool = True
    bias_expiry_days: int = 0          # dias desde calibração
    ip_risk_escalation: int = 0        # níveis adicionados por IP risk
    drift_escalation: int = 0
    proportional_action: str = ""      # ação após proporcionalidade

class JonasStage:
    """
    Responsabilidade proporcional: verifica que a ação respeita
    a incerteza declarada (BiasDeclaration) e o contexto de risco real.

    Jonas pode ESCALAR (nunca abrandar — esse é papel de Gilligan):
    - IP/drift risk elevado → ação mais severa
    - BiasDeclaration expirada → registra aviso no rationale
    """

    def evaluate(
        self,
        evidence: RustEvidence,
        context: RequestContext,
        levinas_result: "LevinasResult",
    ) -> JonasResult:
        action = levinas_result.action_out
        notes = []

        # ── BiasDeclaration check ─────────────────────────────────
        bias_ok = True
        expiry_days = 0
        # calibration_date de TechnicalEvidence (YYYYMMDD como int)
        # Acessado via evidence.bias_calibration_date se disponível
        cal_date = getattr(evidence, "bias_calibration_date", None)
        if cal_date:
            import datetime
            today = int(datetime.date.today().strftime("%Y%m%d"))
            # Diferença simplificada (dias aproximados)
            cal_year = cal_date // 10000
            cal_month = (cal_date // 100) % 100
            cal_day = cal_date % 100
            try:
                d_cal = datetime.date(cal_year, cal_month, cal_day)
                expiry_days = (datetime.date.today() - d_cal).days
                if expiry_days > 90:
                    bias_ok = False
                    notes.append(
                        f"BiasDeclaration expirada ({expiry_days}d > 90d). "
                        "Limitações do detector podem estar desatualizadas."
                    )
            except ValueError:
                pass

        # ── Risk override ─────────────────────────────────────────
        ip_esc   = IP_RISK_ESCALATION.get(context.ip_risk, 0)
        drift_esc = DRIFT_ESCALATION.get(context.drift_level, 0)
        total_esc = ip_esc + drift_esc

        cur_sev = ACTION_SEVERITY.get(action, 0)
        new_sev = min(4, cur_sev + total_esc)
        new_action = SEVERITY_ACTION.get(new_sev, "BLOCK")

        if total_esc > 0:
            notes.append(
                f"Risk override: ip_risk={context.ip_risk} (+{ip_esc}), "
                f"drift={context.drift_level} (+{drift_esc}). "
                f"{action}→{new_action}."
            )

        rationale = (
            f"Jonas (responsabilidade proporcional): "
            + (f"BiasDeclaration OK (calibrada há {expiry_days}d). "
               if bias_ok else f"BiasDeclaration EXPIRADA ({expiry_days}d). ")
            + (f"Risk override: {action}→{new_action}. " if total_esc > 0
               else f"Sem escalada de risco (ip={context.ip_risk}, drift={context.drift_level}). ")
        )
        if notes:
            rationale += " | ".join(notes)

        return JonasResult(
            stage_name="jonas",
            philosopher="Hans Jonas — The Imperative of Responsibility (1979)",
            action_in=action,
            action_out=new_action,
            modified=(new_action != action),
            rationale=rationale,
            bias_calibration_ok=bias_ok,
            bias_expiry_days=expiry_days,
            ip_risk_escalation=ip_esc,
            drift_escalation=drift_esc,
            proportional_action=new_action,
            metadata={
                "ip_risk": context.ip_risk,
                "drift_level": context.drift_level,
                "total_escalation": total_esc,
            },
        )
```

### 2.6 Estágio 4 — Gilligan

```python
# python/buildtovalue/governance/pipeline/gilligan_stage.py

"""
Gilligan Stage v1.0.0 (ADR-038)

Princípio: Ética do Cuidado — Contexto > Regra Rígida.
Mercy é aplicada SOMENTE se Jonas não escalou (responsabilidade tem prioridade).
Os 6 cenários calibrados (S1–S6) permanecem inalterados da v1.8.0.

Função: trust score + mercy scenarios → final_action.
"""

from dataclasses import dataclass
from .base import StageResult
from ..context_engine import RustEvidence, RequestContext
from ..mercy_scenarios import evaluate_scenarios, MercyScenarioResult
from ..mercy_algorithm import MercyCalculator

@dataclass(frozen=True)
class GilliganResult(StageResult):
    mercy_applied: bool = False
    mercy_scenario: str = "S6_DEFAULT_NO_MERCY"
    mercy_score: float = 0.0
    trust_score: float = 0.5
    downgrade_levels: int = 0

_mercy_calc = MercyCalculator()

class GilliganStage:
    """
    Aplica misericórdia contextual SOMENTE se Jonas não escalou.

    Invariante: Gilligan NUNCA escalas a ação (apenas abrandar).
    Invariante: S1_CRITICAL_OVERRIDE impede mercy independente de trust.
    """

    def __init__(self, trust_store: dict):
        self._trust = trust_store
        self._violations: dict[str, int] = {}

    def evaluate(
        self,
        evidence: RustEvidence,
        context: RequestContext,
        jonas_result: "JonasResult",
    ) -> GilliganResult:
        action = jonas_result.action_out

        # Se Jonas escalou: Gilligan não abrand (responsabilidade > compaixão)
        jonas_escalated = jonas_result.ip_risk_escalation + jonas_result.drift_escalation > 0

        trust = self._trust.get(context.session_id, 0.5)
        violation_count = self._violations.get(context.session_id, 0)
        is_first = violation_count == 0

        # Atualiza violation count
        if action in ("BLOCK", "REDACT", "EDUCATE"):
            self._violations[context.session_id] = violation_count + 1

        if jonas_escalated:
            scenario = MercyScenarioResult(
                original_action=action,
                final_action=action,
                downgrade_levels=0,
                scenario_id="S6_DEFAULT_NO_MERCY",
                rationale="Jonas escalou por risco — misericórdia suspensa.",
                mercy_score=0.0,
            )
        else:
            mercy_ctx = {
                "domain": context.domain,
                "session_id": context.session_id,
                "user_role": context.user_role,
            }
            mercy_score = _mercy_calc.calculate(
                evidence=evidence,
                context=mercy_ctx,
                trust_score=trust,
            )
            scenario = evaluate_scenarios(
                action=action,
                mercy_score=mercy_score,
                trust_score=trust,
                finding_count=evidence.finding_count,
                critical_count=evidence.critical_count,
                composite_risk=evidence.composite_risk,
                domain=context.domain,
                is_first_offense=is_first,
            )

        rationale = (
            f"Gilligan (ética do cuidado): trust={trust:.2f}, "
            f"scenario={scenario.scenario_id}, "
            f"mercy_applied={scenario.mercy_applied}, "
            f"{scenario.rationale}"
        )

        return GilliganResult(
            stage_name="gilligan",
            philosopher="Carol Gilligan — In a Different Voice (1982)",
            action_in=action,
            action_out=scenario.final_action,
            modified=scenario.mercy_applied,
            rationale=rationale,
            mercy_applied=scenario.mercy_applied,
            mercy_scenario=scenario.scenario_id,
            mercy_score=getattr(scenario, "mercy_score", 0.0),
            trust_score=trust,
            downgrade_levels=scenario.downgrade_levels,
            metadata={
                "jonas_escalated": jonas_escalated,
                "is_first_offense": is_first,
                "violation_count": violation_count,
            },
        )
```

### 2.7 ExplainDecision Estruturado

```python
# python/buildtovalue/governance/explain_decision.py

"""
ExplainDecision v1.0.0 (ADR-038)

Substitui a string monolítica de explain_decision() por dataclass estruturada.
Auditores LGPD/EU AI Act podem navegar campo a campo.
AppealEngine usa os campos para contextualizar contestações.
"""

from dataclasses import dataclass, asdict
from typing import Optional

@dataclass
class ExplainDecision:
    """
    Justificativa estruturada de uma decisão ética.

    Cada campo corresponde a um estágio ou aspecto verificável.
    Auditável por humanos e máquinas (JSON-serializable).
    """
    # Síntese
    summary: str                    # frase de uma linha para UI/logs
    final_action: str
    original_policy_action: str

    # Por estágio (raciocínio de cada filósofo)
    rawls_rationale: str            # equidade procedimental
    levinas_rationale: str          # dever de cuidado
    jonas_rationale: str            # responsabilidade proporcional
    gilligan_rationale: str         # misericórdia contextual

    # Contexto quantitativo (para auditores técnicos)
    trust_score: float
    mercy_score: float
    composite_risk: float
    finding_count: int
    critical_count: int

    # BiasDeclaration summary (Jonas)
    bias_calibration_ok: bool
    bias_expiry_days: int

    # Contestabilidade (Levinas)
    contestable: bool
    appeal_hint: str

    # Rastreabilidade
    verdict_id: str
    pipeline_trace: list            # [StageResult.stage_name, ...]
    anomaly_detected: bool = False  # Rawls flag

    def to_dict(self) -> dict:
        return asdict(self)

    def to_human_readable(self) -> str:
        """
        Texto para exibição ao usuário final.
        Segue EU AI Act Art. 13 — linguagem acessível.
        """
        lines = [
            f"Decisão: {self.final_action}",
            f"Resumo: {self.summary}",
            "",
            f"Análise de equidade (Rawls): {self.rawls_rationale}",
            f"Análise de cuidado (Levinas): {self.levinas_rationale}",
            f"Análise de responsabilidade (Jonas): {self.jonas_rationale}",
            f"Análise contextual (Gilligan): {self.gilligan_rationale}",
        ]
        if self.contestable and self.appeal_hint:
            lines += ["", f"Recurso: {self.appeal_hint}"]
        return "\n".join(lines)
```

### 2.8 EthicalContextEngine v4.0 — Orquestrador

```python
# python/buildtovalue/governance/context_engine.py — v4.0

import hmac as hmac_lib
import hashlib
import time
import logging
from dataclasses import dataclass, field
from typing import Optional

from .pipeline.rawls_stage import RawlsStage
from .pipeline.levinas_stage import LevinasStage
from .pipeline.jonas_stage import JonasStage
from .pipeline.gilligan_stage import GilliganStage
from .explain_decision import ExplainDecision

logger = logging.getLogger("btv.governance.context_engine")


@dataclass
class EthicalVerdict:
    """
    Veredicto ético v4.0 — estruturado, assinado, contestável.
    Retrocompatível com v1.8.0 (campos existentes preservados).
    """
    verdict_id: str
    timestamp: int
    original_action: str
    final_action: str
    mercy_applied: bool
    mercy_scenario: str
    mercy_score: float
    trust_score: float
    explanation: str                   # str para retrocompatibilidade
    hmac_signature: str
    contestable: bool = True
    appeal_deadline: int = 0
    # NOVO v4.0:
    explain: Optional[ExplainDecision] = None
    pipeline_trace: list = field(default_factory=list)

    def __post_init__(self):
        if self.appeal_deadline == 0:
            self.appeal_deadline = self.timestamp + 86400


class EthicalContextEngine:
    """
    EthicalContextEngine v4.0 — Judiciário da República Algorítmica.

    Pipeline: Rawls → Levinas → Jonas → Gilligan → HMAC → ExplainDecision

    Invariantes:
    - Toda decisão tem ExplainDecision estruturado
    - Toda decisão é assinada (HMAC-SHA256)
    - Toda decisão não-hard-block é contestável (24h SLA)
    - Mercy NUNCA escala severidade
    - Jonas NUNCA abrand (só Gilligan pode abrandar)
    """

    def __init__(self, signing_key: bytes):
        if len(signing_key) < 32:
            raise ValueError("signing_key deve ter >= 32 bytes")
        self._signing_key = signing_key
        self._trust_scores: dict[str, float] = {}
        self._verdict_counter = 0

        # Instâncias dos estágios
        self._rawls   = RawlsStage()
        self._levinas = LevinasStage()
        self._jonas   = JonasStage()
        self._gilligan = GilliganStage(trust_store=self._trust_scores)

    def set_trust_score(self, session_id: str, score: float) -> None:
        self._trust_scores[session_id] = max(0.0, min(1.0, score))

    def decide(
        self,
        evidence: "RustEvidence",
        context: "RequestContext",
    ) -> EthicalVerdict:
        """
        Pipeline filosófico completo.
        Cada estágio recebe o resultado do anterior.
        Fail-secure: qualquer exceção → BLOCK com rationale de erro.
        """
        now = int(time.time())
        self._verdict_counter += 1
        verdict_id = f"VRD-{now}-{self._verdict_counter:06d}"

        try:
            # ── 4 estágios em sequência ───────────────────────────
            r1 = self._rawls.evaluate(evidence, context)
            r2 = self._levinas.evaluate(evidence, context, r1)
            r3 = self._jonas.evaluate(evidence, context, r2)
            r4 = self._gilligan.evaluate(evidence, context, r3)

            final_action = r4.action_out
            pipeline_trace = [r1, r2, r3, r4]

        except Exception as exc:
            # Fail-secure: erro no pipeline → BLOCK
            logger.error(
                "pipeline_error verdict_id=%s error=%s", verdict_id, exc
            )
            final_action = "BLOCK"
            pipeline_trace = []
            r1 = r2 = r3 = r4 = None

        # ── ExplainDecision estruturado ───────────────────────────
        trust = self._trust_scores.get(context.session_id, 0.5)
        explain = self._build_explain(
            verdict_id, evidence, context, trust,
            r1, r2, r3, r4, final_action, pipeline_trace,
        )

        # ── HMAC-SHA256 ───────────────────────────────────────────
        sign_payload = (
            f"{verdict_id}|{evidence.blake3_hash}|{final_action}|{now}"
        )
        signature = hmac_lib.new(
            self._signing_key,
            sign_payload.encode(),
            hashlib.sha256,
        ).hexdigest()

        return EthicalVerdict(
            verdict_id=verdict_id,
            timestamp=now,
            original_action=evidence.policy_action,
            final_action=final_action,
            mercy_applied=r4.mercy_applied if r4 else False,
            mercy_scenario=r4.mercy_scenario if r4 else "S1_CRITICAL_OVERRIDE",
            mercy_score=r4.mercy_score if r4 else 0.0,
            trust_score=trust,
            explanation=explain.to_human_readable(),   # retrocompat
            hmac_signature=signature,
            contestable=r2.contestable if r2 else False,
            explain=explain,
            pipeline_trace=[s.stage_name for s in pipeline_trace],
        )

    def _build_explain(
        self, verdict_id, evidence, context, trust,
        r1, r2, r3, r4, final_action, trace,
    ) -> ExplainDecision:
        return ExplainDecision(
            summary=(
                f"Decisão {final_action} para sessão {context.session_id[:8]}. "
                f"Risk={evidence.composite_risk:.2f}, "
                f"findings={evidence.finding_count}, "
                f"mercy={'sim' if (r4 and r4.mercy_applied) else 'não'}."
            ),
            final_action=final_action,
            original_policy_action=evidence.policy_action,
            rawls_rationale=r1.rationale if r1 else "pipeline error",
            levinas_rationale=r2.rationale if r2 else "pipeline error",
            jonas_rationale=r3.rationale if r3 else "pipeline error",
            gilligan_rationale=r4.rationale if r4 else "pipeline error",
            trust_score=trust,
            mercy_score=r4.mercy_score if r4 else 0.0,
            composite_risk=evidence.composite_risk,
            finding_count=evidence.finding_count,
            critical_count=evidence.critical_count,
            bias_calibration_ok=r3.bias_calibration_ok if r3 else False,
            bias_expiry_days=r3.bias_expiry_days if r3 else 0,
            contestable=r2.contestable if r2 else False,
            appeal_hint=r2.appeal_hint if r2 else "",
            verdict_id=verdict_id,
            pipeline_trace=[s.stage_name for s in trace],
            anomaly_detected=r1.anomaly_detected if r1 else False,
        )

    def verify_signature(self, verdict: EthicalVerdict) -> bool:
        """Verificação constant-time do HMAC."""
        payload = (
            f"{verdict.verdict_id}|"
            f"{verdict.explain.verdict_id if verdict.explain else ''}|"  # retrocompat
            f"{verdict.final_action}|{verdict.timestamp}"
        )
        expected = hmac_lib.new(
            self._signing_key, payload.encode(), hashlib.sha256
        ).hexdigest()
        return hmac_lib.compare_digest(expected, verdict.hmac_signature)
```

---

## 3. Integração com AppealEngine (ADR-037)

O `ExplainDecision` serve como contrato entre `EthicalContextEngine` e `AppealEngine`:

```python
# No AppealEngine.submit() — usa explain para enriquecer o AppealRecord
def _enrich_from_verdict(self, req: AppealRequest) -> dict:
    """
    Se o verdict_id referencia um ExplainDecision em cache,
    adiciona contexto ao AppealRecord para o revisor humano.
    """
    # Consulta cache de verdicts recentes (TTL 24h — alinhado com SLA)
    explain = self._verdict_cache.get(req.verdict_id)
    if explain:
        return {
            "original_action": explain.original_policy_action,
            "final_action": explain.final_action,
            "anomaly_detected": explain.anomaly_detected,
            "bias_ok": explain.bias_calibration_ok,
            "pipeline_stages": explain.pipeline_trace,
        }
    return {}
```

O revisor humano vê, no painel de appeals pendentes:
- Qual estágio tomou a decisão final (ex: "Jonas escalou por ip_risk=Critical")
- Se havia anomalia de Rawls detectada
- Se BiasDeclaration estava expirada (Jonas)
- O rationale completo de cada filósofo

---

## 4. Fundamentos Filosóficos

A separação em 4 estágios não é decorativa — cada filósofo resolve uma **pergunta distinta e não-sobreponível**:

**Rawls (Estágio 1):** *"A decisão seria a mesma para qualquer pessoa nessa posição?"* — procedural, cego à identidade. Detecta inconsistências de policy antes de qualquer avaliação contextual.

**Levinas (Estágio 2):** *"Esta decisão causa dano desproporcional ao Outro concreto que está diante de mim?"* — contextual, sensível à vulnerabilidade. Define o direito de recurso como incondicional.

**Jonas (Estágio 3):** *"A ação é proporcional à certeza do risco? O sistema está cumprindo suas responsabilidades declaradas?"* — prospectivo, verifica que BiasDeclaration não mente e que risco externo (IP/drift) é incorporado.

**Gilligan (Estágio 4):** *"O contexto relacional justifica compaixão?"* — só age se Jonas não escalou. Mercy não é fraqueza do sistema — é o reconhecimento de que regras abstratas podem ser injustas em casos concretos.

A **sequência importa**: Rawls primeiro (procedimento justo), depois Levinas (cuidado), depois Jonas (responsabilidade), depois Gilligan (compaixão). Inverter a ordem mudaria os resultados — Gilligan antes de Jonas permitiria mercy em contextos de alto risco.

---

## 5. Consequências

### Positivas

Cada estágio é testável isoladamente — `RawlsStage`, `LevinasStage` etc. têm testes unitários próprios. O `ExplainDecision` estruturado satisfaz EU AI Act Art. 13 (explicabilidade por componente) e LGPD Art. 20 (rationale acessível). O `pipeline_trace` no `EthicalVerdict` permite auditores forenses identificar qual filósofo tomou qual decisão em qual contexto.

A integração com `AppealEngine` fecha o loop: o revisor humano de um appeal tem acesso ao raciocínio detalhado de cada estágio, não apenas à ação final.

### Negativas e Trade-offs

A separação em 4 arquivos de estágio aumenta a superfície de código. Mitigado pela regra de ≤ 200 linhas por arquivo — cada estágio cabe confortavelmente.

A passagem de resultados entre estágios (`r1 → r2 → r3 → r4`) cria acoplamento sequencial. Uma exceção em `LevinasStage` bloqueia `Jonas` e `Gilligan`. O `try/except` com fail-secure no orquestrador garante que qualquer falha resulta em `BLOCK` — nunca bypass.

Retrocompatibilidade: `EthicalVerdict.explanation` (str) é mantido para não quebrar `app.py` e outros consumidores. `explain: ExplainDecision` é adicional.

---

## 6. Testes Obrigatórios

```
[ ] RawlsStage: ALLOW + risk > 0.8 → anomaly_detected=True, action inalterada
[ ] RawlsStage: BLOCK + risk < 0.1 + 0 findings → anomaly_detected=True
[ ] RawlsStage: caso normal → anomaly_detected=False, action inalterada
[ ] LevinasStage: role=student + BLOCK + 0 críticos → EDUCATE, care_override=True
[ ] LevinasStage: domain=medical + BLOCK → REDACT, care_override=True
[ ] LevinasStage: hard_block marker → contestable=False
[ ] LevinasStage: BLOCK sem vulnerabilidade → appeal_hint preenchido
[ ] JonasStage: ip_risk=Critical → escalada +2 níveis
[ ] JonasStage: drift=High → escalada +1 nível
[ ] JonasStage: BiasDeclaration expirada (> 90d) → bias_calibration_ok=False
[ ] JonasStage: ip_risk=Low + drift=None → action inalterada
[ ] GilliganStage: Jonas escalou → S6_DEFAULT_NO_MERCY, mercy_applied=False
[ ] GilliganStage: trust=0.9 + primeira ocorrência + 0 críticos → S2_HIGH_TRUST_VETERAN
[ ] GilliganStage: mercy NUNCA escala (invariante)
[ ] Pipeline completo: BLOCK + trust=0.9 + primeira ocorrência + ip_risk=Low → EDUCATE
[ ] Pipeline completo: BLOCK + ip_risk=Critical → BLOCK (Jonas anula Gilligan)
[ ] Pipeline fail-secure: exceção em qualquer estágio → final_action=BLOCK
[ ] ExplainDecision: todos os campos não-vazios após decide()
[ ] ExplainDecision.to_human_readable() contém "Rawls", "Levinas", "Jonas", "Gilligan"
[ ] EthicalVerdict.pipeline_trace contém ["rawls", "levinas", "jonas", "gilligan"]
[ ] HMAC: verify_signature(verdict) retorna True para verdict próprio
[ ] Retrocompat: explanation (str) não é None após decide()
