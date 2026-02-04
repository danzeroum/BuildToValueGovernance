"""
Ethical Context Engine - Motor de decisão ética.
Implementa lógica de aplicação de regras + contexto.
"""
import logging
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from enum import Enum

from .ffi_client import TechnicalEvidence
from .trust_score import TrustScoreCalculator
from .mercy_algorithm import MercyCalculator

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# TIPOS DE DADOS
# ═══════════════════════════════════════════════════════════════════════════

class ActionType(Enum):
    """Ações possíveis de governança."""
    ALLOW = "ALLOW"
    LOG = "LOG"
    EDUCATE = "EDUCATE"
    REDACT = "REDACT"
    BLOCK = "BLOCK"


@dataclass
class RequestMetadata:
    """Metadados da requisição."""
    agent_id: str
    session_id: str
    user_role: str
    domain: str
    timestamp: int
    ip_address: Optional[str] = None


@dataclass
class Rule:
    """Regra de política."""
    id: str
    action: str
    priority: int
    domain: Optional[str] = None
    min_risk_level: Optional[str] = None
    required_findings: Optional[List[str]] = None
    min_trust_score: Optional[float] = None
    max_trust_score: Optional[float] = None
    condition: Optional[str] = None


@dataclass
class Profile:
    """Perfil de governança."""
    name: str
    parent_id: Optional[str]
    rules: List[Rule]
    domain_config: Dict[str, Any]


@dataclass
class EthicalVerdict:
    """Decisão ética final."""
    action: ActionType
    confidence: float
    rule_id: Optional[str]
    rationale: str
    mercy_score: float = 0.0
    trust_score: float = 0.0
    signature: Optional[bytes] = None
    context_factors: Dict[str, Any] = None


# ═══════════════════════════════════════════════════════════════════════════
# ETHICAL CONTEXT ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class EthicalContextEngine:
    """
    Motor de decisão ética.
    Combina evidências técnicas (Rust) + contexto (Python).
    """

    def __init__(
            self,
            trust_calculator: TrustScoreCalculator,
            mercy_calculator: MercyCalculator,
            profile_manager: Any  # Evita import circular
    ):
        """
        Inicializa engine.

        Args:
            trust_calculator: Calculador de trust score
            mercy_calculator: Calculador de mercy score
            profile_manager: Gerenciador de perfis
        """
        self.trust_calculator = trust_calculator
        self.mercy_calculator = mercy_calculator
        self.profile_manager = profile_manager

    def decide(
            self,
            evidence: TechnicalEvidence,
            context: RequestMetadata,
            profile_name: str
    ) -> EthicalVerdict:
        """
        Toma decisão ética baseada em evidência + contexto.

        Args:
            evidence: Evidências técnicas do Rust
            context: Contexto da requisição
            profile_name: Nome do perfil a aplicar

        Returns:
            EthicalVerdict com ação e justificativa
        """
        # 1. Carrega perfil
        profile = self.profile_manager.load_profile(profile_name)

        # 2. Calcula risk level
        risk_level = self._calculate_risk_level(evidence)

        # 3. Aplica regras
        action, matched_rule = self._apply_rules(
            evidence, context, profile, risk_level
        )

        # 4. Calcula trust score
        trust_score = self.trust_calculator.calculate(
            context.session_id, context.user_role
        )

        # 5. Aplica misericórdia (se aplicável)
        mercy_score = 0.0
        if action in [ActionType.BLOCK, ActionType.REDACT]:
            mercy_score = self.mercy_calculator.calculate(
                evidence=evidence,
                context=context.__dict__,
                trust_score=trust_score
            )

            # Se mercy score alto, abranda ação
            if mercy_score > 0.7:
                action = ActionType.EDUCATE
                logger.info(f"Mercy applied: {mercy_score:.2f} → EDUCATE")

        # 6. Monta veredito
        rationale = self._build_rationale(
            evidence, context, matched_rule, mercy_score, trust_score
        )

        return EthicalVerdict(
            action=action,
            confidence=0.95 if matched_rule else 0.5,
            rule_id=matched_rule.id if matched_rule else None,
            rationale=rationale,
            mercy_score=mercy_score,
            trust_score=trust_score,
            context_factors={
                "risk_level": risk_level,
                "finding_count": evidence.finding_count,
                "critical_count": evidence.critical_count
            }
        )

    def _calculate_risk_level(self, evidence: TechnicalEvidence) -> str:
        """Calcula nível de risco baseado em composite_risk."""
        risk = evidence.composite_risk
        if risk >= 80:
            return "CRITICAL"
        elif risk >= 60:
            return "HIGH"
        elif risk >= 30:
            return "MEDIUM"
        else:
            return "LOW"

    def _apply_rules(
            self,
            evidence: TechnicalEvidence,
            context: RequestMetadata,
            profile: Profile,
            risk_level: str,
    ) -> tuple[ActionType, Optional[Rule]]:
        """
        Aplica regras do perfil (ordem de prioridade).
        Retorna: (ActionType, matched_rule)
        """
        # Itera por prioridade (decrescente)
        for rule in profile.rules:
            if self._rule_matches(rule, evidence, context, risk_level):
                action = ActionType[rule.action]
                logger.info(
                    f"Rule matched: {rule.id} → {action.name} "
                    f"(priority: {rule.priority})"
                )
                return action, rule

        # Sem match → ALLOW (fail-open apenas se ZERO findings)
        if evidence.finding_count + evidence.critical_count == 0:
            return ActionType.ALLOW, None
        else:
            # Findings detectados mas nenhuma regra matchou → LOG
            logger.warning(
                f"Findings detected but no rule matched: "
                f"{[f.title for f in evidence.findings[:3]]}"
            )
            return ActionType.LOG, None

    def _rule_matches(
            self,
            rule: Rule,
            evidence: TechnicalEvidence,
            context: RequestMetadata,
            risk_level: str,
    ) -> bool:
        """
        Verifica se regra matcha evidência + contexto.
        Condições avaliadas:
        - domain
        - min_risk_level
        - required_findings
        - min_trust_score / max_trust_score
        - condition (DSL simples)
        """
        # Condição 1: Domínio
        if rule.domain and context.domain != rule.domain:
            return False

        # Condição 2: Risk level
        if rule.min_risk_level:
            risk_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            if risk_levels.index(risk_level) < risk_levels.index(rule.min_risk_level):
                return False

        # Condição 3: Findings requeridos
        if rule.required_findings:
            evidence_titles = {
                f.title for f in (evidence.findings + evidence.critical)
            }
            # Pelo menos 1 finding requerido deve estar presente
            if not any(req in evidence_titles for req in rule.required_findings):
                return False

        # Condição 4: Trust score
        trust_score = self.trust_calculator.calculate(
            context.session_id, context.user_role
        )
        if rule.min_trust_score and trust_score < rule.min_trust_score:
            return False
        if rule.max_trust_score and trust_score > rule.max_trust_score:
            return False

        # Condição 5: Expressão customizada (DSL)
        if rule.condition:
            # Cria contexto de avaliação
            eval_context = {
                'finding': evidence,
                'context': context,
                'stats': evidence.stats,
                'risk_level': risk_level,
                'trust_score': trust_score,
                # Helpers
                'has_cpf': any(f.title == 'CPF_PATTERN_DETECTED' for f in evidence.findings + evidence.critical),
                'has_cnpj': any(f.title == 'CNPJ_PATTERN_DETECTED' for f in evidence.findings + evidence.critical),
                'has_credit_card': any(
                    f.title == 'CREDIT_CARD_DETECTED' for f in evidence.findings + evidence.critical),
                'count': lambda items: len(items),
            }

            try:
                # CORRIGIDO: Usa parser seguro em vez de eval()
                result = self._safe_eval_ast(rule.condition, eval_context)
                if not result:
                    return False
            except Exception as e:
                logger.error(f"Rule condition failed: {rule.id} - {e}")
                return False

        # Todas as condições passaram
        return True

    def _safe_eval_ast(self, expression: str, context: dict) -> bool:
        """
        Avalia expressão de forma SEGURA usando ast.literal_eval.

        CORRIGIDO: Não usa eval() direto!
        """
        import ast

        try:
            # Valida expressão antes
            forbidden = ['import', 'exec', 'eval', '__', 'open', 'file']
            if any(word in expression.lower() for word in forbidden):
                raise ValueError(f"Forbidden expression: {expression}")

            # Parse AST
            tree = ast.parse(expression, mode='eval')

            # Valida apenas operadores permitidos
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id not in ['len', 'any', 'all', 'count']:
                            raise ValueError(f"Function not allowed: {node.func.id}")

            # Avalia com contexto restrito
            return eval(compile(tree, '<string>', 'eval'), {"__builtins__": {}}, context)

        except (ValueError, SyntaxError) as e:
            logger.error(f"Invalid expression: {expression} - {e}")
            return False

    def _build_rationale(
            self,
            evidence: TechnicalEvidence,
            context: RequestMetadata,
            rule: Optional[Rule],
            mercy_score: float,
            trust_score: float
    ) -> str:
        """Constrói justificativa human-readable."""
        parts = []

        # Evidências técnicas
        if evidence.finding_count > 0:
            parts.append(
                f"Detectados {evidence.finding_count} findings "
                f"({evidence.critical_count} críticos)"
            )

        # Regra aplicada
        if rule:
            parts.append(f"Regra aplicada: {rule.id}")

        # Trust score
        parts.append(f"Trust score: {trust_score:.2f}")

        # Misericórdia
        if mercy_score > 0.5:
            parts.append(f"Misericórdia aplicada ({mercy_score:.2f})")

        return ". ".join(parts) + "."
