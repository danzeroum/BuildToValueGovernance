
from dataclasses import dataclass
from typing import Optional
import math

from .ffi_client import TechnicalEvidence
from .ethical_context_engine import RequestMetadata

@dataclass
class MercyFactors:
    """Fatores que contribuem para misericórdia"""
    uncertainty_score: float  # 0.0-1.0 (alta incerteza → mais mercy)
    context_justifiability: float  # 0.0-1.0 (contexto justifica → mais mercy)
    trust_score: float  # 0.0-1.0 (alta confiança → mais mercy)
    harm_potential: float  # 0.0-1.0 (baixo potencial de dano → mais mercy)
    first_offense: bool  # True se primeira violação (mais mercy)
    
    def __repr__(self):
        return (
            f"MercyFactors(uncertainty={self.uncertainty_score:.2f}, "
            f"justifiability={self.context_justifiability:.2f}, "
            f"trust={self.trust_score:.2f}, harm={self.harm_potential:.2f}, "
            f"first_offense={self.first_offense})"
        )

class MercyCalculator:
    """
    Implementa "Misericórdia Algorítmica" baseada em Carol Gilligan.
    
    Princípios:
    1. Contexto > Regra: Decisões devem considerar circunstâncias específicas
    2. Cuidado: Priorizar continuidade do serviço quando possível
    3. Relacionamento: Histórico do usuário importa
    4. Incerteza: Quando não temos certeza, erramos para o lado da permissividade
    
    Fórmula de Misericórdia:
    mercy_score = w1*uncertainty + w2*justifiability + w3*trust + w4*(1-harm) + w5*first_offense
    
    onde:
    - w1, w2, w3, w4, w5 são pesos (soma = 1.0)
    - mercy_score > 0.5 → Considera abrandar ação
    - mercy_score > 0.8 → Forte candidato a misericórdia
    """
    
    def __init__(self):
        # Pesos dos fatores (ajustáveis via config)
        self.weights = {
            'uncertainty': 0.35,      # Maior peso (Gilligan: incerteza → cuidado)
            'justifiability': 0.25,   # Contexto justifica?
            'trust': 0.20,            # Histórico do usuário
            'harm': 0.15,             # Potencial de dano
            'first_offense': 0.05,    # Primeira violação
        }
        
        # Thresholds
        self.mercy_threshold_low = 0.5   # Misericórdia mínima
        self.mercy_threshold_high = 0.8  # Misericórdia forte
        
        # Histórico de violações (por session_id)
        self._violation_history: dict[str, int] = {}
    
    def calculate(
        self,
        evidence: TechnicalEvidence,
        context: RequestMetadata,
        trust_score: float,
    ) -> float:
        """
        Calcula score de misericórdia (0.0-1.0).
        
        Retorna:
        - 0.0-0.5: Sem misericórdia (aplicar ação original)
        - 0.5-0.8: Misericórdia moderada (considerar abrandar 1 nível)
        - 0.8-1.0: Misericórdia forte (abrandar 2 níveis)
        """
        
        factors = self._calculate_factors(evidence, context, trust_score)
        
        # Combina fatores com pesos
        mercy_score = (
            self.weights['uncertainty'] * factors.uncertainty_score +
            self.weights['justifiability'] * factors.context_justifiability +
            self.weights['trust'] * factors.trust_score +
            self.weights['harm'] * (1.0 - factors.harm_potential) +
            self.weights['first_offense'] * (1.0 if factors.first_offense else 0.0)
        )
        
        # Log para auditoria
        if mercy_score > self.mercy_threshold_low:
            import logging
            logging.info(
                f"Mercy applied: score={mercy_score:.2f}, factors={factors}"
            )
        
        return mercy_score
    
    def _calculate_factors(
        self,
        evidence: TechnicalEvidence,
        context: RequestMetadata,
        trust_score: float,
    ) -> MercyFactors:
        """Calcula fatores individuais de misericórdia"""
        
        # FATOR 1: UNCERTAINTY (incerteza na detecção)
        uncertainty = self._calculate_uncertainty(evidence)
        
        # FATOR 2: JUSTIFIABILITY (contexto justifica?)
        justifiability = self._calculate_justifiability(evidence, context)
        
        # FATOR 3: TRUST (confiança no usuário)
        trust = trust_score  # Já calculado externamente
        
        # FATOR 4: HARM POTENTIAL (potencial de dano)
        harm = self._calculate_harm_potential(evidence, context)
        
        # FATOR 5: FIRST OFFENSE (primeira violação?)
        first_offense = self._is_first_offense(context.session_id)
        
        return MercyFactors(
            uncertainty_score=uncertainty,
            context_justifiability=justifiability,
            trust_score=trust,
            harm_potential=harm,
            first_offense=first_offense,
        )
    
    def _calculate_uncertainty(self, evidence: TechnicalEvidence) -> float:
        """
        Calcula incerteza na detecção.
        
        Alta incerteza:
        - Alta entropia no input
        - Baixa confiança nas findings
        - Poucas findings (ambíguo)
        
        Retorna: 0.0 (certeza total) a 1.0 (incerteza total)
        """
        
        # Componente 1: Entropia (normalizado para 0-1)
        # Entropia normal ~4.5, alta >6.0, baixa <2.0
        entropy_normalized = evidence.stats.entropy / 8.0
        entropy_uncertainty = abs(entropy_normalized - 0.5625) / 0.5625
        # Entropia longe do normal = incerteza
        
        # Componente 2: Confiança média das findings
        if evidence.finding_count + evidence.critical_count == 0:
            confidence_uncertainty = 0.0  # Sem findings = certeza de ALLOW
        else:
            total_confidence = sum(
                f.confidence / 255.0 
                for f in (evidence.findings[:10] + evidence.critical[:3])
            )
            count = min(evidence.finding_count, 10) + evidence.critical_count
            avg_confidence = total_confidence / count if count > 0 else 0.5
            confidence_uncertainty = 1.0 - avg_confidence
        
        # Componente 3: Número de findings (poucas = ambíguo)
        finding_count = evidence.finding_count + evidence.critical_count
        if finding_count == 0:
            count_uncertainty = 0.0
        elif finding_count == 1:
            count_uncertainty = 0.5  # Uma única finding = ambíguo
        else:
            count_uncertainty = 0.0  # Múltiplas findings = claro
        
        # Combina componentes (média ponderada)
        uncertainty = (
            0.3 * entropy_uncertainty +
            0.5 * confidence_uncertainty +
            0.2 * count_uncertainty
        )
        
        return max(0.0, min(1.0, uncertainty))
    
    def _calculate_justifiability(
        self,
        evidence: TechnicalEvidence,
        context: RequestMetadata,
    ) -> float:
        """
        Calcula se contexto justifica os dados detectados.
        
        Alta justificabilidade:
        - Domínio medical/research/legal (privilegiados)
        - Role apropriado (healthcare_professional, researcher)
        - Findings esperados no contexto (CPF em medical)
        
        Retorna: 0.0 (não justificável) a 1.0 (totalmente justificável)
        """
        
        # Componente 1: Domínio privilegiado
        privileged_domains = {
            'medical': 0.8,
            'research': 0.9,
            'legal': 0.7,
            'financial': 0.6,
            'government': 0.7,
            'general': 0.0,
        }
        domain_score = privileged_domains.get(context.domain, 0.0)
        
        # Componente 2: Role apropriado
        privileged_roles = {
            'healthcare_professional': 0.9,
            'researcher': 0.9,
            'legal_professional': 0.8,
            'financial_advisor': 0.7,
            'patient': 0.5,
            'authenticated': 0.3,
            'anonymous': 0.0,
        }
        role_score = privileged_roles.get(context.user_role, 0.0)
        
        # Componente 3: Findings esperados no contexto
        expected_findings = {
            'medical': {'CPF_PATTERN_DETECTED', 'PHONE_PATTERN_DETECTED', 'EMAIL_PATTERN_DETECTED'},
            'research': {'CPF_PATTERN_DETECTED', 'EMAIL_PATTERN_DETECTED'},
            'legal': {'CPF_PATTERN_DETECTED', 'CNPJ_PATTERN_DETECTED'},
            'financial': {'CPF_PATTERN_DETECTED', 'CNPJ_PATTERN_DETECTED'},
        }
        
        expected_in_context = expected_findings.get(context.domain, set())
        actual_findings = {f.title for f in evidence.findings + evidence.critical}
        
        if not actual_findings:
            finding_score = 1.0  # Sem findings = sempre justificável
        else:
            matched = actual_findings & expected_in_context
            finding_score = len(matched) / len(actual_findings) if actual_findings else 0.0
        
        # Combina componentes
        justifiability = (
            0.4 * domain_score +
            0.3 * role_score +
            0.3 * finding_score
        )
        
        return max(0.0, min(1.0, justifiability))
    
    def _calculate_harm_potential(
        self,
        evidence: TechnicalEvidence,
        context: RequestMetadata,
    ) -> float:
        """
        Calcula potencial de dano se permitir.
        
        Alto potencial:
        - Cartão de crédito detectado
        - Múltiplos CPFs (vazamento)
        - Contexto público (domínio general)
        
        Retorna: 0.0 (sem dano) a 1.0 (alto dano)
        """
        
        # Componente 1: Severidade das findings
        critical_findings = {
            'CREDIT_CARD_DETECTED': 1.0,
            'CPF_PATTERN_DETECTED': 0.7,
            'CNPJ_PATTERN_DETECTED': 0.5,
            'EMAIL_PATTERN_DETECTED': 0.3,
            'PHONE_PATTERN_DETECTED': 0.2,
        }
        
        max_severity = 0.0
        for finding in evidence.findings + evidence.critical:
            severity = critical_findings.get(finding.title, 0.1)
            max_severity = max(max_severity, severity)
        
        # Componente 2: Quantidade de findings (múltiplos = pior)
        count_factor = min(
            (evidence.finding_count + evidence.critical_count) / 5.0,
            1.0
        )
        
        # Componente 3: Contexto público (general = maior dano)
        public_contexts = {'general': 1.0, 'public': 1.0}
        context_factor = public_contexts.get(context.domain, 0.3)
        
        # Combina componentes
        harm = (
            0.5 * max_severity +
            0.2 * count_factor +
            0.3 * context_factor
        )
        
        return max(0.0, min(1.0, harm))
    
    def _is_first_offense(self, session_id: str) -> bool:
        """Verifica se é primeira violação do usuário"""
        
        violation_count = self._violation_history.get(session_id, 0)
        return violation_count == 0
    
    def record_violation(self, session_id: str):
        """Registra violação (para histórico)"""
        
        if session_id not in self._violation_history:
            self._violation_history[session_id] = 0
        
        self._violation_history[session_id] += 1
    
    def get_violation_count(self, session_id: str) -> int:
        """Retorna número de violações do usuário"""
        return self._violation_history.get(session_id, 0)
    
    def should_apply_mercy(self, mercy_score: float, action_severity: int) -> bool:
        """
        Decide se deve aplicar misericórdia.
        
        Args:
            mercy_score: Score calculado (0.0-1.0)
            action_severity: Severidade da ação original (0-4)
        
        Retorna: True se deve abrandar ação
        """
        
        # Threshold dinâmico baseado em severidade
        # Ações mais severas requerem mercy_score mais alto
        dynamic_threshold = self.mercy_threshold_low + (action_severity * 0.05)
        
        return mercy_score >= dynamic_threshold
    
    def get_mercy_explanation(self, mercy_score: float, factors: MercyFactors) -> str:
        """Gera explicação human-readable para misericórdia aplicada"""
        
        reasons = []
        
        if factors.uncertainty_score > 0.6:
            reasons.append(
                f"alta incerteza na detecção ({factors.uncertainty_score:.0%})"
            )
        
        if factors.context_justifiability > 0.6:
            reasons.append(
                f"contexto justifica os dados ({factors.context_justifiability:.0%})"
            )
        
        if factors.trust_score > 0.7:
            reasons.append(
                f"usuário com histórico confiável ({factors.trust_score:.0%})"
            )
        
        if factors.harm_potential < 0.3:
            reasons.append(
                f"baixo potencial de dano ({factors.harm_potential:.0%})"
            )
        
        if factors.first_offense:
            reasons.append("primeira violação detectada")
        
        if not reasons:
            return "Misericórdia aplicada por múltiplos fatores contextuais."
        
        return f"Misericórdia aplicada: {', '.join(reasons)}."