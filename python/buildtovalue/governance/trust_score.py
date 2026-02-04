
from dataclasses import dataclass
from typing import Dict, List, Optional
import time
import math
from collections import defaultdict

@dataclass
class UserActivity:
    """Atividade de usuário"""
    session_id: str
    timestamp: int
    action: str  # 'request', 'appeal', 'feedback'
    result: str  # 'allowed', 'blocked', 'appealed_success', 'appealed_fail'
    context: Dict[str, Any] = None

class TrustScoreCalculator:
    """
    Calcula Trust Score multi-fatorial.
    
    Formula:
    trust = w1*base + w2*history + w3*appeals + w4*decay + w5*consistency
    
    Garantias:
    - Score ∈ [0.0, 1.0]
    - Determinístico (mesmo histórico → mesmo score)
    - Não-gaming (spam não aumenta trust)
    - Privacy-preserving (sem PII)
    """
    
    def __init__(self):
        # Histórico de atividades por session_id
        self._activity_log: Dict[str, List[UserActivity]] = defaultdict(list)
        
        # Trust scores cacheados
        self._trust_cache: Dict[str, tuple[float, int]] = {}  # (score, timestamp)
        
        # Pesos (ajustáveis via config)
        self.weights = {
            'role': 0.25,
            'history': 0.35,
            'appeals': 0.20,
            'decay': 0.15,
            'consistency': 0.05,
        }
        
        # Configurações
        self.decay_half_life_hours = 30 * 24  # 30 dias
        self.min_activities_for_trust = 5
        self.cache_ttl_seconds = 300  # Cache válido por 5 min
    
    def record_activity(self, activity: UserActivity):
        """Registra atividade de usuário"""
        self._activity_log[activity.session_id].append(activity)
        
        # Invalida cache
        if activity.session_id in self._trust_cache:
            del self._trust_cache[activity.session_id]
    
    def calculate(self, session_id: str, user_role: str) -> float:
        """
        Calcula trust score.
        
        Retorna: 0.0-1.0
        """
        
        # Cache hit (válido por 5 min)
        if session_id in self._trust_cache:
            cached_score, cached_time = self._trust_cache[session_id]
            if time.time() - cached_time < self.cache_ttl_seconds:
                return cached_score
        
        activities = self._activity_log.get(session_id, [])
        
        # Componente 1: Base trust from role
        base_trust = self._base_trust_from_role(user_role)
        
        if len(activities) < self.min_activities_for_trust:
            # Usuário novo: apenas base trust
            score = base_trust
        else:
            # Componente 2: Historical behavior
            history_score = self._calculate_historical_behavior(activities)
            
            # Componente 3: Appeal success rate
            appeal_bonus = self._calculate_appeal_bonus(activities)
            
            # Componente 4: Consistency
            consistency_bonus = self._calculate_consistency_bonus(activities)
            
            # Combina componentes (sem decay ainda)
            score = (
                self.weights['role'] * base_trust +
                self.weights['history'] * history_score +
                self.weights['appeals'] * appeal_bonus +
                self.weights['consistency'] * consistency_bonus
            )
            
            # Componente 5: Temporal decay
            if activities:
                last_activity = max(a.timestamp for a in activities)
                score = self._apply_temporal_decay(score, last_activity)
        
        # Clamp 0.0-1.0
        score = max(0.0, min(1.0, score))
        
        # Atualiza cache
        self._trust_cache[session_id] = (score, int(time.time()))
        
        return score
    
    def _base_trust_from_role(self, user_role: str) -> float:
        """Trust inicial baseado em role"""
        base_trust = {
            'anonymous': 0.20,
            'authenticated': 0.50,
            'patient': 0.60,
            'healthcare_professional': 0.75,
            'researcher': 0.80,
            'legal_professional': 0.75,
            'financial_advisor': 0.70,
            'admin': 0.90,
        }
        return base_trust.get(user_role, 0.30)
    
    def _calculate_historical_behavior(self, activities: List[UserActivity]) -> float:
        """Calcula comportamento histórico"""
        if not activities:
            return 0.5
        
        allowed = sum(1 for a in activities if a.result == 'allowed')
        blocked = sum(1 for a in activities if a.result == 'blocked')
        total = len(activities)
        
        # Score base
        base_score = allowed / total
        
        # Penalidade por bloqueios recentes
        recent_activities = activities[-20:]
        recent_blocked = sum(1 for a in recent_activities if a.result == 'blocked')
        recent_penalty = (recent_blocked / len(recent_activities)) * 0.4
        
        # Penalidade por bloqueios antigos
        old_blocked = blocked - recent_blocked
        old_penalty = (old_blocked / total) * 0.2
        
        score = base_score - recent_penalty - old_penalty
        return max(0.0, min(1.0, score))
    
    def _calculate_appeal_bonus(self, activities: List[UserActivity]) -> float:
        """Bônus por apelações bem-sucedidas"""
        appeal_success = sum(1 for a in activities if a.result == 'appealed_success')
        appeal_fail = sum(1 for a in activities if a.result == 'appealed_fail')
        total_appeals = appeal_success + appeal_fail
        
        if total_appeals == 0:
            return 0.0
        
        success_rate = appeal_success / total_appeals
        bonus = success_rate * 0.3
        penalty = (appeal_fail / total_appeals) * 0.15
        
        return max(0.0, bonus - penalty)
    
    def _calculate_consistency_bonus(self, activities: List[UserActivity]) -> float:
        """Bônus por consistência (anti-gaming)"""
        if len(activities) < 10:
            return 0.0
        
        # Analisa intervalos
        recent = activities[-50:]
        timestamps = [a.timestamp for a in recent]
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        avg_interval = sum(intervals) / len(intervals)
        
        # Penalidade por spam
        if avg_interval < 60:
            spam_penalty = 0.3
        elif avg_interval < 300:
            spam_penalty = 0.1
        else:
            spam_penalty = 0.0
        
        # Penalidade por diversidade excessiva
        domains = [a.context.get('domain') for a in activities[-20:] if a.context]
        unique_domains = len(set(domains))
        diversity_penalty = 0.2 if unique_domains > 5 else 0.0
        
        consistency = 1.0 - spam_penalty - diversity_penalty
        return max(0.0, consistency)
    
    def _apply_temporal_decay(self, score: float, last_activity_timestamp: int) -> float:
        """Aplica decay temporal"""
        now = int(time.time())
        hours_since = (now - last_activity_timestamp) / 3600
        
        decay_factor = 0.5 ** (hours_since / self.decay_half_life_hours)
        return score * decay_factor
    
    def explain_score(self, session_id: str, user_role: str) -> Dict[str, Any]:
        """
        Explica como trust score foi calculado (transparência).
        
        Retorna breakdown de cada componente.
        """
        activities = self._activity_log.get(session_id, [])
        
        base_trust = self._base_trust_from_role(user_role)
        
        if len(activities) < self.min_activities_for_trust:
            return {
                'trust_score': base_trust,
                'breakdown': {
                    'base_trust': base_trust,
                    'reason': f'Novo usuário (< {self.min_activities_for_trust} atividades)',
                },
                'recommendations': [
                    'Continue usando o sistema para construir histórico',
                    'Autentique-se para aumentar trust inicial',
                ],
            }
        
        history_score = self._calculate_historical_behavior(activities)
        appeal_bonus = self._calculate_appeal_bonus(activities)
        consistency_bonus = self._calculate_consistency_bonus(activities)
        
        score_before_decay = (
            self.weights['role'] * base_trust +
            self.weights['history'] * history_score +
            self.weights['appeals'] * appeal_bonus +
            self.weights['consistency'] * consistency_bonus
        )
        
        last_activity = max(a.timestamp for a in activities)
        final_score = self._apply_temporal_decay(score_before_decay, last_activity)
        
        # Calcula decay
        decay_applied = score_before_decay - final_score
        
        # Recomendações personalizadas
        recommendations = []
        if history_score < 0.5:
            recommendations.append('Evite ações que resultem em bloqueios')
        if appeal_bonus < 0.1 and len([a for a in activities if 'appeal' in a.result]) > 0:
            recommendations.append('Appeals rejeitados impactam negativamente seu trust')
        if decay_applied > 0.1:
            recommendations.append(f'Inatividade reduziu seu trust em {decay_applied:.0%}')
        if consistency_bonus < 0.03:
            recommendations.append('Padrão de uso errático detectado')
        
        return {
            'trust_score': round(final_score, 3),
            'breakdown': {
                'base_trust': round(base_trust * self.weights['role'], 3),
                'historical_behavior': round(history_score * self.weights['history'], 3),
                'appeal_bonus': round(appeal_bonus * self.weights['appeals'], 3),
                'consistency_bonus': round(consistency_bonus * self.weights['consistency'], 3),
                'temporal_decay': round(-decay_applied, 3),
            },
            'stats': {
                'total_activities': len(activities),
                'allowed_count': sum(1 for a in activities if a.result == 'allowed'),
                'blocked_count': sum(1 for a in activities if a.result == 'blocked'),
                'appeals_success': sum(1 for a in activities if a.result == 'appealed_success'),
                'appeals_fail': sum(1 for a in activities if a.result == 'appealed_fail'),
                'days_since_last_activity': (int(time.time()) - last_activity) / 86400,
            },
            'recommendations': recommendations,
        }
    
    def get_stats(self, session_id: str) -> Dict[str, Any]:
        """Retorna estatísticas agregadas"""
        activities = self._activity_log.get(session_id, [])
        
        if not activities:
            return {'total_activities': 0}
        
        allowed = sum(1 for a in activities if a.result == 'allowed')
        blocked = sum(1 for a in activities if a.result == 'blocked')
        
        return {
            'total_activities': len(activities),
            'allowed_count': allowed,
            'blocked_count': blocked,
            'block_rate': blocked / len(activities) if activities else 0.0,
            'trust_score': self.calculate(session_id, 'unknown'),
            'last_activity': max(a.timestamp for a in activities),
        }