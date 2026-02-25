"""
Trust Score Calculator - Calculador de confiança de usuário.
Score multifatorial baseado em histórico e comportamento.
"""
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
import time
import math
from collections import defaultdict


@dataclass
class UserActivity:
    """Atividade de usuário."""
    session_id: str
    timestamp: int
    action: str  # "request", "appeal", "feedback"
    result: str  # "allowed", "blocked", "appeal_success", "appeal_fail"
    context: Dict[str, Any] = None


class TrustScoreCalculator:
    """
    Calcula Trust Score multi-fatorial.

    Formula:
    trust = w1*base + w2*history + w3*appeals + w4*decay + w5*consistency

    Garantias:
    - Score ∈ [0.0, 1.0]
    - Determinístico: mesmo histórico = mesmo score
    - Não-gaming: spam não aumenta trust
    - Privacy-preserving: sem PII
    """

    def __init__(self):
        """
        Inicializa calculador.

        Pesos padrão (soma = 1.0):
        - base: 0.20 (score inicial por role)
        - history: 0.30 (comportamento passado)
        - appeals: 0.20 (contestações bem-sucedidas)
        - decay: 0.15 (penalidade por violações recentes)
        - consistency: 0.15 (padrão de uso consistente)
        """
        self.weights = {
            'base': 0.20,
            'history': 0.30,
            'appeals': 0.20,
            'decay': 0.15,
            'consistency': 0.15
        }

        # Cache de trust scores (session_id -> (score, timestamp))
        # Em prod: usar Redis com TTL
        self.trust_cache: Dict[str, tuple[float, int]] = {}

        # Histórico de atividades (session_id -> [activities])
        # Em prod: usar TimeSeries DB
        self.activity_log: Dict[str, List[UserActivity]] = defaultdict(list)

    def calculate(self, session_id: str, user_role: str) -> float:
        """
        Calcula trust score.

        Retorna: 0.0-1.0
        """
        # Cache hit (válido por 5 minutos)
        if session_id in self.trust_cache:
            cached_score, cached_time = self.trust_cache[session_id]
            if time.time() - cached_time < 300:  # 5 min
                return cached_score

        # Calcula componentes
        base_score = self._base_score(user_role)
        history_score = self._history_score(session_id)
        appeal_score = self._appeal_score(session_id)
        decay_penalty = self._decay_penalty(session_id)
        consistency_score = self._consistency_score(session_id)

        # Aplica fórmula ponderada
        trust = (
                self.weights['base'] * base_score +
                self.weights['history'] * history_score +
                self.weights['appeals'] * appeal_score +
                self.weights['decay'] * (1.0 - decay_penalty) +
                self.weights['consistency'] * consistency_score
        )

        # Clamp [0.0, 1.0]
        trust = max(0.0, min(1.0, trust))

        # Cacheia
        self.trust_cache[session_id] = (trust, int(time.time()))

        return trust

    def _base_score(self, user_role: str) -> float:
        """
        Score base por role.

        Roles mais privilegiadas começam com trust maior:
        - admin: 0.9
        - developer: 0.7
        - user: 0.5
        - guest: 0.3
        """
        role_scores = {
            'admin': 0.9,
            'developer': 0.7,
            'power_user': 0.6,
            'user': 0.5,
            'guest': 0.3,
            'anonymous': 0.2
        }
        return role_scores.get(user_role, 0.5)

    def _history_score(self, session_id: str) -> float:
        """
        Score baseado em histórico de comportamento.

        Calcula:
        - Ratio de requests allowed vs blocked
        - Penaliza violações repetidas
        - Recompensa uso consistente
        """
        activities = self.activity_log.get(session_id, [])
        if not activities:
            return 0.5  # Neutro se sem histórico

        # Filtra apenas requests (não appeals/feedback)
        requests = [a for a in activities if a.action == "request"]
        if not requests:
            return 0.5

        # Calcula ratio allowed/total
        allowed_count = sum(1 for r in requests if r.result == "allowed")
        total_count = len(requests)
        ratio = allowed_count / total_count

        # Penaliza se muitos bloqueios
        if ratio < 0.5:
            return ratio * 0.8  # Penalidade
        else:
            return ratio

    def _appeal_score(self, session_id: str) -> float:
        """
        Score baseado em appeals bem-sucedidos.

        Appeals bem-sucedidos indicam:
        - Usuário conhece seus direitos
        - Falso positivos do sistema
        - Contexto justificável

        Aumenta trust.
        """
        activities = self.activity_log.get(session_id, [])
        appeals = [a for a in activities if a.action == "appeal"]

        if not appeals:
            return 0.5  # Neutro

        success_count = sum(1 for a in appeals if a.result == "appeal_success")
        total_appeals = len(appeals)

        # Ratio de sucesso
        success_ratio = success_count / total_appeals

        # Normaliza para [0.3, 1.0]
        # (pelo menos 30% de trust mesmo com appeals falhados)
        return 0.3 + (success_ratio * 0.7)

    def _decay_penalty(self, session_id: str) -> float:
        """
        Penalidade por violações recentes.

        Violações mais recentes têm maior impacto.
        Decai exponencialmente com tempo.

        Returns:
            0.0-1.0 (0 = sem penalidade, 1 = máxima penalidade)
        """
        activities = self.activity_log.get(session_id, [])
        blocked = [a for a in activities if a.result == "blocked"]

        if not blocked:
            return 0.0  # Sem penalidade

        now = int(time.time())
        penalty = 0.0

        for activity in blocked:
            # Tempo desde violação (em dias)
            days_ago = (now - activity.timestamp) / 86400

            # Decay exponencial: penalty = e^(-days/30)
            # Após 30 dias, penalidade é ~37% do original
            decay = math.exp(-days_ago / 30)
            penalty += decay * 0.2  # Cada violação = 20% penalty

        return min(1.0, penalty)

    def _consistency_score(self, session_id: str) -> float:
        """
        Score de consistência de uso.

        Uso consistente (mesmo horário, padrões) = maior trust.
        Uso errático = menor trust.

        Calcula:
        - Variância de horários
        - Frequência de uso
        """
        activities = self.activity_log.get(session_id, [])
        if len(activities) < 5:
            return 0.5  # Pouco histórico

        # Calcula variância de timestamps
        timestamps = [a.timestamp for a in activities[-30:]]  # Últimos 30

        if len(timestamps) < 2:
            return 0.5

        # Calcula intervalos entre requests
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]

        # Variância dos intervalos
        mean_interval = sum(intervals) / len(intervals)
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)

        # Normaliza: menor variância = maior consistência
        # Assume intervalo médio de 1 hora = 3600s
        consistency = 1.0 - min(1.0, std_dev / 3600)

        return consistency

    def record_activity(self, activity: UserActivity):
        """
        Registra atividade de usuário.

        Em prod: persistir em TimeSeries DB.
        """
        self.activity_log[activity.session_id].append(activity)

        # Invalida cache
        if activity.session_id in self.trust_cache:
            del self.trust_cache[activity.session_id]

    def explain(self, session_id: str, user_role: str) -> str:
        """
        Gera explicação human-readable do trust score.
        """
        trust = self.calculate(session_id, user_role)

        base = self._base_score(user_role)
        history = self._history_score(session_id)
        appeals = self._appeal_score(session_id)
        decay = self._decay_penalty(session_id)
        consistency = self._consistency_score(session_id)

        lines = [
            f"Trust Score: {trust:.2f}",
            "",
            "Componentes:",
            f"  • Base (role {user_role}): {base:.2f} (peso: {self.weights['base']:.0%})",
            f"  • Histórico: {history:.2f} (peso: {self.weights['history']:.0%})",
            f"  • Appeals: {appeals:.2f} (peso: {self.weights['appeals']:.0%})",
            f"  • Decay penalty: {decay:.2f} (peso: {self.weights['decay']:.0%})",
            f"  • Consistência: {consistency:.2f} (peso: {self.weights['consistency']:.0%})",
        ]

        return "\n".join(lines)

    def adjust(self, user_id: str, delta: float) -> float:
        """
        Ajusta trust score de user_id por delta (ADR-039).
        Usado por adjust_trust_after_appeal() do AppealEngine.
        Retorna novo score clampado em [0.0, 1.0].
        """
        import time

        current = self.calculate(user_id, "anonymous")
        new_score = max(0.0, min(1.0, current + delta))
        # Registrar como atividade para persistência no histórico
        activity = UserActivity(
            session_id=user_id,
            timestamp=int(time.time()),
            action="appeal",
            result="appeal_success" if delta > 0 else "appeal_fail",
        )
        self.record_activity(activity)
        return new_score
