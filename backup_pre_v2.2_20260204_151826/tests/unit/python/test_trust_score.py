
import pytest
import time
from governance.trust_score import TrustScoreCalculator, UserActivity

@pytest.fixture
def calculator():
    return TrustScoreCalculator()

def test_base_trust_from_role(calculator):
    """Testa trust inicial baseado em role"""
    
    assert calculator._base_trust_from_role('anonymous') == 0.20
    assert calculator._base_trust_from_role('authenticated') == 0.50
    assert calculator._base_trust_from_role('healthcare_professional') == 0.75
    assert calculator._base_trust_from_role('researcher') == 0.80
    assert calculator._base_trust_from_role('admin') == 0.90
    assert calculator._base_trust_from_role('unknown_role') == 0.30  # Default

def test_new_user_trust(calculator):
    """Usuário novo deve ter apenas base trust"""
    
    trust = calculator.calculate('new-session', 'authenticated')
    
    # Sem histórico, trust = base_trust do role
    assert trust == 0.50

def test_historical_behavior_perfect_user(calculator):
    """Usuário com histórico perfeito (100% allowed)"""
    
    session_id = 'perfect-user'
    
    # Registra 10 atividades, todas permitidas
    for i in range(10):
        calculator.record_activity(UserActivity(
            session_id=session_id,
            timestamp=int(time.time()) - (10 - i) * 60,  # Últimas 10 min
            action='request',
            result='allowed',
        ))
    
    trust = calculator.calculate(session_id, 'authenticated')
    
    # Trust deve ser alto (> 0.8)
    assert trust > 0.8

def test_historical_behavior_problematic_user(calculator):
    """Usuário com muitos bloqueios"""
    
    session_id = 'problematic-user'
    
    # 50% allowed, 50% blocked
    for i in range(20):
        result = 'allowed' if i % 2 == 0 else 'blocked'
        calculator.record_activity(UserActivity(
            session_id=session_id,
            timestamp=int(time.time()) - (20 - i) * 60,
            action='request',
            result=result,
        ))
    
    trust = calculator.calculate(session_id, 'authenticated')
    
    # Trust deve ser baixo (< 0.5)
    assert trust < 0.5

def test_appeal_bonus(calculator):
    """Apelações bem-sucedidas aumentam trust"""
    
    session_id = 'appeal-user'
    
    # Registra 10 atividades normais
    for i in range(10):
        calculator.record_activity(UserActivity(
            session_id=session_id,
            timestamp=int(time.time()) - 100 + i,
            action='request',
            result='allowed',
        ))
    
    trust_before = calculator.calculate(session_id, 'authenticated')
    
    # Adiciona 3 apelações bem-sucedidas
    for i in range(3):
        calculator.record_activity(UserActivity(
            session_id=session_id,
            timestamp=int(time.time()) - 50 + i,
            action='appeal',
            result='appealed_success',
        ))
    
    trust_after = calculator.calculate(session_id, 'authenticated')
    
    # Trust deve ter aumentado
    assert trust_after > trust_before

def test_appeal_penalty(calculator):
    """Apelações rejeitadas penalizam trust"""
    
    session_id = 'failed-appeal-user'
    
    # Histórico normal
    for i in range(10):
        calculator.record_activity(UserActivity(
            session_id=session_id,
            timestamp=int(time.time()) - 100 + i,
            action='request',
            result='allowed',
        ))
    
    trust_before = calculator.calculate(session_id, 'authenticated')
    
    # Adiciona 5 apelações rejeitadas
    for i in range(5):
        calculator.record_activity(UserActivity(
            session_id=session_id,
            timestamp=int(time.time()) - 50 + i,
            action='appeal',
            result='appealed_fail',
        ))
    
    trust_after = calculator.calculate(session_id, 'authenticated')
    
    # Trust deve ter diminuído
    assert trust_after < trust_before

def test_temporal_decay(calculator):
    """Trust decai com inatividade"""
    
    session_id = 'inactive-user'
    
    # Atividades antigas (60 dias atrás)
    old_timestamp = int(time.time()) - (60 * 24 * 3600)
    
    for i in range(10):
        calculator.record_activity(UserActivity(
            session_id=session_id,
            timestamp=old_timestamp + i,
            action='request',
            result='allowed',
        ))
    
    trust = calculator.calculate(session_id, 'authenticated')
    
    # Trust deve ser baixo devido ao decay (half-life = 30 dias)
    # Após 60 dias: trust = original * 0.5^2 = original * 0.25
    assert trust < 0.5  # Significativamente decaído

def test_consistency_bonus(calculator):
    """Usuário consistente recebe bônus"""
    
    session_id = 'consistent-user'
    
    # Atividades espaçadas regularmente (1 a cada hora)
    base_time = int(time.time()) - (24 * 3600)
    
    for i in range(20):
        calculator.record_activity(UserActivity(
            session_id=session_id,
            timestamp=base_time + (i * 3600),  # 1 hora de intervalo
            action='request',
            result='allowed',
            context={'domain': 'medical'},  # Sempre mesmo domínio
        ))
    
    trust = calculator.calculate(session_id, 'healthcare_professional')
    
    # Trust deve ser alto (consistência + bom histórico)
    assert trust > 0.80

def test_spam_detection(calculator):
    """Spam (muitas requests rápidas) penaliza trust"""
    
    session_id = 'spammer'
    
    # 100 requests em 10 segundos (spam!)
    base_time = int(time.time())
    
    for i in range(100):
        calculator.record_activity(UserActivity(
            session_id=session_id,
            timestamp=base_time + (i // 10),  # 10 req/segundo
            action='request',
            result='allowed',
        ))
    
    trust = calculator.calculate(session_id, 'authenticated')
    
    # Trust deve ser penalizado (spam detectado)
    # Mesmo com 100% allowed, spam reduz trust
    assert trust < 0.60

def test_explain_score(calculator):
    """Testa explicação detalhada do trust score"""
    
    session_id = 'explained-user'
    
    # Adiciona histórico
    for i in range(15):
        calculator.record_activity(UserActivity(
            session_id=session_id,
            timestamp=int(time.time()) - 100 + i,
            action='request',
            result='allowed' if i < 12 else 'blocked',
        ))
    
    explanation = calculator.explain_score(session_id, 'authenticated')
    
    # Verifica estrutura da explicação
    assert 'trust_score' in explanation
    assert 'breakdown' in explanation
    assert 'stats' in explanation
    assert 'recommendations' in explanation
    
    # Breakdown deve conter todos os componentes
    assert 'base_trust' in explanation['breakdown']
    assert 'historical_behavior' in explanation['breakdown']
    assert 'appeal_bonus' in explanation['breakdown']
    assert 'consistency_bonus' in explanation['breakdown']
    assert 'temporal_decay' in explanation['breakdown']
    
    # Stats deve conter métricas
    assert explanation['stats']['total_activities'] == 15
    assert explanation['stats']['allowed_count'] == 12
    assert explanation['stats']['blocked_count'] == 3