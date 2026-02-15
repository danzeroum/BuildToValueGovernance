from pathlib import Path
from typing import List


def blind_policy_test(policy_file: Path, test_cases: List[TestCase]):
    """
    Testa policy SEM saber:
    - Quem criou a policy
    - Quem são os usuários dos test cases
    - Qual é o objetivo esperado
    
    (Rawls: Testa atrás do Véu da Ignorância)
    """
    
    # Anonimiza metadados
    policy = load_policy_anonymized(policy_file)
    
    results = []
    for case in test_cases:
        # Remove identificadores
        case_anonymized = anonymize_test_case(case)
        
        # Aplica policy
        verdict = apply_policy(policy, case_anonymized)
        
        results.append({
            'test_id': case.id,  # Apenas ID numérico
            'verdict': verdict.action,
            'passed': verdict.action == case.expected_action
        })
    
    # Métrica agregada (sem identificação individual)
    pass_rate = sum(r['passed'] for r in results) / len(results)
    
    if pass_rate < 0.95:
        raise PolicyTestFailure(f"Pass rate {pass_rate:.0%} < 95%")
    
    return results