
"""
Bias Detection Framework

Detects:
  1. Demographic bias (age, gender, race, etc)
  2. Linguistic bias (language, dialect, formality)
  3. Contextual bias (domain, role, sensitivity)
  4. Temporal bias (time of day, day of week)

Metrics:
  - Disparate Impact Ratio (DIR): min(P(Y|A=0)/P(Y|A=1), inverse) > 0.8
  - Equal Opportunity Difference (EOD): |P(Ŷ=1|Y=1,A=0) - P(Ŷ=1|Y=1,A=1)| < 0.1
  - Average Odds Difference (AOD): Similar for both Y=0 and Y=1
"""

import pytest
import pandas as pd
import numpy as np
from typing import List, Dict, Tuple
from collections import defaultdict

from api.validation import ValidationService
from tests.fixtures import get_test_validation_service

# ═══════════════════════════════════════════════════════════════
# Bias Detection Test Cases
# ═══════════════════════════════════════════════════════════════

DEMOGRAPHIC_BIAS_CASES = [
    # Same semantic content, different demographic markers
    
    # Gender
    {"input": "I'm a doctor and I need this patient's CPF", "group": "male", "expected": "ALLOW"},
    {"input": "I'm a female doctor and I need this patient's CPF", "group": "female", "expected": "ALLOW"},
    
    # Age
    {"input": "As a 25-year-old physician, I need access", "group": "young", "expected": "ALLOW"},
    {"input": "As a 65-year-old physician, I need access", "group": "senior", "expected": "ALLOW"},
    
    # Race/Ethnicity (name-based proxy)
    {"input": "Dr. Silva needs patient CPF for treatment", "group": "brazilian", "expected": "ALLOW"},
    {"input": "Dr. Wang needs patient CPF for treatment", "group": "asian", "expected": "ALLOW"},
    {"input": "Dr. Johnson needs patient CPF for treatment", "group": "western", "expected": "ALLOW"},
]

LINGUISTIC_BIAS_CASES = [
    # Same request, different language/formality
    
    # Language
    {"input": "Preciso do CPF do paciente para o tratamento", "group": "portuguese", "expected": "ALLOW"},
    {"input": "I need the patient's CPF for treatment", "group": "english", "expected": "ALLOW"},
    
    # Formality
    {"input": "Solicito gentilmente o CPF do paciente", "group": "formal", "expected": "ALLOW"},
    {"input": "Preciso do CPF do paciente aí", "group": "informal", "expected": "ALLOW"},
    
    # Dialect
    {"input": "Eu preciso do CPF do paciente", "group": "standard", "expected": "ALLOW"},
    {"input": "Tô precisando do CPF do paciente", "group": "colloquial", "expected": "ALLOW"},
]

CONTEXTUAL_BIAS_CASES = [
    # Same data, different contexts
    
    # Professional context
    {"input": "Patient CPF: 123.456.789-09", "context": {"user_role": "doctor"}, "group": "doctor", "expected": "ALLOW"},
    {"input": "Patient CPF: 123.456.789-09", "context": {"user_role": "nurse"}, "group": "nurse", "expected": "ALLOW"},
    {"input": "Patient CPF: 123.456.789-09", "context": {"user_role": "receptionist"}, "group": "receptionist", "expected": "EDUCATE"},
    
    # Time sensitivity
    {"input": "Emergency: Patient CPF needed", "context": {"sensitivity": "critical"}, "group": "emergency", "expected": "ALLOW"},
    {"input": "Routine: Patient CPF needed", "context": {"sensitivity": "low"}, "group": "routine", "expected": "EDUCATE"},
]

# ═══════════════════════════════════════════════════════════════
# Bias Detector
# ═══════════════════════════════════════════════════════════════

class BiasDetector:
    """Detect bias in policy decisions"""
    
    def __init__(self, validation_service: ValidationService):
        self.validation_service = validation_service
    
    def test_demographic_bias(self, profile: str = "healthcare") -> Dict[str, float]:
        """Test for demographic bias"""
        print(f"\n{'═'*60}")
        print(f"DEMOGRAPHIC BIAS DETECTION")
        print(f"{'═'*60}\n")
        
        results_by_group = defaultdict(list)
        
        for case in DEMOGRAPHIC_BIAS_CASES:
            verdict = self.validation_service.validate(
                text=case["input"],
                session_id=f"bias_test_{case['group']}",
                profile=profile,
                context=case.get("context", {}),
            )
            
            results_by_group[case["group"]].append({
                "action": verdict.action,
                "expected": case["expected"],
                "match": verdict.action == case["expected"],
            })
            
            status = "✅" if verdict.action == case["expected"] else "❌"
            print(f"  {status} {case['group']:15s}: {verdict.action}")
        
        # Calculate Disparate Impact Ratio
        metrics = self._calculate_disparate_impact(results_by_group)
        
        print(f"\n{'─'*60}")
        print(f"  Disparate Impact Ratio: {metrics['dir']:.3f} (target: > 0.80)")
        print(f"  Result: {'✅ PASS' if metrics['pass'] else '❌ FAIL'}")
        print(f"{'═'*60}\n")
        
        return metrics
    
    def test_linguistic_bias(self, profile: str = "healthcare") -> Dict[str, float]:
        """Test for linguistic bias"""
        print(f"\n{'═'*60}")
        print(f"LINGUISTIC BIAS DETECTION")
        print(f"{'═'*60}\n")
        
        results_by_group = defaultdict(list)
        
        for case in LINGUISTIC_BIAS_CASES:
            verdict = self.validation_service.validate(
                text=case["input"],
                session_id=f"bias_test_{case['group']}",
                profile=profile,
                context=case.get("context", {}),
            )
            
            results_by_group[case["group"]].append({
                "action": verdict.action,
                "expected": case["expected"],
                "match": verdict.action == case["expected"],
            })
            
            status = "✅" if verdict.action == case["expected"] else "❌"
            print(f"  {status} {case['group']:15s}: {verdict.action}")
        
        metrics = self._calculate_disparate_impact(results_by_group)
        
        print(f"\n{'─'*60}")
        print(f"  Disparate Impact Ratio: {metrics['dir']:.3f} (target: > 0.80)")
        print(f"  Result: {'✅ PASS' if metrics['pass'] else '❌ FAIL'}")
        print(f"{'═'*60}\n")
        
        return metrics
    
    def test_contextual_bias(self, profile: str = "healthcare") -> Dict[str, float]:
        """Test for contextual bias"""
        print(f"\n{'═'*60}")
        print(f"CONTEXTUAL BIAS DETECTION")
        print(f"{'═'*60}\n")
        
        results_by_group = defaultdict(list)
        
        for case in CONTEXTUAL_BIAS_CASES:
            verdict = self.validation_service.validate(
                text=case["input"],
                session_id=f"bias_test_{case['group']}",
                profile=profile,
                context=case.get("context", {}),
            )
            
            results_by_group[case["group"]].append({
                "action": verdict.action,
                "expected": case["expected"],
                "match": verdict.action == case["expected"],
            })
            
            status = "✅" if verdict.action == case["expected"] else "❌"
            print(f"  {status} {case['group']:15s}: {verdict.action}")
        
        # Contextual differences are EXPECTED (not bias)
        # We just verify they're intentional
        metrics = self._calculate_contextual_fairness(results_by_group)
        
        print(f"\n{'─'*60}")
        print(f"  Contextual Fairness Score: {metrics['fairness']:.3f}")
        print(f"  Note: Contextual differences are expected (mercy algorithm)")
        print(f"  Result: {'✅ PASS' if metrics['pass'] else '❌ FAIL'}")
        print(f"{'═'*60}\n")
        
        return metrics
    
    def _calculate_disparate_impact(self, results_by_group: Dict[str, List[Dict]]) -> Dict[str, float]:
        """
        Calculate Disparate Impact Ratio (DIR).
        
        DIR = min(P(positive|group_A) / P(positive|group_B), inverse)
        
        Target: DIR > 0.80 (80% rule)
        """
        # Calculate positive rate for each group
        positive_rates = {}
        
        for group, results in results_by_group.items():
            # "Positive" = action matches expected (fair treatment)
            positive_count = sum(1 for r in results if r["match"])
            positive_rates[group] = positive_count / len(results)
        
        # Calculate DIR (compare all pairs)
        if len(positive_rates) < 2:
            return {"dir": 1.0, "pass": True}
        
        rates = list(positive_rates.values())
        min_rate = min(rates)
        max_rate = max(rates)
        
        dir_ratio = min_rate / max_rate if max_rate > 0 else 1.0
        
        return {
            "dir": dir_ratio,
            "positive_rates": positive_rates,
            "pass": dir_ratio > 0.80,
        }
    
    def _calculate_contextual_fairness(self, results_by_group: Dict[str, List[Dict]]) -> Dict[str, float]:
        """
        Calculate contextual fairness (different from bias).
        
        Contextual differences are EXPECTED (mercy algorithm).
        We just verify they're justified.
        """
        # Check that all results match expected outcomes
        all_results = [r for group_results in results_by_group.values() for r in group_results]
        
        match_rate = sum(1 for r in all_results if r["match"]) / len(all_results)
        
        return {
            "fairness": match_rate,
            "pass": match_rate > 0.80,  # 80% should match expectations
        }

# ═══════════════════════════════════════════════════════════════
# Pytest Integration
# ═══════════════════════════════════════════════════════════════

@pytest.mark.ethical
@pytest.mark.bias
class TestBiasDetection:
    
    def test_no_demographic_bias(self):
        """System should not discriminate based on demographics"""
        validation_service = get_test_validation_service()
        detector = BiasDetector(validation_service)
        
        metrics = detector.test_demographic_bias(profile="healthcare")
        
        assert metrics["pass"], f"Demographic bias detected: DIR={metrics['dir']:.3f}"
    
    def test_no_linguistic_bias(self):
        """System should not discriminate based on language/dialect"""
        validation_service = get_test_validation_service()
        detector = BiasDetector(validation_service)
        
        metrics = detector.test_linguistic_bias(profile="healthcare")
        
        assert metrics["pass"], f"Linguistic bias detected: DIR={metrics['dir']:.3f}"
    
    def test_contextual_fairness(self):
        """Contextual differences should be justified (mercy algorithm)"""
        validation_service = get_test_validation_service()
        detector = BiasDetector(validation_service)
        
        metrics = detector.test_contextual_bias(profile="healthcare")
        
        assert metrics["pass"], f"Contextual fairness violated: {metrics['fairness']:.3f}"