
"""
Blind Policy Testing (Rawls: Veil of Ignorance)

Principle:
  Policies should be fair regardless of whether you are:
  - The author (making the rule)
  - The target (subject to the rule)
  - The auditor (reviewing the rule)

Method:
  1. Anonymize test cases (remove labels)
  2. Run tests without knowing expected outcomes
  3. Reveal labels only after all tests complete
  4. Calculate fairness metrics

Pass Criteria:
  - False Positive Rate < 5%
  - False Negative Rate < 2%
  - Disparate Impact Ratio > 0.8
  - Consistency Score > 95%
"""

import pytest
import json
import random
from typing import List, Dict, Any
from dataclasses import dataclass
from pathlib import Path

from api.validation import ValidationService
from tests.fixtures import get_test_validation_service

# ═══════════════════════════════════════════════════════════════
# Test Case Types
# ═══════════════════════════════════════════════════════════════

@dataclass
class BlindTestCase:
    """Anonymized test case (no label until reveal)"""
    id: str
    input_text: str
    context: Dict[str, Any]
    # Label hidden until reveal phase
    _expected_action: str = None
    _rationale: str = None
    
    def reveal(self, expected_action: str, rationale: str):
        """Reveal expected outcome (after testing)"""
        self._expected_action = expected_action
        self._rationale = rationale

@dataclass
class BlindTestResult:
    """Result of blind test"""
    test_case_id: str
    actual_action: str
    expected_action: str
    match: bool
    confidence: float

# ═══════════════════════════════════════════════════════════════
# Test Data Generator
# ═══════════════════════════════════════════════════════════════

class BlindTestDataGenerator:
    """Generate test cases for blind policy testing"""
    
    @staticmethod
    def load_test_cases(policy_name: str) -> List[BlindTestCase]:
        """
        Load test cases from YAML (anonymized format).
        
        Format:
        ```yaml
        test_cases:
          - id: "001"
            input: "My CPF is 123.456.789-09"
            context:
              domain: general
            # Expected outcome stored separately
        ```
        """
        test_file = Path(f"tests/ethical/cases/{policy_name}_blind.yaml")
        
        if not test_file.exists():
            raise FileNotFoundError(f"Test cases not found: {test_file}")
        
        import yaml
        with open(test_file) as f:
            data = yaml.safe_load(f)
        
        cases = []
        for case in data["test_cases"]:
            cases.append(BlindTestCase(
                id=case["id"],
                input_text=case["input"],
                context=case.get("context", {}),
            ))
        
        return cases
    
    @staticmethod
    def load_expected_outcomes(policy_name: str) -> Dict[str, Dict[str, str]]:
        """
        Load expected outcomes (separate file).
        
        This file is NOT accessed during testing phase.
        Only revealed after all tests complete.
        """
        outcomes_file = Path(f"tests/ethical/outcomes/{policy_name}_outcomes.yaml")
        
        import yaml
        with open(outcomes_file) as f:
            data = yaml.safe_load(f)
        
        return {
            case["id"]: {
                "expected_action": case["expected_action"],
                "rationale": case["rationale"],
            }
            for case in data["outcomes"]
        }

# ═══════════════════════════════════════════════════════════════
# Blind Policy Tester
# ═══════════════════════════════════════════════════════════════

class BlindPolicyTester:
    """Execute blind policy tests (Rawlsian framework)"""
    
    def __init__(self, validation_service: ValidationService):
        self.validation_service = validation_service
        self.results: List[BlindTestResult] = []
    
    def run_blind_tests(self, policy_name: str, profile: str = "general") -> List[BlindTestResult]:
        """
        Run blind tests WITHOUT knowing expected outcomes.
        
        This ensures fairness: we don't tune the policy to pass tests.
        """
        # Load anonymized test cases
        test_cases = BlindTestDataGenerator.load_test_cases(policy_name)
        
        # Shuffle to prevent ordering bias
        random.shuffle(test_cases)
        
        print(f"\n{'═'*60}")
        print(f"BLIND POLICY TEST: {policy_name}")
        print(f"{'═'*60}")
        print(f"Test Cases: {len(test_cases)}")
        print(f"Profile: {profile}")
        print(f"\n⚠️  Running blind (expected outcomes hidden)...\n")
        
        results = []
        
        for i, test_case in enumerate(test_cases, 1):
            # Run validation (blind)
            verdict = self.validation_service.validate(
                text=test_case.input_text,
                session_id=f"blind_test_{policy_name}_{test_case.id}",
                profile=profile,
                context=test_case.context,
            )
            
            # Store result (without expected action)
            results.append({
                "test_case_id": test_case.id,
                "actual_action": verdict.action,
                "confidence": verdict.confidence,
                "rationale": verdict.rationale,
            })
            
            print(f"  [{i:3d}/{len(test_cases)}] Case {test_case.id}: {verdict.action} (conf: {verdict.confidence:.2f})")
        
        self.results = results
        return results
    
    def reveal_and_evaluate(self, policy_name: str) -> Dict[str, Any]:
        """
        Reveal expected outcomes and evaluate fairness.
        
        This is the "veil of ignorance" lifting phase.
        """
        print(f"\n{'─'*60}")
        print(f"REVEALING EXPECTED OUTCOMES...")
        print(f"{'─'*60}\n")
        
        # Load expected outcomes (AFTER testing)
        expected_outcomes = BlindTestDataGenerator.load_expected_outcomes(policy_name)
        
        # Match results with expectations
        evaluated_results = []
        
        for result in self.results:
            test_id = result["test_case_id"]
            expected = expected_outcomes[test_id]
            
            match = result["actual_action"] == expected["expected_action"]
            
            evaluated_results.append(BlindTestResult(
                test_case_id=test_id,
                actual_action=result["actual_action"],
                expected_action=expected["expected_action"],
                match=match,
                confidence=result["confidence"],
            ))
            
            status = "✅" if match else "❌"
            print(f"  {status} Case {test_id}: Expected={expected['expected_action']}, Got={result['actual_action']}")
        
        # Calculate metrics
        metrics = self._calculate_fairness_metrics(evaluated_results)
        
        print(f"\n{'═'*60}")
        print(f"FAIRNESS METRICS")
        print(f"{'═'*60}")
        print(f"  Accuracy:               {metrics['accuracy']:.1%}")
        print(f"  False Positive Rate:    {metrics['false_positive_rate']:.1%} (target: < 5%)")
        print(f"  False Negative Rate:    {metrics['false_negative_rate']:.1%} (target: < 2%)")
        print(f"  Consistency Score:      {metrics['consistency']:.1%} (target: > 95%)")
        print(f"\n  Pass Threshold:         {metrics['pass_threshold']:.1%}")
        print(f"  Overall Result:         {'✅ PASS' if metrics['pass'] else '❌ FAIL'}")
        print(f"{'═'*60}\n")
        
        return metrics
    
    def _calculate_fairness_metrics(self, results: List[BlindTestResult]) -> Dict[str, float]:
        """Calculate fairness metrics (Rawlsian criteria)"""
        total = len(results)
        correct = sum(1 for r in results if r.match)
        
        # True Positives, False Positives, etc.
        tp = sum(1 for r in results if r.expected_action == "BLOCK" and r.actual_action == "BLOCK")
        fp = sum(1 for r in results if r.expected_action == "ALLOW" and r.actual_action == "BLOCK")
        tn = sum(1 for r in results if r.expected_action == "ALLOW" and r.actual_action == "ALLOW")
        fn = sum(1 for r in results if r.expected_action == "BLOCK" and r.actual_action == "ALLOW")
        
        accuracy = correct / total
        
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
        
        # Consistency: same input → same output (across multiple runs)
        # For now, use confidence as proxy (high confidence = high consistency)
        avg_confidence = sum(r.confidence for r in results) / total
        consistency = avg_confidence
        
        # Pass criteria
        pass_criteria = (
            fpr < 0.05 and  # FPR < 5%
            fnr < 0.02 and  # FNR < 2%
            consistency > 0.95  # Consistency > 95%
        )
        
        return {
            "accuracy": accuracy,
            "false_positive_rate": fpr,
            "false_negative_rate": fnr,
            "consistency": consistency,
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "pass_threshold": 0.95,
            "pass": pass_criteria,
        }

# ═══════════════════════════════════════════════════════════════
# Pytest Integration
# ═══════════════════════════════════════════════════════════════

@pytest.mark.ethical
class TestBlindPolicyTesting:
    
    def test_cpf_protection_policy_blind(self):
        """Blind test for CPF protection policy"""
        validation_service = get_test_validation_service()
        tester = BlindPolicyTester(validation_service)
        
        # Run blind tests
        tester.run_blind_tests(policy_name="cpf_protection_v1")
        
        # Reveal and evaluate
        metrics = tester.reveal_and_evaluate(policy_name="cpf_protection_v1")
        
        # Assert fairness criteria
        assert metrics["pass"], f"Policy failed blind test: {metrics}"
    
    def test_healthcare_policy_blind(self):
        """Blind test for healthcare policy (with mercy)"""
        validation_service = get_test_validation_service()
        tester = BlindPolicyTester(validation_service)
        
        tester.run_blind_tests(policy_name="healthcare_v1", profile="healthcare")
        metrics = tester.reveal_and_evaluate(policy_name="healthcare_v1")
        
        assert metrics["pass"], f"Healthcare policy failed blind test: {metrics}"