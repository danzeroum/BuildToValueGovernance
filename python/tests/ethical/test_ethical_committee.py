
"""
Ethical Committee Simulator

Simulates human ethical review process:
  1. Case presentation (anonymized)
  2. Deliberation (multiple perspectives)
  3. Vote (2/3 majority required)
  4. Justification (documented rationale)

Perspectives:
  - Rawlsian (Justice as Fairness)
  - Gilliganian (Ethics of Care)
  - Levinasian (Responsibility to Other)
  - Utilitarian (Greatest Good)
  - Deontological (Rule-Based)
"""

import pytest
from typing import List, Dict, Tuple
from enum import Enum
from dataclasses import dataclass

# ═══════════════════════════════════════════════════════════════
# Ethical Perspectives
# ═══════════════════════════════════════════════════════════════

class EthicalPerspective(Enum):
    RAWLSIAN = "rawlsian"  # Justice as Fairness
    GILLIGANIAN = "gilliganian"  # Ethics of Care
    LEVINASIAN = "levinasian"  # Responsibility to Other
    UTILITARIAN = "utilitarian"  # Greatest Good
    DEONTOLOGICAL = "deontological"  # Rule-Based

@dataclass
class EthicalCase:
    """Case for ethical review"""
    case_id: str
    description: str
    current_policy: str
    proposed_change: str
    impact: Dict[str, str]  # stakeholders → impact
    context: Dict[str, any]

@dataclass
class EthicalVote:
    """Vote from ethical committee member"""
    perspective: EthicalPerspective
    decision: str  # APPROVE, REJECT, ABSTAIN
    rationale: str
    confidence: float

# ═══════════════════════════════════════════════════════════════
# Ethical Committee Members (Simulated)
# ═══════════════════════════════════════════════════════════════

class RawlsianReviewer:
    """Reviews from Rawlsian perspective (fairness behind veil of ignorance)"""
    
    def review(self, case: EthicalCase) -> EthicalVote:
        """Would you accept this policy if you didn't know your position?"""
        
        # Key questions:
        # 1. Does it favor any specific group?
        # 2. Would the worst-off be better off?
        # 3. Equal opportunity preserved?
        
        # Simple heuristic: check for explicit group mentions
        policy_text = case.current_policy.lower() + case.proposed_change.lower()
        
        biased_terms = ["rich", "poor", "white", "black", "male", "female", "young", "old"]
        has_bias = any(term in policy_text for term in biased_terms)
        
        # Check if worst-off stakeholders benefit
        negative_impacts = [
            impact for stakeholder, impact in case.impact.items()
            if "worse" in impact.lower() or "harm" in impact.lower()
        ]
        
        if has_bias:
            return EthicalVote(
                perspective=EthicalPerspective.RAWLSIAN,
                decision="REJECT",
                rationale="Policy shows group bias. Would not accept behind veil of ignorance.",
                confidence=0.9,
            )
        
        if len(negative_impacts) > len(case.impact) / 2:
            return EthicalVote(
                perspective=EthicalPerspective.RAWLSIAN,
                decision="REJECT",
                rationale="Policy harms majority of stakeholders. Fails difference principle.",
                confidence=0.85,
            )
        
        return EthicalVote(
            perspective=EthicalPerspective.RAWLSIAN,
            decision="APPROVE",
            rationale="Policy treats all groups fairly and benefits worst-off.",
            confidence=0.8,
        )

class GilliganianReviewer:
    """Reviews from Gilliganian perspective (care ethics)"""
    
    def review(self, case: EthicalCase) -> EthicalVote:
        """Does this policy show care for relationships and context?"""
        
        # Key questions:
        # 1. Does it consider context and relationships?
        # 2. Is there room for mercy and understanding?
        # 3. Does it balance care and justice?
        
        # Check for contextual language
        contextual_terms = ["context", "situation", "relationship", "care", "mercy", "understanding"]
        is_contextual = any(term in case.proposed_change.lower() for term in contextual_terms)
        
        # Check for rigid rules
        rigid_terms = ["always", "never", "must", "forbidden", "zero tolerance"]
        is_rigid = any(term in case.proposed_change.lower() for term in rigid_terms)
        
        if is_rigid and not is_contextual:
            return EthicalVote(
                perspective=EthicalPerspective.GILLIGANIAN,
                decision="REJECT",
                rationale="Policy is too rigid, lacks contextual sensitivity and care.",
                confidence=0.85,
            )
        
        if is_contextual:
            return EthicalVote(
                perspective=EthicalPerspective.GILLIGANIAN,
                decision="APPROVE",
                rationale="Policy shows care for context and relationships.",
                confidence=0.9,
            )
        
        return EthicalVote(
            perspective=EthicalPerspective.GILLIGANIAN,
            decision="ABSTAIN",
            rationale="Policy is neutral on care ethics dimensions.",
            confidence=0.6,
        )

class LevinasianReviewer:
    """Reviews from Levinasian perspective (responsibility to Other)"""
    
    def review(self, case: EthicalCase) -> EthicalVote:
        """Does this policy protect the vulnerable and take responsibility?"""
        
        # Key questions:
        # 1. Does it protect the most vulnerable?
        # 2. Is there accountability (non-repudiation)?
        # 3. Can decisions be contested?
        
        # Check for vulnerability protection
        vulnerability_terms = ["vulnerable", "protect", "safeguard", "prevent harm"]
        protects_vulnerable = any(term in case.proposed_change.lower() for term in vulnerability_terms)
        
        # Check for accountability
        accountability_terms = ["audit", "log", "appeal", "review", "contestable"]
        has_accountability = any(term in case.proposed_change.lower() for term in accountability_terms)
        
        if not protects_vulnerable:
            return EthicalVote(
                perspective=EthicalPerspective.LEVINASIAN,
                decision="REJECT",
                rationale="Policy does not explicitly protect vulnerable parties.",
                confidence=0.8,
            )
        
        if not has_accountability:
            return EthicalVote(
                perspective=EthicalPerspective.LEVINASIAN,
                decision="REJECT",
                rationale="Policy lacks accountability mechanisms.",
                confidence=0.85,
            )
        
        return EthicalVote(
            perspective=EthicalPerspective.LEVINASIAN,
            decision="APPROVE",
            rationale="Policy protects vulnerable and provides accountability.",
            confidence=0.9,
        )

# ═══════════════════════════════════════════════════════════════
# Ethical Committee
# ═══════════════════════════════════════════════════════════════

class EthicalCommittee:
    """Simulated ethical committee for policy review"""
    
    def __init__(self):
        self.reviewers = [
            RawlsianReviewer(),
            GilliganianReviewer(),
            LevinasianReviewer(),
        ]
    
    def review_policy(self, case: EthicalCase) -> Dict[str, any]:
        """Review policy with multiple ethical perspectives"""
        
        print(f"\n{'═'*70}")
        print(f"ETHICAL COMMITTEE REVIEW")
        print(f"{'═'*70}")
        print(f"Case ID: {case.case_id}")
        print(f"Description: {case.description}")
        print(f"\n{'─'*70}")
        print(f"CURRENT POLICY:")
        print(f"  {case.current_policy}")
        print(f"\n{'─'*70}")
        print(f"PROPOSED CHANGE:")
        print(f"  {case.proposed_change}")
        print(f"\n{'─'*70}")
        print(f"STAKEHOLDER IMPACT:")
        for stakeholder, impact in case.impact.items():
            print(f"  • {stakeholder}: {impact}")
        print(f"{'─'*70}\n")
        
        # Collect votes
        votes = []
        for reviewer in self.reviewers:
            vote = reviewer.review(case)
            votes.append(vote)
            
            decision_emoji = {
                "APPROVE": "✅",
                "REJECT": "❌",
                "ABSTAIN": "🤷",
            }[vote.decision]
            
            print(f"{decision_emoji} {vote.perspective.value.upper():15s}: {vote.decision}")
            print(f"   Rationale: {vote.rationale}")
            print(f"   Confidence: {vote.confidence:.2f}\n")
        
        # Count votes
        approve_count = sum(1 for v in votes if v.decision == "APPROVE")
        reject_count = sum(1 for v in votes if v.decision == "REJECT")
        abstain_count = sum(1 for v in votes if v.decision == "ABSTAIN")
        
        total_votes = approve_count + reject_count  # Abstentions don't count
        majority_threshold = total_votes * 2 / 3
        
        # Decision
        if approve_count >= majority_threshold:
            final_decision = "APPROVED"
            emoji = "✅"
        elif reject_count >= majority_threshold:
            final_decision = "REJECTED"
            emoji = "❌"
        else:
            final_decision = "NO CONSENSUS"
            emoji = "🤔"
        
        print(f"{'═'*70}")
        print(f"{emoji} FINAL DECISION: {final_decision}")
        print(f"   Votes: {approve_count} Approve, {reject_count} Reject, {abstain_count} Abstain")
        print(f"   Threshold: {majority_threshold:.1f} (2/3 of {total_votes})")
        print(f"{'═'*70}\n")
        
        return {
            "case_id": case.case_id,
            "decision": final_decision,
            "votes": votes,
            "approve_count": approve_count,
            "reject_count": reject_count,
            "abstain_count": abstain_count,
        }

# ═══════════════════════════════════════════════════════════════
# Pytest Integration
# ═══════════════════════════════════════════════════════════════

@pytest.mark.ethical
@pytest.mark.committee
class TestEthicalCommittee:
    
    def test_fair_policy_approved(self):
        """Fair, contextual policy should be approved"""
        case = EthicalCase(
            case_id="CASE_001",
            description="Add mercy algorithm for first-time offenders",
            current_policy="Block all CPF sharing in general context",
            proposed_change="Apply mercy for first offenders with high trust score and contextual justification",
            impact={
                "first_offenders": "Better: given second chance",
                "repeat_offenders": "No change: still blocked",
                "vulnerable_users": "Protected: policy still blocks actual violations",
            },
            context={"severity": "medium"},
        )
        
        committee = EthicalCommittee()
        result = committee.review_policy(case)
        
        assert result["decision"] == "APPROVED"
    
    def test_biased_policy_rejected(self):
        """Biased policy should be rejected"""
        case = EthicalCase(
            case_id="CASE_002",
            description="Stricter rules for young users",
            current_policy="Same rules for all users",
            proposed_change="Young users (< 25) get stricter validation, older users get leniency",
            impact={
                "young_users": "Worse: discriminated against",
                "older_users": "Better: more lenient",
            },
            context={"severity": "high"},
        )
        
        committee = EthicalCommittee()
        result = committee.review_policy(case)
        
        assert result["decision"] == "REJECTED"
    
    def test_rigid_policy_rejected(self):
        """Overly rigid policy should be rejected"""
        case = EthicalCase(
            case_id="CASE_003",
            description="Zero tolerance for all PII",
            current_policy="Block CPF in general context, allow in healthcare",
            proposed_change="Zero tolerance: block ALL CPF mentions regardless of context",
            impact={
                "doctors": "Worse: cannot do their job",
                "patients": "Worse: care delayed",
                "malicious_actors": "Better: completely blocked",
            },
            context={"severity": "critical"},
        )
        
        committee = EthicalCommittee()
        result = committee.review_policy(case)
        
        assert result["decision"] == "REJECTED"