"""
BuildToValue Governance Layer v2.3.1
Judiciary of the Algorithmic Republic.
Canonical imports — use these instead of reaching into submodules.

v2.3.1: Consolidated EthicalContextEngine (removed context_engine.py v1.9.1 duplicate).
  - EthicalContextEngine = v1.1.0 unified (TechnicalLayer + GovernanceLayer)
  - EthicalContextEngineV3 kept for backward compat with tests (delegates to v1.1.0)
  - AlignmentDegradationTracker imported from agentic/ (strictly superior: DurableLedger,
    HMAC, fail-secure semantics)
"""
from .types import (
    ActionType,
    ACTION_SEVERITY,
    RequestMetadata,
    EthicalContext,
    SimpleFinding,
    SimpleTechnicalEvidence,
)
from .mercy_factor import MercyFactor
from .mercy_algorithm import MercyCalculator
from .trust_score import TrustScoreCalculator
# v2.3.1: Consolidated engine — v1.1.0 unified is the single source of truth.
# context_engine.py (v1.9.1) was removed as part of Phase 1 restructuring.
from .ethical_context_engine import EthicalContextEngine, EthicalContextEngineV3
from .contestability_loop import ContestabilityLoop
from .sensitivity_accumulator import SessionSensitivityAccumulator, SensitivityState
from .bias_guardian import DivergenceLevel
# v2.3.1: AlignmentDegradationTracker imported from agentic/ (ADR-053).
# The governance/ version was removed: the agentic version has DurableLedger integration,
# HMAC-SHA256 signed reports, and fail-secure semantics (score=1.0 on error).
from buildtovalue.agentic.alignment_degradation_tracker import (
    AlignmentDegradationTracker,
    DegradationReport,
)

__all__ = [
    # Types
    "ActionType",
    "ACTION_SEVERITY",
    "RequestMetadata",
    "EthicalContext",
    "SimpleFinding",
    "SimpleTechnicalEvidence",
    "MercyFactor",
    # Engines
    "EthicalContextEngine",
    "EthicalContextEngineV3",
    # Components
    "MercyCalculator",
    "TrustScoreCalculator",
    "ContestabilityLoop",
    "AlignmentDegradationTracker",
    "DegradationReport",
    # ADR-046: Hybrid Alignment
    "SessionSensitivityAccumulator",
    "SensitivityState",
    "DivergenceLevel",
]
from .policy_tester import PolicyTester, BlindTestCase, TestResult, BlindTestReport
from .blind_evaluator import BlindEvaluator, BlindVerdict
from .synthetic_dataset import SyntheticDatasetGenerator
from .model_integrity import ModelStatus, get_model_info, normalize_id, is_known_abliterated
from .model_integrity_verifier import AbliterationDetector, IntegrityVerifier, verify_model_integrity
from .agent_pdp import ActionImpact, AgentVerdict, AgentAction, AgentContext, AgentDecisionRequest, VerdictEnvelope, BiasSummary
from .chatbot_gates import DataClassification, GateResult, message_gate, indexing_gate, rag_gate, training_gate, lora_deploy_gate

# Agent Governance Gaps (A–I)
from .tool_call_guard import ToolCallGuard                         # Gap A
from .output_leakage_detector import OutputLeakageDetector         # Gap G
from .capability_registry import CapabilityRegistry                # Gap C
from .capability_enforcer import CapabilityEnforcer                # Gap C
from .approval_workflow import ApprovalWorkflow, ApprovalStatus    # Gap F
from .conversation_threat_graph import ConversationThreatGraph     # Gap E
from .delegation_ledger import DelegationLedger                    # Gap B
from .agent_budget import AgentBudget, AccountTier, ResourceHierarchy  # Gap I + C30
from .cross_agent_correlator import CrossAgentCorrelator           # Gap D
from .rag_integrity_verifier import (                              # Gap H + C31
    RagIntegrityVerifier,
    MemoryProvenanceRecord,
)

# ── Cenários 26-35: BTV Personal Agent Trust OS ──────────────────────────────

# Sprint 1 — P0: Dano físico/credencial irreversível
from .liveness_monitor import LivenessMonitor, AutonomyLevel       # C29
from .rag_contradiction_detector import (                          # C31
    RagContradictionDetector,
    ContradictionFinding,
)

# Sprint 2 — P1: Dano financeiro com janela de recuperação
from .visual_input_firewall import (                               # C32
    VisualInputFirewall,
    FirewallResult,
    FirewallVerdict,
)
from .skill_behavior_monitor import (                              # C33
    SkillBehaviorMonitor,
    SkillAnomalyFinding,
)

# Sprint 3 — P2: Defesa de longo prazo e ecossistema P2P
from .alignment_manifest import (                                  # C28
    AlignmentManifest,
    AlignmentManifestVerifier,
)
from .oracle_trust_gate import (                                   # C34
    OracleTrustGate,
    OracleRegistry,
    OracleEntry,
    OracleVerdict,
)
