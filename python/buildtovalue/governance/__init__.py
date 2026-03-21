"""
BuildToValue Governance Layer v1.0.0
Judiciary of the Algorithmic Republic.
Canonical imports — use these instead of reaching into submodules.
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
from .context_engine import EthicalContextEngine
from .contestability_loop import ContestabilityLoop
from .sensitivity_accumulator import SessionSensitivityAccumulator, SensitivityState
from .bias_guardian import DivergenceLevel
# Re-export V3 alias for backward compatibility with tests
from .ethical_context_engine import EthicalContextEngineV3

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
