"""
CompliancePlugin Architecture v1.0
Each framework generates its own artifacts from evidence + verdict.
"""

from typing import Protocol, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class ComplianceLevel(str, Enum):
    COMPLIANT = "COMPLIANT"
    PARTIAL = "PARTIAL"
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass
class ComplianceArtifact:
    framework: str
    article: str
    requirement: str
    status: ComplianceLevel
    evidence: str
    recommendation: str
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class ComplianceReport:
    framework: str
    version: str
    total_requirements: int
    compliant: int
    partial: int
    non_compliant: int
    artifacts: List[ComplianceArtifact]
    compliance_rate: float
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class CompliancePlugin(Protocol):
    def framework_id(self) -> str: ...
    def framework_name(self) -> str: ...
    def generate_artifacts(self, evidence: dict, verdict: dict) -> List[ComplianceArtifact]: ...
    def validate_requirements(self) -> ComplianceReport: ...