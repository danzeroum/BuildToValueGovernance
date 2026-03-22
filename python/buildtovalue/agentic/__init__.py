"""
BuildToValue Agentic Layer v0.1.0 — ARIA Scaling Trust Track 2.2

Four ARIA sub-components:
  - PolicyElicitor:     NL → validated YAML policy (sub-component 1)
  - NegotiationEngine:  A2A propose/counter/accept/abort (sub-component 2)
  - NegotiationGuard:   A2A safety wrapper (sub-component 2, safety)
  - ProtocolDesigner:   Rule-based protocol selection (sub-component 3a)
  - ArenaReporter:      Structured (Utility; Security) audit reports (sub-component 4)

Architecture: additive package — imports from buildtovalue.governance.* only,
never modifies existing modules.

ADR-054: Agentic Layer Architecture
"""

__version__ = "0.1.0"
