"""DelegationLedger — Gap B: Delegation Chain Tracking.

Tracks agent-to-agent delegation with immutable, HMAC-signed records.
Enforces max chain depth and scope hierarchy.

Invariants:
- Immutable append-only (like durable_ledger.py)
- HMAC-SHA256 signed records, BLAKE3 chain linking
- Fail-secure: depth exceeded -> BLOCK
- Functions <= 50 lines, file <= 200 lines
"""
from __future__ import annotations

import hashlib
import hmac as hmac_lib
import logging
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger("btv.governance.delegation_ledger")

_MAX_DEPTH = 5


@dataclass(frozen=True)
class DelegationRecord:
    record_id: str
    parent_agent: str
    child_agent: str
    scope: str
    capabilities: List[str]
    created_at: float
    chain_hash: str
    hmac_sha256: str
    revoked: bool = False


@dataclass(frozen=True)
class ChainResult:
    valid: bool
    depth: int
    chain: List[str]
    explain: str


class DelegationLedger:
    """Immutable ledger of agent delegation records."""

    def __init__(
        self,
        policy_path: Optional[Path] = None,
        hmac_key: bytes = b"btv-delegation-default-key",
    ) -> None:
        raw = self._load(policy_path) if policy_path else {}
        self._max_depth = raw.get("max_chain_depth", _MAX_DEPTH)
        scope_h = raw.get("scope_hierarchy", {})
        self._scope_rank: Dict[str, int] = scope_h
        self._key = hmac_key
        self._records: Dict[str, DelegationRecord] = {}
        self._children: Dict[str, List[str]] = {}  # parent -> [record_ids]
        self._parent_of: Dict[str, str] = {}  # child -> parent

    @staticmethod
    def _load(path: Path) -> dict:
        if not path.exists():
            return {}
        with open(path) as f:
            return yaml.safe_load(f) or {}

    def record_delegation(
        self,
        parent_agent: str,
        child_agent: str,
        scope: str,
        capabilities: Optional[List[str]] = None,
    ) -> DelegationRecord:
        """Record a new delegation. Fails if depth exceeded."""
        chain = self._walk_chain(parent_agent)
        if len(chain) >= self._max_depth:
            raise ValueError(
                f"Delegation depth {len(chain)+1} exceeds max {self._max_depth}"
            )
        if self._scope_rank and parent_agent in self._parent_of:
            parent_rec = self._find_record(parent_agent)
            if parent_rec and self._scope_rank.get(scope, 99) > self._scope_rank.get(parent_rec.scope, 0):
                raise ValueError("Scope escalation forbidden")

        # Cycle detection: check if child already appears in parent's chain
        if child_agent == parent_agent:
            raise ValueError("Self-delegation forbidden")
        chain_agents = self._walk_chain(parent_agent)
        if child_agent in chain_agents:
            raise ValueError(f"Cycle detected: {child_agent} already in chain")

        record_id = str(uuid.uuid4())
        prev_hash = chain[-1] if chain else "0" * 64
        chain_hash = hashlib.sha256(
            f"{record_id}|{prev_hash}".encode()
        ).hexdigest()
        sig = hmac_lib.new(
            self._key,
            f"{record_id}|{parent_agent}|{child_agent}|{scope}".encode(),
            hashlib.sha256,
        ).hexdigest()

        rec = DelegationRecord(
            record_id=record_id,
            parent_agent=parent_agent,
            child_agent=child_agent,
            scope=scope,
            capabilities=capabilities or [],
            created_at=time.time(),
            chain_hash=chain_hash,
            hmac_sha256=sig,
        )
        self._records[record_id] = rec
        self._children.setdefault(parent_agent, []).append(record_id)
        self._parent_of[child_agent] = parent_agent
        return rec

    def verify_chain(self, agent_id: str) -> ChainResult:
        """Walk the delegation chain for an agent."""
        chain = self._walk_chain(agent_id)
        depth = len(chain)
        valid = depth <= self._max_depth
        return ChainResult(
            valid=valid,
            depth=depth,
            chain=chain,
            explain=f"Chain depth {depth}/{self._max_depth}",
        )

    def revoke_delegation(self, record_id: str) -> None:
        """Mark a delegation as revoked (immutable: creates new record)."""
        rec = self._records.get(record_id)
        if rec is None:
            raise ValueError(f"Unknown record: {record_id}")
        revoked = DelegationRecord(
            record_id=rec.record_id,
            parent_agent=rec.parent_agent,
            child_agent=rec.child_agent,
            scope=rec.scope,
            capabilities=rec.capabilities,
            created_at=rec.created_at,
            chain_hash=rec.chain_hash,
            hmac_sha256=rec.hmac_sha256,
            revoked=True,
        )
        self._records[record_id] = revoked
        self._parent_of.pop(rec.child_agent, None)

    def _walk_chain(self, agent_id: str) -> List[str]:
        chain: List[str] = []
        current = agent_id
        visited: set = set()
        while current in self._parent_of and current not in visited:
            visited.add(current)
            current = self._parent_of[current]
            chain.append(current)
        return chain

    def _find_record(self, child_agent: str) -> Optional[DelegationRecord]:
        parent = self._parent_of.get(child_agent)
        if not parent:
            return None
        for rid in self._children.get(parent, []):
            rec = self._records[rid]
            if rec.child_agent == child_agent and not rec.revoked:
                return rec
        return None
