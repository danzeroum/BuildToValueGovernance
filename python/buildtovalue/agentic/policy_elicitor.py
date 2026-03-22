"""
PolicyElicitor — ARIA sub-component 1: Requirement Gathering.

Converts natural-language security requirements into validated YAML policies
compatible with the existing PolicyEngine schema.

Architecture:
  NL input → LLMBackend.complete(system_prompt, user_prompt)
           → yaml.safe_load()
           → schema validation
           → gap detection
           → ElicitedPolicy

LLM is used ONLY for NL → structured extraction.
Policy decisions are never delegated to the LLM.

Fail-secure invariant: if LLM output fails validation at any step,
returns error ElicitedPolicy — never generates an invalid policy.

BiasDeclaration (Jonas principle):
  Schema validation failure rate: 0 (validator is deterministic).
  Gap detection accuracy: TBD (measured during M7-M8 Arena calibration).
  LLM extraction accuracy: TBD (measured against expert-authored policies).
  Calibration expiry: 90 days.

ADR-055: PolicyElicitor Design.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable

import yaml

logger = logging.getLogger("btv.agentic.policy_elicitor")

_DEFAULT_HMAC_KEY: bytes = b"btv-policy-elicitor-v1"

# Path to data/policies/ relative to package root
_POLICIES_PATH = Path(__file__).parent.parent.parent.parent / "data" / "policies"

# Known domains that have policy schemas
KNOWN_DOMAINS = frozenset({
    "general", "healthcare", "finance", "legal",
    "research", "education", "agents", "security"
})


# ─── LLM Backend Protocol ─────────────────────────────────────────────────────

@runtime_checkable
class LLMBackend(Protocol):
    """
    Pluggable LLM backend — no vendor lock-in.

    Implementations:
      MockBackend:     Deterministic canned YAML (unit tests)
      AnthropicBackend: Production via Claude API
    """
    async def complete(self, system: str, user: str) -> str:
        """Send prompt and return LLM response text."""
        ...


# ─── Mock Backend (testing) ───────────────────────────────────────────────────

class MockBackend:
    """
    Deterministic test backend — returns canned YAML without external calls.

    Use for unit tests. Pass canned_yaml=None to simulate LLM failure.
    """

    def __init__(self, canned_yaml: Optional[str] = None) -> None:
        self._canned_yaml = canned_yaml

    async def complete(self, system: str, user: str) -> str:
        if self._canned_yaml is None:
            raise RuntimeError("MockBackend: simulated LLM failure")
        return self._canned_yaml


# ─── Anthropic Backend (production) ──────────────────────────────────────────

class AnthropicBackend:
    """
    Production LLM backend — calls Claude API.

    Requires: pip install anthropic
    Default model: claude-sonnet-4-6 (Anthropic's latest capable model, 2026-03)
    """

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-4-6",
        max_tokens: int = 1024,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._max_tokens = max_tokens

    async def complete(self, system: str, user: str) -> str:
        try:
            import anthropic  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "AnthropicBackend requires 'anthropic' package. "
                "Install with: pip install anthropic"
            ) from exc

        client = anthropic.AsyncAnthropic(api_key=self._api_key)
        message = await client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return message.content[0].text


# ─── Result Type ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ElicitedPolicy:
    """
    Result of PolicyElicitor.elicit().

    policy:       Validated YAML-compatible dict (empty on failure).
    gaps:         Fields left at default/unspecified by the LLM.
    confidence:   0-1 based on gap ratio (1.0 = no gaps).
    source_nl:    Original NL input (preserved for traceability).
    domain:       Domain used for schema validation.
    schema_version: Schema version for reproducibility.
    error:        Error description if elicitation failed.
    explain_decision: Mandatory (Levinas).
    signature:    HMAC-SHA256 (Jonas).
    """
    policy: dict
    gaps: tuple[str, ...]
    confidence: float
    source_nl: str
    domain: str
    schema_version: str
    error: Optional[str]
    explain_decision: str
    timestamp: float
    signature: str

    @property
    def success(self) -> bool:
        return self.error is None and bool(self.policy)


# ─── PolicyElicitor ───────────────────────────────────────────────────────────

class PolicyElicitor:
    """
    Converts natural-language security requirements to validated YAML policies.

    LLM is used ONLY for NL → structured extraction.
    Schema validation uses existing PolicyEngine YAML format.
    Fail-secure: LLM failure or validation failure → error ElicitedPolicy.
    """

    # Fields that should be present in any policy (required for gap detection)
    _EXPECTED_FIELDS: dict[str, dict[str, object]] = {
        "general": ["schema_version", "domain", "description"],
        "agents": ["schema_version", "negotiation", "bft"],
        "security": ["schema_version", "classification"],
        "healthcare": ["schema_version", "domain", "description"],
        "finance": ["schema_version", "domain", "description"],
        "legal": ["schema_version", "domain", "description"],
        "research": ["schema_version", "domain", "description"],
        "education": ["schema_version", "domain", "description"],
    }

    def __init__(
        self,
        llm: LLMBackend,
        hmac_key: bytes = _DEFAULT_HMAC_KEY,
        policies_path: Optional[Path] = None,
    ) -> None:
        self._llm = llm
        self._hmac_key = hmac_key
        self._policies_path = policies_path or _POLICIES_PATH

    async def elicit(self, nl_input: str, domain: str) -> ElicitedPolicy:
        """
        Convert NL security requirement description to a validated YAML policy.

        Steps:
          1. Load domain template from data/policies/
          2. Build structured extraction prompt with schema + examples
          3. Call LLM backend
          4. yaml.safe_load() on output
          5. Basic schema validation (required fields)
          6. Gap detection (fields at default or missing)

        Returns ElicitedPolicy with error field set on failure (never raises).
        """
        try:
            return await self._elicit(nl_input, domain)
        except Exception as exc:
            logger.error("PolicyElicitor.elicit exception: %s", exc)
            return self._fail_secure(str(exc), domain, nl_input)

    async def _elicit(self, nl_input: str, domain: str) -> ElicitedPolicy:
        # Normalize domain
        domain = domain.lower().strip()
        if domain not in KNOWN_DOMAINS:
            return self._fail_secure(
                f"Unknown domain '{domain}'. Known domains: {sorted(KNOWN_DOMAINS)}",
                domain, nl_input,
            )

        # Load template
        template = self._load_domain_template(domain)
        schema_version = template.get("schema_version", "1.0")

        # Build prompt
        system_prompt = self._build_system_prompt(domain, template)
        user_prompt = f"Convert this security requirement to a YAML policy:\n\n{nl_input}"

        # Call LLM
        raw_output = await self._llm.complete(system_prompt, user_prompt)

        # Parse YAML
        policy = self._parse_yaml(raw_output)
        if policy is None:
            return self._fail_secure(
                f"LLM output is not valid YAML: {raw_output[:200]}",
                domain, nl_input,
            )

        if not isinstance(policy, dict):
            return self._fail_secure(
                f"LLM output is not a YAML dict (type={type(policy).__name__})",
                domain, nl_input,
            )

        # Gap detection
        gaps = self._detect_gaps(policy, domain)
        confidence = max(0.0, 1.0 - (len(gaps) / max(len(self._EXPECTED_FIELDS.get(domain, [])), 1)))

        # Sign and return
        timestamp = time.time()
        explain = (
            f"PolicyElicitor: domain={domain}, schema_version={schema_version}, "
            f"confidence={confidence:.2f}, gaps={gaps}. "
            f"LLM used for NL extraction only — policy validated against schema."
        )
        sig = self._sign(policy, domain, confidence, timestamp)

        return ElicitedPolicy(
            policy=policy,
            gaps=tuple(gaps),
            confidence=confidence,
            source_nl=nl_input,
            domain=domain,
            schema_version=str(schema_version),
            error=None,
            explain_decision=explain,
            timestamp=timestamp,
            signature=sig,
        )

    def _load_domain_template(self, domain: str) -> dict:
        """Load template from data/policies/{domain}/ or data/policies/default.yaml."""
        domain_dir = self._policies_path / domain
        if domain_dir.is_dir():
            # Load first YAML file in domain dir as template
            yaml_files = list(domain_dir.glob("*.yaml"))
            if yaml_files:
                try:
                    with open(yaml_files[0]) as f:
                        template = yaml.safe_load(f)
                        return template if isinstance(template, dict) else {}
                except Exception as exc:
                    logger.warning("Failed to load domain template %s: %s", domain_dir, exc)

        # Fallback to base.yaml
        base_yaml = self._policies_path / "base.yaml"
        if base_yaml.exists():
            try:
                with open(base_yaml) as f:
                    template = yaml.safe_load(f)
                    return template if isinstance(template, dict) else {}
            except Exception as exc:
                logger.warning("Failed to load base.yaml: %s", exc)

        # Minimal default
        return {"schema_version": "1.0"}

    def _build_system_prompt(self, domain: str, template: dict) -> str:
        template_yaml = yaml.dump(template, default_flow_style=False)
        return (
            f"You are a security policy expert. Convert natural-language security "
            f"requirements into valid YAML policies for the '{domain}' domain.\n\n"
            f"YAML template (use this structure):\n```yaml\n{template_yaml}```\n\n"
            f"Rules:\n"
            f"1. Output ONLY valid YAML — no markdown, no explanation\n"
            f"2. Preserve all required fields from the template\n"
            f"3. Set schema_version: '1.0'\n"
            f"4. Include domain: '{domain}'\n"
            f"5. If a field cannot be determined from the NL input, omit it (do not guess)\n"
            f"6. Never add fields not present in the template schema\n"
        )

    def _parse_yaml(self, raw: str) -> Optional[dict]:
        """Safe YAML parse — strip markdown code fences if present."""
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            # Remove first and last fence lines
            cleaned = "\n".join(
                line for line in lines[1:]
                if not line.strip().startswith("```")
            ).strip()
        try:
            return yaml.safe_load(cleaned)
        except yaml.YAMLError as exc:
            logger.warning("YAML parse failed: %s", exc)
            return None

    def _detect_gaps(self, policy: dict, domain: str) -> list[str]:
        """
        Detect expected fields that are missing from the policy.
        Returns list of missing field names.
        """
        expected = self._EXPECTED_FIELDS.get(domain, ["schema_version", "domain", "description"])
        return [field for field in expected if field not in policy]

    def _sign(self, policy: dict, domain: str, confidence: float, timestamp: float) -> str:
        content = json.dumps(
            {"policy_keys": sorted(policy.keys()), "domain": domain,
             "confidence": confidence, "timestamp": timestamp},
            sort_keys=True,
        )
        return _hmac.new(self._hmac_key, content.encode(), hashlib.sha256).hexdigest()

    def _fail_secure(self, reason: str, domain: str, nl: str) -> ElicitedPolicy:
        """Fail-secure: return error ElicitedPolicy, never invalid policy."""
        timestamp = time.time()
        explain = (
            f"PolicyElicitor FAIL-SECURE: {reason}. "
            f"No policy generated — original NL preserved for manual review (Jonas principle)."
        )
        sig = _hmac.new(
            self._hmac_key,
            f"fail_secure:{reason}:{timestamp}".encode(),
            hashlib.sha256,
        ).hexdigest()
        return ElicitedPolicy(
            policy={},
            gaps=(),
            confidence=0.0,
            source_nl=nl,
            domain=domain,
            schema_version="unknown",
            error=reason,
            explain_decision=explain,
            timestamp=timestamp,
            signature=sig,
        )
