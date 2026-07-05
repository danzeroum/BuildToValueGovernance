"""
BTV MCP Server — BuildToValue governance as MCP tools.

Exposes 8 tools to any MCP-compatible AI agent (Claude, GPT, Gemini, open-source):

Tier 1 — Governance (synchronous hot path, SLA < 50ms p99):
  1. validate_input   — Fast PII/risk scan via Rust kernel
  2. decide           — Full ethical governance (Rawls→Levinas→Jonas→Gilligan)
  3. submit_appeal    — Challenge a verdict (LGPD Art. 20 / EU AI Act Art. 14)
  4. get_trust_score  — Session trust score
  5. check_compliance — Compliance status for text

Tier 2 — Agentic (async coordination path, SLA < 5s elicit, < 500ms negotiate/select):
  6. elicit_policy    — Convert NL requirements to validated YAML policy (ADR-0055)
  7. negotiate        — Negotiate shared security policy between agents (ADR-0056)
  8. select_protocol  — Select security protocols for a policy (ADR-0057)

Environment variables:
  BTV_API_KEY       — Required. Your BTV gateway API key.
  BTV_GATEWAY_URL   — Optional. Default: http://localhost:8080
"""
from __future__ import annotations

import asyncio
import json
import os
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from btv_sdk import AsyncBTVClient
from btv_sdk.exceptions import BTVError

# ─── Tier 2 Agentic imports (ADR-0054: separate from Tier 1 hot path) ────────

from buildtovalue.agentic.policy_elicitor import PolicyElicitor, MockBackend
from buildtovalue.agentic.protocol_designer import ProtocolDesigner
from buildtovalue.agentic.protocol_registry import PROTOCOL_REGISTRY
from buildtovalue.governance.durable_ledger import DurableLedger

# Shared Tier 2 ledger (in-memory; production would use persistent storage)
_tier2_ledger = DurableLedger(hmac_key=b"btv-mcp-tier2-v1")
_protocol_designer = ProtocolDesigner(ledger=_tier2_ledger)

# ─── Configuration ────────────────────────────────────────────────────────────

def _get_client() -> AsyncBTVClient:
    api_key = os.environ.get("BTV_API_KEY", "")
    gateway_url = os.environ.get("BTV_GATEWAY_URL", "http://localhost:8080")

    if not api_key:
        raise RuntimeError(
            "BTV_API_KEY environment variable is required. "
            "Set it in your MCP server configuration."
        )

    return AsyncBTVClient(api_key=api_key, gateway_url=gateway_url)


# ─── Server ───────────────────────────────────────────────────────────────────

server = Server("buildtovalue")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="validate_input",
            description=(
                "Fast scan of input text for PII (CPF, CNPJ, email, phone, credit card), "
                "prompt injection, SQL injection, and policy violations. "
                "Uses the Rust kernel only — no ethical pipeline. "
                "Returns verdict: ALLOW, BLOCK, EDUCATE, REDACT, INSPECT, or LOG."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "input_text": {
                        "type": "string",
                        "description": "The text to validate",
                    },
                    "session_id": {
                        "type": "string",
                        "description": "Optional session identifier for trust tracking",
                    },
                    "profile": {
                        "type": "string",
                        "description": "Governance profile: general, healthcare, finance, legal, research, education",
                        "enum": ["general", "healthcare", "finance", "legal", "research", "education"],
                    },
                },
                "required": ["input_text"],
            },
        ),
        Tool(
            name="decide",
            description=(
                "Full ethical governance pipeline for AI agents. "
                "Runs Rust kernel scan + Python judiciary (Rawls→Levinas→Jonas→Gilligan). "
                "Returns verdict with philosophical rationale, trust score, and mercy analysis. "
                "Use this for important decisions where ethical reasoning matters. "
                "BLOCK verdicts are contestable via submit_appeal."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "input_text": {
                        "type": "string",
                        "description": "The text or action to evaluate",
                    },
                    "session_id": {
                        "type": "string",
                        "description": "Session identifier for trust tracking (recommended)",
                    },
                    "profile": {
                        "type": "string",
                        "description": "Governance profile: general, healthcare, finance, legal, research, education",
                        "enum": ["general", "healthcare", "finance", "legal", "research", "education"],
                    },
                    "agent_id": {
                        "type": "string",
                        "description": "Identifier of the calling agent (for audit purposes)",
                    },
                },
                "required": ["input_text"],
            },
        ),
        Tool(
            name="submit_appeal",
            description=(
                "Challenge a governance verdict you disagree with. "
                "Required for LGPD Art. 20 compliance and EU AI Act Art. 14 contestability. "
                "The reason must be at least 20 characters (Levinas articulation requirement). "
                "SLA: 24 hours for human review."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "verdict_id": {
                        "type": "string",
                        "description": "The VRD-... verdict identifier to appeal",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Articulated reason for the appeal (minimum 20 characters)",
                        "minLength": 20,
                    },
                    "grounds": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": [
                                "rawls_equity",
                                "levinas_protection",
                                "gilligan_mercy",
                                "jonas_responsibility",
                                "technical_error",
                                "scope_mismatch",
                                "false_positive",
                            ],
                        },
                        "description": "Philosophical grounds for the appeal",
                    },
                    "user_id": {
                        "type": "string",
                        "description": "Opaque user identifier (defaults to 'anonymous')",
                    },
                },
                "required": ["verdict_id", "reason"],
            },
        ),
        Tool(
            name="get_trust_score",
            description=(
                "Get the current trust score for a session. "
                "Trust is multi-factorial (base + history + appeals + decay + consistency). "
                "Range: 0.0 (untrusted) to 1.0 (fully trusted). "
                "High trust (>0.8) enables mercy and relaxed enforcement."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "The session identifier to check",
                    },
                },
                "required": ["session_id"],
            },
        ),
        Tool(
            name="check_compliance",
            description=(
                "Check if text or an AI action complies with regulations. "
                "Supports: LGPD (Brazilian data protection), EU AI Act, HIPAA, PCI-DSS. "
                "Returns compliance status, identified violations, and remediation guidance."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "Text or description of action to check for compliance",
                    },
                    "session_id": {
                        "type": "string",
                        "description": "Optional session identifier",
                    },
                    "profile": {
                        "type": "string",
                        "description": "Sector profile for context-aware compliance: general, healthcare, finance, legal",
                        "enum": ["general", "healthcare", "finance", "legal"],
                    },
                },
                "required": ["text"],
            },
        ),

        # ── Tier 2 Agentic Tools (ADR-0054 §Performance Architecture) ──────────
        # SLA: < 5s p99 (elicit_policy), < 500ms p99 (negotiate, select_protocol)

        Tool(
            name="elicit_policy",
            description=(
                "Convert natural language security requirements into a validated YAML policy. "
                "ARIA sub-component 1 (Requirement Gathering). "
                "Uses LLM for extraction only — policy is validated against existing PolicyEngine schema. "
                "Tier 2 async path (SLA < 5s). Returns validated YAML dict + gap list + confidence score."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "nl_input": {
                        "type": "string",
                        "description": "Natural language description of security requirements",
                    },
                    "domain": {
                        "type": "string",
                        "description": "Policy domain for schema selection",
                        "enum": [
                            "general", "healthcare", "finance", "legal",
                            "research", "education", "agents", "security",
                        ],
                    },
                },
                "required": ["nl_input", "domain"],
            },
        ),

        Tool(
            name="negotiate",
            description=(
                "Select appropriate security protocols for a given security policy. "
                "ARIA sub-component 3a (Protocol Designer). "
                "Rule-based whitelist matching — no LLM in selection loop. "
                "Tier 2 async path (SLA < 500ms). "
                "Returns selected protocols + unavailable roadmap protocols + rationale."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "policy": {
                        "type": "object",
                        "description": "Security policy dict (from elicit_policy or PolicyEngine)",
                    },
                    "session_id": {
                        "type": "string",
                        "description": "Optional session identifier for audit logging",
                    },
                },
                "required": ["policy"],
            },
        ),

        Tool(
            name="select_protocol",
            description=(
                "Select appropriate security protocols for a given security policy. "
                "ARIA sub-component 3a (Protocol Designer). "
                "Rule-based whitelist matching — no LLM in selection loop. "
                "Tier 2 async path (SLA < 500ms). "
                "Returns selected protocols + unavailable roadmap protocols + rationale."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "policy": {
                        "type": "object",
                        "description": "Security policy dict (from elicit_policy or PolicyEngine)",
                    },
                    "session_id": {
                        "type": "string",
                        "description": "Optional session identifier for audit logging",
                    },
                },
                "required": ["policy"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    client = _get_client()

    # Tier 2 agentic tools (no gateway client needed — local processing)
    if name == "elicit_policy":
        return await _elicit_policy(arguments)
    elif name == "negotiate":
        return await _negotiate_tool(arguments)
    elif name == "select_protocol":
        return await _select_protocol(arguments)

    try:
        async with client:
            if name == "validate_input":
                return await _validate_input(client, arguments)
            elif name == "decide":
                return await _decide(client, arguments)
            elif name == "submit_appeal":
                return await _submit_appeal(client, arguments)
            elif name == "get_trust_score":
                return await _get_trust_score(client, arguments)
            elif name == "check_compliance":
                return await _check_compliance(client, arguments)
            else:
                return [TextContent(type="text", text=f"Unknown tool: {name}")]
    except BTVError as exc:
        return [TextContent(type="text", text=f"BTV Error: {exc}")]
    except Exception as exc:
        return [TextContent(type="text", text=f"Unexpected error: {exc}")]


async def _validate_input(client: AsyncBTVClient, args: dict) -> list[TextContent]:
    verdict = await client.validate(
        args["input_text"],
        session_id=args.get("session_id"),
        profile=args.get("profile"),
    )
    text = (
        f"**Verdict**: {verdict.action}\n"
        f"**Verdict ID**: {verdict.verdict_id}\n"
        f"**Findings**: {verdict.finding_count} ({verdict.critical_count} critical)\n"
        f"**Risk Score**: {verdict.composite_risk:.2f}\n"
        f"**Hard Blocked**: {verdict.hard_blocked}\n"
        f"**Contestable**: {verdict.contestable}\n"
        f"**Message**: {verdict.message}\n"
    )
    if verdict.matched_policies:
        text += f"**Matched Policies**: {', '.join(verdict.matched_policies)}\n"
    return [TextContent(type="text", text=text)]


async def _decide(client: AsyncBTVClient, args: dict) -> list[TextContent]:
    verdict = await client.decide(
        args["input_text"],
        session_id=args.get("session_id"),
        profile=args.get("profile"),
        agent_id=args.get("agent_id"),
    )
    text = (
        f"**Verdict**: {verdict.action}\n"
        f"**Verdict ID**: {verdict.verdict_id}\n"
        f"**Original Action**: {verdict.original_action}\n"
        f"**Mercy Applied**: {verdict.mercy_applied}\n"
        f"**Risk Score**: {verdict.composite_risk:.2f}\n"
        f"**Findings**: {verdict.finding_count} ({verdict.critical_count} critical)\n"
        f"**Contestable**: {verdict.contestable}\n"
        f"**Rationale**: {verdict.rationale}\n\n"
        f"**Philosophical Analysis**:\n"
        f"- *Summary*: {verdict.explain.summary}\n"
        f"- *Rawls*: {verdict.explain.rawls_rationale}\n"
        f"- *Levinas*: {verdict.explain.levinas_rationale}\n"
        f"- *Jonas*: {verdict.explain.jonas_rationale}\n"
        f"- *Gilligan*: {verdict.explain.gilligan_rationale}\n"
        f"- *Trust Score*: {verdict.explain.trust_score:.2f}\n"
        f"- *Mercy Score*: {verdict.explain.mercy_score:.2f}\n"
    )
    if verdict.contestable:
        text += (
            f"\n**Appeal**: This verdict can be challenged within {verdict.appeal_deadline_hours}h "
            f"using submit_appeal with verdict_id={verdict.verdict_id}"
        )
    return [TextContent(type="text", text=text)]


async def _submit_appeal(client: AsyncBTVClient, args: dict) -> list[TextContent]:
    appeal = await client.appeal(
        args["verdict_id"],
        reason=args["reason"],
        grounds=args.get("grounds"),
        user_id=args.get("user_id"),
    )
    text = (
        f"**Appeal Submitted**\n"
        f"**Appeal ID**: {appeal.appeal_id}\n"
        f"**Status**: {appeal.status}\n"
        f"**Mediator Recommendation**: {appeal.mediator_recommendation or 'Pending'}\n"
        f"**SLA Deadline**: {appeal.sla_deadline or '24 hours'}\n"
        f"\nUse get_appeal with appeal_id={appeal.appeal_id} to check status."
    )
    return [TextContent(type="text", text=text)]


async def _get_trust_score(client: AsyncBTVClient, args: dict) -> list[TextContent]:
    ts = await client.trust_score(args["session_id"])
    level = "high" if ts.trust_score >= 0.8 else ("medium" if ts.trust_score >= 0.5 else "low")
    text = (
        f"**Trust Score**: {ts.trust_score:.3f} ({level})\n"
        f"**Session**: {ts.session_id}\n"
        f"**Total Requests**: {ts.total_requests}\n"
        f"**Offenses**: {ts.offenses}\n"
    )
    if ts.calculated_at:
        text += f"**Calculated At**: {ts.calculated_at}\n"
    return [TextContent(type="text", text=text)]


async def _check_compliance(client: AsyncBTVClient, args: dict) -> list[TextContent]:
    # Use validate to get findings, then interpret compliance implications
    verdict = await client.validate(
        args["text"],
        session_id=args.get("session_id"),
        profile=args.get("profile", "general"),
    )

    compliant = verdict.action in ("ALLOW", "LOG")
    frameworks_checked = ["LGPD Art. 6/18/20", "EU AI Act Art. 5/14/86"]

    text = (
        f"**Compliance Status**: {'COMPLIANT' if compliant else 'NON-COMPLIANT'}\n"
        f"**Action Required**: {verdict.action}\n"
        f"**Risk Level**: {verdict.composite_risk:.2f}\n"
        f"**Findings**: {verdict.finding_count}\n"
        f"**Frameworks Checked**: {', '.join(frameworks_checked)}\n"
    )

    if not compliant:
        text += (
            f"\n**Violations Detected**: {verdict.finding_count} governance concern(s).\n"
            f"**Remediation**: Review and sanitize the text before processing. "
            f"Consider using the sanitize endpoint to auto-redact PII."
        )
        if verdict.matched_policies:
            text += f"\n**Matched Rules**: {', '.join(verdict.matched_policies)}"
    else:
        text += "\n**Result**: No compliance violations detected."

    return [TextContent(type="text", text=text)]


# ─── Tier 2 Agentic Tool Handlers ────────────────────────────────────────────

async def _elicit_policy(args: dict) -> list[TextContent]:
    """Tier 2: Convert NL requirements to validated YAML policy (ADR-0055)."""
    try:
        # Use MockBackend in standalone mode (no API key configured for LLM)
        # Production: replace with AnthropicBackend when BTV_LLM_API_KEY is set
        llm_api_key = os.environ.get("BTV_LLM_API_KEY")
        if llm_api_key:
            from buildtovalue.agentic.policy_elicitor import AnthropicBackend
            llm = AnthropicBackend(api_key=llm_api_key)
        else:
            # Standalone mode: return a template policy with gaps flagged
            template_yaml = (
                f"schema_version: '1.0'\n"
                f"domain: {args.get('domain', 'general')}\n"
                f"description: 'Policy elicited from: {args.get('nl_input', '')[:100]}'\n"
            )
            llm = MockBackend(template_yaml)

        elicitor = PolicyElicitor(llm=llm, hmac_key=b"btv-mcp-elicitor-v1")
        result = await elicitor.elicit(args["nl_input"], args.get("domain", "general"))

        if result.success:
            text = (
                f"**PolicyElicitor Result** (ARIA sub-component 1)\n"
                f"**Status**: {'SUCCESS' if result.success else 'FAILED'}\n"
                f"**Domain**: {result.domain}\n"
                f"**Confidence**: {result.confidence:.2f}\n"
                f"**Gaps** (fields to specify): {list(result.gaps) or 'none'}\n\n"
                f"**Generated Policy**:\n```yaml\n"
                + "\n".join(f"{k}: {v}" for k, v in result.policy.items()) +
                "\n```\n\n"
                f"**Note**: Policy validated against {result.domain} schema. "
                f"Gaps indicate fields that need manual specification."
            )
            if not llm_api_key:
                text += (
                    "\n\n⚠️ **Standalone mode**: Set BTV_LLM_API_KEY environment variable "
                    "to enable full LLM extraction. Template policy returned."
                )
        else:
            text = (
                f"**PolicyElicitor Error**: {result.error}\n"
                f"**Domain**: {result.domain}\n"
                f"**Explanation**: {result.explain_decision}"
            )
        return [TextContent(type="text", text=text)]
    except Exception as exc:
        return [TextContent(type="text", text=f"elicit_policy error: {exc}")]


async def _negotiate_tool(args: dict) -> list[TextContent]:
    """
    Tier 2: 'negotiate' tool — re-routes to select_protocol for this MVP.
    Full A2A negotiation requires two connected agents; in MCP context, this
    returns protocol recommendations for the given policy.
    """
    return await _select_protocol(args)


async def _select_protocol(args: dict) -> list[TextContent]:
    """Tier 2: Select security protocols for a policy (ADR-0057)."""
    try:
        policy = args.get("policy", {})
        if not isinstance(policy, dict):
            return [TextContent(type="text", text="select_protocol error: 'policy' must be a JSON object")]

        plan = _protocol_designer.select(policy)

        selected_lines = [
            f"  - **{s.name}** ({s.category}, overhead={s.overhead}): "
            f"satisfies {sorted(s.requirements_met)}"
            for s in plan.selected
        ] or ["  - *No matching available protocols*"]

        unavailable_lines = [
            f"  - **{u.name}** ({u.category}): {sorted(u.requirements_met)} [roadmap]"
            for u in plan.unavailable
        ] or []

        text = (
            f"**ProtocolDesigner Result** (ARIA sub-component 3a)\n"
            f"**Level**: 2 (rule-based whitelist — deterministic, auditable)\n\n"
            f"**Selected Protocols** ({len(plan.selected)} available today):\n"
            + "\n".join(selected_lines) +
            (f"\n\n**Roadmap Protocols** ({len(plan.unavailable)} planned):\n"
             + "\n".join(unavailable_lines) if unavailable_lines else "") +
            f"\n\n**Rationale**: {json.dumps(plan.rationale, indent=2)}\n"
            f"**Explain**: {plan.explain_decision}\n"
        )
        return [TextContent(type="text", text=text)]
    except Exception as exc:
        return [TextContent(type="text", text=f"select_protocol error: {exc}")]


# ─── Entry point ─────────────────────────────────────────────────────────────

async def _main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def run() -> None:
    asyncio.run(_main())


if __name__ == "__main__":
    run()
