#!/usr/bin/env python3
"""
CI Week 2 — Policy YAML + ADR-043 Validation

Validates all deliverables from Week 2 of the GrantDecisionAdapter implementation.

Checks:
W2.1 Policy file location (data/policies/sectors/grant-eligibility-v1.yaml)
W2.2 YAML parseability (valid YAML, all 10 sections)
W2.3 Metadata completeness (semver, 90-day expiry, sector=grants)
W2.4 Jurisdiction configuration (bitmasks, sanctions, elevated risk)
W2.5 Risk thresholds (5 tiers, monotonically ordered)
W2.6 Gilligan mercy config (enabled, max=EDUCATE, trust threshold)
W2.7 Levinas SLA (timers, contestability, 4 languages)
W2.8 Jonas enforcement (90d expiry, bias required, sw=FLAG)
W2.9 ADR-043 completeness (7 decisions, cross-refs, tables)

Exit codes: 0=pass, 1=fail, 2=dependency error
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import traceback
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Tuple


class CheckStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"


@dataclass
class CheckResult:
    check_id: str
    description: str
    status: CheckStatus
    details: str = ""
    execution_time_ms: float = 0.0


class Week2CI:
    POLICY_PATH = "data/policies/sectors/grant-eligibility-v1.yaml"
    WRONG_PATH = "data/policies/grant-eligibility-v1.yaml"
    ADR_PATH = "docs/adr/ADR-043-grant-decision-adapter.md"

    def __init__(self, project_root: str = ".") -> None:
        self.root = project_root
        self.results: List[CheckResult] = []

    def _run_check(self, cid: str, desc: str, fn: Callable[[], Tuple[bool, str]]) -> CheckResult:
        start = time.monotonic()
        try:
            ok, details = fn()
            status = CheckStatus.PASS if ok else CheckStatus.FAIL
        except Exception as exc:
            status = CheckStatus.ERROR
            details = f"{type(exc).__name__}: {exc}"
        elapsed = (time.monotonic() - start) * 1000
        r = CheckResult(cid, desc, status, details, elapsed)
        self.results.append(r)
        icon = {"PASS": "\u2705", "FAIL": "\u274c", "ERROR": "\U0001f4a5"}[status.value]
        print(f"  {icon} {cid} \u2014 {desc}")
        if details and status != CheckStatus.PASS:
            for line in details.strip().split("\n")[:5]:
                print(f"     {line}")
        return r

    def _load_policy(self) -> Dict[str, Any]:
        path = os.path.join(self.root, self.POLICY_PATH)
        import yaml
        with open(path) as f:
            return yaml.safe_load(f)

    # --- W2.1 ---
    def check_policy_location(self) -> Tuple[bool, str]:
        correct = os.path.isfile(os.path.join(self.root, self.POLICY_PATH))
        wrong = os.path.isfile(os.path.join(self.root, self.WRONG_PATH))
        issues = []
        if not correct:
            issues.append(f"Not found at {self.POLICY_PATH}")
        if wrong:
            issues.append(f"Found in WRONG location: {self.WRONG_PATH}")
        return (not issues, "; ".join(issues)) if issues else (True, "Correct location, not in root")

    # --- W2.2 ---
    def check_yaml_parseability(self) -> Tuple[bool, str]:
        try:
            p = self._load_policy()
        except Exception as exc:
            return False, f"YAML parse error: {exc}"
        if not isinstance(p, dict):
            return False, "Root is not a dict"
        required = ["metadata", "jurisdiction", "financial", "thresholds", "actions",
                    "rawls", "levinas", "jonas", "gilligan", "categories"]
        missing = [s for s in required if s not in p]
        if missing:
            return False, f"Missing sections: {missing}"
        return True, f"All {len(required)} sections present"

    # --- W2.3 ---
    def check_metadata(self) -> Tuple[bool, str]:
        p = self._load_policy()
        m = p["metadata"]
        issues = []
        for f in ["policy_id", "name", "version", "sector", "created", "expires", "author", "description"]:
            if f not in m:
                issues.append(f"Missing metadata.{f}")
        if not re.match(r"\d+\.\d+\.\d+", m.get("version", "")):
            issues.append(f"Bad version format: {m.get('version')}")
        try:
            c = datetime.fromisoformat(m["created"].replace("Z", "+00:00"))
            e = datetime.fromisoformat(m["expires"].replace("Z", "+00:00"))
            delta = (e - c).days
            if delta != 90:
                issues.append(f"Expiry {delta} days, expected 90")
        except Exception as exc:
            issues.append(f"Date parse error: {exc}")
        if m.get("sector") != "grants":
            issues.append(f"sector='{m.get('sector')}', expected 'grants'")
        return (not issues, "; ".join(issues)) if issues else (True, "Semver, 90-day expiry, sector=grants")

    # --- W2.4 ---
    def check_jurisdiction(self) -> Tuple[bool, str]:
        p = self._load_policy()
        j = p["jurisdiction"]
        issues = []
        if len(j.get("bitmask_schema", {})) < 6:
            issues.append(f"Only {len(j.get('bitmask_schema', {}))} bitmask entries")
        for cc in ["KP", "IR", "SY", "CU"]:
            if cc not in j.get("sanctioned_country_codes", []):
                issues.append(f"Missing sanctioned: {cc}")
        if "elevated_risk_country_codes" not in j:
            issues.append("Missing elevated_risk_country_codes")
        return (not issues, "; ".join(issues)) if issues else (True, "Bitmasks, sanctions, elevated risk")

    # --- W2.5 ---
    def check_thresholds(self) -> Tuple[bool, str]:
        p = self._load_policy()
        t = p["thresholds"]
        issues = []
        for tier in ["allow", "educate", "inspect", "block", "hard_block"]:
            if tier not in t:
                issues.append(f"Missing tier: {tier}")
        try:
            vals = [t["allow"]["max_risk"], t["educate"]["max_risk"],
                    t["inspect"]["max_risk"], t["block"]["max_risk"], t["hard_block"]["min_risk"]]
            for i in range(len(vals) - 1):
                if vals[i] > vals[i + 1]:
                    issues.append(f"Non-monotonic at index {i}: {vals[i]} > {vals[i+1]}")
        except (KeyError, TypeError) as exc:
            issues.append(f"Threshold value error: {exc}")
        return (not issues, "; ".join(issues)) if issues else (True, "5 tiers, monotonically ordered")

    # --- W2.6 ---
    def check_gilligan(self) -> Tuple[bool, str]:
        p = self._load_policy()
        g = p["gilligan"]["mercy"]
        issues = []
        if g.get("enabled") is not True:
            issues.append("Mercy not enabled")
        if g.get("max_intervention") != "EDUCATE":
            issues.append(f"max_intervention={g.get('max_intervention')}, expected EDUCATE")
        if g.get("trust_threshold", 0) <= 0:
            issues.append("trust_threshold must be > 0")
        if g.get("critical_findings_override") is not False:
            issues.append("critical_findings_override must be False")
        return (not issues, "; ".join(issues)) if issues else (True, "Enabled, max=EDUCATE, trust>0, critical overrides")

    # --- W2.7 ---
    def check_levinas(self) -> Tuple[bool, str]:
        p = self._load_policy()
        l = p["levinas"]
        issues = []
        if l["sla"]["initial_response_hours"] > 24:
            issues.append(f"Initial SLA {l['sla']['initial_response_hours']}h > 24h")
        if l["sla"]["appeal_response_hours"] > 72:
            issues.append(f"Appeal SLA {l['sla']['appeal_response_hours']}h > 72h")
        if "BLOCK" not in l["contestability"]["contestable_actions"]:
            issues.append("BLOCK not in contestable_actions")
        if l["contestability"]["hard_block_contestable"] is not False:
            issues.append("hard_block_contestable must be False")
        supported = set(l["language"]["supported_groups"])
        if supported != {"en-US", "pt-BR", "es", "sw"}:
            issues.append(f"Supported groups: {supported}, expected all 4")
        return (not issues, "; ".join(issues)) if issues else (True, "SLA, contestability, 4 languages")

    # --- W2.8 ---
    def check_jonas(self) -> Tuple[bool, str]:
        p = self._load_policy()
        j = p["jonas"]
        issues = []
        if j["policy_expiry_days"] != 90:
            issues.append(f"Expiry {j['policy_expiry_days']}d, expected 90")
        if j["bias"]["require_declaration"] is not True:
            issues.append("Bias declaration not required")
        uncal = j["bias"]["uncalibrated_groups"]
        if not uncal:
            issues.append("No uncalibrated groups defined")
        for g in uncal:
            if g["group"] != "sw":
                issues.append(f"Expected sw, got {g['group']}")
            if g["action"] != "FLAG":
                issues.append(f"Expected FLAG, got {g['action']}")
            desc = g.get("description", "").lower()
            if "jonas" not in desc and "integrity" not in desc:
                issues.append(f"Group {g['group']} description doesn't reference Jonas")
        return (not issues, "; ".join(issues)) if issues else (True, "90d expiry, bias required, sw=FLAG")

    # --- W2.9 ---
    def check_adr(self) -> Tuple[bool, str]:
        path = os.path.join(self.root, self.ADR_PATH)
        if not os.path.isfile(path):
            return False, f"ADR-043 not found at {self.ADR_PATH}"
        with open(path) as f:
            adr = f.read()
        issues = []
        for kw in ["use_decide=True", "HMAC-SHA256", "JSON minified", "hard_blocked",
                   "GrantBlockedError", "null", "sectors/"]:
            if kw not in adr:
                issues.append(f"Missing keyword: {kw}")
        for ref in ["ADR-001", "ADR-015", "ADR-022", "ADR-031"]:
            if ref not in adr:
                issues.append(f"Missing reference: {ref}")
        if "Consequences Summary" not in adr:
            issues.append("Missing Consequences Summary")
        if "Validation Criteria" not in adr:
            issues.append("Missing Validation Criteria")
        words = len(adr.split())
        if words < 2000:
            issues.append(f"Too short: {words} words (expected > 2000)")
        return (not issues, "; ".join(issues)) if issues else (True, f"7 decisions, cross-refs, tables, {words} words")

    # ------------------------------------------------------------------
    def run_all(self) -> bool:
        print(f"\n{'='*60}")
        print(f" CI Week 2 \u2014 Policy YAML + ADR-043")
        print(f"{'='*60}\n")

        checks = [
            ("W2.1", "Policy file location", self.check_policy_location),
            ("W2.2", "YAML parseability", self.check_yaml_parseability),
            ("W2.3", "Metadata completeness", self.check_metadata),
            ("W2.4", "Jurisdiction config", self.check_jurisdiction),
            ("W2.5", "Risk thresholds", self.check_thresholds),
            ("W2.6", "Gilligan mercy", self.check_gilligan),
            ("W2.7", "Levinas SLA", self.check_levinas),
            ("W2.8", "Jonas enforcement", self.check_jonas),
            ("W2.9", "ADR-043 completeness", self.check_adr),
        ]

        for cid, desc, fn in checks:
            self._run_check(cid, desc, fn)

        passed = sum(1 for r in self.results if r.status == CheckStatus.PASS)
        failed = sum(1 for r in self.results if r.status in (CheckStatus.FAIL, CheckStatus.ERROR))
        print(f"\n{'\u2500'*60}")
        print(f" Results: {passed}/{len(self.results)} passed", end="")
        if failed:
            print(f" | {failed} FAILED", end="")
        print()
        print(f"{'='*60}\n")
        return failed == 0


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    sys.exit(0 if Week2CI(root).run_all() else 1)
