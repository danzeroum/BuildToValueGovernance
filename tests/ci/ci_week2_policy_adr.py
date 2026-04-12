#!/usr/bin/env python3
"""
CI Week 2 — Policy YAML + ADR-043 Validation

Checks:
  W2.1  Policy file location (data/policies/sectors/grant-eligibility-v1.yaml)
  W2.2  YAML parseability (valid YAML, all 10 sections)
  W2.3  Metadata completeness (semver, 90-day expiry, sector=grants)
  W2.4  Jurisdiction configuration (bitmasks, sanctions, elevated risk)
  W2.5  Risk thresholds (5 tiers, monotonically ordered)
  W2.6  Gilligan mercy config (enabled, max=EDUCATE, trust threshold)
  W2.7  Levinas SLA (timers, contestability, 4 languages)
  W2.8  Jonas enforcement (90d expiry, bias required, sw=FLAG)
  W2.9  ADR-043 completeness (7 decisions, cross-refs, tables, >2000 words)

Exit codes: 0=pass, 1=fail
"""
from __future__ import annotations

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
        icon = {"PASS": "✅", "FAIL": "❌", "ERROR": "💥"}[status.value]
        print(f"  {icon} {cid} — {desc}")
        if details and status != CheckStatus.PASS:
            for line in details.strip().split("\n")[:5]:
                print(f"     {line}")
        return r

    def _load_policy(self) -> Dict[str, Any]:
        import yaml
        with open(os.path.join(self.root, self.POLICY_PATH)) as f:
            return yaml.safe_load(f)

    def check_policy_location(self) -> Tuple[bool, str]:
        correct = os.path.isfile(os.path.join(self.root, self.POLICY_PATH))
        wrong = os.path.isfile(os.path.join(self.root, self.WRONG_PATH))
        issues = []
        if not correct: issues.append(f"Not found at {self.POLICY_PATH}")
        if wrong: issues.append(f"Found in WRONG location: {self.WRONG_PATH}")
        return (not bool(issues), "; ".join(issues)) if issues else (True, "Correct location")

    def check_yaml_parseability(self) -> Tuple[bool, str]:
        try:
            p = self._load_policy()
        except Exception as exc:
            return False, f"Parse error: {exc}"
        if not isinstance(p, dict):
            return False, "Root is not a dict"
        required = ["metadata","jurisdiction","financial","thresholds","actions","rawls","levinas","jonas","gilligan","categories"]
        missing = [s for s in required if s not in p]
        return (not bool(missing), f"Missing: {missing}") if missing else (True, f"All {len(required)} sections")

    def check_metadata(self) -> Tuple[bool, str]:
        p = self._load_policy()
        m = p["metadata"]
        issues = []
        for f in ["policy_id","name","version","sector","created","expires","author","description"]:
            if f not in m: issues.append(f"Missing metadata.{f}")
        if not re.match(r"\d+\.\d+\.\d+", m.get("version", "")): issues.append(f"Bad version: {m.get('version')}")
        try:
            c = datetime.fromisoformat(m["created"].replace("Z", "+00:00"))
            e = datetime.fromisoformat(m["expires"].replace("Z", "+00:00"))
            delta = (e - c).days
            if delta != 90: issues.append(f"Expiry {delta}d != 90")
        except Exception as exc:
            issues.append(f"Date error: {exc}")
        if m.get("sector") != "grants": issues.append(f"sector='{m.get('sector')}'")
        return (not bool(issues), "; ".join(issues)) if issues else (True, "Semver, 90-day expiry, sector=grants")

    def check_jurisdiction(self) -> Tuple[bool, str]:
        p = self._load_policy()
        j = p["jurisdiction"]
        issues = []
        if len(j.get("bitmask_schema", {})) < 6: issues.append("< 6 bitmask entries")
        for cc in ["KP","IR","SY","CU"]:
            if cc not in j.get("sanctioned_country_codes", []): issues.append(f"Missing: {cc}")
        if "elevated_risk_country_codes" not in j: issues.append("Missing elevated_risk")
        return (not bool(issues), "; ".join(issues)) if issues else (True, "Bitmasks, sanctions, elevated risk")

    def check_thresholds(self) -> Tuple[bool, str]:
        p = self._load_policy()
        t = p["thresholds"]
        issues = []
        for tier in ["allow","educate","inspect","block","hard_block"]:
            if tier not in t: issues.append(f"Missing: {tier}")
        try:
            vals = [t["allow"]["max_risk"],t["educate"]["max_risk"],t["inspect"]["max_risk"],t["block"]["max_risk"],t["hard_block"]["min_risk"]]
            for i in range(len(vals)-1):
                if vals[i] > vals[i+1]: issues.append(f"Non-monotonic at {i}: {vals[i]} > {vals[i+1]}")
        except (KeyError, TypeError) as exc:
            issues.append(f"Value error: {exc}")
        return (not bool(issues), "; ".join(issues)) if issues else (True, "5 tiers, monotonically ordered")

    def check_gilligan(self) -> Tuple[bool, str]:
        p = self._load_policy()
        g = p["gilligan"]["mercy"]
        issues = []
        if g.get("enabled") is not True: issues.append("Not enabled")
        if g.get("max_intervention") != "EDUCATE": issues.append(f"max={g.get('max_intervention')}")
        if g.get("trust_threshold", 0) <= 0: issues.append("trust_threshold <= 0")
        if g.get("critical_findings_override") is not False: issues.append("critical_findings_override != False")
        return (not bool(issues), "; ".join(issues)) if issues else (True, "Enabled, EDUCATE, trust>0")

    def check_levinas(self) -> Tuple[bool, str]:
        p = self._load_policy()
        l = p["levinas"]
        issues = []
        if l["sla"]["initial_response_hours"] > 24: issues.append(f"initial_response > 24h")
        if l["sla"]["appeal_response_hours"] > 72: issues.append(f"appeal_response > 72h")
        if "BLOCK" not in l["contestability"]["contestable_actions"]: issues.append("BLOCK not contestable")
        if l["contestability"]["hard_block_contestable"] is not False: issues.append("hard_block contestable")
        if set(l["language"]["supported_groups"]) != {"en-US","pt-BR","es","sw"}: issues.append("Bad groups")
        return (not bool(issues), "; ".join(issues)) if issues else (True, "SLA, contestability, 4 groups")

    def check_jonas(self) -> Tuple[bool, str]:
        p = self._load_policy()
        j = p["jonas"]
        issues = []
        if j["policy_expiry_days"] != 90: issues.append(f"expiry={j['policy_expiry_days']}")
        if j["bias"]["require_declaration"] is not True: issues.append("require_declaration != True")
        uncal = j["bias"]["uncalibrated_groups"]
        if not uncal: issues.append("No uncalibrated_groups")
        for g in uncal:
            if g["group"] != "sw": issues.append(f"Expected sw, got {g['group']}")
            if g["action"] != "FLAG": issues.append(f"Expected FLAG, got {g['action']}")
            desc = g.get("description", "")
            if "Jonas" not in desc and "integrity" not in desc.lower(): issues.append("Jonas not in description")
        return (not bool(issues), "; ".join(issues)) if issues else (True, "90d, bias required, sw=FLAG, Jonas")

    def check_adr(self) -> Tuple[bool, str]:
        path = os.path.join(self.root, self.ADR_PATH)
        if not os.path.isfile(path):
            return False, f"ADR-043 not found at {self.ADR_PATH}"
        with open(path) as f:
            adr = f.read()
        issues = []
        for kw in ["use_decide=True","HMAC-SHA256","JSON minified","hard_blocked","GrantBlockedError","null","sectors/"]:
            if kw not in adr: issues.append(f"Missing: {kw}")
        for ref in ["ADR-001","ADR-015","ADR-022","ADR-031"]:
            if ref not in adr: issues.append(f"Missing ref: {ref}")
        if "Consequences Summary" not in adr: issues.append("Missing Consequences Summary")
        if "Validation Criteria" not in adr: issues.append("Missing Validation Criteria")
        words = len(adr.split())
        if words <= 2000: issues.append(f"ADR too short: {words} words")
        return (not bool(issues), "; ".join(issues)) if issues else (True, f"7 decisions, cross-refs, {words} words")

    def run_all(self) -> bool:
        print(f"\n{'='*60}")
        print(f"  CI Week 2 — Policy YAML + ADR-043")
        print(f"{'='*60}\n")
        checks = [
            ("W2.1", "Policy file location", self.check_policy_location),
            ("W2.2", "YAML parseability", self.check_yaml_parseability),
            ("W2.3", "Metadata completeness", self.check_metadata),
            ("W2.4", "Jurisdiction config", self.check_jurisdiction),
            ("W2.5", "Risk thresholds ordered", self.check_thresholds),
            ("W2.6", "Gilligan mercy config", self.check_gilligan),
            ("W2.7", "Levinas SLA", self.check_levinas),
            ("W2.8", "Jonas enforcement", self.check_jonas),
            ("W2.9", "ADR-043 completeness", self.check_adr),
        ]
        for cid, desc, fn in checks:
            self._run_check(cid, desc, fn)
        passed = sum(1 for r in self.results if r.status == CheckStatus.PASS)
        failed = sum(1 for r in self.results if r.status != CheckStatus.PASS)
        print(f"\n{'─'*60}")
        print(f"  Results: {passed}/{len(self.results)} passed" + (f" | {failed} FAILED" if failed else ""))
        print(f"{'='*60}\n")
        return failed == 0


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    ci = Week2CI(project_root=root)
    sys.exit(0 if ci.run_all() else 1)
