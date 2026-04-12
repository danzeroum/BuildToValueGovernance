#!/usr/bin/env python3
"""
CI Week 1 — Adapter Core Invariants

Checks:
  W1.1  File existence (4 files in sdk/integrations/grants/btv_grants/)
  W1.2  Module imports (13 public symbols from __init__.py)
  W1.3  HMAC-SHA256 for session_id (no BLAKE3, 64 hex chars, deterministic)
  W1.4  JSON minified for to_btv_input() (no English prefixes, compact)
  W1.5  GrantBlockedError fields (contestable, appeal_deadline_hours)
  W1.6  hard_blocked checked BEFORE action (source code ordering)
  W1.7  use_decide=True as default (ADR-043 §1)
  W1.8  BiasDeclaration Jonas enforcement (sw=null, calibrated groups valid)

Exit codes: 0=pass, 1=fail, 2=import error
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import traceback
from dataclasses import dataclass
from enum import Enum
from typing import Callable, List, Tuple


class CheckStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"


@dataclass
class CheckResult:
    check_id: str
    description: str
    status: CheckStatus
    details: str = ""
    execution_time_ms: float = 0.0


class Week1CI:
    """CI validator for Week 1 adapter core invariants."""

    ADAPTER_DIR = "sdk/integrations/grants/btv_grants"
    REQUIRED_FILES = ["__init__.py", "adapter.py", "models.py", "exceptions.py"]

    def __init__(self, project_root: str = ".") -> None:
        self.project_root = project_root
        self.adapter_path = os.path.join(project_root, self.ADAPTER_DIR)
        self.results: List[CheckResult] = []

    def _ensure_path(self) -> bool:
        if not os.path.isdir(self.adapter_path):
            print(f"FATAL: Adapter directory not found: {self.adapter_path}")
            return False
        return True

    def _run_check(self, check_id: str, description: str, fn: Callable[[], Tuple[bool, str]]) -> CheckResult:
        start = time.monotonic()
        try:
            passed, details = fn()
            status = CheckStatus.PASS if passed else CheckStatus.FAIL
        except Exception as exc:
            status = CheckStatus.ERROR
            details = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}"
        elapsed = (time.monotonic() - start) * 1000
        result = CheckResult(check_id, description, status, details, elapsed)
        self.results.append(result)
        icon = {"PASS": "✅", "FAIL": "❌", "SKIP": "⏭️", "ERROR": "💥"}[status.value]
        print(f"  {icon} {check_id} — {description}")
        if details and status in (CheckStatus.FAIL, CheckStatus.ERROR):
            for line in details.strip().split("\n")[:5]:
                print(f"     {line}")
        return result

    def check_file_existence(self) -> Tuple[bool, str]:
        missing = [f for f in self.REQUIRED_FILES if not os.path.isfile(os.path.join(self.adapter_path, f))]
        if missing:
            return False, f"Missing: {missing}"
        return True, f"All {len(self.REQUIRED_FILES)} files present"

    def check_module_imports(self) -> Tuple[bool, str]:
        sys.path.insert(0, self.adapter_path)
        try:
            from exceptions import GrantBlockedError, GrantValidationError, GrantSanitizationError, BiasDeclarationError  # noqa
            from models import GrantProposal, GrantCategory, GrantStage, LinguisticGroup, ActionImpact, BiasDeclaration, DEFAULT_BIAS_DECLARATIONS  # noqa
            from adapter import GrantGuard, GrantGuardConfig  # noqa
            from btv_grants import GrantGuard, GrantGuardConfig, GrantProposal, GrantCategory, GrantStage, LinguisticGroup, ActionImpact, BiasDeclaration, DEFAULT_BIAS_DECLARATIONS, GrantBlockedError, GrantValidationError, GrantSanitizationError, BiasDeclarationError  # noqa
            return True, "All 13 public symbols imported"
        except ImportError as exc:
            return False, f"Import failed: {exc}"

    def check_hmac_sha256(self) -> Tuple[bool, str]:
        from models import GrantProposal, GrantCategory
        issues = []
        p = GrantProposal(applicant_id="0xci-hmac", title="CI HMAC", description="Testing session ID", category=GrantCategory.OTHER)
        sid = p.to_session_id()
        if len(sid) != 64:
            issues.append(f"Length {len(sid)} != 64")
        try:
            int(sid, 16)
        except ValueError:
            issues.append("Not valid hex")
        if sid != p.to_session_id():
            issues.append("Non-deterministic")
        if sid == p.to_session_id(secret=b"rotated-salt"):
            issues.append("Salt rotation has no effect")
        for filename in ["models.py", "adapter.py"]:
            src = open(os.path.join(self.adapter_path, filename)).read()
            # Strip comments and docstrings before checking
            import re as _re
            src_code = _re.sub(r'#.*', '', src)
            src_code = _re.sub(r'""".*?"""', '', src_code, flags=_re.DOTALL)
            src_code = _re.sub(r"'''.*?'''", '', src_code, flags=_re.DOTALL)
            if "blake3" in src_code.lower():
                issues.append(f"BLAKE3 in executable code of {filename}")
        return (not bool(issues), "; ".join(issues)) if issues else (True, "HMAC-SHA256, 64 hex, deterministic, no BLAKE3")

    def check_json_minified(self) -> Tuple[bool, str]:
        from models import GrantProposal, GrantCategory, LinguisticGroup
        test_cases = [
            (LinguisticGroup.PT_BR, "Monitoramento Ambiental", "Sensoriamento na Amazônia"),
            (LinguisticGroup.ES, "Identidad Descentralizada", "Plataforma soberana en Ethereum"),
            (LinguisticGroup.SW, "Mradi wa Maji", "Ukusafisha maji kwa jamii"),
        ]
        issues = []
        for lg, title, desc in test_cases:
            p = GrantProposal(applicant_id=f"0xci-{lg.value}", title=title, description=desc, category=GrantCategory.PUBLIC_GOODS, linguistic_group=lg)
            raw = p.to_btv_input()
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError as exc:
                issues.append(f"[{lg.value}] Not valid JSON: {exc}")
                continue
            if parsed.get("title") != title:
                issues.append(f"[{lg.value}] Title not preserved")
            for prefix in ["Title:", "Description:", "Budget:"]:
                if prefix in raw:
                    issues.append(f"[{lg.value}] English prefix '{prefix}'")
            if "  " in raw:
                issues.append(f"[{lg.value}] Non-compact JSON")
        return (not bool(issues), "; ".join(issues)) if issues else (True, "All 3 groups: valid JSON, no prefixes, compact")

    def check_blocked_error_fields(self) -> Tuple[bool, str]:
        from exceptions import GrantBlockedError
        issues = []
        try:
            err = GrantBlockedError(verdict_id="VRD-CIW100", action="BLOCK", rationale="CI", contestable=True, appeal_deadline_hours=168, composite_risk=0.75, trust_score=0.8)
        except TypeError as exc:
            return False, f"Constructor failed: {exc}"
        if err.contestable is not True: issues.append("contestable != True")
        if err.appeal_deadline_hours != 168: issues.append("appeal_deadline_hours != 168")
        if err.composite_risk != 0.75: issues.append("composite_risk not 0.75")
        msg = str(err)
        if "Contestable: YES" not in msg: issues.append("Missing 'Contestable: YES'")
        if "168h" not in msg: issues.append("Missing '168h'")
        err_hard = GrantBlockedError(verdict_id="VRD-HC", action="BLOCK", rationale="hard", contestable=False, appeal_deadline_hours=0)
        msg_hard = str(err_hard)
        if "no appeal pathway" not in msg_hard: issues.append("Missing 'no appeal pathway'")
        return (not bool(issues), "; ".join(issues)) if issues else (True, "contestable, appeal_deadline_hours, messages OK")

    def check_hardblock_priority(self) -> Tuple[bool, str]:
        source = open(os.path.join(self.adapter_path, "adapter.py")).read()
        hb_pos = source.find("verdict.hard_blocked")
        ac_pos = source.find("action_str in self._config.block_on")
        if hb_pos < 0: return False, "'verdict.hard_blocked' not found"
        if ac_pos < 0: return False, "'action_str in self._config.block_on' not found"
        if hb_pos >= ac_pos: return False, f"FAIL-SAFE VIOLATION: hard_blocked({hb_pos}) >= action({ac_pos})"
        eval_src = source[source.find("def evaluate("):source.find("def evaluate_batch(")]
        missing = [s for s in ["_validate(proposal)","_sanitize(proposal)","to_btv_input()","to_session_id(","client.decide(","verdict.hard_blocked"] if s not in eval_src]
        if missing: return False, f"Missing pipeline steps: {missing}"
        return True, f"hard_blocked({hb_pos}) < action({ac_pos}), 6-step pipeline OK"

    def check_use_decide_default(self) -> Tuple[bool, str]:
        from adapter import GrantGuardConfig
        c = GrantGuardConfig()
        if c.use_decide is not True: return False, f"use_decide={c.use_decide}"
        c2 = GrantGuardConfig(use_decide=False)
        if c2.use_decide is not False: return False, "not overridable"
        return True, "use_decide=True default, overridable"

    def check_bias_jonas(self) -> Tuple[bool, str]:
        from models import BiasDeclaration, LinguisticGroup, DEFAULT_BIAS_DECLARATIONS
        issues = []
        try:
            bd = BiasDeclaration(group=LinguisticGroup.SW)
            if bd.fpr is not None or bd.fnr is not None: issues.append("sw default not null")
        except Exception as exc:
            issues.append(f"sw null failed: {exc}")
        for field, val in [("fpr", 0.05), ("fnr", 0.10)]:
            try:
                BiasDeclaration(group=LinguisticGroup.SW, **{field: val})
                issues.append(f"sw {field}={val} should raise ValueError")
            except ValueError:
                pass
        try:
            BiasDeclaration(group=LinguisticGroup.EN_US, fpr=0.03, fnr=0.05)
        except Exception as exc:
            issues.append(f"en-US valid bias failed: {exc}")
        for field, val in [("fpr", 1.5), ("fnr", -0.1)]:
            try:
                BiasDeclaration(group=LinguisticGroup.EN_US, **{field: val})
                issues.append(f"{field}={val} should raise")
            except ValueError:
                pass
        for lg in [LinguisticGroup.EN_US, LinguisticGroup.PT_BR, LinguisticGroup.ES, LinguisticGroup.SW]:
            if lg not in DEFAULT_BIAS_DECLARATIONS: issues.append(f"{lg.value} missing")
        sw = DEFAULT_BIAS_DECLARATIONS[LinguisticGroup.SW]
        if sw.fpr is not None or sw.fnr is not None or sw.sample_size != 0: issues.append("DEFAULT sw not null")
        return (not bool(issues), "; ".join(issues)) if issues else (True, "sw=null, boundaries, all 4 groups")

    def run_all(self) -> bool:
        if not self._ensure_path():
            return False
        print(f"\n{'='*60}")
        print(f"  CI Week 1 — Adapter Core Invariants")
        print(f"{'='*60}\n")
        checks = [
            ("W1.1", "File existence", self.check_file_existence),
            ("W1.2", "Module imports", self.check_module_imports),
            ("W1.3", "HMAC-SHA256 invariant", self.check_hmac_sha256),
            ("W1.4", "JSON minified invariant", self.check_json_minified),
            ("W1.5", "GrantBlockedError fields", self.check_blocked_error_fields),
            ("W1.6", "hard_blocked priority", self.check_hardblock_priority),
            ("W1.7", "use_decide=True default", self.check_use_decide_default),
            ("W1.8", "BiasDeclaration Jonas", self.check_bias_jonas),
        ]
        for check_id, desc, fn in checks:
            self._run_check(check_id, desc, fn)
        passed = sum(1 for r in self.results if r.status == CheckStatus.PASS)
        failed = sum(1 for r in self.results if r.status in (CheckStatus.FAIL, CheckStatus.ERROR))
        print(f"\n{'─'*60}")
        print(f"  Results: {passed}/{len(self.results)} passed" + (f" | {failed} FAILED" if failed else ""))
        print(f"{'='*60}\n")
        return failed == 0


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    ci = Week1CI(project_root=root)
    sys.exit(0 if ci.run_all() else 1)
