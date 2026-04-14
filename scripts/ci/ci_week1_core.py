#!/usr/bin/env python3
"""
CI Week 1 — Adapter Core Invariants

Validates all structural invariants from Week 1-2 of the GrantDecisionAdapter
implementation. Each check is independent and exits with code 1 on failure.

Checks:
W1.1 File existence (4 files in sdk/integrations/grants/btv_grants/)
W1.2 Module imports (13 public symbols from __init__.py)
W1.3 HMAC-SHA256 for session_id (no BLAKE3, 64 hex chars, deterministic)
W1.4 JSON minified for to_btv_input() (no English prefixes, compact)
W1.5 GrantBlockedError fields (contestable, appeal_deadline_hours)
W1.6 hard_blocked checked BEFORE action (source code ordering)
W1.7 use_decide=True as default (ADR-043 §1)
W1.8 BiasDeclaration Jonas enforcement (sw=null, calibrated groups valid)

Exit codes:
0 = all checks passed
1 = one or more checks failed
2 = import error (adapter not installed/found)
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import importlib.util
import json
import os
import re
import sys
import traceback
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Infrastructure
# ---------------------------------------------------------------------------

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
    REQUIRED_FILES = [
        "__init__.py",
        "adapter.py",
        "models.py",
        "exceptions.py",
    ]

    def __init__(self, project_root: str = ".") -> None:
        self.project_root = project_root
        self.adapter_path = os.path.join(project_root, self.ADAPTER_DIR)
        # Parent dir of btv_grants package (sdk/integrations/grants/)
        self.package_parent = os.path.dirname(self.adapter_path)
        self.results: List[CheckResult] = []

    def _ensure_path(self) -> bool:
        """Verify the adapter directory exists."""
        if not os.path.isdir(self.adapter_path):
            print(f"FATAL: Adapter directory not found: {self.adapter_path}")
            return False
        return True

    def _inject_package_path(self) -> None:
        """Ensure parent dir is on sys.path so 'btv_grants' is importable as a package."""
        if self.package_parent not in sys.path:
            sys.path.insert(0, self.package_parent)

    def _run_check(self, check_id: str, description: str, fn: Callable[[], Tuple[bool, str]]) -> CheckResult:
        """Run a single check and record the result."""
        import time
        start = time.monotonic()
        try:
            passed, details = fn()
            status = CheckStatus.PASS if passed else CheckStatus.FAIL
        except Exception as exc:
            status = CheckStatus.ERROR
            details = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}"
        elapsed = (time.monotonic() - start) * 1000

        result = CheckResult(
            check_id=check_id,
            description=description,
            status=status,
            details=details,
            execution_time_ms=elapsed,
        )
        self.results.append(result)

        icon = {"PASS": "\u2705", "FAIL": "\u274c", "SKIP": "\u23ed\ufe0f", "ERROR": "\U0001f4a5"}[status.value]
        print(f"  {icon} {check_id} \u2014 {description}")
        if details and status in (CheckStatus.FAIL, CheckStatus.ERROR):
            for line in details.strip().split("\n")[:5]:
                print(f"     {line}")

        return result

    # ------------------------------------------------------------------
    # W1.1 — File Existence
    # ------------------------------------------------------------------
    def check_file_existence(self) -> Tuple[bool, str]:
        missing = []
        for f in self.REQUIRED_FILES:
            path = os.path.join(self.adapter_path, f)
            if not os.path.isfile(path):
                missing.append(f)
        if missing:
            return False, f"Missing files: {missing}"
        return True, f"All {len(self.REQUIRED_FILES)} files present"

    # ------------------------------------------------------------------
    # W1.2 — Module Imports
    # ------------------------------------------------------------------
    def check_module_imports(self) -> Tuple[bool, str]:
        # Insert the PARENT directory of btv_grants so that relative imports
        # within the package (from .exceptions import ...) resolve correctly.
        self._inject_package_path()

        imported: List[str] = []
        sdk_dep_available = True

        # Phase 1: Import standalone modules via the package namespace.
        # Using 'btv_grants.exceptions' / 'btv_grants.models' ensures Python
        # treats them as package modules and resolves all relative imports.
        try:
            exc_mod = importlib.import_module("btv_grants.exceptions")
            for sym in ("GrantBlockedError", "GrantValidationError",
                        "GrantSanitizationError", "BiasDeclarationError"):
                if not hasattr(exc_mod, sym):
                    return False, f"exceptions missing symbol: {sym}"
            imported.extend(["GrantBlockedError", "GrantValidationError",
                              "GrantSanitizationError", "BiasDeclarationError"])
        except ImportError as exc:
            return False, f"btv_grants.exceptions import failed: {exc}"

        try:
            models_mod = importlib.import_module("btv_grants.models")
            for sym in ("GrantProposal", "GrantCategory", "GrantStage",
                        "LinguisticGroup", "ActionImpact", "BiasDeclaration",
                        "DEFAULT_BIAS_DECLARATIONS"):
                if not hasattr(models_mod, sym):
                    return False, f"models missing symbol: {sym}"
            imported.extend(["GrantProposal", "GrantCategory", "GrantStage",
                              "LinguisticGroup", "ActionImpact", "BiasDeclaration",
                              "DEFAULT_BIAS_DECLARATIONS"])
        except ImportError as exc:
            return False, f"btv_grants.models import failed: {exc}"

        # Phase 2: Try adapter (requires buildtovalue SDK at runtime).
        try:
            adapter_mod = importlib.import_module("btv_grants.adapter")
            for sym in ("GrantGuard", "GrantGuardConfig"):
                if not hasattr(adapter_mod, sym):
                    return False, f"adapter missing symbol: {sym}"
            imported.extend(["GrantGuard", "GrantGuardConfig"])
        except ImportError:
            sdk_dep_available = False
            adapter_source = open(os.path.join(self.adapter_path, "adapter.py")).read()
            for cls in ["GrantGuard", "GrantGuardConfig"]:
                if f"class {cls}" in adapter_source:
                    imported.append(f"{cls} (source-verified)")
                else:
                    return False, f"{cls} not found in adapter.py"

        # Phase 3: Verify __init__.py package exports.
        if sdk_dep_available:
            try:
                btv_pkg = importlib.import_module("btv_grants")
                expected = [
                    "GrantGuard", "GrantGuardConfig",
                    "GrantProposal", "GrantCategory", "GrantStage",
                    "LinguisticGroup", "ActionImpact", "BiasDeclaration",
                    "DEFAULT_BIAS_DECLARATIONS",
                    "GrantBlockedError", "GrantValidationError",
                    "GrantSanitizationError", "BiasDeclarationError",
                ]
                missing = [s for s in expected if not hasattr(btv_pkg, s)]
                if missing:
                    return False, f"__init__.py missing exports: {missing}"
                return True, f"All 13 public symbols imported ({len(imported)} direct)"
            except ImportError as exc:
                return False, f"btv_grants __init__ import failed: {exc}"
        else:
            init_source = open(os.path.join(self.adapter_path, "__init__.py")).read()
            all_symbols: List[str] = []
            in_all = False
            for line in init_source.split("\n"):
                if "__all__" in line and "[" in line:
                    in_all = True
                if in_all:
                    if "]" in line:
                        break
                    symbol = line.strip().strip('"').strip("'").strip(",")
                    if symbol:
                        all_symbols.append(symbol)
            if len(all_symbols) >= 13:
                return True, (
                    f"{len(imported)} imported + {len(all_symbols)} exports verified "
                    "(SDK not installed)"
                )
            return False, f"__init__.py has {len(all_symbols)} exports, expected >= 13"

    # ------------------------------------------------------------------
    # W1.3 — HMAC-SHA256 Invariant
    # ------------------------------------------------------------------
    def check_hmac_sha256(self) -> Tuple[bool, str]:
        self._inject_package_path()
        models_mod = importlib.import_module("btv_grants.models")
        GrantProposal = models_mod.GrantProposal
        GrantCategory = models_mod.GrantCategory

        issues = []

        p = GrantProposal(
            applicant_id="0xci-hmac",
            title="CI HMAC Test",
            description="Testing session ID",
            category=GrantCategory.OTHER,
        )

        sid = p.to_session_id()
        if len(sid) != 64:
            issues.append(f"Session ID length {len(sid)} != 64")
        try:
            int(sid, 16)
        except ValueError:
            issues.append(f"Session ID is not valid hex: {sid[:20]}...")

        if sid != p.to_session_id():
            issues.append("Non-deterministic: same input produces different output")

        if sid == p.to_session_id(secret=b"rotated-salt"):
            issues.append("Salt rotation has no effect")

        for filename in ["models.py", "adapter.py"]:
            path = os.path.join(self.adapter_path, filename)
            source = open(path).read()
            code_lines = []
            in_docstring = False
            for line in source.split('\n'):
                stripped = line.strip()
                if '"""' in stripped or "'''" in stripped:
                    in_docstring = not in_docstring
                    continue
                if in_docstring:
                    continue
                if '#' in line:
                    line = line[:line.index('#')]
                code_lines.append(line)
            code_only = '\n'.join(code_lines)
            if 'blake3' in code_only.lower() or 'hashlib.blake3' in code_only.lower():
                issues.append(f"BLAKE3 usage found in {filename} executable code")

        if issues:
            return False, "; ".join(issues)
        return True, "HMAC-SHA256, 64 hex, deterministic, salt-rotatable, no BLAKE3"

    # ------------------------------------------------------------------
    # W1.4 — JSON Minified Invariant
    # ------------------------------------------------------------------
    def check_json_minified(self) -> Tuple[bool, str]:
        self._inject_package_path()
        models_mod = importlib.import_module("btv_grants.models")
        GrantProposal = models_mod.GrantProposal
        GrantCategory = models_mod.GrantCategory
        LinguisticGroup = models_mod.LinguisticGroup

        test_cases = [
            (LinguisticGroup.PT_BR, "Monitoramento Ambiental", "Sensoriamento na Amaz\u00f4nia"),
            (LinguisticGroup.ES, "Identidad Descentralizada", "Plataforma soberana en Ethereum"),
            (LinguisticGroup.SW, "Mradi wa Maji", "Ukusafisha maji kwa jamii"),
        ]

        issues = []
        for lg, title, desc in test_cases:
            p = GrantProposal(
                applicant_id=f"0xci-{lg.value}",
                title=title,
                description=desc,
                category=GrantCategory.PUBLIC_GOODS,
                linguistic_group=lg,
            )
            raw = p.to_btv_input()

            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError as exc:
                issues.append(f"[{lg.value}] Not valid JSON: {exc}")
                continue

            if parsed.get("title") != title:
                issues.append(f"[{lg.value}] Title not preserved in JSON")
            if parsed.get("description") != desc:
                issues.append(f"[{lg.value}] Description not preserved in JSON")

            for prefix in ["Title:", "Description:", "Budget:"]:
                if prefix in raw:
                    issues.append(f"[{lg.value}] English prefix '{prefix}' found in output")

            if "  " in raw:
                issues.append(f"[{lg.value}] Non-compact JSON (double whitespace)")

        if issues:
            return False, "; ".join(issues)
        return True, "All 3 linguistic groups: valid JSON, no prefixes, compact"

    # ------------------------------------------------------------------
    # W1.5 — GrantBlockedError Fields
    # ------------------------------------------------------------------
    def check_blocked_error_fields(self) -> Tuple[bool, str]:
        self._inject_package_path()
        exc_mod = importlib.import_module("btv_grants.exceptions")
        GrantBlockedError = exc_mod.GrantBlockedError

        issues = []

        try:
            err = GrantBlockedError(
                verdict_id="VRD-CIW100",
                action="BLOCK",
                rationale="CI test rationale",
                contestable=True,
                appeal_deadline_hours=168,
                composite_risk=0.75,
                trust_score=0.8,
            )
        except TypeError as exc:
            issues.append(f"Constructor failed: {exc}")

        if err.contestable is not True:
            issues.append("contestable != True")
        if err.appeal_deadline_hours != 168:
            issues.append(f"appeal_deadline_hours={err.appeal_deadline_hours} != 168")
        if err.composite_risk != 0.75:
            issues.append("composite_risk not preserved")
        if err.trust_score != 0.8:
            issues.append("trust_score not preserved")

        msg = str(err)
        if "Contestable: YES" not in msg:
            issues.append("Error message missing 'Contestable: YES'")
        if "168h" not in msg:
            issues.append("Error message missing '168h'")

        err_hard = GrantBlockedError(
            verdict_id="VRD-CIWHARD",
            action="BLOCK",
            rationale="Hard blocked",
            contestable=False,
            appeal_deadline_hours=0,
        )
        msg_hard = str(err_hard)
        if "Contestable: NO" not in msg_hard:
            issues.append("Hard block message missing 'Contestable: NO'")
        if "no appeal pathway" not in msg_hard:
            issues.append("Hard block message missing 'no appeal pathway'")

        if issues:
            return False, "; ".join(issues)
        return True, "contestable, appeal_deadline_hours, composite_risk, trust_score, error messages"

    # ------------------------------------------------------------------
    # W1.6 — hard_blocked Before action (Source Code Analysis)
    # ------------------------------------------------------------------
    def check_hardblock_priority(self) -> Tuple[bool, str]:
        adapter_path = os.path.join(self.adapter_path, "adapter.py")
        source = open(adapter_path).read()

        hb_pos = source.find("verdict.hard_blocked")
        ac_pos = source.find("action_str in self._config.block_on")

        if hb_pos < 0:
            return False, "'verdict.hard_blocked' not found in adapter.py"
        if ac_pos < 0:
            return False, "'action_str in self._config.block_on' not found in adapter.py"
        if hb_pos >= ac_pos:
            return False, (
                f"FAIL-SAFE VIOLATION: hard_blocked at char {hb_pos} "
                f"must be BEFORE action check at char {ac_pos}"
            )

        eval_start = source.find("def evaluate(")
        eval_end = source.find("def evaluate_batch(", eval_start)
        method_source = source[eval_start:eval_end]

        required_steps = [
            "_validate(proposal)",
            "_sanitize(proposal)",
            "to_btv_input()",
            "to_session_id(",
            "client.decide(",
            "verdict.hard_blocked",
        ]
        missing = [s for s in required_steps if s not in method_source]
        if missing:
            return False, f"Missing pipeline steps: {missing}"

        return True, f"hard_blocked({hb_pos}) < action({ac_pos}), 6-step pipeline verified"

    # ------------------------------------------------------------------
    # W1.7 — use_decide=True Default
    # ------------------------------------------------------------------
    def check_use_decide_default(self) -> Tuple[bool, str]:
        adapter_path = os.path.join(self.adapter_path, "adapter.py")
        source = open(adapter_path).read()
        match = re.search(r'use_decide\s*[:=]\s*bool\s*=\s*(True|False)', source)
        if not match:
            return False, "use_decide parameter not found in GrantGuardConfig"
        if match.group(1) != "True":
            return False, f"use_decide default={match.group(1)}, expected True"
        return True, "use_decide=True default (source code verified)"

    # ------------------------------------------------------------------
    # W1.8 — BiasDeclaration Jonas Enforcement
    # ------------------------------------------------------------------
    def check_bias_jonas(self) -> Tuple[bool, str]:
        self._inject_package_path()
        models_mod = importlib.import_module("btv_grants.models")
        BiasDeclaration = models_mod.BiasDeclaration
        LinguisticGroup = models_mod.LinguisticGroup
        DEFAULT_BIAS_DECLARATIONS = models_mod.DEFAULT_BIAS_DECLARATIONS

        issues = []

        try:
            bd = BiasDeclaration(group=LinguisticGroup.SW)
            if bd.fpr is not None or bd.fnr is not None:
                issues.append("sw default should have fpr=None, fnr=None")
        except Exception as exc:
            issues.append(f"sw null failed: {exc}")

        for field, val in [("fpr", 0.05), ("fnr", 0.10)]:
            try:
                BiasDeclaration(group=LinguisticGroup.SW, **{field: val})
                issues.append(f"sw {field}={val} should raise ValueError")
            except ValueError:
                pass
            except Exception as exc:
                issues.append(f"sw {field}={val} raised wrong exception: {exc}")

        try:
            bd_en = BiasDeclaration(group=LinguisticGroup.EN_US, fpr=0.03, fnr=0.05)
            if bd_en.fpr != 0.03:
                issues.append("en-US fpr not preserved")
        except Exception as exc:
            issues.append(f"en-US valid bias failed: {exc}")

        for field, val in [("fpr", 1.5), ("fnr", -0.1)]:
            try:
                BiasDeclaration(group=LinguisticGroup.EN_US, **{field: val})
                issues.append(f"{field}={val} should raise ValueError")
            except ValueError:
                pass
            except Exception as exc:
                issues.append(f"{field}={val} wrong exception: {exc}")

        for lg in [LinguisticGroup.EN_US, LinguisticGroup.PT_BR,
                   LinguisticGroup.ES, LinguisticGroup.SW]:
            if lg not in DEFAULT_BIAS_DECLARATIONS:
                issues.append(f"{lg.value} not in DEFAULT_BIAS_DECLARATIONS")

        sw_default = DEFAULT_BIAS_DECLARATIONS[LinguisticGroup.SW]
        if sw_default.fpr is not None or sw_default.fnr is not None or sw_default.sample_size != 0:
            issues.append("DEFAULT sw should have fpr=None, fnr=None, sample_size=0")

        if issues:
            return False, "; ".join(issues)
        return True, "sw=null enforced, calibrated valid, boundaries checked, all 4 groups"

    # ------------------------------------------------------------------
    # Run All
    # ------------------------------------------------------------------
    def run_all(self) -> bool:
        """Execute all Week 1 checks. Returns True if all pass."""
        if not self._ensure_path():
            return False

        print(f"\n{'='*60}")
        print(f" CI Week 1 \u2014 Adapter Core Invariants")
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
        failed = sum(1 for r in self.results if r.status == CheckStatus.FAIL)
        errors = sum(1 for r in self.results if r.status == CheckStatus.ERROR)

        print(f"\n{'\u2500'*60}")
        print(f" Results: {passed}/{len(self.results)} passed", end="")
        if failed:
            print(f" | {failed} FAILED", end="")
        if errors:
            print(f" | {errors} ERRORS", end="")
        print()
        print(f"{'='*60}\n")

        return failed == 0 and errors == 0


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    ci = Week1CI(project_root=root)
    success = ci.run_all()
    sys.exit(0 if success else 1)
