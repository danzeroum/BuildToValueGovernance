#!/usr/bin/env python3
"""
CI Week 3 — Test Suite (800 Adversarial Cases)

Validates the adversarial test suite deliverables from Week 3.

Checks:
W3.1 Test file existence (tests/test_grants_adapter.py, min 1000 lines)
W3.2 800+ total test cases in ALL_TEST_CASES
W3.3 All 8 categories present with 100+ cases each
W3.4 All 4 linguistic groups represented (en-US, pt-BR, es, sw)
W3.5 Ground truth coverage (ALLOW, BLOCK, HARD_BLOCK, EDUCATE, etc.)
W3.6 TestCase data integrity (required fields, proposal_data)
W3.7 ID format uniqueness (PREFIX-NNN, no duplicates, prefix/category match)
W3.8 Hard block tests consistency (should_raise + GrantBlockedError)

Exit codes: 0=pass, 1=fail
"""

from __future__ import annotations

import os
import re
import sys
import time
import traceback
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, List, Tuple


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


class Week3CI:
    TEST_FILE = "tests/test_grants_adapter.py"

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

    def _import_cases(self):
        """Import ALL_TEST_CASES from the test module."""
        test_path = os.path.join(self.root, self.TEST_FILE)
        adapter_dir = os.path.join(self.root, "sdk/integrations/grants/btv_grants")
        sys.path.insert(0, adapter_dir)
        sys.path.insert(0, os.path.dirname(test_path))
        from test_grants_adapter import ALL_TEST_CASES  # noqa: F401
        return ALL_TEST_CASES

    # --- W3.1 ---
    def check_file_existence(self) -> Tuple[bool, str]:
        path = os.path.join(self.root, self.TEST_FILE)
        if not os.path.isfile(path):
            return False, f"{self.TEST_FILE} not found"
        with open(path) as f:
            lines = len(f.readlines())
        if lines < 1000:
            return False, f"Only {lines} lines (expected >= 1000)"
        return True, f"test_grants_adapter.py ({lines} lines)"

    # --- W3.2 ---
    def check_total_count(self) -> Tuple[bool, str]:
        cases = self._import_cases()
        total = len(cases)
        if total < 800:
            return False, f"{total} cases, need >= 800"
        return True, f"{total} cases (>= 800)"

    # --- W3.3 ---
    def check_categories(self) -> Tuple[bool, str]:
        sys.path.insert(0, os.path.join(self.root, "sdk/integrations/grants/btv_grants"))
        sys.path.insert(0, os.path.join(self.root, "tests"))

        from test_grants_adapter import (
            STRUCTURAL_VALIDATION_TESTS, SANITIZATION_TESTS, HARD_BLOCK_TESTS,
            POLICY_BLOCK_TESTS, MERCY_TESTS, LANGUAGE_TESTS, BIAS_TESTS, SESSION_TESTS,
            ALL_TEST_CASES,
        )

        categories = {
            "structural": STRUCTURAL_VALIDATION_TESTS,
            "sanitization": SANITIZATION_TESTS,
            "hard_block": HARD_BLOCK_TESTS,
            "policy_block": POLICY_BLOCK_TESTS,
            "mercy": MERCY_TESTS,
            "language": LANGUAGE_TESTS,
            "bias": BIAS_TESTS,
            "session": SESSION_TESTS,
        }

        issues = []
        for name, cases in sorted(categories.items()):
            if len(cases) < 100:
                issues.append(f"{name}: {len(cases)} < 100")

        union = sum(len(c) for c in categories.values())
        if union != len(ALL_TEST_CASES):
            issues.append(f"Union ({union}) != ALL_TEST_CASES ({len(ALL_TEST_CASES)})")

        if issues:
            return False, "; ".join(issues)
        return True, "All 8 categories >= 100, union matches"

    # --- W3.4 ---
    def check_linguistic_groups(self) -> Tuple[bool, str]:
        cases = self._import_cases()
        groups = Counter(tc.linguistic_group for tc in cases)
        issues = []
        for lg in ["en-US", "pt-BR", "es", "sw"]:
            if groups.get(lg, 0) == 0:
                issues.append(f"No cases for {lg}")
        if issues:
            return False, "; ".join(issues)
        dist = ", ".join(f"{k}={v}" for k, v in sorted(groups.items()))
        return True, f"All 4 groups: {dist}"

    # --- W3.5 ---
    def check_ground_truth(self) -> Tuple[bool, str]:
        cases = self._import_cases()
        gt = Counter(tc.ground_truth for tc in cases)
        issues = []
        for rt in ["ALLOW", "BLOCK", "HARD_BLOCK"]:
            if gt.get(rt, 0) == 0:
                issues.append(f"No {rt} cases")
        if issues:
            return False, "; ".join(issues)
        dist = ", ".join(f"{k}={v}" for k, v in sorted(gt.items(), key=lambda x: -x[1]))
        return True, f"Coverage: {dist}"

    # --- W3.6 ---
    def check_data_integrity(self) -> Tuple[bool, str]:
        cases = self._import_cases()
        issues = 0
        for tc in cases:
            if not tc.id or not tc.category or len(tc.description) < 10:
                issues += 1
            if not tc.ground_truth or not tc.linguistic_group:
                issues += 1
            if not tc.proposal_data:
                issues += 1
            elif "applicant_id" not in tc.proposal_data or "title" not in tc.proposal_data:
                issues += 1
        if issues:
            return False, f"{issues} cases with data issues"
        return True, f"All {len(cases)} cases pass integrity checks"

    # --- W3.7 ---
    def check_id_uniqueness(self) -> Tuple[bool, str]:
        cases = self._import_cases()
        ids = [tc.id for tc in cases]
        issues = []
        if len(ids) != len(set(ids)):
            dupes = [i for i in set(ids) if ids.count(i) > 1]
            issues.append(f"Duplicate IDs: {dupes[:10]}")
        pattern = re.compile(r"^[A-Z]{2,4}-\d{3,4}$")
        invalid = [i for i in ids if not pattern.match(i)]
        if invalid:
            issues.append(f"Invalid format: {invalid[:10]}")
        prefix_map = {
            "SV": "structural", "SAN": "sanitization", "HB": "hard_block",
            "PB": "policy_block", "MC": "mercy", "LANG": "language",
            "BIAS": "bias", "SES": "session",
        }
        for tc in cases:
            pfx = tc.id.split("-")[0]
            expected = prefix_map.get(pfx)
            if expected and tc.category != expected:
                issues.append(f"{tc.id}: prefix={pfx} ({expected}) != category={tc.category}")
        if issues:
            return False, "; ".join(issues[:5])
        return True, f"{len(set(ids))} unique IDs, valid format, prefix/category match"

    # --- W3.8 ---
    def check_hardblock_consistency(self) -> Tuple[bool, str]:
        sys.path.insert(0, os.path.join(self.root, "sdk/integrations/grants/btv_grants"))
        sys.path.insert(0, os.path.join(self.root, "tests"))
        from test_grants_adapter import HARD_BLOCK_TESTS

        issues = 0
        for tc in HARD_BLOCK_TESTS:
            if tc.ground_truth == "HARD_BLOCK" and not tc.should_raise:
                issues += 1
            if tc.ground_truth == "HARD_BLOCK" and tc.expected_exception != "GrantBlockedError":
                issues += 1
        if issues:
            return False, f"{issues} hard_block inconsistencies"
        return True, f"All {len(HARD_BLOCK_TESTS)} hard_block tests consistent"

    # ------------------------------------------------------------------
    def run_all(self) -> bool:
        print(f"\n{'='*60}")
        print(f" CI Week 3 \u2014 Test Cases (800)")
        print(f"{'='*60}\n")

        checks = [
            ("W3.1", "File existence", self.check_file_existence),
            ("W3.2", "800+ total cases", self.check_total_count),
            ("W3.3", "8 categories x 100", self.check_categories),
            ("W3.4", "4 linguistic groups", self.check_linguistic_groups),
            ("W3.5", "Ground truth coverage", self.check_ground_truth),
            ("W3.6", "Data integrity", self.check_data_integrity),
            ("W3.7", "ID uniqueness", self.check_id_uniqueness),
            ("W3.8", "Hard block consistency", self.check_hardblock_consistency),
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
    sys.exit(0 if Week3CI(root).run_all() else 1)
