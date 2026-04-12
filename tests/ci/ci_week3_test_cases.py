#!/usr/bin/env python3
"""
CI Week 3 — Adversarial Test Cases (800+)

Checks:
  W3.1  Test file existence (tests/test_grants_adapter.py)
  W3.2  800+ test cases total
  W3.3  All 8 categories × 100+ cases each
  W3.4  All 4 linguistic groups represented
  W3.5  Ground truth coverage (ALLOW, BLOCK, HARD_BLOCK)
  W3.6  TestCase data integrity (id, category, description ≥10 chars)
  W3.7  ID format + uniqueness (PREFIX-NNN, no duplicates)
  W3.8  Hard block test consistency (should_raise=True, GrantBlockedError)

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
from typing import Callable, List, Tuple


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
    ADAPTER_PATH = "sdk/integrations/grants"

    def __init__(self, project_root: str = ".") -> None:
        self.root = project_root
        self.results: List[CheckResult] = []
        self._test_module = None

    def _run_check(self, cid: str, desc: str, fn: Callable[[], Tuple[bool, str]]) -> CheckResult:
        start = time.monotonic()
        try:
            ok, details = fn()
            status = CheckStatus.PASS if ok else CheckStatus.FAIL
        except Exception as exc:
            status = CheckStatus.ERROR
            details = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}"
        elapsed = (time.monotonic() - start) * 1000
        r = CheckResult(cid, desc, status, details, elapsed)
        self.results.append(r)
        icon = {"PASS": "✅", "FAIL": "❌", "ERROR": "💥"}[status.value]
        print(f"  {icon} {cid} — {desc}")
        if details and status != CheckStatus.PASS:
            for line in details.strip().split("\n")[:5]:
                print(f"     {line}")
        return r

    def _load_module(self):
        if self._test_module is None:
            adapter_path = os.path.join(self.root, self.ADAPTER_PATH)
            test_path = os.path.join(self.root, "tests")
            sys.path.insert(0, adapter_path)
            sys.path.insert(0, test_path)
            import importlib
            self._test_module = importlib.import_module("test_grants_adapter")
        return self._test_module

    def check_file_existence(self) -> Tuple[bool, str]:
        path = os.path.join(self.root, self.TEST_FILE)
        if not os.path.isfile(path):
            return False, f"Not found: {self.TEST_FILE}"
        with open(path) as f:
            lines = sum(1 for _ in f)
        return True, f"{lines} lines"

    def check_total_count(self) -> Tuple[bool, str]:
        m = self._load_module()
        total = len(m.ALL_TEST_CASES)
        if total < 800: return False, f"Need 800+, got {total}"
        return True, f"{total} >= 800"

    def check_categories(self) -> Tuple[bool, str]:
        m = self._load_module()
        cats = {
            "structural": m.STRUCTURAL_VALIDATION_TESTS,
            "sanitization": m.SANITIZATION_TESTS,
            "hard_block": m.HARD_BLOCK_TESTS,
            "policy_block": m.POLICY_BLOCK_TESTS,
            "mercy": m.MERCY_TESTS,
            "language": m.LANGUAGE_TESTS,
            "bias": m.BIAS_TESTS,
            "session": m.SESSION_TESTS,
        }
        issues = []
        for name, cases in sorted(cats.items()):
            print(f"     {'✅' if len(cases) >= 100 else '❌'} {name:20s} {len(cases):4d}")
            if len(cases) < 100: issues.append(f"{name}: {len(cases)} < 100")
        total = sum(len(c) for c in cats.values())
        if total != len(m.ALL_TEST_CASES): issues.append(f"Sum {total} != ALL_TEST_CASES {len(m.ALL_TEST_CASES)}")
        return (not bool(issues), "; ".join(issues)) if issues else (True, "All 8 categories >= 100")

    def check_linguistic_groups(self) -> Tuple[bool, str]:
        m = self._load_module()
        groups = Counter(tc.linguistic_group for tc in m.ALL_TEST_CASES)
        missing = [g for g in ["en-US","pt-BR","es","sw"] if groups.get(g, 0) == 0]
        if missing: return False, f"Missing groups: {missing}"
        return True, f"All 4 groups: {dict(groups)}"

    def check_ground_truth(self) -> Tuple[bool, str]:
        m = self._load_module()
        truths = Counter(tc.ground_truth for tc in m.ALL_TEST_CASES)
        missing = [rt for rt in ["ALLOW","BLOCK","HARD_BLOCK"] if truths.get(rt, 0) == 0]
        if missing: return False, f"Missing ground truths: {missing}"
        return True, f"Coverage: {dict(truths)}"

    def check_data_integrity(self) -> Tuple[bool, str]:
        m = self._load_module()
        issues = []
        for tc in m.ALL_TEST_CASES:
            if not tc.id: issues.append("Case missing id")
            elif not tc.category: issues.append(f"{tc.id}: missing category")
            elif len(tc.description) < 10: issues.append(f"{tc.id}: desc too short ({len(tc.description)}c)")
            elif not tc.ground_truth: issues.append(f"{tc.id}: missing ground_truth")
            elif not tc.linguistic_group: issues.append(f"{tc.id}: missing linguistic_group")
            elif not tc.proposal_data: issues.append(f"{tc.id}: missing proposal_data")
            elif "applicant_id" not in tc.proposal_data: issues.append(f"{tc.id}: missing applicant_id")
        if issues: return False, f"{len(issues)} issues: " + "; ".join(issues[:3])
        return True, f"All {len(m.ALL_TEST_CASES)} cases pass integrity"

    def check_id_uniqueness(self) -> Tuple[bool, str]:
        m = self._load_module()
        ids = [tc.id for tc in m.ALL_TEST_CASES]
        dupes = [i for i in set(ids) if ids.count(i) > 1]
        if dupes: return False, f"Duplicates: {dupes[:5]}"
        pattern = re.compile(r'^[A-Z]{2,4}-\d{3,4}$')
        invalid = [i for i in ids if not pattern.match(i)]
        if invalid: return False, f"Invalid format: {invalid[:5]}"
        prefix_map = {"SV":"structural","SAN":"sanitization","HB":"hard_block","PB":"policy_block","MC":"mercy","LANG":"language","BIAS":"bias","SES":"session"}
        mismatches = []
        for tc in m.ALL_TEST_CASES:
            pfx = tc.id.split("-")[0]
            expected = prefix_map.get(pfx)
            if expected and tc.category != expected:
                mismatches.append(f"{tc.id}: {pfx}→{expected} but cat={tc.category}")
        if mismatches: return False, "; ".join(mismatches[:3])
        return True, f"{len(set(ids))} unique IDs, format OK"

    def check_hardblock_consistency(self) -> Tuple[bool, str]:
        m = self._load_module()
        issues = []
        for tc in m.HARD_BLOCK_TESTS:
            if tc.ground_truth == "HARD_BLOCK" and not tc.should_raise:
                issues.append(f"{tc.id}: HARD_BLOCK but should_raise=False")
            if tc.ground_truth == "HARD_BLOCK" and tc.expected_exception != "GrantBlockedError":
                issues.append(f"{tc.id}: expected_exception={tc.expected_exception}")
        return (not bool(issues), "; ".join(issues)) if issues else (True, f"{len(m.HARD_BLOCK_TESTS)} consistent")

    def run_all(self) -> bool:
        print(f"\n{'='*60}")
        print(f"  CI Week 3 — Adversarial Test Cases (800+)")
        print(f"{'='*60}\n")
        checks = [
            ("W3.1", "Test file existence", self.check_file_existence),
            ("W3.2", "800+ cases total", self.check_total_count),
            ("W3.3", "8 categories × 100+", self.check_categories),
            ("W3.4", "4 linguistic groups", self.check_linguistic_groups),
            ("W3.5", "Ground truth coverage", self.check_ground_truth),
            ("W3.6", "TestCase data integrity", self.check_data_integrity),
            ("W3.7", "ID format + uniqueness", self.check_id_uniqueness),
            ("W3.8", "Hard block consistency", self.check_hardblock_consistency),
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
    ci = Week3CI(project_root=root)
    sys.exit(0 if ci.run_all() else 1)
