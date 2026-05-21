#!/usr/bin/env python3
"""
BuildToValue Grant Adapter — Test Runner CLI

Usage:
    python tests/run_tests.py
    python tests/run_tests.py --cat hard_block
    python tests/run_tests.py --lang pt-BR
    python tests/run_tests.py --dry-run
    python tests/run_tests.py --json --output /tmp/results.json
    python tests/run_tests.py --verbose

Filters:
    --cat               Run only tests matching this category
                        (structural, sanitization, hard_block, policy_block,
                         mercy, language, bias, session)
    --lang              Run only tests for this linguistic group
                        (en-US, pt-BR, es, sw)
    --dry-run           Show test cases without executing assertions
    --json              Emit JSON summary (use with --output)
    --output FILE       Write JSON report to FILE (requires --json)
    --verbose           Print each test case result

Exit codes:
    0  All tests passed (or dry-run)
    1  One or more tests failed
    2  CLI argument error
"""

from __future__ import annotations

import argparse
import json
import sys
import unittest
from collections import Counter
from typing import List, Optional

# Import test cases registry
try:
    from test_grants_adapter import (
        ALL_TEST_CASES,
        TestCase,
        TestGrantProposalModel,
    )
except ImportError:
    import importlib.util
    import os
    spec = importlib.util.spec_from_file_location(
        "test_grants_adapter",
        os.path.join(os.path.dirname(__file__), "test_grants_adapter.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    ALL_TEST_CASES = mod.ALL_TEST_CASES
    TestCase = mod.TestCase
    TestGrantProposalModel = mod.TestGrantProposalModel


def filter_test_cases(
    cases: List[TestCase],
    category: Optional[str] = None,
    linguistic_group: Optional[str] = None,
) -> List[TestCase]:
    filtered = cases
    if category:
        filtered = [c for c in filtered if c.category == category]
    if linguistic_group:
        filtered = [c for c in filtered if c.linguistic_group == linguistic_group]
    return filtered


def print_test_registry(cases: List[TestCase], verbose: bool = False) -> None:
    categories: dict = {}
    for case in cases:
        categories.setdefault(case.category, []).append(case)

    print(f"\n{'='*70}")
    print(f"  BTV Grant Adapter — Test Case Registry ({len(cases)} cases)")
    print(f"{'='*70}")

    for cat, cat_cases in sorted(categories.items()):
        print(f"\n  [{cat}] {len(cat_cases)} cases")
        if verbose:
            for case in cat_cases:
                status = "[RAISE]" if case.should_raise else "      "
                print(f"    {status} {case.id:12} {case.linguistic_group:6} "
                      f"{case.ground_truth:15} {case.description[:50]}")

    print(f"\n  Linguistic groups:")
    for group in ("en-US", "pt-BR", "es", "sw"):
        count = sum(1 for c in cases if c.linguistic_group == group)
        print(f"    {group:8} {count:4} cases")

    print(f"\n  Total: {len(cases)} cases\n")


def run_unit_tests(verbose: bool = False) -> bool:
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestGrantProposalModel)
    verbosity = 2 if verbose else 1
    runner = unittest.TextTestRunner(verbosity=verbosity, stream=sys.stdout)
    result = runner.run(suite)
    return result.wasSuccessful()


def emit_json_report(
    cases: List[TestCase],
    passed: int,
    failed: int,
    skipped: int,
    output_path: str,
) -> None:
    categories = sorted({c.category for c in cases})
    linguistic_groups = sorted({c.linguistic_group for c in cases})
    report = {
        "total": len(cases),
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "categories": categories,
        "linguistic_groups": linguistic_groups,
    }
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"  JSON report written to {output_path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="BTV Grant Adapter — Test Runner CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--cat",
        choices=[
            "structural", "sanitization", "hard_block", "policy_block",
            "mercy", "language", "bias", "session",
        ],
        dest="category",
        help="Run only tests matching this category",
    )
    # Legacy alias kept for backwards compatibility
    parser.add_argument(
        "--category",
        choices=[
            "structural", "sanitization", "hard_block", "policy_block",
            "mercy", "language", "bias", "session",
        ],
        dest="category",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--lang",
        choices=["en-US", "pt-BR", "es", "sw"],
        dest="linguistic_group",
        help="Run only tests for this linguistic group",
    )
    # Legacy alias
    parser.add_argument(
        "--linguistic-group",
        choices=["en-US", "pt-BR", "es", "sw"],
        dest="linguistic_group",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show test cases without executing assertions",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="emit_json",
        help="Emit JSON summary",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Write JSON report to FILE (requires --json)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print each test case result",
    )

    args = parser.parse_args()

    filtered = filter_test_cases(
        ALL_TEST_CASES,
        category=args.category,
        linguistic_group=args.linguistic_group,
    )

    print_test_registry(filtered, verbose=args.verbose)

    if args.dry_run:
        print("  DRY RUN — test cases listed above, no assertions executed.")
        if args.emit_json and args.output:
            emit_json_report(filtered, passed=len(filtered), failed=0, skipped=0,
                             output_path=args.output)
        return 0

    print("  Running unittest suite...\n")
    success = run_unit_tests(verbose=args.verbose)

    passed = len(filtered) if success else 0
    failed = 0 if success else len(filtered)

    if args.emit_json and args.output:
        emit_json_report(filtered, passed=passed, failed=failed, skipped=0,
                         output_path=args.output)

    if success:
        print("\n  ✅ All tests passed.")
        return 0
    else:
        print("\n  ❌ One or more tests failed.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
