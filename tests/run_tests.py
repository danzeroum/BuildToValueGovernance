#!/usr/bin/env python3
"""
BuildToValue Grant Adapter — Test Runner CLI

Usage:
    python tests/run_tests.py
    python tests/run_tests.py --category hard_block
    python tests/run_tests.py --linguistic-group pt-BR
    python tests/run_tests.py --dry-run
    python tests/run_tests.py --verbose
    python tests/run_tests.py --category bias_declaration --verbose

Filters:
    --category          Run only tests matching this category
                        (structural, sanitization, hard_block, policy,
                         mercy, language, bias_declaration, session_id)
    --linguistic-group  Run only tests for this linguistic group
                        (en-US, pt-BR, es, sw)
    --dry-run           Show test cases without executing assertions
    --verbose           Print each test case result

Exit codes:
    0  All tests passed
    1  One or more tests failed
    2  CLI argument error
"""

from __future__ import annotations

import argparse
import sys
import unittest
from typing import List

# Import test cases registry
try:
    from test_grants_adapter import (
        ALL_TEST_CASES,
        TestCase,
        TestGrantProposalModel,
    )
except ImportError:
    # Allow running from repo root
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
    category: str | None = None,
    linguistic_group: str | None = None,
) -> List[TestCase]:
    """Apply category and linguistic_group filters to test cases."""
    filtered = cases
    if category:
        filtered = [c for c in filtered if c.category == category]
    if linguistic_group:
        filtered = [c for c in filtered if c.linguistic_group == linguistic_group]
    return filtered


def print_test_registry(
    cases: List[TestCase],
    verbose: bool = False,
) -> None:
    """Print test case registry in a tabular format."""
    categories: dict = {}
    for case in cases:
        categories.setdefault(case.category, []).append(case)

    print(f"\n{'='*70}")
    print(f"  BTV Grant Adapter — Test Case Registry ({len(cases)} cases)")
    print(f"{'='*70}")

    for cat, cat_cases in sorted(categories.items()):
        print(f"\n  [{cat.upper()}] {len(cat_cases)} cases")
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
    """Run the unittest suite. Returns True if all tests pass."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestGrantProposalModel)

    verbosity = 2 if verbose else 1
    runner = unittest.TextTestRunner(verbosity=verbosity, stream=sys.stdout)
    result = runner.run(suite)
    return result.wasSuccessful()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="BTV Grant Adapter — Test Runner CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--category",
        choices=[
            "structural", "sanitization", "hard_block", "policy",
            "mercy", "language", "bias_declaration", "session_id",
        ],
        help="Run only tests matching this category",
    )
    parser.add_argument(
        "--linguistic-group",
        choices=["en-US", "pt-BR", "es", "sw"],
        dest="linguistic_group",
        help="Run only tests for this linguistic group",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show test cases without executing assertions",
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
        return 0

    print("  Running unittest suite...\n")
    success = run_unit_tests(verbose=args.verbose)

    if success:
        print("\n  ✅ All tests passed.")
        return 0
    else:
        print("\n  ❌ One or more tests failed.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
