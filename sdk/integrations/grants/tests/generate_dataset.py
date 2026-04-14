"""
BuildToValue Grant Decision Adapter — Dataset Generator

Generates a JSON fixture file with all 800 adversarial test cases
for use in CI/CD pipelines, documentation, and statistical analysis.

Usage:
    python generate_dataset.py
    python generate_dataset.py --output fixtures/adversarial_dataset.json
    python generate_dataset.py --summary-only
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.test_adversarial import ALL_TEST_CASES, TestCase


def test_case_to_dict(tc: TestCase) -> Dict[str, Any]:
    """Serialize a TestCase to a JSON-serializable dict."""
    return {
        "id": tc.id,
        "category": tc.category,
        "description": tc.description,
        "ground_truth": tc.ground_truth,
        "linguistic_group": tc.linguistic_group,
        "risk_level": tc.risk_level,
        "proposal_data": tc.proposal_data,
        "mock_verdict_override": (
            {k: v.value if hasattr(v, "value") else v
             for k, v in tc.mock_verdict_override.items()}
            if tc.mock_verdict_override else None
        ),
        "should_raise": tc.should_raise,
        "expected_exception": tc.expected_exception,
        "notes": tc.notes,
    }


def generate_dataset(output_path: str, summary_only: bool = False) -> None:
    """Generate the adversarial dataset JSON file."""
    total = len(ALL_TEST_CASES)
    categories: Dict[str, int] = {}
    linguistic_groups: Dict[str, int] = {}
    ground_truths: Dict[str, int] = {}

    for tc in ALL_TEST_CASES:
        categories[tc.category] = categories.get(tc.category, 0) + 1
        linguistic_groups[tc.linguistic_group] = linguistic_groups.get(tc.linguistic_group, 0) + 1
        ground_truths[tc.ground_truth] = ground_truths.get(tc.ground_truth, 0) + 1

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "schema_version": "1.0.0",
        "total_cases": total,
        "categories": categories,
        "linguistic_groups": linguistic_groups,
        "ground_truths": ground_truths,
        "invariants": {
            "hard_block_contestable_false": "All HARD_BLOCK cases must have contestable=False",
            "swahili_bias_null": "All sw cases must have BiasDeclaration FPR=None, FNR=None",
            "hmac_sha256": "session_id derives from HMAC-SHA256, NOT hashlib.blake3",
            "json_input": "to_btv_input() produces JSON minified, NOT text with English prefixes",
            "fail_secure": "hard_blocked gate checked BEFORE action (ADR-043)",
        },
    }

    if summary_only:
        print(json.dumps(summary, indent=2))
        return

    dataset = {
        "meta": summary,
        "test_cases": [test_case_to_dict(tc) for tc in ALL_TEST_CASES],
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(dataset, f, ensure_ascii=False, indent=2)

    print(f"Dataset written to: {output_path}")
    print(f"Total cases: {total}")
    print(f"Categories: {json.dumps(categories, indent=2)}")
    print(f"Linguistic groups: {json.dumps(linguistic_groups, indent=2)}")
    print(f"Ground truths: {json.dumps(ground_truths, indent=2)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate BTV Grant adversarial dataset")
    parser.add_argument(
        "--output",
        default=os.path.join(os.path.dirname(__file__), "fixtures", "adversarial_dataset.json"),
    )
    parser.add_argument("--summary-only", action="store_true")
    args = parser.parse_args()
    generate_dataset(output_path=args.output, summary_only=args.summary_only)
