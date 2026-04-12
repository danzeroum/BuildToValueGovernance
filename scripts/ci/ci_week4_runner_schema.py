#!/usr/bin/env python3
"""
CI Week 4 — Runner + Schema + Integration

Validates the test runner, dataset schema, and integration readiness
from Week 4 of the GrantDecisionAdapter implementation.

Checks:
W4.1 Runner file existence (run_tests.py + dataset_schema.json)
W4.2 Runner CLI help (--help exits 0)
W4.3 Runner dry-run mode (exits 0, outputs plan)
W4.4 Runner category filter (--cat works for all 8)
W4.5 Runner linguistic group filter (--lang works for all 4)
W4.6 JSON output (--json produces valid JSON with required fields)
W4.7 Dataset schema (JSON Schema v7, minItems>=800, sw=null)
W4.8 Unit test execution (unittest discovers and runs)

Exit codes: 0=pass, 1=fail
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, List, Tuple


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


class Week4CI:
    RUNNER_PATH = "tests/run_tests.py"
    SCHEMA_PATH = "tests/adversarial_data/dataset_schema.json"
    TEST_DIR = "tests"

    def __init__(self, project_root: str = ".") -> None:
        self.root = project_root
        self.results: List[CheckResult] = []

    def _runner_cmd(self, *args: str, timeout: int = 30) -> Tuple[int, str, str]:
        """Execute the runner script and return (exit_code, stdout, stderr)."""
        runner = os.path.join(self.root, self.RUNNER_PATH)
        cmd = [sys.executable, runner] + list(args)
        env = os.environ.copy()
        env["PYTHONPATH"] = (
            os.path.join(self.root, "sdk/integrations/grants/btv_grants")
            + os.pathsep
            + os.path.join(self.root, self.TEST_DIR)
            + os.pathsep
            + env.get("PYTHONPATH", "")
        )
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, env=env,
                cwd=os.path.join(self.root, self.TEST_DIR),
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except FileNotFoundError:
            return -2, "", f"Runner not found: {runner}"

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
        icon = {"PASS": "\u2705", "FAIL": "\u274c", "SKIP": "\u23ed\ufe0f", "ERROR": "\U0001f4a5"}[status.value]
        print(f"  {icon} {cid} \u2014 {desc}")
        if details and status != CheckStatus.PASS:
            for line in details.strip().split("\n")[:5]:
                print(f"     {line}")
        return r

    # --- W4.1 ---
    def check_files(self) -> Tuple[bool, str]:
        issues = []
        for path, label in [(self.RUNNER_PATH, "run_tests.py"), (self.SCHEMA_PATH, "dataset_schema.json")]:
            full = os.path.join(self.root, path)
            if not os.path.isfile(full):
                issues.append(f"{label} not found")
        if issues:
            return False, "; ".join(issues)
        runner_lines = len(open(os.path.join(self.root, self.RUNNER_PATH)).readlines())
        return True, f"run_tests.py ({runner_lines} lines), dataset_schema.json present"

    # --- W4.2 ---
    def check_help(self) -> Tuple[bool, str]:
        code, out, err = self._runner_cmd("--help")
        if code != 0:
            return False, f"--help exited with code {code}"
        if not out.strip():
            return False, "--help produced no output"
        return True, "--help works, shows usage"

    # --- W4.3 ---
    def check_dry_run(self) -> Tuple[bool, str]:
        code, out, err = self._runner_cmd("--dry-run")
        if code != 0:
            return False, f"dry-run exited with code {code}: {err[:200]}"
        if "DRY RUN" not in out and "Would execute" not in out:
            return False, "Output doesn't contain dry-run indicators"
        return True, "dry-run exits 0, shows plan"

    # --- W4.4 ---
    def check_category_filter(self) -> Tuple[bool, str]:
        categories = ["structural", "sanitization", "hard_block", "policy_block",
                      "mercy", "language", "bias", "session"]
        issues = []
        for cat in categories:
            code, out, err = self._runner_cmd("--cat", cat, "--dry-run")
            if code != 0:
                issues.append(f"--cat {cat}: exit code {code}")
            elif cat not in out:
                issues.append(f"--cat {cat}: '{cat}' not in output")
        if issues:
            return False, "; ".join(issues[:3])
        return True, f"All {len(categories)} category filters work"

    # --- W4.5 ---
    def check_lang_filter(self) -> Tuple[bool, str]:
        langs = ["en-US", "pt-BR", "es", "sw"]
        issues = []
        for lang in langs:
            code, out, err = self._runner_cmd("--lang", lang, "--dry-run")
            if code != 0:
                issues.append(f"--lang {lang}: exit code {code}")
            elif lang not in out:
                issues.append(f"--lang {lang}: '{lang}' not in output")
        if issues:
            return False, "; ".join(issues[:3])
        return True, f"All {len(langs)} language filters work"

    # --- W4.6 ---
    def check_json_output(self) -> Tuple[bool, str]:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
            tmp_path = tmp.name

        try:
            code, out, err = self._runner_cmd("--dry-run", "--json", "--output", tmp_path)
            if code != 0:
                return False, f"JSON output failed: code {code}"

            if not os.path.isfile(tmp_path) or os.path.getsize(tmp_path) == 0:
                return False, "JSON file empty or not created"

            with open(tmp_path) as f:
                data = json.load(f)

            missing = []
            for field in ["total", "passed", "failed", "skipped", "categories", "linguistic_groups"]:
                if field not in data:
                    missing.append(field)

            if missing:
                return False, f"Missing JSON fields: {missing}"

            return True, f"Valid JSON: total={data['total']}, passed={data['passed']}, failed={data['failed']}"
        except json.JSONDecodeError as exc:
            return False, f"Invalid JSON: {exc}"
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    # --- W4.7 ---
    def check_schema(self) -> Tuple[bool, str]:
        schema_path = os.path.join(self.root, self.SCHEMA_PATH)
        try:
            with open(schema_path) as f:
                schema = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as exc:
            return False, f"Schema error: {exc}"

        issues = []

        if schema.get("$schema") != "http://json-schema.org/draft-07/schema#":
            issues.append(f"Not draft-07: {schema.get('$schema')}")

        for field in ["version", "generated_at", "total_cases", "categories", "linguistic_groups", "cases"]:
            if field not in schema.get("required", []):
                issues.append(f"Missing required field: {field}")

        min_items = schema.get("properties", {}).get("cases", {}).get("minItems", 0)
        if min_items < 800:
            issues.append(f"minItems={min_items}, expected >= 800")

        try:
            lg_enum = schema["properties"]["linguistic_groups"]["items"]["enum"]
            if set(lg_enum) != {"en-US", "pt-BR", "es", "sw"}:
                issues.append(f"lg enum: {lg_enum}")
        except (KeyError, TypeError):
            issues.append("Cannot read linguistic_groups enum")

        try:
            gt_enum = schema["properties"]["cases"]["items"]["properties"]["ground_truth"]["enum"]
            if "HARD_BLOCK" not in gt_enum:
                issues.append("HARD_BLOCK not in ground_truth enum")
            if "VALIDATION_ERROR" not in gt_enum:
                issues.append("VALIDATION_ERROR not in ground_truth enum")
        except (KeyError, TypeError):
            issues.append("Cannot read ground_truth enum")

        try:
            sw_props = schema["properties"]["bias_declarations"]["properties"]["sw"]["properties"]
            if sw_props.get("fpr", {}).get("type") != "null":
                issues.append("sw fpr type != null")
            if sw_props.get("fnr", {}).get("type") != "null":
                issues.append("sw fnr type != null")
        except (KeyError, TypeError):
            issues.append("Cannot read sw bias declaration schema")

        if issues:
            return False, "; ".join(issues)
        return True, "Draft-07, required fields, minItems>=800, sw=null"

    # --- W4.8 ---
    def check_unit_tests(self) -> Tuple[bool, str]:
        """Run unit tests from test_grants_adapter.py."""
        test_dir = os.path.join(self.root, self.TEST_DIR)
        adapter_dir = os.path.join(self.root, "sdk/integrations/grants/btv_grants")
        env = os.environ.copy()
        env["PYTHONPATH"] = adapter_dir + os.pathsep + test_dir + os.pathsep + env.get("PYTHONPATH", "")
        cmd = [sys.executable, "-m", "unittest", "test_grants_adapter", "-v"]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60,
                cwd=test_dir, env=env,
            )
            out = result.stdout + result.stderr
            if "OK" in out or result.returncode == 0:
                import re
                match = re.search(r"Ran (\d+) test", out)
                count = match.group(1) if match else "?"
                return True, f"{count} unit tests passed"
            else:
                return False, f"Unit tests failed (code {result.returncode}): {out[-300:]}"
        except subprocess.TimeoutExpired:
            return False, "Unit tests timed out (60s)"
        except Exception as exc:
            return False, f"Unit test error: {exc}"

    # ------------------------------------------------------------------
    def run_all(self) -> bool:
        print(f"\n{'='*60}")
        print(f" CI Week 4 \u2014 Runner + Schema")
        print(f"{'='*60}\n")

        checks = [
            ("W4.1", "File existence", self.check_files),
            ("W4.2", "Runner --help", self.check_help),
            ("W4.3", "Runner dry-run", self.check_dry_run),
            ("W4.4", "Category filters", self.check_category_filter),
            ("W4.5", "Language filters", self.check_lang_filter),
            ("W4.6", "JSON output", self.check_json_output),
            ("W4.7", "Dataset schema", self.check_schema),
            ("W4.8", "Unit tests", self.check_unit_tests),
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
    sys.exit(0 if Week4CI(root).run_all() else 1)
