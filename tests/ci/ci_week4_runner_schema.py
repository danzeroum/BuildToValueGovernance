#!/usr/bin/env python3
"""
CI Week 4 — Runner CLI + Dataset Schema

Checks:
  W4.1  File existence (tests/run_tests.py, tests/adversarial_data/dataset_schema.json)
  W4.2  Runner CLI --help
  W4.3  Runner --dry-run exits 0
  W4.4  Runner --cat filter works for all 8 categories
  W4.5  Runner --lang filter works for all 4 linguistic groups
  W4.6  Runner --json --output produces valid JSON with required keys
  W4.7  Dataset schema: Draft-07, required fields, minItems>=800, sw=null
  W4.8  Unit tests executable (PYTHONPATH set)

Exit codes: 0=pass, 1=fail
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import traceback
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


class Week4CI:
    RUNNER = "tests/run_tests.py"
    SCHEMA = "tests/adversarial_data/dataset_schema.json"
    ADAPTER_PATH = "sdk/integrations/grants"

    def __init__(self, project_root: str = ".") -> None:
        self.root = project_root
        self.results: List[CheckResult] = []
        self._runner = os.path.join(project_root, self.RUNNER)
        self._schema = os.path.join(project_root, self.SCHEMA)
        self._tests_dir = os.path.join(project_root, "tests")
        self._adapter_dir = os.path.join(project_root, self.ADAPTER_PATH)

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

    def _run_runner(self, args: List[str], capture: bool = True) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env["PYTHONPATH"] = f"{self._adapter_dir}:{self._tests_dir}:" + env.get("PYTHONPATH", "")
        return subprocess.run(
            [sys.executable, self._runner] + args,
            cwd=self._tests_dir,
            env=env,
            capture_output=capture,
            text=True,
        )

    def check_file_existence(self) -> Tuple[bool, str]:
        missing = []
        for path in [self._runner, self._schema]:
            if not os.path.isfile(path): missing.append(path)
        return (not bool(missing), f"Missing: {missing}") if missing else (True, "run_tests.py + schema present")

    def check_cli_help(self) -> Tuple[bool, str]:
        result = self._run_runner(["--help"])
        if result.returncode != 0:
            return False, f"--help exited {result.returncode}: {result.stderr[:200]}"
        return True, "--help exits 0"

    def check_dry_run(self) -> Tuple[bool, str]:
        result = self._run_runner(["--dry-run"])
        if result.returncode != 0:
            return False, f"--dry-run exited {result.returncode}: {result.stderr[:200]}"
        return True, "--dry-run exits 0"

    def check_category_filter(self) -> Tuple[bool, str]:
        categories = ["structural","sanitization","hard_block","policy_block","mercy","language","bias","session"]
        issues = []
        for cat in categories:
            result = self._run_runner(["--cat", cat, "--dry-run"])
            output = result.stdout + result.stderr
            if cat not in output:
                issues.append(f"--cat {cat}: not in output")
        return (not bool(issues), "; ".join(issues)) if issues else (True, "All 8 categories filter OK")

    def check_lang_filter(self) -> Tuple[bool, str]:
        langs = ["en-US","pt-BR","es","sw"]
        issues = []
        for lang in langs:
            result = self._run_runner(["--lang", lang, "--dry-run"])
            output = result.stdout + result.stderr
            if lang not in output:
                issues.append(f"--lang {lang}: not in output")
        return (not bool(issues), "; ".join(issues)) if issues else (True, "All 4 langs filter OK")

    def check_json_output(self) -> Tuple[bool, str]:
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_path = f.name
        try:
            result = self._run_runner(["--dry-run", "--json", "--output", out_path])
            if result.returncode != 0:
                return False, f"exited {result.returncode}: {result.stderr[:200]}"
            with open(out_path) as f:
                d = json.load(f)
            required_keys = ["total","passed","failed","skipped","categories","linguistic_groups"]
            missing = [k for k in required_keys if k not in d]
            if missing: return False, f"Missing keys: {missing}"
            return True, f"JSON valid: total={d['total']}"
        finally:
            try:
                os.unlink(out_path)
            except OSError:
                pass

    def check_schema(self) -> Tuple[bool, str]:
        with open(self._schema) as f:
            s = json.load(f)
        issues = []
        if s.get("$schema") != "http://json-schema.org/draft-07/schema#":
            issues.append(f"Wrong $schema: {s.get('$schema')}")
        for field in ["version","generated_at","total_cases","categories","linguistic_groups","cases"]:
            if field not in s.get("required", []): issues.append(f"Missing required: {field}")
        if s["properties"]["cases"]["minItems"] < 800: issues.append("minItems < 800")
        lg = s["properties"]["linguistic_groups"]["items"]["enum"]
        if set(lg) != {"en-US","pt-BR","es","sw"}: issues.append(f"Bad groups: {lg}")
        sw_props = s["properties"]["bias_declarations"]["properties"]["sw"]["properties"]
        if sw_props["fpr"]["type"] != "null": issues.append("sw.fpr type != null")
        if sw_props["fnr"]["type"] != "null": issues.append("sw.fnr type != null")
        return (not bool(issues), "; ".join(issues)) if issues else (True, "Draft-07, required, minItems>=800, sw=null")

    def check_unit_tests(self) -> Tuple[bool, str]:
        env = os.environ.copy()
        env["PYTHONPATH"] = f"{self._adapter_dir}:{self._tests_dir}:" + env.get("PYTHONPATH", "")
        result = subprocess.run(
            [sys.executable, "-m", "unittest", "test_grants_adapter", "-v"],
            cwd=self._tests_dir,
            env=env,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            stderr_tail = result.stderr.strip().split("\n")[-5:]
            return False, "\n".join(stderr_tail)
        return True, "unittest executed OK"

    def run_all(self) -> bool:
        print(f"\n{'='*60}")
        print(f"  CI Week 4 — Runner CLI + Dataset Schema")
        print(f"{'='*60}\n")
        checks = [
            ("W4.1", "File existence", self.check_file_existence),
            ("W4.2", "Runner CLI --help", self.check_cli_help),
            ("W4.3", "Runner --dry-run", self.check_dry_run),
            ("W4.4", "Category filter", self.check_category_filter),
            ("W4.5", "Linguistic group filter", self.check_lang_filter),
            ("W4.6", "JSON output", self.check_json_output),
            ("W4.7", "Dataset schema", self.check_schema),
            ("W4.8", "Unit tests", self.check_unit_tests),
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
    ci = Week4CI(project_root=root)
    sys.exit(0 if ci.run_all() else 1)
