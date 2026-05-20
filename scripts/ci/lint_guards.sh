#!/usr/bin/env bash
# BuildToValue — Lint Guards (PR-3)
#
# Runs a set of fast static checks that catch regressions of recently fixed
# security and architectural issues. Designed to be cheap enough for pre-commit
# and authoritative enough for CI.
#
# Exit code: 0 if all guards pass; non-zero otherwise.
#
# Usage:
#   scripts/ci/lint_guards.sh            # check the whole tree
#   scripts/ci/lint_guards.sh --staged   # check only staged files (pre-commit)
#
# Guards:
#   G1  sqlite3.connect(  — only allowed inside buildtovalue/security/db.py
#   G2  Hardcoded HMAC sentinels in source (S-01 regression)
#   G3  CORS allow_origins=["*"]  outside known dev defaults

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

MODE="all"
if [[ "${1:-}" == "--staged" ]]; then
  MODE="staged"
fi

FAILED=0

# ─────────────────────────────────────────────────────────────────────────────
# Helper: list files in scope
# ─────────────────────────────────────────────────────────────────────────────
list_python_files() {
  if [[ "$MODE" == "staged" ]]; then
    git diff --cached --name-only --diff-filter=ACMR \
      | grep -E '^python/buildtovalue/.*\.py$' || true
  else
    find python/buildtovalue -name '*.py' -type f 2>/dev/null || true
  fi
}

list_yaml_or_compose() {
  if [[ "$MODE" == "staged" ]]; then
    git diff --cached --name-only --diff-filter=ACMR \
      | grep -E '\.(yml|yaml|toml)$' || true
  else
    {
      find ops -type f \( -name '*.yml' -o -name '*.yaml' -o -name '*.toml' \) 2>/dev/null
      find . -maxdepth 2 -name 'fly.toml' -type f 2>/dev/null
    }
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# G1 — Direct sqlite3.connect( forbidden outside the central helper
# ─────────────────────────────────────────────────────────────────────────────
echo "[G1] sqlite3.connect( usage outside buildtovalue/security/db.py"
G1_HITS="$(
  list_python_files \
    | grep -v 'buildtovalue/security/db.py' \
    | xargs --no-run-if-empty grep -nE 'sqlite3\.connect\(' \
    || true
)"
if [[ -n "$G1_HITS" ]]; then
  echo "FAIL: direct sqlite3.connect( found. Use buildtovalue.security.sqlite_connect_wal."
  echo "$G1_HITS"
  FAILED=1
else
  echo "OK"
fi

# ─────────────────────────────────────────────────────────────────────────────
# G2 — Insecure HMAC sentinels reintroduced (S-01)
# ─────────────────────────────────────────────────────────────────────────────
echo "[G2] Hardcoded HMAC sentinels (S-01 regression check)"
# Patterns we want to forbid in source (allowed inside the keys.py marker list
# and inside tests that explicitly reference them).
# Note: ``btv-dev-key-NOT`` is the literal sentinel; ``btv-dev-key`` alone is
# kept off the list to avoid false positives in CLI examples and test API keys.
PATTERNS='NOT-FOR-PRODUCTION|demo-key-NOT|btv-policy-engine-v1-adr011|btv-verdict-hmac-v1|btv-kernel-supply-guard-v1|btv-dev-key-NOT|btv-dev-jwt'

# Allowlist: keys.py itself enumerates the sentinels as a denylist; tests may
# reference them when validating the rejection path; dev-only compose files
# are intentional fallbacks for onboarding (they are clearly marked in name);
# ops/.env will be excised by the scheduled git filter-repo.
# Each entry matches the leading "path:" produced by git grep -n.
ALLOWLIST_REGEX='^(python/buildtovalue/security/keys\.py|python/buildtovalue/api/routes/auth\.py|rust/kernel/src/keys\.rs|tests/|.*test.*\.py:|ops/\.env(\.example)?:|ops/docker-compose\.(quickstart|e2e)\.yml:|docs/.*\.md:|CHANGELOG[^:]*:|scripts/ci/lint_guards\.sh:)'

G2_HITS="$(
  git grep -nE "$PATTERNS" -- ':!**/__pycache__/**' 2>/dev/null \
    | grep -vE "$ALLOWLIST_REGEX" \
    || true
)"
if [[ -n "$G2_HITS" ]]; then
  echo "FAIL: insecure HMAC sentinel found in source. Rotate via BTV_HMAC_KEY env var."
  echo "$G2_HITS"
  FAILED=1
else
  echo "OK"
fi

# ─────────────────────────────────────────────────────────────────────────────
# G3 — Wildcard CORS reintroduced
# ─────────────────────────────────────────────────────────────────────────────
echo "[G3] CORS allow_origins=[\"*\"] regression"
G3_HITS="$(
  list_python_files \
    | xargs --no-run-if-empty grep -nE 'allow_origins\s*=\s*\[\s*"\*"\s*\]' \
    || true
)"
if [[ -n "$G3_HITS" ]]; then
  echo "FAIL: wildcard CORS found. Use BTV_CORS_ORIGINS env var."
  echo "$G3_HITS"
  FAILED=1
else
  echo "OK"
fi

# ─────────────────────────────────────────────────────────────────────────────
exit "$FAILED"
