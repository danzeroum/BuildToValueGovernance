#!/bin/bash
# fix_imports.sh — Migrate legacy test imports to buildtovalue.*
# Run from: python/ directory
# Creates backup before changes

set -e

TESTS_DIR="tests"
BACKUP_DIR="tests/.backup_$(date +%Y%m%d_%H%M%S)"
LOG="tests/import_fix.log"

echo "=== Import Migration $(date) ===" > "$LOG"
echo "Backup dir: $BACKUP_DIR" >> "$LOG"

# Backup all .py test files
mkdir -p "$BACKUP_DIR"
find "$TESTS_DIR" -name "*.py" -exec cp --parents {} "$BACKUP_DIR/" \;
echo "✅ Backup created: $BACKUP_DIR"

# ── Fix 1: governance.* → buildtovalue.governance.* ──────────
find "$TESTS_DIR" -name "*.py" -exec grep -l "from governance\." {} \; | while read f; do
    echo "FIX1: $f" >> "$LOG"
    sed -i 's/from governance\./from buildtovalue.governance./g' "$f"
    sed -i 's/import governance\./import buildtovalue.governance./g' "$f"
done

# ── Fix 2: api.* → buildtovalue.api.* ────────────────────────
find "$TESTS_DIR" -name "*.py" -exec grep -l "from api\." {} \; | while read f; do
    echo "FIX2: $f" >> "$LOG"
    sed -i 's/from api\./from buildtovalue.api./g' "$f"
    sed -i 's/import api\./import buildtovalue.api./g' "$f"
done

# ── Fix 3: ffi_client → buildtovalue.core.ffi_client ─────────
find "$TESTS_DIR" -name "*.py" -exec grep -l "from ffi_client" {} \; | while read f; do
    echo "FIX3: $f" >> "$LOG"
    sed -i 's/from ffi_client/from buildtovalue.core.ffi_client/g' "$f"
done

# ── Fix 4: python.buildtovalue → buildtovalue (residual) ─────
find "$TESTS_DIR" -name "*.py" -exec grep -l "python\.buildtovalue" {} \; | while read f; do
    echo "FIX4: $f" >> "$LOG"
    sed -i 's/from python\.buildtovalue\./from buildtovalue./g' "$f"
done

# ── Report ────────────────────────────────────────────────────
echo ""
echo "=== Results ==="
REMAINING=$(grep -r "from governance\.\|from api\.validation\|from ffi_client\|python\.buildtovalue" "$TESTS_DIR" --include="*.py" -l 2>/dev/null || true)

if [ -z "$REMAINING" ]; then
    echo "✅ All imports fixed"
    echo "RESULT: ALL FIXED" >> "$LOG"
else
    echo "⚠️  Remaining issues:"
    echo "$REMAINING"
    echo "REMAINING: $REMAINING" >> "$LOG"
fi

echo ""
echo "Log: $LOG"
echo "Backup: $BACKUP_DIR"
echo "Verify: python -m pytest tests/ --collect-only 2>&1 | grep ERROR"