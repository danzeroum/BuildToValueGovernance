#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# BuildToValue Red-Team — Orquestrador
# Roda todos os RT-XXX scripts e agrega resultados
# Usage: cd ops/red-team && bash run-all.sh
# ═══════════════════════════════════════════════════════════════

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

TOTAL_PASS=0
TOTAL_FAIL=0
FAILED_SCRIPTS=()

echo "═══════════════════════════════════════════════════════"
echo "  BuildToValue Red-Team Suite"
echo "  Started: $(date)"
echo "═══════════════════════════════════════════════════════"

for script in "$SCRIPT_DIR"/RT-*.sh; do
    echo ""
    echo "▶ Running: $(basename "$script")"
    if bash "$script"; then
        TOTAL_PASS=$((TOTAL_PASS + 1))
    else
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
        FAILED_SCRIPTS+=("$(basename "$script")")
    fi
done

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  RED-TEAM SUITE RESULTS"
echo "  Scripts passed: $TOTAL_PASS | Failed: $TOTAL_FAIL"
[[ ${#FAILED_SCRIPTS[@]} -gt 0 ]] && echo "  Failed: ${FAILED_SCRIPTS[*]}"
echo "  Reports: ops/red-team/reports/"
echo "═══════════════════════════════════════════════════════"

[[ $TOTAL_FAIL -eq 0 ]] && exit 0 || exit 1