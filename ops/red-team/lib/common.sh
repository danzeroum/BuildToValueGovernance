#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# BuildToValue Red-Team — Common Library
# Shared helpers para todos os RT-XXX scripts
# ═══════════════════════════════════════════════════════════════

GATEWAY="${GATEWAY:-http://localhost:8080}"
GOVERNANCE="${GOVERNANCE:-http://localhost:8000}"

# Contadores globais (importados pelo script pai)
RT_PASS=0
RT_FAIL=0
RT_TOTAL=0
RT_DETECTIONS=0
RT_BYPASSES=0
RT_FP=0

# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

rt_validate() {
    curl -s --max-time 20 -X POST "$GATEWAY/v1/validate" \
        -H "Content-Type: application/json" \
        -d "{\"input\": \"$1\"}"
}

rt_get_field() {
    echo "$1" | python -c "import sys,json; print(json.load(sys.stdin).get('$2',''))" 2>/dev/null || echo ""
}

rt_get_int() {
    echo "$1" | python -c "import sys,json; print(json.load(sys.stdin).get('$2',0))" 2>/dev/null || echo "0"
}

# Verifica que ataque FOI detectado (detection test)
rt_should_detect() {
    local name="$1" response="$2" expected_action="${3:-BLOCK}"
    RT_TOTAL=$((RT_TOTAL + 1))
    local action
    action=$(rt_get_field "$response" "action")
    local finding_count
    finding_count=$(rt_get_int "$response" "finding_count")

    if [[ "$action" == "$expected_action" || "$action" == "BLOCK" || "$action" == "EDUCATE" || "$finding_count" -gt 0 ]]; then
        echo "  ✅ [DETECTED] $name → action=$action findings=$finding_count"
        RT_PASS=$((RT_PASS + 1))
        RT_DETECTIONS=$((RT_DETECTIONS + 1))
    else
        echo "  ❌ [BYPASS]   $name → action=$action findings=$finding_count (EXPECTED BLOCK)"
        RT_FAIL=$((RT_FAIL + 1))
        RT_BYPASSES=$((RT_BYPASSES + 1))
    fi
}

# Verifica que input legítimo NÃO foi bloqueado (false positive test)
rt_should_allow() {
    local name="$1" response="$2"
    RT_TOTAL=$((RT_TOTAL + 1))
    local action
    action=$(rt_get_field "$response" "action")

    if [[ "$action" == "ALLOW" || "$action" == "LOG" ]]; then
        echo "  ✅ [ALLOWED]  $name → action=$action (no false positive)"
        RT_PASS=$((RT_PASS + 1))
    else
        echo "  ⚠️  [FP]       $name → action=$action (FALSE POSITIVE)"
        RT_FAIL=$((RT_FAIL + 1))
        RT_FP=$((RT_FP + 1))
    fi
}

# Salva relatório JSON
rt_save_report() {
    local script_id="$1" script_name="$2"
    local report_file="reports/${script_id}-$(date +%Y%m%d-%H%M%S).json"
    local detection_rate=0
    local fpr=0

    [[ $RT_DETECTIONS -gt 0 ]] && detection_rate=$(python -c "print(round($RT_DETECTIONS/max($RT_TOTAL,1)*100,1))")
    [[ $RT_FP -gt 0 ]] && fpr=$(python -c "print(round($RT_FP/max($RT_TOTAL,1)*100,1))")

    mkdir -p "$(dirname "$report_file")"
    cat > "$report_file" << EOF
{
    "script_id": "$script_id",
    "script_name": "$script_name",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "gateway": "$GATEWAY",
    "results": {
        "total": $RT_TOTAL,
        "passed": $RT_PASS,
        "failed": $RT_FAIL,
        "detections": $RT_DETECTIONS,
        "bypasses": $RT_BYPASSES,
        "false_positives": $RT_FP,
        "detection_rate_pct": $detection_rate,
        "fpr_pct": $fpr
    },
    "bias_declaration_comparison": {
        "declared_fnr_pct": 18.0,
        "declared_fpr_pct": 8.0,
        "measured_bypass_rate_pct": $( [[ $RT_TOTAL -gt 0 ]] && python -c "print(round($RT_BYPASSES/max($RT_TOTAL,1)*100,1))" || echo 0 ),
        "measured_fpr_pct": $fpr
    }
}
EOF
    echo ""
    echo "  📄 Report: $report_file"
}

# Summary final
rt_summary() {
    local script_id="$1" script_name="$2"
    echo ""
    echo "═══════════════════════════════════════════════════════"
    echo "  $script_id — $script_name"
    echo "  Detections: $RT_DETECTIONS | Bypasses: $RT_BYPASSES | FP: $RT_FP"
    echo "  RESULTS: $RT_PASS passed, $RT_FAIL failed (total $RT_TOTAL)"
    echo "═══════════════════════════════════════════════════════"
    rt_save_report "$script_id" "$script_name"
    [[ $RT_BYPASSES -eq 0 ]] && exit 0 || exit 1
}