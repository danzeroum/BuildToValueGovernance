#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# BuildToValue — E2E Curl Tests
# Validates full pipeline: Gateway (:8080) ↔ Governance (:8000)
# Usage: cd ops && bash e2e-tests.sh
# ═══════════════════════════════════════════════════════════════

set -uo pipefail

GATEWAY="http://localhost:8080"
GOVERNANCE="http://localhost:8000"
PASS=0
FAIL=0
SKIP=0
TOTAL=0

# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────
check() {
    local name="$1" field="$2" expected="$3" response="$4"
    TOTAL=$((TOTAL + 1))
    actual=$(echo "$response" | python -c "import sys,json; print(json.load(sys.stdin).get('$field',''))" 2>/dev/null || echo "PARSE_ERROR")
    if [[ "$actual" == *"$expected"* ]]; then
        echo "  ✅ $name: $field=$actual"
        PASS=$((PASS + 1))
    else
        echo "  ❌ $name: expected $field~$expected, got $actual"
        FAIL=$((FAIL + 1))
    fi
}

check_gte() {
    local name="$1" field="$2" min="$3" response="$4"
    TOTAL=$((TOTAL + 1))
    actual=$(echo "$response" | python -c "import sys,json; print(json.load(sys.stdin).get('$field',0))" 2>/dev/null || echo "0")
    if [[ "$actual" -ge "$min" ]]; then
        echo "  ✅ $name: $field=$actual (>=$min)"
        PASS=$((PASS + 1))
    else
        echo "  ❌ $name: expected $field>=$min, got $actual"
        FAIL=$((FAIL + 1))
    fi
}

skip() {
    local name="$1" reason="$2"
    TOTAL=$((TOTAL + 1))
    SKIP=$((SKIP + 1))
    echo "  ⚠️  SKIP $name: $reason"
}

validate() {
    local input="$1" session="${2:-}"
    local body="{\"input\": \"$input\""
    [[ -n "$session" ]] && body="$body, \"session_id\": \"$session\""
    body="$body}"
    curl -s --max-time 20 -X POST "$GATEWAY/v1/validate" \
        -H "Content-Type: application/json" \
        -d "$body"
}

sanitize() {
    curl -s --max-time 10 -X POST "$GATEWAY/v1/sanitize" \
        -H "Content-Type: application/json" \
        -d "{\"text\": \"$1\"}"
}

decide() {
    curl -s --max-time 20 -X POST "$GOVERNANCE/v1/decide" \
        -H "Content-Type: application/json" \
        -d "$1"
}

# ─────────────────────────────────────────────────────────────
# 0. Health Checks
# ─────────────────────────────────────────────────────────────
echo "═══ 0. Health Checks ═══"
R=$(curl -s --max-time 5 "$GATEWAY/health" || echo "{}")
check "Gateway health" "status" "ok" "$R"
R=$(curl -s --max-time 5 "$GOVERNANCE/health" || echo "{}")
check "Governance health" "status" "healthy" "$R"

# ─────────────────────────────────────────────────────────────
# 1. PII Validators
# ─────────────────────────────────────────────────────────────
echo ""
echo "═══ 1. PII Validators ═══"

echo "  --- CPF ---"
R=$(validate "CPF 123.456.789-09")
check "CPF detection" "action" "BLOCK" "$R"
check_gte "CPF findings" "finding_count" 1 "$R"
check "CPF contestable" "contestable" "True" "$R"

echo "  --- Email ---"
R=$(validate "contato: joao.silva@empresa.com.br")
check_gte "Email findings" "finding_count" 1 "$R"

echo "  --- Phone ---"
R=$(validate "ligue para +55 11 98765-4321")
check_gte "Phone findings" "finding_count" 1 "$R"

echo "  --- Credit Card ---"
R=$(validate "cartao 4111 1111 1111 1111")
check_gte "Credit card findings" "finding_count" 1 "$R"

echo "  --- CNPJ ---"
R=$(validate "CNPJ 11.222.333/0001-81")
check_gte "CNPJ findings" "finding_count" 1 "$R"

echo "  --- Clean input ---"
R=$(validate "ola tudo bem como vai")
check "Clean input" "action" "ALLOW" "$R"
check "Clean no findings" "finding_count" "0" "$R"

# ─────────────────────────────────────────────────────────────
# 2. Deobfuscation
# ─────────────────────────────────────────────────────────────
echo ""
echo "═══ 2. Deobfuscation ═══"

echo "  --- Base64 ---"
B64=$(python -c "import base64; print(base64.b64encode(b'CPF 123.456.789-09').decode())")
R=$(validate "$B64")
check_gte "Base64 deobfuscation" "finding_count" 1 "$R"

echo "  --- Hex ---"
HEX=$(python -c "print('48656c6c6f20576f726c642054657374')")
R=$(validate "$HEX")
check_gte "Hex deobfuscation" "finding_count" 1 "$R"

echo "  --- Leetspeak ---"
R=$(validate "3m41l t3st3@gm41l.c0m s3nh4 p4ssw0rd 1nj3ct d4t4 l34k")
check_gte "Leetspeak detection" "finding_count" 1 "$R"

# ─────────────────────────────────────────────────────────────
# 3. Injection Detection
# ─────────────────────────────────────────────────────────────
echo ""
echo "═══ 3. Injection Detection ═══"

echo "  --- SQL Injection ---"
R=$(validate "SELECT * FROM users; DROP TABLE users")
check "SQL injection" "action" "BLOCK" "$R"
check "SQL hard block" "hard_blocked" "True" "$R"

echo "  --- XSS ---"
R=$(validate "<script>alert('xss')</script>")
check "XSS detection" "action" "BLOCK" "$R"
check "XSS hard block" "hard_blocked" "True" "$R"

# ─────────────────────────────────────────────────────────────
# 4. PII Sanitization
# ─────────────────────────────────────────────────────────────
echo ""
echo "═══ 4. PII Sanitization ═══"

R=$(sanitize "email joao@empresa.com CPF 123.456.789-09")
SANITIZED=$(echo "$R" | python -c "import sys,json; print(json.load(sys.stdin).get('sanitized_text',''))" 2>/dev/null || echo "")
echo "  Sanitized: $SANITIZED"
TOTAL=$((TOTAL + 1))
if [[ "$SANITIZED" == *"***"* ]]; then
    echo "  ✅ PII masked"
    PASS=$((PASS + 1))
else
    echo "  ❌ PII not masked"
    FAIL=$((FAIL + 1))
fi
check_gte "Mask count" "masked_count" 2 "$R"

# ─────────────────────────────────────────────────────────────
# 5. Mercy Flow (Gilligan) — via governance direct
# ─────────────────────────────────────────────────────────────
echo ""
echo "═══ 5. Mercy Flow (direct governance) ═══"

SESSION="mercy-e2e-$(date +%s)"
echo "  Building trust (10 clean messages, session=$SESSION)..."
for i in $(seq 1 10); do
    decide "{\"finding_count\":0,\"critical_count\":0,\"composite_risk\":0.0,\"action\":\"ALLOW\",\"hard_blocked\":false,\"matched_policies\":[],\"session_id\":\"$SESSION\",\"profile\":\"\",\"input_text\":\"mensagem limpa $i\"}" > /dev/null
done

R=$(curl -s --max-time 5 "$GOVERNANCE/v1/trust/$SESSION" || echo "{}")
TRUST=$(echo "$R" | python -c "import sys,json; print(json.load(sys.stdin).get('trust_score',0))" 2>/dev/null || echo "0")
REQS=$(echo "$R" | python -c "import sys,json; print(json.load(sys.stdin).get('total_requests',0))" 2>/dev/null || echo "0")
echo "  Trust: $TRUST, Requests: $REQS"

# Now test with PII — mercy should soften
R=$(decide "{\"finding_count\":1,\"critical_count\":0,\"composite_risk\":0.5,\"action\":\"REDACT\",\"hard_blocked\":false,\"matched_policies\":[\"email->Redact\"],\"session_id\":\"$SESSION\",\"profile\":\"\",\"input_text\":\"email teste@gmail.com\"}")
ACTION=$(echo "$R" | python -c "import sys,json; print(json.load(sys.stdin).get('action',''))" 2>/dev/null || echo "")
MERCY=$(echo "$R" | python -c "import sys,json; print(json.load(sys.stdin).get('mercy_applied',''))" 2>/dev/null || echo "")
echo "  Action: $ACTION, Mercy: $MERCY"
TOTAL=$((TOTAL + 1))
if [[ "$MERCY" == "True" || "$ACTION" == "LOG" || "$ACTION" == "EDUCATE" || "$ACTION" == "ALLOW" ]]; then
    echo "  ✅ Mercy flow: action softened or mercy applied"
    PASS=$((PASS + 1))
else
    echo "  ❌ Mercy flow: expected leniency, got action=$ACTION mercy=$MERCY"
    FAIL=$((FAIL + 1))
fi

# ─────────────────────────────────────────────────────────────
# 6. Trust Score
# ─────────────────────────────────────────────────────────────
echo ""
echo "═══ 6. Trust Score ═══"

R=$(curl -s --max-time 5 "$GOVERNANCE/v1/trust/$SESSION" || echo "{}")
check "Trust score exists" "session_id" "$SESSION" "$R"

# ─────────────────────────────────────────────────────────────
# 7. Appeals (Contestability) — via governance direct
# ─────────────────────────────────────────────────────────────
echo ""
echo "═══ 7. Appeals ═══"

# Get a verdict_id directly from governance
R_VERDICT=$(decide "{\"finding_count\":1,\"critical_count\":1,\"composite_risk\":0.75,\"action\":\"BLOCK\",\"hard_blocked\":false,\"matched_policies\":[\"cpf->Block\"],\"session_id\":\"appeal-test\",\"profile\":\"\",\"input_text\":\"CPF 123.456.789-09\"}")
VERDICT_ID=$(echo "$R_VERDICT" | python -c "import sys,json; print(json.load(sys.stdin).get('verdict_id',''))" 2>/dev/null || echo "")
echo "  Verdict to appeal: $VERDICT_ID"

if [[ -n "$VERDICT_ID" && "$VERDICT_ID" != "None" && "$VERDICT_ID" != "" ]]; then
    R=$(curl -s --max-time 10 -X POST "$GOVERNANCE/v1/appeals" \
        -H "Content-Type: application/json" \
        -d "{\"audit_trail_id\": \"$VERDICT_ID\", \"user_id\": \"e2e-tester\", \"reason\": \"E2E test appeal\"}")
    check "Appeal submitted" "status" "pending" "$R"

    APPEAL_ID=$(echo "$R" | python -c "import sys,json; print(json.load(sys.stdin).get('appeal_id',''))" 2>/dev/null || echo "")
    echo "  Appeal ID: $APPEAL_ID"

    if [[ -n "$APPEAL_ID" && "$APPEAL_ID" != "None" ]]; then
        R=$(curl -s --max-time 10 -X POST "$GOVERNANCE/v1/appeals/$APPEAL_ID/resolve" \
            -H "Content-Type: application/json" \
            -d "{\"reviewer_notes\": \"E2E confirmed false positive\", \"new_action\": \"ALLOW\"}")
        check "Appeal resolved" "status" "approved" "$R"
    else
        skip "Appeal resolve" "no appeal_id returned"
    fi
else
    skip "Appeal submit" "no verdict_id from governance"
    skip "Appeal resolve" "depends on appeal submit"
fi

# ─────────────────────────────────────────────────────────────
# 8. Compliance
# ─────────────────────────────────────────────────────────────
echo ""
echo "═══ 8. Compliance ═══"

R=$(curl -s --max-time 10 "$GOVERNANCE/v1/compliance/report/EU_AI_ACT" 2>/dev/null || echo "")
TOTAL=$((TOTAL + 1))
if echo "$R" | python -c "import sys,json; d=json.load(sys.stdin); assert 'framework' in d" 2>/dev/null; then
    echo "  ✅ EU AI Act report: valid"
    PASS=$((PASS + 1))
else
    echo "  ❌ EU AI Act report failed"
    FAIL=$((FAIL + 1))
fi

R=$(curl -s --max-time 10 "$GOVERNANCE/v1/compliance/report/LGPD" 2>/dev/null || echo "")
TOTAL=$((TOTAL + 1))
if echo "$R" | python -c "import sys,json; d=json.load(sys.stdin); assert 'framework' in d" 2>/dev/null; then
    echo "  ✅ LGPD report: valid"
    PASS=$((PASS + 1))
else
    echo "  ❌ LGPD report failed"
    FAIL=$((FAIL + 1))
fi

# ─────────────────────────────────────────────────────────────
# 9. Metrics
# ─────────────────────────────────────────────────────────────
echo ""
echo "═══ 9. Metrics ═══"

R=$(curl -s --max-time 5 "$GATEWAY/metrics" || echo "")
TOTAL=$((TOTAL + 1))
if echo "$R" | grep -q "btv_decisions_total"; then
    echo "  ✅ Prometheus metrics exposed"
    PASS=$((PASS + 1))
else
    echo "  ❌ Prometheus metrics not found"
    FAIL=$((FAIL + 1))
fi

# ─────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════"
echo "  RESULTS: $PASS passed, $FAIL failed, $SKIP skipped (total $TOTAL)"
echo "═══════════════════════════════════════════════════════"

[[ $FAIL -eq 0 ]] && exit 0 || exit 1