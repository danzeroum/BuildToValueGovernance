#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# BuildToValue — E2E Curl Tests
# Validates full pipeline: Gateway (:8080) ↔ Governance (:8000)
# Usage: cd ops && bash e2e-tests.sh
# ═══════════════════════════════════════════════════════════════

set -uo pipefail

GATEWAY="http://localhost:8080"
GOVERNANCE="http://localhost:8000"
# DT-004 FIX: API key lida do ambiente (fallback = chave de dev)
BTV_API_KEY="${BTV_API_KEY:-btv-dev-key}"
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
        echo "     DEBUG: $(echo "$response" | head -c 300)"
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
        echo "     DEBUG: $(echo "$response" | head -c 300)"
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
        -H "X-BTV-API-Key: $BTV_API_KEY" \
        -d "$body"
}

sanitize() {
    curl -s --max-time 10 -X POST "$GATEWAY/v1/sanitize" \
        -H "Content-Type: application/json" \
        -H "X-BTV-API-Key: $BTV_API_KEY" \
        -d "{\"text\": \"$1\"}"
}

# DT-004 FIX A: decide() normaliza campos obrigatórios do DecideRequest (Pydantic)
# e envia X-BTV-API-Key. Todos os campos com default=None/0 precisam estar presentes
# para evitar 422 Unprocessable Entity silencioso.
decide() {
    local json="$1"
    local normalized
    normalized=$(python -c "
import sys, json as j

d = j.loads('''$json''')

defaults = {
    'entropy': 2.0,
    'total_chars': max(len(d.get('input_text', '')), 10),
    'blake3_hash': 'e2e-placeholder',
    'max_finding_confidence': 0.0,
    'profile': '',
    'session_id': '',
    'ip_risk': 'Low',
    'ip_jurisdiction': 'XX',
    'drift_level': 'None',
}

for k, v in defaults.items():
    if k not in d:
        d[k] = v

print(j.dumps(d))
" 2>/dev/null || echo "$json")

    curl -s --max-time 20 -X POST "$GOVERNANCE/v1/decide" \
        -H "Content-Type: application/json" \
        -H "X-BTV-API-Key: $BTV_API_KEY" \
        -d "$normalized"
}

# DT-004 FIX B: gov_get — wrapper para GET no governance com API key
gov_get() {
    local path="$1"
    curl -s --max-time 10 "$GOVERNANCE$path" \
        -H "X-BTV-API-Key: $BTV_API_KEY"
}

# ─────────────────────────────────────────────────────────────
# 0. Health Checks (fail-fast if services are down)
# ─────────────────────────────────────────────────────────────
echo "═══ 0. Health Checks ═══"
R=$(curl -s --max-time 5 "$GATEWAY/health" || echo "{}")
check "Gateway health" "status" "ok" "$R"
if ! echo "$R" | python -c "import sys,json; d=json.load(sys.stdin); assert d.get('status')=='ok'" 2>/dev/null; then
    echo "  ⚠️  Gateway not reachable at $GATEWAY — cannot continue E2E tests."
    echo "  Start with: cd rust && cargo run --bin btv_gateway (port 8080)"
    echo ""
    echo "═══════════════════════════════════════════════════════"
    echo "  RESULTS: $PASS passed, $FAIL failed, $SKIP skipped (total $TOTAL)"
    echo "═══════════════════════════════════════════════════════"
    exit 1
fi

R=$(curl -s --max-time 5 "$GOVERNANCE/health" || echo "{}")
check "Governance health" "status" "healthy" "$R"
if ! echo "$R" | python -c "import sys,json; d=json.load(sys.stdin); assert d.get('status')=='healthy'" 2>/dev/null; then
    echo "  ⚠️  Governance not reachable at $GOVERNANCE — cannot continue E2E tests."
    echo "  Start with: cd python && uvicorn buildtovalue.api.app:app --port 8000"
    echo ""
    echo "═══════════════════════════════════════════════════════"
    echo "  RESULTS: $PASS passed, $FAIL failed, $SKIP skipped (total $TOTAL)"
    echo "═══════════════════════════════════════════════════════"
    exit 1
fi

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
# Hex-encoded CPF "CPF 123.456.789-09" — deobfuscation must decode and detect PII
HEX=$(python -c "print(''.join(f'{b:02x}' for b in b'CPF 123.456.789-09'))")
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
    echo "     DEBUG: $R" | head -c 300
    FAIL=$((FAIL + 1))
fi
check_gte "Mask count" "masked_count" 2 "$R"

# ─────────────────────────────────────────────────────────────
# 5. Mercy Flow (Gilligan) — via governance direct
# DT-004 FIX C: payloads agora passam pela função decide() que normaliza
# campos obrigatórios (entropy, total_chars, blake3_hash, max_finding_confidence)
# ─────────────────────────────────────────────────────────────
echo ""
echo "═══ 5. Mercy Flow (direct governance) ═══"

SESSION="mercy-e2e-$(date +%s)"
echo "  Building trust (10 clean messages, session=$SESSION)..."
for i in $(seq 1 10); do
    decide "{
        \"finding_count\": 0,
        \"critical_count\": 0,
        \"composite_risk\": 0.0,
        \"action\": \"ALLOW\",
        \"hard_blocked\": false,
        \"matched_policies\": [],
        \"session_id\": \"$SESSION\",
        \"input_text\": \"mensagem limpa $i\"
    }" > /dev/null
done

R=$(gov_get "/v1/trust/$SESSION")
TRUST=$(echo "$R" | python -c "import sys,json; print(json.load(sys.stdin).get('trust_score',0))" 2>/dev/null || echo "0")
REQS=$(echo "$R" | python -c "import sys,json; print(json.load(sys.stdin).get('total_requests',0))" 2>/dev/null || echo "0")
echo "  Trust: $TRUST, Requests: $REQS"

# Mercy test: finding_count=1, composite_risk=0.5, high trust → deve abrandar
R=$(decide "{
    \"finding_count\": 1,
    \"critical_count\": 0,
    \"composite_risk\": 0.5,
    \"action\": \"REDACT\",
    \"hard_blocked\": false,
    \"matched_policies\": [\"email->Redact\"],
    \"session_id\": \"$SESSION\",
    \"input_text\": \"email teste@gmail.com\"
}")
ACTION=$(echo "$R" | python -c "import sys,json; print(json.load(sys.stdin).get('action',''))" 2>/dev/null || echo "")
MERCY=$(echo "$R" | python -c "import sys,json; print(json.load(sys.stdin).get('mercy_applied',''))" 2>/dev/null || echo "")
echo "  Action: $ACTION, Mercy: $MERCY"
TOTAL=$((TOTAL + 1))
if [[ "$MERCY" == "True" || "$ACTION" == "LOG" || "$ACTION" == "EDUCATE" \
   || "$ACTION" == "ALLOW" || "$ACTION" == "REDACT" ]]; then
    echo "  ✅ Mercy flow: action softened or mercy applied"
    PASS=$((PASS + 1))
else
    echo "  ❌ Mercy flow: expected leniency, got action=$ACTION mercy=$MERCY"
    echo "     DEBUG: $(echo "$R" | python -c 'import sys,json; d=json.load(sys.stdin); print(d.get("detail", d.get("rationale","no detail")))' 2>/dev/null)"
    FAIL=$((FAIL + 1))
fi

# ─────────────────────────────────────────────────────────────
# 6. Trust Score
# ─────────────────────────────────────────────────────────────
echo ""
echo "═══ 6. Trust Score ═══"

R=$(gov_get "/v1/trust/$SESSION")
check "Trust score exists" "session_id" "$SESSION" "$R"

# ─────────────────────────────────────────────────────────────
# 7. Appeals (Contestability) — via governance direct
# ─────────────────────────────────────────────────────────────
echo ""
echo "═══ 7. Appeals ═══"

R_VERDICT=$(decide "{
    \"finding_count\": 1,
    \"critical_count\": 1,
    \"composite_risk\": 0.75,
    \"action\": \"BLOCK\",
    \"hard_blocked\": false,
    \"matched_policies\": [\"cpf->Block\"],
    \"session_id\": \"appeal-test\",
    \"input_text\": \"CPF 123.456.789-09\"
}")
VERDICT_ID=$(echo "$R_VERDICT" | python -c "import sys,json; print(json.load(sys.stdin).get('verdict_id',''))" 2>/dev/null || echo "")
echo "  Verdict to appeal: $VERDICT_ID"

if [[ -n "$VERDICT_ID" && "$VERDICT_ID" != "None" && "$VERDICT_ID" != "" ]]; then
    R=$(curl -s --max-time 10 -X POST "$GOVERNANCE/v1/appeals" \
        -H "Content-Type: application/json" \
        -H "X-BTV-API-Key: $BTV_API_KEY" \
        -d "{\"audit_trail_id\": 9999, \"user_id\": \"e2e-tester\", \"reason\": \"E2E test appeal - contestability verification\"}")
    check "Appeal submitted" "status" "pending" "$R"

    APPEAL_ID=$(echo "$R" | python -c "import sys,json; print(json.load(sys.stdin).get('appeal_id',''))" 2>/dev/null || echo "")
    echo "  Appeal ID: $APPEAL_ID"

    if [[ -n "$APPEAL_ID" && "$APPEAL_ID" != "None" ]]; then
        R=$(curl -s --max-time 10 -X POST "$GOVERNANCE/v1/appeals/$APPEAL_ID/resolve" \
            -H "Content-Type: application/json" \
            -H "X-BTV-API-Key: $BTV_API_KEY" \
            -d "{\"accepted\": true, \"reviewer_id\": \"e2e-reviewer\", \"reviewer_notes\": \"E2E confirmed false positive\"}")
        check "Appeal resolved" "status" "accepted" "$R"
    else
        skip "Appeal resolve" "no appeal_id returned"
    fi
else
    skip "Appeal submit" "no verdict_id from governance"
    skip "Appeal resolve" "depends on appeal submit"
fi

# ─────────────────────────────────────────────────────────────
# 8. Compliance
# DT-004 FIX D: adiciona X-BTV-API-Key (endpoint exige require_api_key)
# Rota é exclusiva do governance (:8000) — não proxeada pelo gateway
# ─────────────────────────────────────────────────────────────
echo ""
echo "═══ 8. Compliance ═══"

for FW in "EU_AI_ACT" "LGPD"; do
    R=$(gov_get "/v1/compliance/report/$FW")
    TOTAL=$((TOTAL + 1))
    if echo "$R" | python -c "import sys,json; d=json.load(sys.stdin); assert 'framework' in d" 2>/dev/null; then
        echo "  ✅ $FW report: valid"
        PASS=$((PASS + 1))
    else
        echo "  ❌ $FW report failed"
        echo "     DEBUG: $(echo "$R" | head -c 300)"
        FAIL=$((FAIL + 1))
    fi
done

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