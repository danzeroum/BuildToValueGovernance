#!/bin/bash
# validate_day2.sh - Validação Day 2 (FFI Safety)

set -e

echo "======================================================================="
echo "🔐 DAY 2 VALIDATION: FFI SAFETY & INTEGRITY"
echo "======================================================================="
echo ""

# Cores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Contadores
PASSED=0
FAILED=0

# ═══════════════════════════════════════════════════════════════════════════
# 1. BUILD RUST
# ═══════════════════════════════════════════════════════════════════════════

echo "[1/5] Building Rust kernel..."
cd rust
if cargo build --release; then
    echo -e "${GREEN}✅ Rust build OK${NC}"
    ((PASSED++))
else
    echo -e "${RED}❌ Rust build FAILED${NC}"
    ((FAILED++))
    exit 1
fi
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# 2. UNIT TESTS
# ═══════════════════════════════════════════════════════════════════════════

echo "[2/5] Running Rust unit tests..."
if cargo test --lib ffi_security; then
    echo -e "${GREEN}✅ Unit tests OK${NC}"
    ((PASSED++))
else
    echo -e "${RED}❌ Unit tests FAILED${NC}"
    ((FAILED++))
fi
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# 3. PROPERTY-BASED TESTS
# ═══════════════════════════════════════════════════════════════════════════

echo "[3/5] Running property-based tests (fuzzing)..."
if cargo test --test ffi_security_tests -- --test-threads=1; then
    echo -e "${GREEN}✅ Property tests OK${NC}"
    ((PASSED++))
else
    echo -e "${RED}❌ Property tests FAILED${NC}"
    ((FAILED++))
fi
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# 4. PERFORMANCE BENCHMARKS
# ═══════════════════════════════════════════════════════════════════════════

echo "[4/5] Running performance benchmarks..."
if cargo test --test ffi_security_tests benchmarks -- --nocapture; then
    echo -e "${GREEN}✅ Benchmarks OK${NC}"
    ((PASSED++))
else
    echo -e "${YELLOW}⚠️  Benchmarks failed (non-blocking)${NC}"
fi
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# 5. SECURITY AUDIT
# ═══════════════════════════════════════════════════════════════════════════

echo "[5/5] Running security audit..."
if cargo audit; then
    echo -e "${GREEN}✅ Security audit OK${NC}"
    ((PASSED++))
else
    echo -e "${YELLOW}⚠️  Security audit warnings (review manually)${NC}"
fi
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# REPORT
# ═══════════════════════════════════════════════════════════════════════════

echo "======================================================================="
echo "📊 RESULTS"
echo "======================================================================="
echo ""
echo "Passed: $PASSED"
echo "Failed: $FAILED"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ GATE G1 APPROVED${NC}"
    echo "FFI Safety module is production-ready!"
    echo ""
    exit 0
else
    echo -e "${RED}❌ GATE G1 REJECTED${NC}"
    echo "Fix blockers before proceeding."
    echo ""
    exit 1
fi
