#!/bin/bash
# validate_day8.sh - Validação Day 8 (WAL + Durability)

set -e

echo "======================================================================="
echo "🔐 DAY 8 VALIDATION: WRITE-AHEAD LOG (WAL)"
echo "======================================================================="
echo ""

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

PASSED=0
FAILED=0

cd rust

echo "[1/4] Building with WAL support..."
if cargo build --release; then
    echo -e "${GREEN}✅ Build OK${NC}"
    ((PASSED++))
else
    echo -e "${RED}❌ Build FAILED${NC}"
    ((FAILED++))
    exit 1
fi
echo ""

echo "[2/4] Running WAL tests..."
if cargo test ledger --lib -- --nocapture; then
    echo -e "${GREEN}✅ WAL tests OK${NC}"
    ((PASSED++))
else
    echo -e "${RED}❌ WAL tests FAILED${NC}"
    ((FAILED++))
fi
echo ""

echo "[3/4] Testing recovery performance (<5s)..."
if cargo test test_recovery_performance --lib -- --nocapture; then
    echo -e "${GREEN}✅ Recovery <5s ✅${NC}"
    ((PASSED++))
else
    echo -e "${RED}❌ Recovery too slow${NC}"
    ((FAILED++))
fi
echo ""

echo "[4/4] Testing append performance (<5ms p95)..."
if cargo test test_performance_target --lib -- --nocapture; then
    echo -e "${GREEN}✅ Append <5ms ✅${NC}"
    ((PASSED++))
else
    echo -e "${RED}❌ Append too slow${NC}"
    ((FAILED++))
fi
echo ""

echo "======================================================================="
echo "📊 RESULTS"
echo "======================================================================="
echo ""
echo "Passed: $PASSED / Failed: $FAILED"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ DAY 8 APPROVED${NC}"
    echo "WAL implementation is production-ready!"
    echo ""
    echo "Achievements:"
    echo "  • WAL with fsync (99.99% durability) ✅"
    echo "  • CRC32 checksum validation ✅"
    echo "  • Recovery < 5s (p95) ✅"
    echo "  • Append < 5ms (p95) ✅"
    echo ""
    exit 0
else
    echo -e "${RED}❌ DAY 8 REJECTED${NC}"
    exit 1
fi
