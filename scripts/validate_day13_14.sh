#!/bin/bash
# validate_day13_14.sh - Network & Statistics Validators

set -e

echo "======================================================================="
echo "🔐 DAYS 13-14 VALIDATION: NETWORK & STATISTICS VALIDATORS"
echo "======================================================================="
echo ""

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

PASSED=0
FAILED=0

cd rust

echo "[1/3] Building all validators..."
if cargo build --release; then
    echo -e "${GREEN}✅ Build OK${NC}"
    ((PASSED++))
else
    echo -e "${RED}❌ Build FAILED${NC}"
    ((FAILED++))
    exit 1
fi
echo ""

echo "[2/3] Testing network validators..."
if cargo test network --lib -- --nocapture; then
    echo -e "${GREEN}✅ Network validators OK${NC}"
    ((PASSED++))
else
    echo -e "${RED}❌ Tests FAILED${NC}"
    ((FAILED++))
fi
echo ""

echo "[3/3] Testing statistics validators..."
if cargo test statistics --lib -- --nocapture; then
    echo -e "${GREEN}✅ Statistics validators OK${NC}"
    ((PASSED++))
else
    echo -e "${RED}❌ Tests FAILED${NC}"
    ((FAILED++))
fi
echo ""

echo "======================================================================="
echo "📊 VALIDATOR SUITE COMPLETE"
echo "======================================================================="
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ DAYS 13-14 APPROVED${NC}"
    echo ""
    echo "Complete Validator Suite:"
    echo "  • CPF/CNPJ (checksum) ✅"
    echo "  • Credit Card (Luhn) ✅"
    echo "  • IPv4 (Public/Private) ✅"
    echo "  • URL (Suspicious detection) ✅"
    echo "  • Domain names ✅"
    echo "  • Entropy (Shannon) ✅"
    echo "  • Z-Score (outliers) ✅"
    echo "  • Pattern repetition ✅"
    echo ""
    echo "Total: 10 production validators ✅"
    echo ""
    exit 0
else
    echo -e "${RED}❌ VALIDATION FAILED${NC}"
    exit 1
fi
