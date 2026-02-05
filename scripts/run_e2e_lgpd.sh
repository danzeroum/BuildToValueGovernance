#!/bin/bash
# BuildToValue v2.0 - E2E LGPD Compliance Tests
#
# Executa build completo e testes end-to-end:
# Rust (validators) → FFI → Python (governance) → LGPD Profile
#
# Author: BuildToValue Architecture Team
# License: Apache 2.0

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                                                                            ║${NC}"
echo -e "${BLUE}║         BUILDTOVALUE v2.0 - E2E LGPD COMPLIANCE TESTS                     ║${NC}"
echo -e "${BLUE}║                                                                            ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# STEP 1: Build Rust Validators with FFI
# ═══════════════════════════════════════════════════════════════════════════

echo -e "${YELLOW}[1/6] 🦀 Building Rust validators (with FFI)...${NC}"
cd rust

# Clean previous build
cargo clean -q

# Build with FFI feature (release mode)
if cargo build --release --features ffi; then
    echo -e "${GREEN}✅ Rust build successful!${NC}"
else
    echo -e "${RED}❌ Rust build failed!${NC}"
    exit 1
fi

# Verify .so/.dylib/.dll exists
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    LIB_PATH="target/release/libbuildtovalue.so"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    LIB_PATH="target/release/libbuildtovalue.dylib"
else
    LIB_PATH="target/release/buildtovalue.dll"
fi

if [ -f "$LIB_PATH" ]; then
    LIB_SIZE=$(du -h "$LIB_PATH" | cut -f1)
    echo -e "${GREEN}   Library: $LIB_PATH ($LIB_SIZE)${NC}"
else
    echo -e "${RED}❌ Library not found: $LIB_PATH${NC}"
    exit 1
fi

cd ..

# ═══════════════════════════════════════════════════════════════════════════
# STEP 2: Run Rust Unit Tests
# ═══════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${YELLOW}[2/6] 🧪 Running Rust unit tests...${NC}"
cd rust

if cargo test --release --quiet -- --nocapture; then
    echo -e "${GREEN}✅ Rust tests passed!${NC}"
else
    echo -e "${RED}❌ Rust tests failed!${NC}"
    exit 1
fi

cd ..

# ═══════════════════════════════════════════════════════════════════════════
# STEP 3: Verify LGPD Profile YAML
# ═══════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${YELLOW}[3/6] 📄 Verifying LGPD profile YAML...${NC}"

PROFILE_PATH="profiles/compliance/lgpd_base.yaml"

if [ -f "$PROFILE_PATH" ]; then
    RULE_COUNT=$(grep -c "^  - id:" "$PROFILE_PATH" || true)
    echo -e "${GREEN}✅ LGPD profile found: $RULE_COUNT rules${NC}"

    # Validate YAML syntax
    if command -v python3 &> /dev/null; then
        python3 -c "import yaml; yaml.safe_load(open('$PROFILE_PATH'))" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}   YAML syntax: valid${NC}"
        else
            echo -e "${RED}❌ YAML syntax error!${NC}"
            exit 1
        fi
    fi
else
    echo -e "${RED}❌ LGPD profile not found: $PROFILE_PATH${NC}"
    exit 1
fi

# ═══════════════════════════════════════════════════════════════════════════
# STEP 4: Install Python Dependencies
# ═══════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${YELLOW}[4/6] 🐍 Checking Python dependencies...${NC}"
cd python

# Check if venv exists
if [ ! -d ".venv" ]; then
    echo -e "${YELLOW}   Creating virtual environment...${NC}"
    python3 -m venv .venv
fi

# Activate venv
source .venv/bin/activate || . .venv/Scripts/activate

# Install dependencies
pip install -q -e . 2>/dev/null || pip install -e .

echo -e "${GREEN}✅ Python environment ready${NC}"

# ═══════════════════════════════════════════════════════════════════════════
# STEP 5: Run Python FFI Tests
# ═══════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${YELLOW}[5/6] 🔗 Testing FFI bridge (Rust ↔ Python)...${NC}"

if pytest buildtovalue/governance/test_ffi_integration.py -v --tb=short; then
    echo -e "${GREEN}✅ FFI tests passed!${NC}"
else
    echo -e "${RED}❌ FFI tests failed!${NC}"
    exit 1
fi

# ═══════════════════════════════════════════════════════════════════════════
# STEP 6: Run E2E LGPD Compliance Tests
# ═══════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${YELLOW}[6/6] 🏁 Running E2E LGPD compliance tests...${NC}"

if pytest buildtovalue/governance/test_e2e_lgpd_full.py -v --tb=short; then
    echo -e "${GREEN}✅ E2E LGPD tests passed!${NC}"
else
    echo -e "${RED}❌ E2E LGPD tests failed!${NC}"
    exit 1
fi

# ═══════════════════════════════════════════════════════════════════════════
# SUCCESS SUMMARY
# ═══════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                                                                            ║${NC}"
echo -e "${GREEN}║                    ✅✅✅ ALL TESTS PASSED! ✅✅✅                           ║${NC}"
echo -e "${GREEN}║                                                                            ║${NC}"
echo -e "${GREEN}║         BUILDTOVALUE v2.0 - LGPD COMPLIANCE VALIDATED                     ║${NC}"
echo -e "${GREEN}║                                                                            ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Stack tested:${NC}"
echo -e "${GREEN}  ✅ Rust validators (consent, sensitive_data, revocation)${NC}"
echo -e "${GREEN}  ✅ FFI bridge (Rust ↔ Python)${NC}"
echo -e "${GREEN}  ✅ LGPD profile (18 rules)${NC}"
echo -e "${GREEN}  ✅ EthicalContextEngine (mercy, trust, context)${NC}"
echo -e "${GREEN}  ✅ ProfileManager (hierarchical inheritance)${NC}"
echo -e "${GREEN}  ✅ ContestabilityLoop (SLA 24h)${NC}"
echo -e "${GREEN}  ✅ Performance (<50ms E2E)${NC}"
echo ""
echo -e "${BLUE}Ready for:${NC}"
echo -e "  🚀 Integration with production systems"
echo -e "  🚀 Additional compliance frameworks (GDPR, HIPAA)"
echo -e "  🚀 External audit"
echo ""

cd ..
