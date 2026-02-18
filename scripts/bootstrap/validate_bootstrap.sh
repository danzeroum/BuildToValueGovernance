#!/bin/bash
# scripts/validate_bootstrap.sh
# BuildToValue v2.2 - Validação de bootstrap
# Criado: 2026-02-04

set -euo pipefail

ERRORS=0
WARNINGS=0

echo "════════════════════════════════════════════════════════════════"
echo "🔍 BuildToValue v1.0 Bootstrap Validation"
echo "════════════════════════════════════════════════════════════════"

# Check Rust
echo ""
echo "🦀 Validating Rust Environment..."
if [ ! -f "rust/kernel/Cargo.toml" ]; then
    echo "  ❌ Missing: rust/kernel/Cargo.toml"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✅ rust/kernel/Cargo.toml found"
fi

if [ ! -f "rust/kernel/src/lib.rs" ]; then
    echo "  ❌ Missing: rust/kernel/src/lib.rs"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✅ rust/kernel/src/lib.rs found"
fi

# Check Python
echo ""
echo "🐍 Validating Python Environment..."
if [ ! -f "python/buildtovalue/__init__.py" ]; then
    echo "  ❌ Missing: python/buildtovalue/__init__.py"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✅ python/buildtovalue/__init__.py found"
fi

if [ ! -f "python/pyproject.toml" ]; then
    echo "  ❌ Missing: python/pyproject.toml"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✅ python/pyproject.toml found"
fi

# Check Data
echo ""
echo "💾 Validating Data Layer..."
if [ ! -d "data/policies" ]; then
    echo "  ❌ Missing: data/policies/"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✅ data/policies/ found"
fi

# Check policies
POLICY_COUNT=$(find data/policies -name "*.yaml" 2>/dev/null | wc -l)
if [ "$POLICY_COUNT" -eq 0 ]; then
    echo "  ⚠️  WARNING: No policies found (run seal_sovereignty.sh)"
    WARNINGS=$((WARNINGS + 1))
else
    echo "  ✅ Found $POLICY_COUNT policy files"
fi

# Check checksums
if [ ! -f "data/policies/_metadata/checksums.json" ]; then
    echo "  ⚠️  WARNING: checksums.json not found (run seal_sovereignty.sh)"
    WARNINGS=$((WARNINGS + 1))
else
    echo "  ✅ checksums.json found"
fi

# Try Rust build
echo ""
echo "🔨 Testing Rust Build..."
if command -v cargo &> /dev/null; then
    if cd rust/kernel && cargo check --quiet 2>/dev/null; then
        echo "  ✅ Rust kernel: BUILD OK"
    else
        echo "  ❌ Rust kernel: BUILD FAILED"
        ERRORS=$((ERRORS + 1))
    fi
    cd - > /dev/null
else
    echo "  ⚠️  WARNING: cargo not found (install Rust)"
    WARNINGS=$((WARNINGS + 1))
fi

# Try Python install
echo ""
echo "🐍 Testing Python Install..."
if command -v python3 &> /dev/null; then
    if cd python && python3 -c "import sys; sys.path.insert(0, '.'); import buildtovalue" 2>/dev/null; then
        echo "  ✅ Python package: IMPORT OK"
    else
        echo "  ⚠️  Python package: IMPORT FAILED (run pip install -e .)"
        WARNINGS=$((WARNINGS + 1))
    fi
    cd - > /dev/null
else
    echo "  ⚠️  WARNING: python3 not found"
    WARNINGS=$((WARNINGS + 1))
fi

# Summary
echo ""
echo "════════════════════════════════════════════════════════════════"
if [ $ERRORS -eq 0 ]; then
    echo "✅ Bootstrap validation: PASSED"
    echo "🚀 Ready to implement Sovereign Trust OS"
    if [ $WARNINGS -gt 0 ]; then
        echo "⚠️  $WARNINGS warnings (non-blocking)"
    fi
else
    echo "❌ Bootstrap validation: FAILED ($ERRORS errors, $WARNINGS warnings)"
    echo "🔧 Fix errors above and re-run validation"
fi
echo "════════════════════════════════════════════════════════════════"

exit $ERRORS
