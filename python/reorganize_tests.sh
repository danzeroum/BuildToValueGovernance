#!/bin/bash
# reorganize_tests.sh — Move legacy tests, create pytest.ini
set -e

echo "=== Test Reorganization ==="

# 1. Create _legacy dir
mkdir -p tests/_legacy/ethical
mkdir -p tests/_legacy/unit/python
mkdir -p tests/_legacy/adversarial
mkdir -p tests/_legacy/e2e

# 2. Move legacy tests (fail due to missing modules/APIs)
mv tests/ethical/test_gilligan.py tests/_legacy/ethical/ 2>/dev/null || true
mv tests/ethical/test_levinas.py tests/_legacy/ethical/ 2>/dev/null || true
mv tests/ethical/test_bias_detection.py tests/_legacy/ethical/ 2>/dev/null || true
mv tests/ethical/test_blind_policy.py tests/_legacy/ethical/ 2>/dev/null || true
mv tests/ethical/test_rawls.py tests/_legacy/ethical/ 2>/dev/null || true
mv tests/unit/test_governance.py tests/_legacy/unit/ 2>/dev/null || true
mv tests/unit/python/test_mercy.py tests/_legacy/unit/python/ 2>/dev/null || true
mv tests/unit/python/test_trust_score.py tests/_legacy/unit/python/ 2>/dev/null || true
mv tests/adversarial/ tests/_legacy/ 2>/dev/null || true
mv tests/e2e/ tests/_legacy/ 2>/dev/null || true
mv tests/test_compliance_e2e.py tests/_legacy/ 2>/dev/null || true
mv tests/test_rust_integration.py tests/_legacy/ 2>/dev/null || true

# 3. Fix sector_loader test (medical → medical-agent)
sed -i 's/pm.load_profile("medical")/pm.load_profile("medical-agent")/g' tests/unit/test_sector_loader.py

# 4. Create _legacy README
cat > tests/_legacy/README.md << 'EOF'
# Legacy Tests (v1.x)

These tests were generated from the v1.x documentation (32-part spec)
and reference APIs/modules that were never implemented or have since
changed. They are kept for reference but **do not pass**.

## Why they fail

| Category | Cause |
|:---|:---|
| `FFIClient`, `buildtovalue_kernel` | Rust→Python FFI bridge not built |
| `create_governance_engine()` | Conceptual function, never implemented |
| `TechnicalEvidence()` no args | API signature changed |
| `ValidationService` | Module never created |
| `_base_trust_from_role()` | Method renamed/redesigned |
| E2E tests | Require Docker Compose running |

## When to revisit

- FFI tests → after `maturin develop` works (v2.0)
- E2E tests → after Docker CI pipeline exists
- Ethical tests → rewrite against actual `app.py` API
- Trust/Mercy tests → rewrite against actual implementations
EOF

# 5. Create pytest.ini
cat > pytest.ini << 'EOF'
[pytest]
testpaths = tests/unit tests/integration
addopts = --strict-markers -v
markers =
    ethical: Ethical philosophy tests
    e2e: End-to-end (requires Docker)
    ffi: Requires Rust FFI (maturin develop)
EOF

# 6. Ensure __init__.py exists
touch tests/__init__.py
touch tests/unit/__init__.py
touch tests/integration/__init__.py

# 7. Keep ethical_committee (it passes)
# Already in tests/ethical/ — add to testpaths
sed -i 's|testpaths = tests/unit tests/integration|testpaths = tests/unit tests/integration tests/ethical|' pytest.ini

echo ""
echo "=== Done ==="
echo "Moved legacy tests to tests/_legacy/"
echo "Created pytest.ini with clean testpaths"
echo ""
echo "Verify: python -m pytest"