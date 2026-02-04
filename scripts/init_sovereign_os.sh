#!/bin/bash
# scripts/init_sovereign_os.sh
# BuildToValue v2.2 - Inicialização completa do Sovereign Trust OS
# Criado: 2026-02-04

set -euo pipefail

VERSION="2.2.0"
PROJECT_ROOT="$(pwd)"

echo "════════════════════════════════════════════════════════════════"
echo "  BuildToValue v${VERSION} - Sovereign Trust OS"
echo "  Initializing Golden Record Structure..."
echo "════════════════════════════════════════════════════════════════"

# Verificar se já foi inicializado
if [ -f "${PROJECT_ROOT}/.buildtovalue_initialized" ]; then
    echo "⚠️  WARNING: System already initialized"
    echo "    Remove .buildtovalue_initialized to force re-initialization"
    exit 1
fi

# 1. HEMISFÉRIO RUST
echo ""
echo "🦀 Creating Rust Hemisphere..."
mkdir -p rust/kernel/src/{validators,statistics,ledger,compliance,deobfuscator,security,observability}
mkdir -p rust/kernel/{tests,benches}
mkdir -p rust/bindings/src

# 2. HEMISFÉRIO PYTHON
echo "🐍 Creating Python Hemisphere..."
mkdir -p python/buildtovalue/{api/routes,governance,compliance,intelligence,core,observability,cli/commands}
mkdir -p python/tests/{unit,integration,e2e}

# 3. CAMADA DE DADOS
echo "💾 Creating Data Layer..."
mkdir -p data/policies/{core,compliance,profiles,_metadata}
mkdir -p data/ledger/{wal,snapshots}
mkdir -p data/intelligence

# 4. CONTRATOS
echo "📜 Creating Contracts Layer..."
mkdir -p spec/{protobuf,openapi}

# 5. INFRA
echo "☸️  Creating Infrastructure Layer..."
mkdir -p k8s/{base,overlays/{staging,production},argocd,monitoring}

# 6. FERRAMENTAS
echo "🛠️  Creating Tools Layer..."
mkdir -p scripts
mkdir -p docs/architecture/adr

# 7. VERIFICAR ARQUIVOS ESSENCIAIS
echo ""
echo "🔍 Verifying essential files..."

# Cargo.toml workspace
if [ ! -f "Cargo.toml" ]; then
    echo "  ⚠️  Creating Cargo.toml workspace..."
    cat > Cargo.toml << 'EOF'
[workspace]
members = ["rust/kernel", "rust/bindings"]
resolver = "2"

[workspace.package]
version = "2.2.0"
edition = "2021"
authors = ["BuildToValue Team"]
license = "Apache-2.0"
EOF
fi

# Python pyproject.toml
if [ ! -f "python/pyproject.toml" ]; then
    echo "  ⚠️  Creating python/pyproject.toml..."
    cat > python/pyproject.toml << 'EOF'
[build-system]
requires = ["hatchling>=1.18.0"]
build-backend = "hatchling.build"

[project]
name = "buildtovalue"
version = "2.2.0"
description = "Sovereign Trust OS - Ethical AI Governance"
requires-python = ">=3.10"

dependencies = [
    "fastapi>=0.109.0",
    "pydantic>=2.5.0",
    "PyYAML>=6.0",
]

[project.scripts]
btv = "buildtovalue.cli.main:cli"

[tool.hatch.build.targets.wheel]
packages = ["buildtovalue"]
EOF
fi

# 8. SEAL POLICIES (se existirem)
echo ""
if [ -d "data/policies" ] && [ "$(find data/policies -name '*.yaml' | wc -l)" -gt 0 ]; then
    echo "🔐 Sealing policies..."
    if [ -f "scripts/seal_sovereignty.sh" ]; then
        bash scripts/seal_sovereignty.sh
    else
        echo "  ⚠️  seal_sovereignty.sh not found, skipping..."
    fi
else
    echo "⚠️  No policies found to seal (create them first)"
fi

# 9. MARCAR COMO INICIALIZADO
echo "${VERSION}" > "${PROJECT_ROOT}/.buildtovalue_initialized"
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> "${PROJECT_ROOT}/.buildtovalue_initialized"

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "✅ BuildToValue v${VERSION} Initialized Successfully!"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "📊 Summary:"
echo "   Rust modules:     $(find rust -name '*.rs' 2>/dev/null | wc -l) files"
echo "   Python packages:  $(find python/buildtovalue -name '__init__.py' 2>/dev/null | wc -l) packages"
echo "   Data directories: $(find data -type d 2>/dev/null | wc -l) directories"
echo "   Policies:         $(find data/policies -name '*.yaml' 2>/dev/null | wc -l) files"
echo ""
echo "🚀 Next steps:"
echo "   1. cd rust/kernel && cargo build"
echo "   2. cd python && pip install -e ."
echo "   3. Run ./scripts/validate_bootstrap.sh"
echo ""
echo "════════════════════════════════════════════════════════════════"
