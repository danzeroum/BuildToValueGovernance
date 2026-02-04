#!/bin/bash
# scripts/migrate_to_v2.2_structure.sh
# BuildToValue v2.2 - ENHANCED Migration Script with Conflict Resolution

set -euo pipefail

VERSION="2.2.0"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="backup_pre_v2.2_${TIMESTAMP}"
LOG_FILE="migration_${TIMESTAMP}.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "${LOG_FILE}"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "${LOG_FILE}"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "${LOG_FILE}"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "${LOG_FILE}"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "${LOG_FILE}"
}

echo "═══════════════════════════════════════════════════════════════════"
echo "  BuildToValue v${VERSION} - Structure Migration"
echo "  Enhanced with Intelligent Conflict Resolution"
echo "  Timestamp: ${TIMESTAMP}"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

# ============================================================================
# FASE 0: VALIDAÇÃO PRÉ-MIGRAÇÃO
# ============================================================================

log_info "FASE 0: Validação pré-migração..."

# Verificar se estamos na raiz do projeto
if [ ! -f "docker-compose.yml" ] && [ ! -f "documentacao.md" ]; then
    log_error "Execute este script da raiz do projeto BuildToValue"
    exit 1
fi

# Verificar Git (opcional, mas recomendado)
if git rev-parse --git-dir > /dev/null 2>&1; then
    if ! git diff-index --quiet HEAD -- 2>/dev/null; then
        log_warning "Você tem mudanças não commitadas no Git"
        read -p "Continuar mesmo assim? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_error "Migração cancelada pelo usuário"
            exit 1
        fi
    fi
else
    log_warning "Git não detectado. Recomenda-se usar controle de versão."
fi

log_success "Validação pré-migração concluída"

# ============================================================================
# FASE 1: BACKUP COMPLETO
# ============================================================================

log_info "FASE 1: Criando backup completo..."

mkdir -p "${BACKUP_DIR}"

# Backup de diretórios críticos
for dir in src governance profiles config buildtovaluesdk tests; do
    if [ -d "$dir" ]; then
        log "   Backing up ${dir}/..."
        cp -r "$dir" "${BACKUP_DIR}/" 2>/dev/null || true
    fi
done

# Backup de arquivos de configuração importantes
for file in *.yml *.yaml *.toml *.md Cargo.toml; do
    if [ -f "$file" ]; then
        cp "$file" "${BACKUP_DIR}/" 2>/dev/null || true
    fi
done

log_success "Backup criado: ${BACKUP_DIR}/"

# ============================================================================
# FASE 2: CRIAR NOVA ESTRUTURA v2.2
# ============================================================================

log_info "FASE 2: Criando estrutura Golden Record v2.2..."

mkdir -p rust/kernel/src/{validators,statistics,ledger,compliance}
mkdir -p rust/kernel/{tests,benches}
mkdir -p rust/bindings/src
mkdir -p python/buildtovalue/{api/routes,governance,compliance,intelligence,core,observability,cli/commands}
mkdir -p python/tests/{unit,integration,e2e}
mkdir -p data/policies/{core,compliance,profiles,_metadata}
mkdir -p data/ledger/{wal,snapshots}
mkdir -p data/intelligence
mkdir -p spec/{protobuf,openapi}
mkdir -p k8s/{base,overlays/{staging,production}}
mkdir -p scripts docs/architecture/adr

log_success "Estrutura v2.2 criada"

# ============================================================================
# FASE 3: MIGRAR CÓDIGO RUST
# ============================================================================

log_info "FASE 3: Migrando código Rust..."

rust_files_found=0

move_rust_file() {
    local src_file="$1"
    local dest_file="$2"

    if [ -f "$src_file" ]; then
        log "   ${src_file} → ${dest_file}"
        mkdir -p "$(dirname "$dest_file")"

        if [ -f "$dest_file" ]; then
            log_warning "Destino existe: ${dest_file}, fazendo backup"
            mv "$dest_file" "${dest_file}.backup_${TIMESTAMP}"
        fi

        mv "$src_file" "$dest_file"
        rust_files_found=$((rust_files_found + 1))
    fi
}

# Mover arquivos Rust conhecidos
move_rust_file "src/buildtovalue/lib.rs" "rust/kernel/src/lib.rs"
move_rust_file "src/buildtovalue/btv.rs" "rust/kernel/src/btv.rs"
move_rust_file "src/kernel/lib.rs" "rust/kernel/src/kernel_legacy.rs"
move_rust_file "src/buildtovaluecompliance/ajlmetrics.rs" "rust/kernel/src/compliance/ajl_metrics.rs"
move_rust_file "src/buildtovaluecompliance/penaltycalculator.rs" "rust/kernel/src/compliance/penalty_calculator.rs"
move_rust_file "src/buildtovaluecompliance/penaltycalculatorv2.rs" "rust/kernel/src/compliance/penalty_calculator_v2.rs"
move_rust_file "src/buildtovaluecomplianceffi/lib.rs" "rust/bindings/src/lib.rs"
move_rust_file "src/buildtovaluecomplianceffi/batch.rs" "rust/bindings/src/batch.rs"
move_rust_file "src/ffi/lib.rs" "rust/bindings/src/ffi_legacy.rs"

if [ -d "src" ]; then
    find src -name "*.rs" -type f 2>/dev/null | while read -r rust_file; do
        filename=$(basename "$rust_file")
        if [[ "$rust_file" == *"ffi"* ]] || [[ "$rust_file" == *"bindings"* ]]; then
            dest="rust/bindings/src/${filename}"
        else
            dest="rust/kernel/src/${filename}"
        fi
        move_rust_file "$rust_file" "$dest"
    done
fi

log_success "${rust_files_found} arquivos Rust migrados"

# ============================================================================
# FASE 4: MIGRAR CÓDIGO PYTHON
# ============================================================================

log_info "FASE 4: Migrando código Python..."

merge_directory() {
    local src_dir="$1"
    local dest_dir="$2"
    local strategy="${3:-preserve}"

    if [ ! -d "$src_dir" ]; then
        return 0
    fi

    log "   Mesclando ${src_dir} → ${dest_dir} (${strategy})"
    mkdir -p "$dest_dir"

    find "$src_dir" -type f 2>/dev/null | while read -r src_file; do
        rel_path="${src_file#$src_dir/}"
        dest_file="${dest_dir}/${rel_path}"

        if [ -f "$dest_file" ]; then
            case "$strategy" in
                preserve)
                    log_warning "Preservando existente: ${dest_file}"
                    cp "$src_file" "${dest_file}.from_${TIMESTAMP}" 2>/dev/null || true
                    ;;
                overwrite)
                    log_warning "Sobrescrevendo: ${dest_file}"
                    cp "$dest_file" "${dest_file}.backup_${TIMESTAMP}" 2>/dev/null || true
                    mv "$src_file" "$dest_file"
                    ;;
            esac
        else
            mkdir -p "$(dirname "$dest_file")"
            mv "$src_file" "$dest_file"
        fi
    done
}

# Resolver conflito: governance/ duplicado
log_info "Resolvendo CONFLITO: governance/ duplicado..."
if [ -d "governance" ]; then
    merge_directory "governance" "python/buildtovalue/governance" "preserve"
fi
if [ -d "src/buildtovalue/governance" ]; then
    merge_directory "src/buildtovalue/governance" "python/buildtovalue/governance" "overwrite"
fi
rm -rf governance src/buildtovalue/governance 2>/dev/null || true
log_success "governance/ mesclado"

# Mover outros diretórios Python
for dir_pair in "src/buildtovalue/api:python/buildtovalue/api" \
                "src/api:python/buildtovalue/api" \
                "src/buildtovalue/compliance:python/buildtovalue/compliance" \
                "src/buildtovalue/intelligence:python/buildtovalue/intelligence" \
                "src/buildtovalueintelligence:python/buildtovalue/intelligence" \
                "buildtovaluesdk:python/buildtovalue/sdk" \
                "tests:python/tests"; do
    IFS=':' read -r src dest <<< "$dir_pair"
    if [ -d "$src" ]; then
        merge_directory "$src" "$dest" "preserve"
        rm -rf "$src" 2>/dev/null || true
    fi
done

log_success "Código Python migrado"

# ============================================================================
# FASE 5: MIGRAR POLÍTICAS
# ============================================================================

log_info "FASE 5: Migrando políticas..."

# Resolver conflito: profiles/ duplicado
log_info "Resolvendo CONFLITO: profiles/ duplicado..."
if [ -d "profiles" ]; then
    merge_directory "profiles" "data/policies/profiles" "preserve"
    rm -rf profiles 2>/dev/null || true
fi
if [ -d "config/agent" ]; then
    merge_directory "config/agent" "data/policies/profiles" "overwrite"
fi
log_success "profiles/ mesclado"

# Mover YAMLs de config/
if [ -d "config" ]; then
    find config -maxdepth 1 \( -name "*.yaml" -o -name "*.yml" \) 2>/dev/null | while read -r yaml_file; do
        mv "$yaml_file" "data/policies/compliance/" 2>/dev/null || true
    done
    rm -rf config 2>/dev/null || true
fi

log_success "Políticas migradas"

# ============================================================================
# FASE 6: CRIAR ARQUIVOS DE ANCORAGEM
# ============================================================================

log_info "FASE 6: Criando arquivos de ancoragem..."

# Rust kernel lib.rs
cat > rust/kernel/src/lib.rs << 'RUSTEOF'
//! BuildToValue Sovereign Kernel v2.2.0

pub mod validators;
pub mod statistics;
pub mod ledger;
pub mod compliance;
RUSTEOF

# Rust modules
for module in validators statistics ledger compliance; do
    cat > "rust/kernel/src/${module}/mod.rs" << MODEOF
//! ${module^} module
MODEOF
done

# Rust bindings
cat > rust/bindings/src/lib.rs << 'BINDEOF'
//! BuildToValue FFI Bindings (PyO3)

use pyo3::prelude::*;

#[pymodule]
fn buildtovalue_bindings(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    Ok(())
}

#[pyfunction]
fn version() -> String {
    "2.2.0".to_string()
}
BINDEOF

# Python __init__.py
for module in python/buildtovalue python/buildtovalue/{api,governance,compliance,intelligence,core,observability,cli,sdk}; do
    [ -d "$module" ] && echo '__version__ = "2.2.0"' > "${module}/__init__.py"
done

log_success "Arquivos de ancoragem criados"

# ============================================================================
# FASE 7: CRIAR CONFIGURAÇÕES
# ============================================================================

log_info "FASE 7: Criando configurações..."

# Cargo.toml workspace
cat > Cargo.toml << 'CARGOEOF'
[workspace]
members = ["rust/kernel", "rust/bindings"]
resolver = "2"

[workspace.package]
version = "2.2.0"
edition = "2021"
authors = ["BuildToValue Team"]
license = "Apache-2.0"
CARGOEOF

# rust/kernel/Cargo.toml
cat > rust/kernel/Cargo.toml << 'KERNELEOF'
[package]
name = "buildtovalue-kernel"
version.workspace = true
edition.workspace = true

[dependencies]
serde = { version = "1.0", features = ["derive"] }
blake3 = "1.5"

[lib]
crate-type = ["staticlib", "cdylib"]
KERNELEOF

# rust/bindings/Cargo.toml
cat > rust/bindings/Cargo.toml << 'BINDINGEOF'
[package]
name = "buildtovalue-bindings"
version.workspace = true
edition.workspace = true

[dependencies]
buildtovalue-kernel = { path = "../kernel" }
pyo3 = { version = "0.20", features = ["extension-module"] }

[lib]
crate-type = ["cdylib"]
BINDINGEOF

# python/pyproject.toml
cat > python/pyproject.toml << 'PYEOF'
[build-system]
requires = ["hatchling>=1.18.0"]
build-backend = "hatchling.build"

[project]
name = "buildtovalue"
version = "2.2.0"
description = "Sovereign Trust OS"
requires-python = ">=3.10"
dependencies = ["fastapi>=0.109.0", "pydantic>=2.5.0", "PyYAML>=6.0"]

[project.scripts]
btv = "buildtovalue.cli.main:cli"

[tool.hatch.build.targets.wheel]
packages = ["buildtovalue"]
PYEOF

log_success "Configurações criadas"

# ============================================================================
# FASE 8: GERAR CHECKSUMS
# ============================================================================

log_info "FASE 8: Gerando checksums..."

if [ -d "data/policies" ]; then
    cd data/policies
    {
        echo "{"
        find . \( -name "*.yaml" -o -name "*.yml" \) -type f | while read -r f; do
            hash=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
            echo "  \"${f#./}\": \"${hash}\","
        done | sed '$ s/,$//'
        echo "}"
    } > _metadata/checksums.json
    cd - > /dev/null
    log_success "Checksums gerados"
fi

# ============================================================================
# LIMPEZA & RELATÓRIO
# ============================================================================

log_info "FASE 9: Limpeza..."
[ -d "src" ] && find src -type d -empty -delete 2>/dev/null
[ -d "src" ] && [ -z "$(ls -A src)" ] && rmdir src 2>/dev/null
log_success "Limpeza concluída"

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  MIGRAÇÃO CONCLUÍDA ✅"
echo "═══════════════════════════════════════════════════════════════════"
log ""
log "📊 Resumo:"
log "   Backup: ${BACKUP_DIR}/"
log "   Log: ${LOG_FILE}"
log "   Rust: ${rust_files_found} arquivos migrados"
log ""
log "🚀 Próximos passos:"
log "   1. Validar: ./scripts/validate_structure_v2.2.sh"
log "   2. Build: cd rust/kernel && cargo build"
log "   3. Install: cd python && pip install -e ."
log ""
log "📍 Rollback: cp -r ${BACKUP_DIR}/* ."
echo "═══════════════════════════════════════════════════════════════════"
