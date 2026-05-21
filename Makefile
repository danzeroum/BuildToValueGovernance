# ═══════════════════════════════════════════════════════════════════════════
# BuildToValue v0.1.0-alpha.1 - Sovereign Orquestrator Makefile
# ═══════════════════════════════════════════════════════════════════════════

.PHONY: help build develop test e2e clean install quick dashboard benchmark

help:
	@echo "BuildToValue Governance v0.1.0-alpha.1 - Orquestração Soberana"
	@echo ""
	@echo "Comandos de Rust:"
	@echo "  make build        - Compila o Workspace Rust (release)"
	@echo "  make quick        - Executa apenas testes unitários do Kernel"
	@echo ""
	@echo "Comandos de Integração (Python + Rust):"
	@echo "  make develop      - Compila Rust e instala no venv Python (via Maturin)"
	@echo "  make install      - Instala dependências Python e a lib Rust"
	@echo "  make test         - Executa todos os testes (Rust + Python)"
	@echo "  make e2e          - Executa testes de conformidade LGPD ponta-a-ponta"
	@echo ""
	@echo "Manutenção:"
	@echo "  make clean        - Remove artefatos de build de ambos os mundos"
	@echo ""

# Compilação pura de Rust
build:
	@echo "🦀 Compilando Workspace Rust (Kernel + CLI + Bindings)..."
	cd rust && cargo build --release

# A mágica da integração: Maturin instala o Rust dentro do seu venv Python
# O workspace exige -m apontando para o crate de bindings (pyo3)
develop:
	@echo "🌉 Instalando Rust Bindings no ambiente Python..."
	cd rust && maturin develop --release -m bindings/Cargo.toml

# Instalação completa do ambiente
install:
	@echo "📦 Instalando dependências Python..."
	cd python && pip install -e .
	@make develop

# Bateria completa de testes
test: develop
	@echo "🧪 Executando testes do Rust Kernel..."
	cd rust && cargo test --release
	@echo "🐍 Executando testes de Governança Python..."
	cd python && pytest tests/ -v

# Testes de ponta-a-ponta (Caminho corrigido para scripts/ci/)
e2e: develop
	@echo "🏁 Iniciando validação E2E LGPD..."
	bash scripts/ci/run_e2e_lgpd.sh

# Limpeza total
clean:
	@echo "🧹 Limpando o território..."
	cd rust && cargo clean
	cd python && rm -rf build/ dist/ *.egg-info .pytest_cache __pycache__
	find . -name "*.pyc" -delete

# React Dashboard
dashboard:
	@echo "Building React dashboard..."
	cd dashboard && npm ci && npm run build

# Public Benchmark
benchmark:
	@echo "Running BTV benchmark..."
	cd benchmarks/comparative && python runner.py --adapters btv

# ARIA Scaling Trust Arena — iterative demo (Streamlit)
arena-demo:
	@echo "Launching Arena demo on http://localhost:8501 ..."
	streamlit run playground/arena_demo.py

# ARIA Scaling Trust Arena — iterative demo (CLI walkthrough)
arena-demo-cli:
	@echo "Walking through all Arena scenarios in the terminal..."
	cd python && python -m buildtovalue.cli.main arena-demo --scenario all

# Atalho para desenvolvedor Rust
quick:
	@echo "⚡ Teste rápido do Kernel..."
	cd rust && cargo test --release -p buildtovalue-kernel
