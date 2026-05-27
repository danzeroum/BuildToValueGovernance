# ═══════════════════════════════════════════════════════════════════════════
# BuildToValue v0.1.0-alpha.1 - Sovereign Orquestrator Makefile
# ═══════════════════════════════════════════════════════════════════════════

# Caminhos absolutos do venv — usados em todos os targets
# Evita depender de `source activate` (não funciona em subshell Make)
VENV      = python/venv
PYTHON    = $(VENV)/bin/python
PIP       = $(VENV)/bin/pip
UVICORN   = $(VENV)/bin/uvicorn
PYTEST    = $(VENV)/bin/pytest

.PHONY: help build develop test e2e clean install quick dashboard benchmark setup run run-dev venv docs-reference docs-validate docs-build emulator-up emulator-down

help:
	@echo "BuildToValue Governance v0.1.0-alpha.1 - Orquestração Soberana"
	@echo ""
	@echo "Primeiros passos / VPS:"
	@echo "  make setup       - Cria venv, instala maturin e tudo mais (primeira vez)"
	@echo "  make run         - Sobe a API com .env (requer .env na raiz)"
	@echo "  make run-dev     - Sobe a API sem .env (modo dev, com --reload)"
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
	@echo "Nota: após 'make setup', ative o venv no terminal com:"
	@echo "  source python/venv/bin/activate"
	@echo ""

# Cria o venv se ainda não existir
venv:
	@test -d $(VENV) || (echo "🐍 Criando venv em $(VENV)..." && python3 -m venv $(VENV))

# Primeiro uso / nova VPS: cria venv, instala maturin e tudo mais
setup: venv
	@echo "🚀 Configurando ambiente completo..."
	$(PIP) install --upgrade pip
	$(PIP) install maturin
	@$(MAKE) install
	@echo ""
	@echo "✅ Setup concluído! Ative o venv com:"
	@echo "   source python/venv/bin/activate"

# Sobe a API em produção com variáveis do .env
run:
	@echo "▶️  Iniciando API com .env..."
	cd python && $(CURDIR)/$(UVICORN) buildtovalue.api.app:app --host 0.0.0.0 --port 8000 --env-file $(CURDIR)/.env

# Sobe a API em modo dev (sem .env, usa fallbacks, com auto-reload)
run-dev:
	@echo "▶️  Iniciando API em modo dev..."
	cd python && $(CURDIR)/$(UVICORN) buildtovalue.api.app:app --host 0.0.0.0 --port 8000 --reload

# Compilação pura de Rust
build:
	@echo "🦀 Compilando Workspace Rust (Kernel + CLI + Bindings)..."
	cd rust && cargo build --release

# A mágica da integração: Maturin instala o Rust dentro do venv Python
# O workspace exige -m apontando para o crate de bindings (pyo3)
develop:
	@echo "🌉 Instalando Rust Bindings no ambiente Python..."
	cd rust && $(CURDIR)/$(VENV)/bin/maturin develop --release -m bindings/Cargo.toml

# Instalação completa do ambiente
install:
	@echo "📦 Instalando dependências Python..."
	cd python && $(CURDIR)/$(PIP) install -e .
	@$(MAKE) develop

# Bateria completa de testes
test: develop
	@echo "🧪 Executando testes do Rust Kernel..."
	cd rust && cargo test --release
	@echo "🐍 Executando testes de Governança Python..."
	cd python && $(CURDIR)/$(PYTEST) tests/ -v

# Testes de ponta-a-ponta
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
	cd benchmarks/comparative && $(PYTHON) runner.py --adapters btv

# ARIA Scaling Trust Arena — iterative demo (Streamlit)
arena-demo:
	@echo "Launching Arena demo on http://localhost:8501 ..."
	streamlit run playground/arena_demo.py

# ARIA Scaling Trust Arena — iterative demo (CLI walkthrough)
arena-demo-cli:
	@echo "Walking through all Arena scenarios in the terminal..."
	cd python && $(PYTHON) -m buildtovalue.cli.main arena-demo --scenario all

# Atalho para desenvolvedor Rust
quick:
	@echo "⚡ Teste rápido do Kernel..."
	cd rust && cargo test --release -p buildtovalue-kernel

# ─── Portal do Desenvolvedor ────────────────────────────────────────────────
docs-reference: ## Gera docs/developer/reference/index.md a partir dos crates Rust
	python3 scripts/autogen_reference.py

docs-validate: ## Valida invariantes documentais (CI)
	python3 scripts/validate_invariants.py

docs-build: docs-reference docs-validate ## Build estrito do site MkDocs
	mkdocs build --strict

docs-serve: docs-reference ## Serve o portal localmente em localhost:9091 (PT/EN)
	mkdocs serve -a 0.0.0.0:9091

emulator-up: ## Sobe o emulador local do gateway+kernel (tag = git SHA)
	docker compose -f ops/emulator/docker-compose.yml up --build -d

emulator-down: ## Derruba o emulador local
	docker compose -f ops/emulator/docker-compose.yml down
