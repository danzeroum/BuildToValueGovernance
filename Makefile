# BuildToValue v2.0 - Makefile
# Quick commands for build, test, and deploy

.PHONY: help build test e2e clean install

help:
	@echo "BuildToValue v2.0 - Available commands:"
	@echo ""
	@echo "  make build        - Build Rust validators (release)"
	@echo "  make test         - Run all tests (Rust + Python)"
	@echo "  make e2e          - Run E2E LGPD compliance tests"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make install      - Install Python dependencies"
	@echo "  make quick        - Quick test (Rust only)"
	@echo ""

build:
	@echo "🦀 Building Rust validators..."
	cd rust && cargo build --release --features ffi

test: build
	@echo "🧪 Running Rust tests..."
	cd rust && cargo test --release
	@echo "🐍 Running Python tests..."
	cd python && pytest buildtovalue/governance/ -v

e2e: build
	@echo "🏁 Running E2E LGPD compliance tests..."
	bash scripts/run_e2e_lgpd.sh

clean:
	@echo "🧹 Cleaning build artifacts..."
	cd rust && cargo clean
	cd python && rm -rf build/ dist/ *.egg-info .pytest_cache __pycache__

install:
	@echo "📦 Installing Python dependencies..."
	cd python && pip install -e .

quick:
	@echo "⚡ Quick Rust tests..."
	cd rust && cargo test --release --lib
