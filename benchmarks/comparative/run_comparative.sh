#!/usr/bin/env bash
# =============================================================================
# BTV Comparative Benchmark
# Measures end-to-end decision latency for:
#   1. BTV sidecar (Rust kernel via HTTP)
#   2. Guardrails AI (Python, via openai-compatible stub)
#   3. NeMo Guardrails (Python)
#
# Usage:
#   bash benchmarks/comparative/run_comparative.sh [--requests N] [--concurrency C]
#
# Requirements:
#   - Docker (for BTV sidecar)
#   - Python 3.10+
#   - pip install guardrails-ai nemoguardrails httpx rich
#
# Output: terminal table + benchmarks/comparative/results/latest.json
# =============================================================================

set -euo pipefail

# --- Config -------------------------------------------------------------------
N_REQUESTS=${1:-10000}
CONCURRENCY=${2:-10}
BTV_URL="http://localhost:3000"
RESULTS_DIR="$(dirname "$0")/results"
MKDIR_P() { mkdir -p "$1"; }
MKDIR_P "$RESULTS_DIR"

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║   BTV vs Guardrails AI vs NeMo — ${N_REQUESTS} requests           ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# --- Step 1: Start BTV sidecar -----------------------------------------------
echo "[▶] Starting BTV gateway sidecar..."

if ! docker ps --format '{{.Names}}' | grep -q btv-bench; then
  docker run -d --rm --name btv-bench \
    -p 3000:3000 \
    -e BTV_HMAC_KEY=bench-key \
    buildtovalue/gateway:latest > /dev/null 2>&1 || {
      echo "[!] Docker image buildtovalue/gateway:latest not found."
      echo "    Build locally: cd rust && cargo build --release && docker build -t buildtovalue/gateway ."
      exit 1
    }
  echo "    Waiting for gateway health..."
  for i in $(seq 1 10); do
    if curl -sf "$BTV_URL/health" > /dev/null 2>&1; then
      echo "    Gateway ready."
      break
    fi
    sleep 1
  done
else
  echo "    BTV gateway already running."
fi

# --- Step 2: Run benchmark ---------------------------------------------------
echo ""
echo "[▶] Running benchmark (${N_REQUESTS} requests, concurrency=${CONCURRENCY})..."
echo ""

python3 "$(dirname "$0")/bench_runner.py" \
  --requests "$N_REQUESTS" \
  --concurrency "$CONCURRENCY" \
  --btv-url "$BTV_URL" \
  --output "$RESULTS_DIR/latest.json"

# --- Step 3: Stop sidecar ---------------------------------------------------
echo ""
echo "[▶] Stopping BTV sidecar..."
docker stop btv-bench > /dev/null 2>&1 || true

echo ""
echo "[✓] Results saved to $RESULTS_DIR/latest.json"
echo ""
