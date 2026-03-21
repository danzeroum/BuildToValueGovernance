#!/bin/bash
# Run the full BTV public benchmark
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BENCH_DIR="$(dirname "$SCRIPT_DIR")"

cd "$BENCH_DIR"

echo "=== BuildToValue Public Benchmark ==="
echo "Adapters: ${1:-btv}"
echo ""

python runner.py \
    --adapters "${1:-btv}" \
    --dataset datasets/ \
    --output results/ \
    --warmup 3

echo ""
echo "=== Benchmark Complete ==="
echo "Results in: $BENCH_DIR/results/"
