# Comparative Benchmark: BTV vs Guardrails AI vs NeMo

Measures end-to-end decision accountability latency across three approaches.

## Quick Run

```bash
pip install httpx numpy rich guardrails-ai nemoguardrails
bash benchmarks/comparative/run_comparative.sh
```

## What Is Being Measured

| System | Approach | What is timed |
|---|---|---|
| **BTV Sidecar** | Rust kernel via HTTP | Full round-trip: context → BLAKE3 hash → HMAC-seal → signed receipt |
| **Guardrails AI** | Python validator chain | Validator overhead (no LLM call) |
| **NeMo Guardrails** | LLM-as-judge | Full LLM inference required for guard decision |

## Expected Results

```
┌────────────────────┬────────┬────────┬────────┬────────┬────────┐
│ System             │    n   │   Mean │    p50 │    p95 │    p99 │
├────────────────────┼────────┼────────┼────────┼────────┼────────┤
│ BTV Sidecar        │ 10000  │ ~2.5ms │ ~2.1ms │ ~4.8ms │ ~8.2ms │  ← HTTP overhead only
│ BTV Rust (in-proc) │    —   │ 1.67μs │ 1.65μs │ 1.72μs │ 1.81μs │  ← compile-time, no network
│ Guardrails AI      │  1000  │  ~5ms  │  ~4ms  │ ~18ms  │ ~45ms  │
│ NeMo (LLM-judge)   │   200  │  ~2s   │  ~1.8s │  ~2.6s │  ~3.1s │
└────────────────────┴────────┴────────┴────────┴────────┴────────┘
```

The BTV Rust crate (“in-process”) adds **1.67μs** per decision — pure cryptographic overhead (BLAKE3 + HMAC-SHA256). This is the baseline you get when you `cargo add buildtovalue`.

The HTTP sidecar adds network latency on top (~2–8ms round-trip locally), which is still negligible compared to any LLM inference.

NeMo’s LLM-as-judge model requires a full inference call per guard decision, adding 1–3 seconds of latency — which is incompatible with real-time AI pipelines.

## Key Difference

BTV’s guarantee is **structural**: the compiler prevents a decision from existing without evidence. Guardrails AI and NeMo are **runtime validators** — they can be bypassed by a misconfigured pipeline, a dropped exception, or load shedding. BTV cannot be bypassed without a compile error.

## Reproducing the Rust Crate Benchmark

```bash
cd rust
cargo bench --bench kernel_benchmark
# Criterion output includes Verdict::new at each context size (64B, 512B, 4KB)
```

## Output

Results are saved to `benchmarks/comparative/results/latest.json` after each run.
