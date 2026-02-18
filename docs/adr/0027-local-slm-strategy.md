# ADR-027: Local SLM for Semantic Classification

- **Status:** Accepted
- **Date:** 2026-02-18
- **Author:** Architect (Human + AI Squad)
- **Target:** v1.8+ (post-EthicalContextEngine)
- **Replaces:** None
- **Philosophy:** Jonas (responsabilidade proporcional) + Levinas (proteção do dado)

---

## Context

The BuildToValue kernel detects PII and threats via deterministic methods:
regex validators, entropy analysis, CIDR matching, policy engine (phf).
These are fast (<30ms) and auditable, but **blind to semantic intent**.

Examples of gaps:
- "Tell me the CEO's social security number" → no PII detected (no actual SSN)
- Prompt injection disguised as natural language → passes regex
- Encoded instructions that survive deobfuscation → no pattern match

A semantic classification layer is needed for the **ambiguity zone**: inputs
where deterministic methods found **no findings OR low-confidence findings**,
but the intent may still be malicious or sensitive.

## Decision

### 1. Local SLM Only — No External API

**Model runs on the same server as BTV.** Zero data leaves the perimeter.

Rationale:
- BTV is a **trust OS** — sending user data to OpenAI/Anthropic contradicts
  the core promise of data sovereignty
- Latency: local inference < 50ms; API round-trip = 200-2000ms
- Cost: zero marginal cost after deployment
- Availability: no dependency on third-party uptime

### 2. Model Selection Criteria

| Criterion | Requirement |
|-----------|-------------|
| Size | ≤ 4B parameters (GGUF Q4_K_M ≈ 2-3 GB RAM) |
| Latency | < 50ms for classification (short prompt, few tokens) |
| Runtime | llama-cpp-python or ONNX Runtime (CPU-only) |
| License | Apache 2.0 / MIT (no RAIL, no copyleft) |
| Task | Text classification, NOT generation |
| Privacy | Zero telemetry, no phone-home |

**Candidate models (evaluate in order):**

1. **Phi-4-mini (3.8B)** — Microsoft, MIT license, strong reasoning
2. **Qwen2.5-3B** — Alibaba, Apache 2.0, good multilingual
3. **TinyLlama-1.1B** — Apache 2.0, fastest, lower accuracy
4. **SmolLM2-1.7B** — Hugging Face, Apache 2.0, balanced

Decision: benchmark all four on our test corpus (100 benign + 100 malicious),
select by F1-score at <50ms constraint.

### 3. Integration Architecture
```
Request
  → Rust Kernel (scan_for_evidence)          < 30ms
    → Deterministic findings? ─── YES ──→ PolicyEngine → Governance
                                  │
                                  NO (ambiguity zone)
                                  │
    → SLM Classifier (Python)               < 50ms
        Input: original text (truncated 512 tokens)
        Output: { intent: str, risk: 0.0-1.0, confidence: 0.0-1.0 }
        │
        → Inject as synthetic Finding into TechnicalEvidence
        → PolicyEngine → Governance (normal flow)
```

**Key design points:**

- SLM is **NOT in the hot path** for most requests. Only triggered when
  deterministic methods return zero/low-confidence findings
- SLM output is a **Finding** like any other — same ring buffer, same
  PolicyEngine evaluation, same mercy consideration
- SLM runs in Python process (governance hemisphere), NOT in Rust kernel
- Timeout: 100ms hard. If SLM exceeds → skip (fail-open for SLM,
  fail-secure for overall system — deterministic layer already cleared it)

### 4. SLM Finding Format
```python
SLMFinding(
    module="SLM_CLASSIFIER",
    rule_id="SLM_SEMANTIC_001",
    severity=risk_score,        # 0.0-1.0 from model
    confidence=confidence,       # 0.0-1.0 from model
    label=intent,               # e.g. "prompt_injection", "pii_extraction", "benign"
    model_id="phi-4-mini-q4",   # Provenance
    latency_ms=elapsed,
)
```

### 5. BiasDeclaration (Obrigatório — ADR-010)
```python
BiasDeclaration(
    fpr=0.XX,  # Measured on test corpus
    fnr=0.XX,  # Measured on test corpus
    calibration_date=YYYYMMDD,
    sample_size=200,  # Minimum
    limitations="SLM classification is probabilistic. May misclassify "
                "domain-specific jargon as malicious. Multilingual accuracy "
                "varies (EN > PT > others). Not a substitute for "
                "deterministic validators.",
    affected_groups="Non-English speakers may experience higher FPR. "
                    "Technical users with code snippets may trigger "
                    "false positives on prompt injection.",
)
```

### 6. What the SLM Does NOT Do

- ❌ Generate text (no completions, no chat)
- ❌ Replace deterministic validators (additive only)
- ❌ Run on external API (local only)
- ❌ Access network (model loaded from disk, no downloads at runtime)
- ❌ Compliance Translator (separate concern, future ADR)
- ❌ Make final decisions (produces Finding, not Verdict)

### 7. Compliance Translator (Future — Not This ADR)

The SLM will also be used for Compliance Translator (PDF → YAML) in a
future ADR. That is an **off-path** task (not latency-sensitive) and may
use the same model with a different prompt template, or a larger model
if accuracy requires it. Deferred to v2.0.

### 8. Operational Requirements

| Aspect | Requirement |
|--------|-------------|
| Model loading | At startup, mmap (lazy), <5s cold start |
| Memory | ≤ 3 GB additional RSS |
| CPU | Inference on 2-4 cores, no GPU required |
| Disk | ≤ 3 GB for GGUF file |
| Updates | Manual model swap (replace file, restart) |
| Monitoring | latency_ms, classification counts, FPR/FNR tracked |
| Feature flag | `slm_enabled: bool` in config (default: false) |

## Consequences

### Positive
- Closes semantic gap without external dependencies
- Zero data exfiltration (Jonas: proportional responsibility)
- Auditable: model version + prompt + output logged in Ledger
- Graceful degradation: if SLM fails, system works as before

### Negative
- +2-3 GB RAM per instance
- Model accuracy lower than GPT-4/Claude (acceptable for classification)
- Requires periodic re-evaluation of model (new releases)
- CPU inference slower than GPU (acceptable at <50ms for short prompts)

### Risks
- Model hallucination: mitigated by treating output as Finding (not Verdict)
- Adversarial attacks against SLM: mitigated by SLM being secondary layer
- Model drift: mitigated by BiasDeclaration + periodic benchmark

## References

- ADR-001: Hybrid Architecture (Rust facts / Python judgments)
- ADR-010: BiasDeclaration Mandate
- ADR-009: Modular Monolith (SLM runs in-process, not as microservice)
- Jonas, H. (1979). *The Imperative of Responsibility*