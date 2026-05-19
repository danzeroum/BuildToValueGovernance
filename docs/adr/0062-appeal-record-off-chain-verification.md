# ADR-062 — AppealRecord Off-Chain Verification

**Status:** Accepted  
**Date:** 2026-05-19  
**Legal:** LGPD Art. 20 (right to explanation), EU AI Act Art. 14

## Context

`VerdictRecord.explanation_hash` (BLAKE3) was recorded in the Ledger, but
the full explanation text was discarded after the response. An affected
person exercising their LGPD Art. 20 right could not verify that the
explanation they received was the one produced at decision time — the hash
was in the Ledger, the text was nowhere.

## Decision

### Rust: `AppealRecord` in `kernel/src/core/types.rs`

Fixed-size, zero-heap record persisted in `appeals.db`:

| Field                  | Type      | Notes                              |
|------------------------|-----------|------------------------------------|
| `verdict_id`           | `[u8;16]` | Links to Ledger VerdictRecord      |
| `explanation_hash`     | `[u8;32]` | BLAKE3 of full explanation text    |
| `bias_declaration_hash`| `[u8;32]` | BLAKE3 of the BiasDeclaration      |
| `timestamp_utc`        | `u64`     | Unix seconds                       |
| `appeal_deadline_utc`  | `u64`     | `timestamp_utc + 86400` (24h SLA)  |
| `appeal_url_hash`      | `[u8;32]` | BLAKE3 of the contestation URL     |

### Python: `verify_appeal_text()` in `explanation_store.py`

```python
def verify_appeal_text(explanation_text: str, stored_hash: bytes) -> bool
```

Computes `blake3(explanation_text.encode())` and compares with
`stored_hash` using `hmac.compare_digest()` (constant-time). Returns
`True` only on a matching digest.

## Authenticity invariant

`blake3(explanation_text) == VerdictRecord.explanation_hash`

If either side is tampered with, the invariant fails and `verify_appeal_text`
returns `False`. The Ledger is immutable (ADR-004), so only the text can
be tampered; the hash is the canonical source of truth.

## Consequences

- Full explanation text is retained in `appeals.db` and verifiable at any
  time against the Ledger.
- `verify_appeal_text` must be called before serving an explanation to an
  affected person; a mismatch is a LGPD Art. 20 violation signal.
