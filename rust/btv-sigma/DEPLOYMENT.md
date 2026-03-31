# btv-sigma Deployment Guide

## Constitutional Role

`btv-sigma` is the Guardian of Σ — the append-only state of the algorithmic institution.
It is **NOT** infrastructure. It is the fourth element of the BTV institution `⟨L, E, J, Σ⟩`
(Paper 5, Definition 3.1).

The separation is load-bearing: if `btv-sigma` were operated by the same entity as
`btv-executive`, the System Operator could rewrite history. The institutional guarantee
collpases (Paper 2, §VI-A).

## Key Isolation (MANDATORY)

The Ed25519 signing key **MUST** be under custody of an authority independent
from the System Operator (Paper 2, Axiom III-C).

| Option | Strength | Notes |
|--------|----------|-------|
| Separate organization operates btv-sigma | ★★★ | Strongest — independent operator |
| HSM-backed key (AWS CloudHSM, Azure Managed HSM) | ★★★ | IAM must block operator access |
| Multi-party ceremony key in HSM | ★★ | Operator never sees private material |
| Environment variable on separate machine | ★ | Only acceptable in dev/staging |

## Anti-patterns: DO NOT

- Run `btv-sigma` on the same machine or AWS account as `btv-executive`
- Store the Ed25519 signing key in environment variables accessible to the operator
- Use the same IAM role for `btv-sigma` and `btv-executive`
- Derive the signing key from the HMAC key used by `btv-core`

## Verifying Key Distribution

At startup, `btv-sigma` prints its verifying key (hex) to stderr:

```
=== BTV-SIGMA LOG AUTHORITY ===
Verifying key (hex): <64 hex chars>
Pin this key via BTV_LOG_VERIFYING_KEY in all LogClient instances.
```

This key **must be distributed out-of-band** — never fetched from the log's own API
(Paper 2, Case D attack vector). Recommended channels:
- Secure internal secret manager (Vault, AWS Secrets Manager) with read-only IAM for operators
- Signed configuration bundle committed to an append-only audit trail

Configure in `btv-executive` deployment:

```bash
export BTV_LOG_ENDPOINT=https://log.internal:3100
export BTV_LOG_VERIFYING_KEY=<hex from out-of-band channel>
```

## Misbehaviour Detection

Paper 2, §VI-A recommends CT Gossip model:

- Deploy ≥ 2 independent `btv-sigma` instances (Paper 2, §VI-B) with different operators
- Require receipts from all *k* logs before `DeliveryToken::seal` is called
- Implement periodic root consistency checks between instances
- Log all `/append` requests to an independent audit trail

## Health Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/root` | GET | Current Merkle root + tree size |
| `/append` | POST | Append verdict hash, receive signed receipt |
| `/proof/{index}` | GET | Merkle inclusion proof for log entry |

## Dependency Invariant (CI-enforced)

`btv-sigma` imports **only** `btv-types` from the BTV crate graph.
It **never** imports `btv-core`. This is enforced by `cargo tree` in CI.

```
btv-types  (wire formats, MerkleProof, InclusionReceiptWire)
    ↑
btv-sigma  (binary — independent process, isolated key)
```
