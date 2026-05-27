---
title: "Tutorial 03 — Cryptographic Verification (`btv-cli`)"
---

# Tutorial 03 — Inspector Mode: `btv-cli verify`

Trust in BTV does not depend on the browser. Every evidence can be audited
**outside the system** with the `btv-cli` binary, living in
[`rust/cli/`](https://github.com/danzeroum/BuildToValueGovernance/tree/main/rust/cli).

## Prerequisites

- Rust toolchain (`rustup`).
- An evidence exported from the playground or the gateway (JSON).

## Step 1 — Build the CLI

```bash
cd rust && cargo build --release -p btv-cli
```

## Step 2 — Verify

The `verify` command requires **two inputs**: the evidence hash and the HMAC
signature. This teaches the integrator the fundamental principle of the
Algorithmic Republic: **data without proof has no value**.

```bash
./target/release/btv-cli verify \
  --hash <hex hash from the X-BTV-Evidence-Hash header> \
  --signature <hex hmac>
```

Expected response:

```
OK: valid signature.
  Evidence size: <constitutional value, see reference/index.md>
  Merkle root: <hex>
```

## Step 3 — Falsify to understand

Flip one character in the signature and run again. The CLI must respond
`ERROR: invalid signature` with exit code `!= 0`. **This is the correct
behavior.**

## Next

- [Legislator / Judge track — Tutorial 04](04-propose-policy.md).
- [CAP Protocol](../cap-protocol.md).
