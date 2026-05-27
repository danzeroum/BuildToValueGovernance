---
title: Portal Risk Register
---

# Developer Portal Risk Register

Reviewed quarterly. Owner: repository maintainers.

| # | Risk | Prob. | Impact | Status | Current mitigation |
| --- | --- | --- | --- | --- | --- |
| R1 | Byte drift between code and docs | Medium | High | **Mitigated** | `scripts/autogen_reference.py` fail-secure; `validate_invariants.py` in CI |
| R2 | `--feature test-env` / `/debug/time-drift` not implemented | High | Medium | **Open** | Playground uses a client-side mock with the `[DIDACTIC SIMULATION]` badge; kernel implementation pending |
| R3 | Duplication `docs/adr/` vs `docs/adrs/` | Confirmed | Low | **Mitigated** | Consolidated in Phase 0; `docs/adrs/README.md` is a redirect |
| R4 | Docker emulator ↔ kernel drift | Medium | High | **Partial** | Dockerfile uses `Cargo.lock`; tag = git SHA via `make emulator-up` |
| R5 | Visual drift between playground and `demo/` | Low | Medium | **Mitigated** | `demo/playground/` reuses `demo/css/btv.css` |
| R6 | Contributor resistance to the tracks | Low | Medium | **Mitigated** | Single `CONTRIBUTING.md`, three explicit tracks |
| R7 | Emerging risks (AI, privacy) | Medium | Medium | **Open** | Quarterly review in this register |
| R8 | ADR-0047/0067 ambiguity | Confirmed | Medium | **Open** | Canonical mapping in [`concepts/contestability-loop.md`](concepts/contestability-loop.md); issue #150 |
| R9 | `autogen_reference.py` as injection vector | Low | Critical | **Mitigated** | `.github/workflows/docs.yml` with minimal permissions; no HMAC/Ledger credentials |
| R10 | `time-drift` mock induces false perception | High | Medium | **Mitigated** | Inamovible badge in the playground |
| R11 | Generated `reference/index.md` on `main` | Medium | Low | **Mitigated** | `docs/developer/reference/.gitignore` |
| R12 | Missing `policy_signer.py` blocks Panel 1 | High | High | **Mitigated** | `scripts/policy_signer.py` created (Phase 0 of the Governance Console) |
| R13 | `alignment_regression.yml` only covers `model_registry.yaml` | Confirmed | High | **Mitigated** | `paths` expanded to `data/policies/**` + `validate_policy_schema.py` step |
| R14 | Gilligan S1–S6 algorithm without ADR | Confirmed | Medium | **Mitigated** | `docs/adr/0072-gilligan-sla-mercy-algorithm.md` (+ `.en.md`) |
| R15 | UI writing runtime without signature | Low | Critical | **Mitigated** | Policy Editor has no route to `POST /reload`; required flow → PR + CI + signed Ed25519 reload |
| R16 | Missing EN pages break `/en/` | Medium | Medium | **Mitigated** | `validate_invariants.py` now checks each nav `.md` against its `.en.md` pair |
| R17 | Duplication with `python/buildtovalue/{compliance,governance}` | Medium | Medium | **In use** | YAML map references `compliance_evaluator`, `frameworks`, LGPD/EU AI Act plugins; Audit Trail references `document_exporter.py` |
| R18 | `data/policies/compliance/gdpr.yaml` has a YAML parse error around line 248 | Confirmed | Medium | **Open** | Detected by `validate_policy_schema.py` (Phase 0); file an issue to fix before the next policy deploy. Does not block the console, but blocks merges touching `gdpr.yaml` |

## Review procedure

Quarterly:

1. Reopen each **Open** or **Partial** row and update the status.
2. Check for new emerging risks (cybersecurity, AI, sustainability).
3. Record changes via PR — every change to the risk register is a constitutional
   decision (follow the [CAP Protocol](cap-protocol.md)).
