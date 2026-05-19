# BuildToValue — Release Gates

Each phase of the refinement plan (`/root/.claude/plans/fa-a-uma-analise-do-shiny-wave.md`)
must pass three gates before the next phase begins. The product sells
"Responsibility Signed" — its own releases practice the same discipline.

## Three Gates per Phase

| Gate | Criterion | Evidence |
|---|---|---|
| **Technical** | All declared DoD items resolved or migrated to follow-up issues. CI green: `cargo check --workspace`, `cargo test --workspace`, `pytest`, lint guards (`scripts/ci/lint_guards.sh`). Coverage does not regress beyond the codecov threshold. | CI run URL + green badge |
| **Human review** | At least one reviewer approves. The phase checklist below is filled out in the PR description. Open follow-ups link to GitHub issues with owner + target phase. | Approval on the PR |
| **Signed close-out** | The commit that closes the phase carries a verified signature (`git commit -S` GPG or `git commit -s` SSH-signed). `git log --show-signature` confirms verification. | Signed commit SHA |

Reviewers are expected to verify the signature locally with
`git verify-commit <sha>` before approving the close-out commit.

---

## Phase -1 — Critical Security (S-01 .. S-09)

Bloqueador para qualquer publicação externa, marketing, ou release tagged.

- [ ] S-01 HMAC keys: centralized via `buildtovalue.security.get_hmac_key` (Python) and `buildtovalue_kernel::keys::kernel_mac_key` (Rust). No literal sentinels survive in source.
- [ ] S-02 Sensitive files: `.gitignore` covers `.env`, `*.db`, `*.key`, `*.crt`, `*.pem`, `*.bin`. `ops/.env.example` documents key generation. **Open**: `git filter-repo` of history + rotation of every credential ever shipped — scheduled in a separate maintenance window.
- [ ] S-03 CORS: `BTV_CORS_ORIGINS` env var honored; production raises on empty.
- [ ] S-04 SQLite WAL: all connections go through `sqlite_connect_wal`; lint guard active in CI (see `scripts/ci/lint_guards.sh`).
- [ ] S-05 `from_bytes` validation in `kernel/src/evidence/technical.rs` — **Open**, scheduled with btv-auth work.
- [ ] S-06 `logger` import in `policy_engine.py` — closed.
- [ ] S-07 License conflict resolved (`LICENSE` = Apache-2.0; OpenAPI aligned).
- [ ] S-08 Version drift — partially closed (Cargo workspace + pyproject aligned); full 12-point sweep tracked in Phase 2.
- [ ] S-09 HMAC retained without zeroize — closed by `_KeyHolder` (Python) and `Zeroizing<Vec<u8>>` (Rust). **Open**: `app.py` snapshots `HMAC_KEY` at import time → migrate four call sites to `get_hmac_key()` (PR-4).

**Close-out**: signed commit on `main` with title `phase(-1): security gates closed`.

---

## Phase 0 — Cleanup

- [ ] `readmeAntigo.md`, `docs/documentacao.md`, `docs/documentacaoInicial.md`, `docs/estruturaArquivos/data.md` moved to `docs/archive/`.
- [ ] `rust/_legacy/` deleted.
- [ ] ADR-043 / ADR-057 duplication resolved.
- [ ] `mkdocs.yml` nav excludes `docs/archive/`.
- [ ] Dockerfile sprawl consolidated to one base + targets.
- [ ] `mkdocs build --strict` clean; `lychee` reports zero broken links.

---

## Phase 1 — Honesty (feature flags, status, known-issues)

- [ ] `btv-redaction` bumped to `0.1.0-alpha.1`; features `experimental | zk-noir | mock` declared; default `mock`.
- [ ] `btv-governance` flagged `experimental`; lib returns `NotImplemented` until wired.
- [ ] Gateway features `jwt-real | dev-noauth`; default `jwt-real`; quickstart compose sets `dev-noauth`.
- [ ] `docs/status.md` lists every component with maturity (GA / Beta / Experimental / Roadmap).
- [ ] `docs/known-issues.md` documents the 4 e2e fails with root cause and workaround.
- [ ] CI: coverage upload (codecov), license scan (cargo-deny, pip-licenses), SLSA L2 provenance, lychee link check.
- [ ] `p99_latency_ms` replaced by `hdrhistogram` (P99 real) — preserves the marketing claim with a real metric.

---

## Phase 2 — Conceptual Coherence

- [ ] Sigma (`btv-sigma`) introduced as 4th branch ⟨L,E,J,Σ⟩ in `README.md`, `docs/concepts.md`, `docs/index.md`.
- [ ] Verdict `Report` (ADR-043) listed in README + concepts + `docs/api-reference.md`.
- [ ] PDP described in `docs/pdp.md` and linked from concepts.
- [ ] Glossary entry distinguishes Governance Plane / Policy Governance / Constitutional Governance.
- [ ] `ARCHITECTURE_ATLAS.md` carries a hard-coded banner pointing to `docs/status.md` for current state.
- [ ] Contestability text reconciled across `compliance.md` and `PRICING.md` (24h universal; Pro+ adds human mediation 4h).
- [ ] Version unification: every site lists `2.4.0` (Cargo workspace, pyproject, `__init__.py`, `app.py`, `cli/main.py`, dashboard, Makefile, gateway, OpenAPI). Internally-independent versions live in `status.md`.
- [ ] `INSPECT` ghost in `concepts.md` resolved (implement or remove).
- [ ] `EthicalContextEngine` duplicate audited and the older copy deleted.
- [ ] `_reserved` fields renamed to `payload_metadata`.

---

## Phase 3 — Repositioning

- [ ] New README headline: "Sua IA toma uma decisão. O BTV prova que foi governada. Um regulador verifica a prova em 327 nanossegundos."
- [ ] Dual-track sub-headlines (Engineers / Compliance).
- [ ] One-path quickstart with measurable "aha moment".
- [ ] `docs/comparisons.md` with public-info disclaimer.
- [ ] `docs/red-team.md` table format (RT-ID / vector / cases / result / status).
- [ ] `SECURITY.md` (GitHub template).
- [ ] Pricing tier "Professional" labeled Beta until validation; SLA claims removed until SRE runbooks exist.
- [ ] Pre-built Docker Hub images `buildtovalue/gateway:2.4.0` and `:governance:2.4.0`.
- [ ] Dashboard renders text by default; `is_html=True` opt-in with `bleach.clean(allowed_tags=…)`.

---

## Phase 3.5 — Orchestrator Integration

- [ ] LangChain `tool_call_guard` snippet (≤10 lines) in `docs/integrations/langchain.md`.
- [ ] AutoGen `register_reply` interceptor in `docs/integrations/autogen.md`.
- [ ] CrewAI `Tool` wrapper in `docs/integrations/crewai.md`.
- [ ] MCP server-side filter clarified in `docs/integrations/mcp.md`.
- [ ] Each file carries the `dev-noauth` disclaimer header.

---

## Phase 4 — Credibility

- [ ] `benchmarks/REPRODUCE.md` with reproducer script + real p50/p95/p99.
- [ ] `docs/case-studies/fintech-br.md` with explicit "synthetic scenario" banner.
- [ ] ADR consolidation: ADR active = (code on `main`) OR (open issue); rest moved to `docs/adr/archive/` with `INDEX.md`. ADRs sancionados nesta sessão (060–064) entram automaticamente.
- [ ] Hosted demo at a public URL.
- [ ] `zeroize` discipline test (no core-dump leak of `BTV_HMAC_KEY`).
- [ ] `CONTRIBUTING.md` + `CODE_OF_CONDUCT.md`.

---

## Signing Setup

Either GPG or SSH signing works. SSH is simpler in CI environments:

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true

# Verify:
git commit --allow-empty -m "test: signed close-out"
git log --show-signature -1
```

GitHub branch protection on `main` should require signed commits in the
"Require signed commits" setting once Phase 0 closes.
