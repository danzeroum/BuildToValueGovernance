# UI Reference — BFF Contract (Lab v3.0)

These HTML/JS files are the **reference designs** for the Lab, Fleet and Dashboard
surfaces. They are versioned here as a **BFF (Backend-for-Frontend) contract**: the
field names returned by the API must match the `data-*` attributes / element IDs the
markup binds to. When a divergence appears, resolve it by **adjusting the API payload**,
not the markup, to preserve presentation integrity.

> These are reference artifacts only. The live, wired pages are in [`../../demo/`](../../demo/)
> (`lab.html`, `fleet.html`, `dashboard.html`), which fetch real data from the API and fall
> back to static rendering when offline.

## Endpoint ↔ surface mapping

| Reference file | Live page | Endpoint | Key fields |
|---|---|---|---|
| `Lab.html` | `demo/lab.html` | `POST /v1/decide`, `POST /v1/multi-decide` | `signature`, `bias_declaration.{equity_score,pii_redacted,long_term_impact,mercy_applied,explain}` |
| `Fleet.html` | `demo/fleet.html` | `GET /v1/fleet` | `id,name,owner,bundle,model,risk,status,blockRate,decisions24h,trust,fria,friaDate,jurisdictions,capabilities` |
| `Dashboard.html` | `demo/dashboard.html` | `GET /v1/metrics?range=24h\|7d\|30d` | `total_decisions,block_rate,trust_avg,heatmap (7×24),top_vectors[],activity[]` |
| `search.js` | (global Cmd/Ctrl+K search) | — | static index reference |

## Integrity notes

- `TechnicalEvidence` is fixed at **9632 bytes** (kernel invariant, ADR-063). There is no
  `buffer_size` field exposed; the frontend validates the `signature` field for Fail-Secure.
- The kernel signs with BLAKE3 keyed-hash (ADR-031b); the Python verdict envelope exposes
  `hmac_sha256` / `signature`.
