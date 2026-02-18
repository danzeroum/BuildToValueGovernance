ADR-023: Expose ContestabilityLoop as HTTP API
Status: PROPOSED
Version: v1.5.0 (current sprint)
Date: 2026-02-17
Author: Architect (AI Squad)

## Context

ContestabilityLoop v2.0 exists in python/buildtovalue/governance/contestability_loop.py
with full test coverage (unit, E2E, LGPD Art. 20 scenarios). It implements:
- submit_appeal(audit_trail_id, user_id, reason, evidence?) → Appeal
- resolve_appeal(appeal_id, accepted, reviewer_notes, reviewer_id) → Appeal
- get_appeal(appeal_id) → Appeal
- list_pending_appeals() → List[Appeal]
- list_expired_appeals() → List[Appeal]
- get_metrics() → Dict

However, ZERO HTTP endpoints expose this functionality. The /v1/decide endpoint
returns contestable=True and appeal_deadline_hours=24, creating a legal promise
(LGPD Art. 20, EU AI Act Art. 86) with no mechanism for fulfillment.

## Philosophical Foundation

LEVINAS: The Other has an absolute right to contest power exercised over them.
Returning contestable=True without an endpoint is performative ethics — 
appearance without substance. This ADR corrects that.

RAWLS: Behind the veil of ignorance, any person could be the one blocked.
They must have a real mechanism to appeal, not just a field in JSON.

## Decision

Add 5 endpoints to python/buildtovalue/api/app.py (FastAPI, port 8000):

### Endpoints

POST /v1/appeals
  Input:  { audit_trail_id: int, user_id: str, reason: str, evidence?: str }
  Output: { appeal_id: str, status: "pending", sla_deadline: str }
  Status: 201 Created
  Errors: 400 (reason < 20 chars), 422 (validation)

GET /v1/appeals/{appeal_id}
  Output: Full Appeal object (status, timestamps, reviewer_notes if resolved)
  Status: 200
  Errors: 404 (not found)

GET /v1/appeals?status=pending&user_id=xxx
  Output: { appeals: [...], total: int }
  Status: 200
  Filtering: status (pending|accepted|rejected|expired), user_id

POST /v1/appeals/{appeal_id}/resolve
  Input:  { accepted: bool, reviewer_notes: str, reviewer_id: str }
  Output: Updated Appeal object
  Status: 200
  Errors: 404, 409 (already resolved)

GET /v1/appeals/metrics
  Output: { appeals_submitted, appeals_accepted, appeals_rejected,
            sla_compliance_rate, appeal_success_rate, pending_appeals }
  Status: 200

### Architecture

- All endpoints delegate to existing ContestabilityLoop instance
- ContestabilityLoop initialized as singleton on app startup
- In-memory storage (dict) — acceptable for v1.5, persistent DB in v1.8+
- No auth required in v1.5 (auth is gap #3, separate ADR)

### Axum Gateway (optional, v1.9+ only)

The Rust gateway MAY proxy /v1/appeals/* to Python :8000 in v1.9+.
For v1.5, appeals are Python-only endpoints on port 8000.

### BiasDeclaration

module: appeals_api
fpr: N/A (human decision, not automated)
fnr: N/A
known_limitation: "In-memory storage loses appeals on restart. 
                   SLA tracking depends on system clock accuracy."
calibration_date: 2026-02-17

## Constraints

- explain_decision(): Every resolve must include reviewer_notes (min 10 chars)
- Fail-secure: If ContestabilityLoop raises, return 500 (never silently drop appeal)
- HMAC: Not required on appeals (they are human workflow, not automated verdicts)
- SLA: list_expired_appeals() called on every GET /v1/appeals to detect breaches
- Logging: Every submit and resolve logged with structured fields

## Files to Create/Modify

| File | Action | Lines |
|------|--------|-------|
| python/buildtovalue/api/app.py | MODIFY | +80 |
| python/buildtovalue/api/schemas.py | CREATE | ~60 |

## Tests Required

1. POST /v1/appeals — happy path (201)
2. POST /v1/appeals — reason too short (400)
3. GET /v1/appeals/{id} — found (200)
4. GET /v1/appeals/{id} — not found (404)
5. POST /v1/appeals/{id}/resolve — accept (200)
6. POST /v1/appeals/{id}/resolve — reject (200)
7. POST /v1/appeals/{id}/resolve — already resolved (409)
8. GET /v1/appeals?status=pending — filtering
9. GET /v1/appeals/metrics — all fields present
10. E2E: /v1/decide → /v1/appeals → /v1/appeals/{id}/resolve

## Rejected Alternatives

1. REST sub-resource under /v1/decisions/{id}/appeal — Over-nested.
   Appeals are first-class entities with their own lifecycle.
2. WebSocket for real-time appeal status — Premature for v1.5.
3. Persistent DB now — In-memory is acceptable for single-process 
   monolith. DB migration planned for v1.8 with ContestabilityLoop v3.