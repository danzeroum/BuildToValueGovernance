/**
 * Tests for BTVClient.
 * Uses global fetch mock to intercept HTTP calls.
 */

import { describe, it, expect, beforeEach, jest } from "@jest/globals";
import { BTVClient, BTVSession } from "../src/client.js";
import {
  BTVAuthError,
  BTVBlockedError,
  BTVGatewayError,
  BTVValidationError,
} from "../src/errors.js";
import type { Verdict, ValidateVerdict, Appeal, TrustScore, SanitizeResult } from "../src/types.js";

const GATEWAY = "http://localhost:8080";
const API_KEY = "test-key";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const VERDICT_ALLOW: Verdict = {
  verdict_id: "VRD-01ARZ3NDEKTSV4RRFFQ69G5FAV",
  action: "ALLOW",
  original_action: "ALLOW",
  mercy_applied: false,
  finding_count: 0,
  critical_count: 0,
  composite_risk: 0.01,
  hard_blocked: false,
  contestable: false,
  appeal_deadline_hours: 0,
  signature: "abc123",
  rationale: "Clean input.",
  jurisdiction_bitmask: 1,
  latency_ms: 12.5,
  explain: {
    summary: "No concerns.",
    rawls_rationale: "Policy passed.",
    levinas_rationale: "No duty-of-care issue.",
    jonas_rationale: "No long-term risk.",
    gilligan_rationale: "No mercy needed.",
    trust_score: 0.85,
    mercy_score: 0.0,
    pipeline_stages: ["rawls", "levinas", "jonas", "gilligan"],
  },
};

const VERDICT_BLOCK: Verdict = {
  ...VERDICT_ALLOW,
  verdict_id: "VRD-01ARZ3NDEKTSV4RRFFQ69G5FAW",
  action: "BLOCK",
  original_action: "BLOCK",
  contestable: true,
  appeal_deadline_hours: 24,
  composite_risk: 0.95,
  finding_count: 3,
  critical_count: 2,
  rationale: "SQL injection detected.",
};

const VALIDATE_ALLOW: ValidateVerdict = {
  verdict_id: "VRD-VAL-001",
  action: "ALLOW",
  original_action: "ALLOW",
  mercy_applied: false,
  finding_count: 0,
  critical_count: 0,
  composite_risk: 0.01,
  hard_blocked: false,
  hard_block_term: null,
  contestable: false,
  appeal_deadline_hours: 0,
  message: "Clean.",
  matched_policies: [],
  max_finding_confidence: 0.0,
  entropy: 2.5,
  total_chars: 20,
  blake3_hash: "abc",
  drift_level: "None",
  signature: "sig",
  latency_ms: 5.0,
};

const APPEAL_RESP: Appeal = {
  appeal_id: "APL-001",
  verdict_id: "VRD-01ARZ3NDEKTSV4RRFFQ69G5FAV",
  user_id: "anonymous",
  reason: "This is a test CPF for ABNT compliance testing.",
  grounds: ["technical_error"],
  status: "pending",
  submitted_at: "2026-03-20T12:00:00Z",
  resolved_at: null,
  resolution: null,
  mediator_recommendation: null,
  sla_deadline: "2026-03-21T12:00:00Z",
  evidence_hash: null,
};

const TRUST_SCORE: TrustScore = {
  session_id: "sess-001",
  trust_score: 0.82,
  total_requests: 10,
  offenses: 0,
  calculated_at: "2026-03-20T12:00:00Z",
};

const SANITIZE_RESP: SanitizeResult = {
  sanitized: "My [REDACTED] is hidden.",
  redactions: 1,
  latency_ms: 3.0,
};

// ─── Mock fetch ───────────────────────────────────────────────────────────────

function mockFetch(status: number, body: unknown, headers?: Record<string, string>) {
  const response = new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
  global.fetch = jest.fn(() => Promise.resolve(response)) as typeof fetch;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("BTVClient", () => {
  let client: BTVClient;

  beforeEach(() => {
    client = new BTVClient({ apiKey: API_KEY, gatewayUrl: GATEWAY, maxRetries: 0 });
  });

  describe("decide()", () => {
    it("returns verdict on 200", async () => {
      mockFetch(200, VERDICT_ALLOW);
      const verdict = await client.decide("Hello world", { sessionId: "sess-001" });
      expect(verdict.action).toBe("ALLOW");
      expect(verdict.verdict_id).toBe(VERDICT_ALLOW.verdict_id);
    });

    it("sends X-API-Key header", async () => {
      mockFetch(200, VERDICT_ALLOW);
      await client.decide("test");
      const call = (fetch as jest.Mock).mock.calls[0];
      const init = call[1] as RequestInit;
      expect((init.headers as Record<string, string>)["X-API-Key"]).toBe(API_KEY);
    });

    it("sends session_id in body", async () => {
      mockFetch(200, VERDICT_ALLOW);
      await client.decide("test", { sessionId: "my-session" });
      const call = (fetch as jest.Mock).mock.calls[0];
      const init = call[1] as RequestInit;
      const body = JSON.parse(init.body as string);
      expect(body.session_id).toBe("my-session");
    });

    it("sends profile in body", async () => {
      mockFetch(200, VERDICT_ALLOW);
      await client.decide("test", { profile: "healthcare" });
      const call = (fetch as jest.Mock).mock.calls[0];
      const init = call[1] as RequestInit;
      const body = JSON.parse(init.body as string);
      expect(body.profile).toBe("healthcare");
    });

    it("throws BTVAuthError on 401", async () => {
      mockFetch(401, { error: "Unauthorized" });
      await expect(client.decide("test")).rejects.toThrow(BTVAuthError);
    });

    it("throws BTVValidationError on 422", async () => {
      mockFetch(422, { error: "Invalid input" });
      await expect(client.decide("test")).rejects.toThrow(BTVValidationError);
    });

    it("throws BTVBlockedError when raiseOnBlock=true and action=BLOCK", async () => {
      mockFetch(200, VERDICT_BLOCK);
      const blockingClient = new BTVClient({
        apiKey: API_KEY,
        gatewayUrl: GATEWAY,
        maxRetries: 0,
        raiseOnBlock: true,
      });
      await expect(blockingClient.decide("DROP TABLE users")).rejects.toThrow(BTVBlockedError);
    });

    it("does not throw on BLOCK when raiseOnBlock=false (default)", async () => {
      mockFetch(200, VERDICT_BLOCK);
      const verdict = await client.decide("DROP TABLE users");
      expect(verdict.action).toBe("BLOCK");
    });
  });

  describe("validate()", () => {
    it("returns validate verdict on 200", async () => {
      mockFetch(200, VALIDATE_ALLOW);
      const verdict = await client.validate("Hello");
      expect(verdict.action).toBe("ALLOW");
      expect(verdict.matched_policies).toEqual([]);
    });
  });

  describe("sanitize()", () => {
    it("returns sanitized text", async () => {
      mockFetch(200, SANITIZE_RESP);
      const result = await client.sanitize("My SSN is 123-45-6789");
      expect(result.sanitized).toBe(SANITIZE_RESP.sanitized);
      expect(result.redactions).toBe(1);
    });
  });

  describe("appeal()", () => {
    it("submits appeal and returns record", async () => {
      mockFetch(201, APPEAL_RESP);
      const appeal = await client.appeal(
        "VRD-01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "This is a test CPF for ABNT compliance testing.",
        { grounds: ["technical_error"] }
      );
      expect(appeal.appeal_id).toBe("APL-001");
      expect(appeal.status).toBe("pending");
    });

    it("sends verdict_id and grounds in body", async () => {
      mockFetch(201, APPEAL_RESP);
      await client.appeal("VRD-123", "Reason at least 20 chars long.", {
        grounds: ["false_positive"],
        userId: "user-001",
      });
      const call = (fetch as jest.Mock).mock.calls[0];
      const init = call[1] as RequestInit;
      const body = JSON.parse(init.body as string);
      expect(body.verdict_id).toBe("VRD-123");
      expect(body.grounds).toContain("false_positive");
      expect(body.user_id).toBe("user-001");
    });
  });

  describe("getAppeal()", () => {
    it("fetches appeal by ID", async () => {
      mockFetch(200, APPEAL_RESP);
      const appeal = await client.getAppeal("APL-001");
      expect(appeal.appeal_id).toBe("APL-001");
    });
  });

  describe("trustScore()", () => {
    it("returns trust score", async () => {
      mockFetch(200, TRUST_SCORE);
      const ts = await client.trustScore("sess-001");
      expect(ts.trust_score).toBe(0.82);
      expect(ts.session_id).toBe("sess-001");
    });
  });

  describe("health()", () => {
    it("calls /health without auth", async () => {
      mockFetch(200, { status: "ok", uptime_seconds: 3600 });
      const result = await client.health();
      expect(result.status).toBe("ok");
      const call = (fetch as jest.Mock).mock.calls[0];
      expect(call[0]).toContain("/health");
      const init = call[1] as RequestInit | undefined;
      // health() uses plain fetch without headers
      expect(init).toBeUndefined();
    });
  });
});

describe("BTVSession", () => {
  it("injects sessionId into decide()", async () => {
    mockFetch(200, VERDICT_ALLOW);
    const client = new BTVClient({ apiKey: API_KEY, gatewayUrl: GATEWAY, maxRetries: 0 });
    const session = client.session("my-session-id");

    await session.decide("Hello");

    const call = (fetch as jest.Mock).mock.calls[0];
    const init = call[1] as RequestInit;
    const body = JSON.parse(init.body as string);
    expect(body.session_id).toBe("my-session-id");
  });

  it("injects sessionId into validate()", async () => {
    mockFetch(200, VALIDATE_ALLOW);
    const client = new BTVClient({ apiKey: API_KEY, gatewayUrl: GATEWAY, maxRetries: 0 });
    const session = client.session("sess-xyz");

    await session.validate("Hello");

    const call = (fetch as jest.Mock).mock.calls[0];
    const init = call[1] as RequestInit;
    const body = JSON.parse(init.body as string);
    expect(body.session_id).toBe("sess-xyz");
  });
});

describe("Error classes", () => {
  it("BTVBlockedError carries verdict", async () => {
    mockFetch(200, VERDICT_BLOCK);
    const client = new BTVClient({
      apiKey: API_KEY,
      gatewayUrl: GATEWAY,
      maxRetries: 0,
      raiseOnBlock: true,
    });

    try {
      await client.decide("bad input");
      expect(true).toBe(false); // should not reach
    } catch (err) {
      expect(err).toBeInstanceOf(BTVBlockedError);
      const blocked = err as BTVBlockedError;
      expect(blocked.verdict.verdict_id).toBe(VERDICT_BLOCK.verdict_id);
      expect(blocked.verdict.contestable).toBe(true);
    }
  });
});
