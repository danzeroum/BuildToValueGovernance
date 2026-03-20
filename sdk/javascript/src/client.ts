/**
 * BTVClient — TypeScript client for the BuildToValue governance gateway.
 * Zero runtime dependencies. Uses native fetch (Node 18+, Deno, Bun).
 *
 * Quick start:
 *   import { BTVClient } from "@buildtovalue/sdk";
 *
 *   const btv = new BTVClient({ apiKey: "...", gatewayUrl: "http://localhost:8080" });
 *   const verdict = await btv.decide("Meu CPF é 123.456.789-09", { sessionId: "sess-001" });
 *
 *   if (verdict.action === "BLOCK") {
 *     const appeal = await btv.appeal(verdict.verdict_id,
 *       "CPF de teste ABNT — não é dado real",
 *       { grounds: ["technical_error"] }
 *     );
 *   }
 */

import {
  BTVAuthError,
  BTVBlockedError,
  BTVGatewayError,
  BTVRateLimitError,
  BTVValidationError,
} from "./errors.js";
import type {
  Appeal,
  AppealOptions,
  BTVClientOptions,
  DecideOptions,
  SanitizeResult,
  TrustScore,
  ValidateOptions,
  ValidateVerdict,
  Verdict,
} from "./types.js";

const DEFAULT_GATEWAY = "http://localhost:8080";
const DEFAULT_TIMEOUT = 30_000; // ms
const RETRYABLE_STATUS = new Set([429, 500, 502, 503, 504]);

// ─── Retry ───────────────────────────────────────────────────────────────────

async function withRetry<T>(
  fn: () => Promise<Response>,
  maxRetries: number,
  baseDelay: number
): Promise<Response> {
  let lastError: Error | null = null;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const resp = await fn();
      if (!RETRYABLE_STATUS.has(resp.status)) {
        return resp;
      }
      if (attempt === maxRetries) {
        if (resp.status === 429) {
          const retryAfter = parseInt(resp.headers.get("Retry-After") ?? "0") || null;
          throw new BTVRateLimitError(retryAfter);
        }
        const text = await resp.text();
        throw new BTVGatewayError(resp.status, text.slice(0, 200));
      }
    } catch (err) {
      if (err instanceof BTVGatewayError || err instanceof BTVRateLimitError) throw err;
      lastError = err as Error;
      if (attempt === maxRetries) throw new BTVGatewayError(0, String(lastError));
    }
    await sleep(baseDelay * Math.pow(2, attempt));
  }

  throw new BTVGatewayError(0, String(lastError));
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function raiseForStatus(resp: Response): Promise<void> {
  if (resp.status === 401) throw new BTVAuthError();
  if (resp.status >= 400 && resp.status < 500) {
    let detail = "";
    try {
      const body = await resp.clone().json();
      detail = body.error ?? body.detail ?? "";
    } catch {
      detail = (await resp.text()).slice(0, 200);
    }
    throw new BTVValidationError(resp.status, detail);
  }
}

// ─── Session ─────────────────────────────────────────────────────────────────

export class BTVSession {
  constructor(
    private readonly client: BTVClient,
    public readonly sessionId: string
  ) {}

  async decide(input: string, opts?: Omit<DecideOptions, "sessionId">): Promise<Verdict> {
    return this.client.decide(input, { ...opts, sessionId: this.sessionId });
  }

  async validate(input: string, opts?: Omit<ValidateOptions, "sessionId">): Promise<ValidateVerdict> {
    return this.client.validate(input, { ...opts, sessionId: this.sessionId });
  }

  async trustScore(): Promise<TrustScore> {
    return this.client.trustScore(this.sessionId);
  }

  async appeal(verdictId: string, reason: string, opts?: AppealOptions): Promise<Appeal> {
    return this.client.appeal(verdictId, reason, opts);
  }
}

// ─── Client ──────────────────────────────────────────────────────────────────

export class BTVClient {
  private readonly baseUrl: string;
  private readonly headers: Record<string, string>;
  private readonly timeout: number;
  private readonly maxRetries: number;
  private readonly raiseOnBlock: boolean;

  constructor(options: BTVClientOptions) {
    this.baseUrl = (options.gatewayUrl ?? DEFAULT_GATEWAY).replace(/\/$/, "");
    this.headers = {
      "X-API-Key": options.apiKey,
      "Content-Type": "application/json",
    };
    this.timeout = options.timeout ?? DEFAULT_TIMEOUT;
    this.maxRetries = options.maxRetries ?? 3;
    this.raiseOnBlock = options.raiseOnBlock ?? false;
  }

  /** Return a BTVSession that pins sessionId for all calls. */
  session(sessionId?: string): BTVSession {
    return new BTVSession(this, sessionId ?? crypto.randomUUID());
  }

  private async post<T>(path: string, body: Record<string, unknown>): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const resp = await withRetry(
        () =>
          fetch(url, {
            method: "POST",
            headers: this.headers,
            body: JSON.stringify(body),
            signal: controller.signal,
          }),
        this.maxRetries,
        2000
      );
      await raiseForStatus(resp);
      return (await resp.json()) as T;
    } finally {
      clearTimeout(timer);
    }
  }

  private async get<T>(path: string): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const resp = await withRetry(
        () =>
          fetch(url, {
            method: "GET",
            headers: this.headers,
            signal: controller.signal,
          }),
        this.maxRetries,
        2000
      );
      await raiseForStatus(resp);
      return (await resp.json()) as T;
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Run the full ethical governance pipeline (Rust kernel + Python judiciary).
   * Returns a Verdict with action, philosophical rationale, trust score, etc.
   */
  async decide(input: string, opts?: DecideOptions): Promise<Verdict> {
    const body: Record<string, unknown> = { input };
    if (opts?.sessionId) body.session_id = opts.sessionId;
    if (opts?.profile) body.profile = opts.profile;
    if (opts?.agentId) body.agent_id = opts.agentId;

    const verdict = await this.post<Verdict>("/v1/decide", body);

    if (this.raiseOnBlock && verdict.action === "BLOCK") {
      throw new BTVBlockedError(verdict);
    }

    return verdict;
  }

  /**
   * Run Rust-only scan (no ethical pipeline). Faster, less reasoning.
   * Use decide() for full governance.
   */
  async validate(input: string, opts?: ValidateOptions): Promise<ValidateVerdict> {
    const body: Record<string, unknown> = { input };
    if (opts?.sessionId) body.session_id = opts.sessionId;
    if (opts?.profile) body.profile = opts.profile;

    const verdict = await this.post<ValidateVerdict>("/v1/validate", body);

    if (this.raiseOnBlock && verdict.action === "BLOCK") {
      throw new BTVBlockedError(verdict);
    }

    return verdict;
  }

  /** Mask PII and neutralize injection patterns in text. */
  async sanitize(text: string, sessionId?: string): Promise<SanitizeResult> {
    const body: Record<string, unknown> = { text };
    if (sessionId) body.session_id = sessionId;
    return this.post<SanitizeResult>("/v1/sanitize", body);
  }

  /**
   * Submit an appeal against a verdict.
   * @param verdictId - The VRD-... identifier from a prior decide/validate call.
   * @param reason - Articulated reason (min 20 chars — Levinas principle).
   */
  async appeal(verdictId: string, reason: string, opts?: AppealOptions): Promise<Appeal> {
    const body: Record<string, unknown> = {
      verdict_id: verdictId,
      user_id: opts?.userId ?? "anonymous",
      reason,
      grounds: opts?.grounds ?? ["false_positive"],
    };
    if (opts?.evidence) body.evidence = opts.evidence;
    return this.post<Appeal>("/v1/appeals", body);
  }

  /** Get the current status of an appeal. */
  async getAppeal(appealId: string): Promise<Appeal> {
    return this.get<Appeal>(`/v1/appeals/${appealId}`);
  }

  /** Get the multi-factorial trust score for a session. */
  async trustScore(sessionId: string): Promise<TrustScore> {
    return this.get<TrustScore>(`/v1/trust/${sessionId}`);
  }

  /** Check gateway health (no auth required). */
  async health(): Promise<{ status: string; uptime_seconds?: number }> {
    const resp = await fetch(`${this.baseUrl}/health`);
    return resp.json();
  }
}
