/**
 * Errors thrown by the BTV SDK.
 */
import type { Verdict, ValidateVerdict } from "./types.js";

export class BTVError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BTVError";
  }
}

export class BTVAuthError extends BTVError {
  constructor() {
    super("Invalid or missing X-API-Key");
    this.name = "BTVAuthError";
  }
}

export class BTVBlockedError extends BTVError {
  verdict: Verdict | ValidateVerdict;

  constructor(verdict: Verdict | ValidateVerdict) {
    super(
      `Input blocked by BTV governance. verdict_id=${verdict.verdict_id} contestable=${verdict.contestable}`
    );
    this.name = "BTVBlockedError";
    this.verdict = verdict;
  }
}

export class BTVRateLimitError extends BTVError {
  retryAfter: number | null;

  constructor(retryAfter: number | null = null) {
    const msg = retryAfter
      ? `BTV rate limit exceeded — retry after ${retryAfter}s`
      : "BTV rate limit exceeded";
    super(msg);
    this.name = "BTVRateLimitError";
    this.retryAfter = retryAfter;
  }
}

export class BTVGatewayError extends BTVError {
  statusCode: number;

  constructor(statusCode: number, detail: string = "") {
    super(`BTV gateway error ${statusCode}: ${detail}`);
    this.name = "BTVGatewayError";
    this.statusCode = statusCode;
  }
}

export class BTVValidationError extends BTVError {
  statusCode: number;

  constructor(statusCode: number, detail: string = "") {
    super(`BTV validation error ${statusCode}: ${detail}`);
    this.name = "BTVValidationError";
    this.statusCode = statusCode;
  }
}
