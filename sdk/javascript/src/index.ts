/**
 * @buildtovalue/sdk — TypeScript SDK for the BuildToValue AI Governance Gateway.
 *
 * Quick start:
 *   npm install @buildtovalue/sdk
 *
 *   import { BTVClient } from "@buildtovalue/sdk";
 *
 *   const btv = new BTVClient({ apiKey: "...", gatewayUrl: "http://localhost:8080" });
 *   const verdict = await btv.decide("Meu CPF é 123.456.789-09", { sessionId: "sess-001" });
 *
 *   if (verdict.action === "BLOCK") {
 *     console.log(verdict.rationale);
 *     const appeal = await btv.appeal(verdict.verdict_id,
 *       "CPF de teste ABNT — não é dado real",
 *       { grounds: ["technical_error"] }
 *     );
 *   }
 */

export { BTVClient, BTVSession } from "./client.js";
export {
  BTVError,
  BTVAuthError,
  BTVBlockedError,
  BTVRateLimitError,
  BTVGatewayError,
  BTVValidationError,
} from "./errors.js";
export type {
  Verdict,
  ValidateVerdict,
  ExplainDecision,
  Appeal,
  TrustScore,
  SanitizeResult,
  VerdictAction,
  AppealStatus,
  AppealGrounds,
  GovernanceProfile,
  DecideOptions,
  ValidateOptions,
  AppealOptions,
  BTVClientOptions,
} from "./types.js";
