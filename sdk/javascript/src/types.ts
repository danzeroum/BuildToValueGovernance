/**
 * TypeScript types for the BuildToValue governance API.
 * Maps directly to gateway response schemas.
 */

export type VerdictAction = "ALLOW" | "BLOCK" | "INSPECT" | "REDACT" | "EDUCATE" | "LOG";

export type AppealStatus = "pending" | "under_review" | "accepted" | "rejected" | "expired";

export type AppealGrounds =
  | "rawls_equity"
  | "levinas_protection"
  | "gilligan_mercy"
  | "jonas_responsibility"
  | "technical_error"
  | "scope_mismatch"
  | "false_positive";

export type GovernanceProfile =
  | "general"
  | "healthcare"
  | "finance"
  | "legal"
  | "research"
  | "education";

export interface ExplainDecision {
  summary: string;
  rawls_rationale: string;
  levinas_rationale: string;
  jonas_rationale: string;
  gilligan_rationale: string;
  trust_score: number;
  mercy_score: number;
  pipeline_stages: string[];
}

/** Full governance verdict from /v1/decide (with ethical pipeline). */
export interface Verdict {
  verdict_id: string;
  action: VerdictAction;
  original_action: VerdictAction;
  mercy_applied: boolean;
  finding_count: number;
  critical_count: number;
  composite_risk: number;
  hard_blocked: boolean;
  contestable: boolean;
  appeal_deadline_hours: number;
  signature: string;
  rationale: string;
  explain: ExplainDecision;
  jurisdiction_bitmask: number;
  latency_ms: number;
}

/** Verdict from /v1/validate (Rust-only, no ethical pipeline). */
export interface ValidateVerdict {
  verdict_id: string;
  action: VerdictAction;
  original_action: VerdictAction;
  mercy_applied: boolean;
  finding_count: number;
  critical_count: number;
  composite_risk: number;
  hard_blocked: boolean;
  hard_block_term: string | null;
  contestable: boolean;
  appeal_deadline_hours: number;
  message: string;
  matched_policies: string[];
  max_finding_confidence: number;
  entropy: number;
  total_chars: number;
  blake3_hash: string;
  drift_level: string;
  signature: string;
  latency_ms: number;
}

/** Appeal record. */
export interface Appeal {
  appeal_id: string;
  verdict_id: string;
  user_id: string;
  reason: string;
  grounds: AppealGrounds[];
  status: AppealStatus;
  submitted_at: string | null;
  resolved_at: string | null;
  resolution: string | null;
  mediator_recommendation: string | null;
  sla_deadline: string | null;
  evidence_hash: string | null;
}

/** Session trust score. */
export interface TrustScore {
  session_id: string;
  trust_score: number;
  total_requests: number;
  offenses: number;
  calculated_at: string | null;
}

/** Sanitize result. */
export interface SanitizeResult {
  sanitized: string;
  redactions: number;
  latency_ms: number;
}

/** Options for the decide() call. */
export interface DecideOptions {
  sessionId?: string;
  profile?: GovernanceProfile;
  agentId?: string;
}

/** Options for the validate() call. */
export interface ValidateOptions {
  sessionId?: string;
  profile?: GovernanceProfile;
}

/** Options for the appeal() call. */
export interface AppealOptions {
  grounds?: AppealGrounds[];
  userId?: string;
  evidence?: string;
}

/** BTVClient constructor options. */
export interface BTVClientOptions {
  apiKey: string;
  gatewayUrl?: string;
  timeout?: number;
  maxRetries?: number;
  raiseOnBlock?: boolean;
}
