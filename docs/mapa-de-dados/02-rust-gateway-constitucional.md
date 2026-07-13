# Mapa de Dados — Rust gateway + crates constitucionais

> Catálogo a **nível de campo** de `rust/gateway`, `btv-core`, `btv-types`, `btv-executive`, `btv-judicial`, `btv-governance`, `btv-redaction`, `btv-sigma`, `bindings`, `cli`.
> **Role:** INPUT (corpo HTTP/externo) / OUTPUT (resposta/entrega) / INTERMEDIATE (estado interno) / PERSISTED (disco/DB/ledger/wire). Parte do [Mapa de Dados](README.md).

## 1 · Gateway — corpos de request/response HTTP

### `routes/decide.rs` (POST /v1/decide)
- **DecideRequest** (IN): input:String, session_id?, profile?, agent_id?, source?, channel?, agent_policies?:Vec<String>, group_classification?, decision_confidence?:f64
- **DecideResponse** (OUT): action, original_action, mercy_applied:bool, finding_count:u32, critical_count:u32, composite_risk:f32, hard_blocked:bool, contestable:bool, appeal_deadline_hours:u32, verdict_id, signature, rationale, explain:ExplainDecision, jurisdiction_bitmask:u32, latency_ms:f64, trust_score:f32, mercy_score:f32, mercy_scenario, risk_classification, entropy:f32, ip_risk, ip_jurisdiction, drift_level
- **ExplainDecision** (OUT nested): summary, rawls/levinas/jonas/gilligan_rationale, trust_score:f32, mercy_score:f32, pipeline_stages:Vec<String>, legacy_error?:EthicalError, governance_errors:Vec<EthicalError>
- **GovernanceDecideRequest** (OUT→wire p/ Python): finding_count, critical_count:u32, composite_risk:f32, action, hard_blocked, matched_policies:Vec<String>, session_id?, profile?, agent_id?, input_text, jurisdiction_bitmask:u32, pipeline_stage, verdict_id, max_finding_confidence:f32, entropy:f32, total_chars:u32, blake3_hash, ip_risk, ip_jurisdiction, drift_level, source?, channel?, agent_policies?
- **GovernanceDecideVerdict** (IN←Python): verdict_id, action, mercy_applied, rationale, signature, contestable, appeal_deadline_hours:u32, trust_score, mercy_score:f32, mercy_scenario, risk_classification, entropy, ip_risk, ip_jurisdiction, drift_level, explain?:GovernanceExplain
- **FairnessWiringResult** (INT): composed_action:Action, composition_changed_action, apply_override, human_review_required:bool
- `severity_rank`: E131=100, E130=90, E160/E161=50, E120=30, E429=20, else 10.

### `routes/validate.rs` (POST /v1/validate, /v1/scan)
- **ValidateRequest** (IN): input, session_id?, profile?
- **ValidateResponse** (OUT): finding_count:u32, critical_count:u32, composite_risk:f32, action, original_action, mercy_applied, latency_ms:f64, contestable, appeal_deadline_hours:u32, message, hard_blocked, matched_policies:Vec<String>, verdict_id, signature, rationale
- **ScanResult** (INT): finding_count, critical_count, composite_risk, policy_action, hard_blocked, hard_block_term?, matched_policies, max_finding_confidence:f32, entropy:f32, total_chars:u32, blake3_hash, drift_level

### outras rotas
- **SanitizeRequest**(IN: text) / **SanitizeResponse**(OUT: original_length:u32, sanitized_text, masked_count:u32, masked_types:Vec<String>, latency_ms)
- **GuardRequest**(IN: text, session_id?, xss_protection:bool=true, rescan:bool=true) / **GuardResponse**(OUT: text, pii_masked:u32, masked_types, xss_patterns_found:Vec<String>, rescan_clean, latency_ms, modified)
- **PolicyTestRequest**(IN: policy_yaml, test_inputs:Vec<TestInput{input,label}>) / **PolicyTestResponse**(OUT: results:Vec<TestResult{label,finding_count,action,matched_rules}>, summary:TestSummary{total,blocked,allowed,logged:usize, fairness_score:f32}, blind_review, latency_ms)
- **HealthResponse**(OUT: status, version, uptime_seconds:u64) / **BiasHealthResponse**(OUT: bias_ok, governance_reachable:bool, details?:BiasDetails, message); **BiasDetails**(validator_id, declared_fnr_pct/measured_fnr_pct/divergence_pct:f32, level, calibration_age_days:u32, calibration_expired:bool)
- **ReloadResponse**(OUT: tenant_id, status:TenantStatus, fairness_mode) / **EvictResponse**(OUT: tenant_id, evicted:EvictionReport)
- **proxy** (ANY /v1/proxy/*): ProxyGovernanceRequest(→wire), ProxyGovernanceVerdict(action); bloqueio HTTP 451 JSON `{blocked:true, verdict:"BLOCK", reason, appeal_url:"/v1/appeals"}`; FORWARD_HEADERS=[content-type, authorization, user-agent, accept, accept-language, accept-encoding]
- **appeals/trust** — proxies puros com `serde_json::Value`.

## 2 · Gateway — estado, registries, enums
- **AppState** (INT, `Arc<AppState>`): gatekeeper:Mutex<Gatekeeper>, ip_classifier, jurisdiction_mapper, session_tracker:Mutex<SessionTracker>, http_client:reqwest::Client, start_time:Instant, tenant_router:TenantStorageRouter, tenant_deriver:TenantKeyDeriver, rawls_monitor, jonas_monitor, fairness_modes:FairnessModeRegistry, tenant_statuses:TenantStatusRegistry, policies_dir:PathBuf, audit_dir:PathBuf, audit_tx:AuditChannel, _audit_handle, plugin_registry
- **EvictionReport** (OUT): router, jonas, rawls, fairness_mode, status:bool
- **FairnessMode** enum (serde lowercase): Disabled(default), Shadow, Enforced
- **TenantStatus** enum (serde tag="state"): Initializing, Active(default), Degraded{cause:DegradationCause}
- **DegradationCause** enum: MissingBaseline, InvalidBaseline{reason}, InvalidFairnessYaml{reason}, BaselineHashMismatch{expected,actual}
- **HookContext**{hook:&str, request_id}; **GatewayPluginRegistry**{plugins:RwLock<Vec<Box<dyn GatewayPlugin>>>}
- **FairnessYaml**{mode:FairnessMode}; **TenantLoadResult**{tenant_id, status, fairness_mode}
- **Métricas Prometheus** (lazy_static): DECISIONS_TOTAL[action], MERCY_APPLIED_TOTAL, HARD_BLOCKS_TOTAL, LATENCY_MS, FINDINGS_TOTAL[type], SANITIZE_TOTAL, SANITIZE_MASKED_TOTAL[type], RATE_LIMITED_TOTAL, AUTH_REJECTED_TOTAL, DECIDE_TOTAL[action], DECIDE_LATENCY_MS, APPEALS_SUBMITTED/RESOLVED_TOTAL, PIPELINE_RAWLS/GILLIGAN_DURATION, TRUST_ADJUSTMENTS_TOTAL[direction], BIAS_GATE_VIOLATIONS_TOTAL, PROXY_REQUESTS/BLOCKED_TOTAL, PROXY_FORWARD_LATENCY_MS.

## 3 · Gateway — middleware
- **TenantId**(newtype String, Extension); **BtvClaims**(IN←JWT): tenant_id?, exp?:u64, sub?; layer com `jwt_secret:Arc<Option<Vec<u8>>>`. Sem token→DEFAULT_TENANT_ID; inválido→401; tenant inválido→403 E131.
- **ApiKeyLayer**{valid_keys:Arc<HashSet<String>>, jwt_secret}; PUBLIC_PATHS=[/health,/metrics,/v1/auth]; STATIC_EXTENSIONS=[.js,.css,.svg,.png,.ico,.html,.json,.woff,.woff2,.map]; 401 JSON `{error:"UNAUTHORIZED", message}`
- **KeyCheck**{Ok,WrongKey,Disabled}; **InternalSecret**=Arc<Option<Zeroizing<Vec<u8>>>>; HEADER `X-BTV-Internal-Key`, ENV `BTV_INTERNAL_SECRET`, MIN_SECRET_BYTES=32, compare constant-time (subtle)
- **RateLimitLayer**{max_requests:u32, window:Duration}; buckets:Cache<String,Arc<AtomicU32>>; chave `tenant:{blake3[..16]}` ou `ip:{first_ip}`; `BTV_RATE_LIMIT_RPM`(60), window 60s, moka 100_000; headers x-ratelimit-limit/remaining, retry-after
- **TraceContext**{trace_id, span_id, parent_span_id}; TRACEPARENT `00-{trace_id32}-{span_id16}-01`

## 4 · Gateway — auditoria
- **FairnessAuditEvent** (PERSISTED JSONL+gRPC): schema_version, event_id (UUID v7), ts_unix_ms:u128, tenant_id, verdict_id, fairness_mode, tenant_status, tentative_action, applied_action, composed_action, composition_changed_action, apply_override, rawls_violation, jonas_critical, jonas_warning, hard_block, human_review_required:bool, governance_error_codes:Vec<String>, legacy_error_code?. SCHEMA_VERSION="v1alpha".
- **AuditChannel**{sender:mpsc::Sender}; AUDIT_CHANNEL_CAPACITY=10_000; métricas AUDIT_EVENTS_DROPPED_TOTAL[reason], AUDIT_DRAINER_PANICS_TOTAL, AUDIT_EVENTS_EMITTED_TOTAL
- **AuditSink** trait; **JsonlAuditSink**{base_dir, writers:Mutex<HashMap>} → `{base}/{tenant}/events.jsonl`; StdoutAuditSink (target `btv_audit`); MultiAuditSink; NullAuditSink
- **pb::FairnessDecision** (gRPC `btv.audit.v1alpha`): mesmos campos do evento com `ts_unix_ms:u64`; **pb::StreamRequest**{tenant_id, resume_after_event_id}; METADATA_KEY `x-btv-internal-key`, POLL 100ms, STREAM_CHANNEL 1024.

## 5 · btv-core — tokens lineares (sem Clone/Copy, #[must_use], campos privados)
| Entity | Campos |
|---|---|
| `EvidenceToken` | hash:Blake3Hash |
| `ComplianceToken` | jurisdiction, policy_version:String, contestability_hours:u32 |
| `ComplianceAuthority` | registry:Box<dyn ComplianceRegistry> |
| `ComplianceError` | UnknownJurisdiction(String), InvalidPolicy(String,String), Unavailable |
| `Verdict` | evidence_hash:Blake3Hash, decision:Decision, explanation:String, hmac_seal:[u8;32], jurisdiction, policy_version:String, bias:BiasDeclaration |
| `OperatorToken` | operator_id:String, hmac_seal:[u8;32] |
| `EscalatedVerdict` | operator_id, reason:String, hmac_seal:[u8;32] |
| `AttestedEvidenceToken` | inner:EvidenceToken, attestation_sig:[u8;64], signer_pubkey:[u8;32] |
| `InclusionReceipt` | log_index:u64, merkle_root:[u8;32], signature:[u8;64], timestamp:u64 |
| `DeliveryToken` | verdict_record:VerdictRecord, receipt_wire:InclusionReceiptWire |
| `DeliveryPayload` | verdict:VerdictRecord, receipt:InclusionReceiptWire |
| `LogClient` | endpoint:String, verifying_key:VerifyingKey (Ed25519 pinada), http:reqwest::Client |
| `AppendResponseWire` | index:u64, root:[u8;32], signature:[u8;64], timestamp:u64 |
| `AppealWriter` | tx:mpsc::Sender<AppealRecord> (CHANNEL 1024) |

`LogClient` assina `index(8)‖root(32)‖verdict_hash(32)‖timestamp(8)`. SQLite: `schema_version`, `appeal_records`. Env `BTV_LOG_ENDPOINT`, `BTV_LOG_VERIFYING_KEY`.

## 6 · btv-types — tipos wire (`lib.rs`)
Blake3Hash([u8;32]); Decision{Allow=0,Deny=1,Block=2}; RiskLevel{Safe..Critical}; KnownDisparity{group, disparity_magnitude_pct:f32, ethical_justification, approved_at:u64}; **BiasDeclaration**{false_positive_rate/false_negative_rate:f32, validated_groups:Vec<String>, known_disparities:Vec<KnownDisparity>, measurement_tool_version}; NegotiationDeadlockReason{rounds_exhausted:u8, agent_ids:Vec<String>, last_proposal_hashes:Vec<[u8;32]>, negotiation_started_at/deadlocked_at:u64}; **AppealRecord**{evidence_hash:[u8;32], explanation_text, bias_declaration, deadlock_reason?, appeal_token, appeal_sla_deadline:u64, created_at}; **VerdictRecord**{evidence_hash:Blake3Hash, decision, explanation_hash:Blake3Hash, hmac_tag:[u8;32], legislative_version:u64, bias_declaration}; MerkleProof{path:Vec<[u8;32]>, leaf_index:u64}; InclusionReceiptWire{log_index:u64, merkle_root:[u8;32], signature:[u8;64], timestamp:u64}; DeliveryPayload; AuditEntry{verdict_hash:[u8;32], decision, risk_level, composite_risk:f32, findings_count:usize, log_index:u64, timestamp_us/latency_us:u64}; **RedactionReceiptWire**{batch_id, entries_count:usize, commitment_before/after:[u8;32], epsilon:f64, affected_groups:Vec<String>, proof_bytes:Vec<u8>, public_inputs:Vec<[u8;32]>, timestamp:u64, authority_signature:[u8;64], authority_pubkey:[u8;32]}; **BiasDeclarationFixed** repr(C) **104B**{tool_version_hash:[u8;32], fpr/fnr:f32, validated_groups_hash:[u8;32], known_disparities_hash:[u8;32]}; **TechnicalEvidence** repr(C) **9596B**{evidence_hash:[u8;32], decision:u8, _pad:[u8;3], explanation_hash:[u8;32], hmac_tag:[u8;32], legislative_version:[u8;8], bias_declaration:BiasDeclarationFixed, _reserved:[u8;9384]}; BranchRole{Legislative=0,Judicial=1,ExecutiveRep=2}; SignatureWire{signer_role, pubkey:[u8;32], signature:[u8;64]}; MandateWire{legislative_version:u64, expiry_utc:u64, ratification_sigs:[SignatureWire;3]}.

## 7 · btv-executive
`ScanSummary`{findings_count/critical_count:usize, risk_level, composite_risk:f32, executed_stages:u8, input_entropy:f32, detected_language:String, scan_duration_us:u64}; `ExecutiveResult`{delivery:DeliveryPayload, scan_summary, decision_latency_us:u64}; `Executive`{authority, log_client, scanner:GatekeeperBridge, decision_maker}; `DecisionMaker`{threat_threshold(0.95), deny_threshold(0.80), _escalate_threshold(0.60):f32}; `DecisionError`{GatekeeperFailed, ComplianceUnavailable, LogUnavailable, IntegrityFailure, InputViolation(String)}.

## 8 · btv-judicial
`PayloadVerification`{hmac_valid, signature_valid, merkle_valid, root_consistent, overall_valid:bool, verdict_hash:[u8;32], details:String}; `FailureDetail`{verdict_hash:[u8;32], log_index:u64, reason}; `AuditReport`{report_id, timestamp, payloads_verified/passed/failed:usize, failures:Vec<FailureDetail>, auditor_id, log_root:[u8;32], tree_size:u64, signature:[u8;64], auditor_pubkey:[u8;32]}; `JudicialError`{ConfigurationMissing, CryptoError, VerificationFailed, LogQueryFailed(String)}; `HmacVerifier`{key:Vec<u8>}; `VerifiedPayload`{verdict_hash:[u8;32], log_index:u64, decision, valid:bool, details}; `Monitor`{hmac_verifier, receipt_verifier, ledger:LedgerQuery, auditor}. Env `BTV_HMAC_KEY`.

## 9 · btv-governance
`AmendmentId`{Genesis, Amendment(u64)}; `RatificationProof`{amendment, legislative/judicial/executive_rep_sig:[u8;64], nonce:[u8;32], timestamp:DateTime<Utc>, 3×_pubkey:[u8;32]}; `MandateToken`(linear){legislative_version:u64, expiry:DateTime<Utc>, ratification, mandate_hash:[u8;32]}; `MandateWire`(variante governance){legislative_version:u64, expiry_utc:i64, ratification:RatificationProof, mandate_hash:[u8;32]}; `SystemState`{Active{version,expires_at}, Interregnum{since,last_version}}; `ConstitutionalState`{current_mandate:Option<MandateToken>, mandate_history:Vec, current_version:u64}; `Amendment`{id, kind:AmendmentKind, description, target_version/previous_version:u64, proposed_at, nonce:[u8;32]}; `AmendmentKind`{PolicyUpdate(PolicyDelta), ConstitutionalAmendment(ConstitutionalDelta)}; `StoneClause`{id, title, description, invariant, paper_reference, established_at_version:u64} (SC-001..SC-006); `SunsetPolicy`{policy_id, created_at, sunset_at, max_renewals/renewal_count:u32, authorized_by}; `LegislativeVersion`{version:u64, activated_at, change_summary, mandate_hash:[u8;32]}; `GovernanceError`{MandateExpired, NoMandate, InvalidRatification, VersionMismatch, GenesisMandateExpired, SunsetPolicyExhausted, LogPublicationFailed, ConfigurationMissing}; `BranchKeys`{legislative/judicial/executive_rep:VerifyingKey}.

## 10 · btv-redaction
`RedactionConfig`{epsilon(0.05):f64, max_batch_size(1000):usize, protected_groups:Vec<String>(11 default), zk_enabled(true)}; `RedactionError`{AuthorizationFailed, BatchTooLarge{count,max}, EmptyBatch, NoProtectedGroupsAffected, ProvingFailed, ProofInvalid, EpsilonViolation{group,delta,epsilon}}; `RedactionResult`{receipt:RedactionReceipt, new_statistics:LedgerStatistics}; `GroupStats`{group_label, total/approved/denied/redacted:u64}; `LedgerStatistics`{groups:Vec<GroupStats>, total_decisions:u64, timestamp}; `RedactionEntry`{verdict_hash:[u8;32], group_label, was_approved:bool, subject_signature:[u8;64], subject_pubkey:[u8;32]}; `StateCommitment`{commitment_point:[u8;32], timestamp:u64}; `RedactionReceipt`{batch_id, entries_count, commitment_before/after:StateCommitment, epsilon:f64, affected_groups, proof_bytes:Vec<u8>, public_inputs:Vec<[u8;32]>, timestamp:u64, authority_signature:[u8;64], authority_pubkey:[u8;32]}. Invariante ε: `∀g: |taxa_antes − taxa_depois| ≤ ε`.

## 11 · btv-sigma
`AppState`{store:Arc<dyn LogStore>, signer:LogSigner}; `AppendRequest`(IN){verdict_hash:[u8;32]}; `AppendResponse`(OUT){index:u64, root:[u8;32], signature:[u8;64], timestamp:u64}; `RootResponse`{root:[u8;32], tree_size:u64}; `ProofResponse`{leaf_hash:[u8;32], proof:Vec<[u8;32]>, root:[u8;32], wire_proof:MerkleProof}; `MerkleTree`{leaves:Vec<[u8;32]>, nodes}; `LogSigner`{signing_key:SigningKey (Ed25519, sem Clone/Serialize)}; `InMemoryStore`{tree:Mutex<MerkleTree>}. Assinatura `index(8)‖root(32)‖verdict_hash(32)‖timestamp(8)`=80B; `hash_pair`=SHA256(min‖max). Env `BTV_LOG_VERIFYING_KEY`.

## 12 · bindings / cli
`TechnicalEvidence` repr(C) C-FFI{protocol_version:u8, audit_trail_id:u128, timestamp:u64, evidence_hash:[u8;32], composite_risk:u8, risk_level:u8, finding_count:u8, critical_count:u8, input_size:usize, processing_time_us:u64}; C_API_VERSION=2; MAX_INPUT_SIZE=10MB; `ThreatType`/`RegulatoryFramework` enums; `PenaltyCalculatorV2` (tabela (ThreatType,Framework)→i64); `Cli{command:Commands{Validate{text}, Health}}`.

## Variáveis de ambiente (Rust, gateway+constitucional)
`BTV_API_KEYS`, `BTV_JWT_SECRET`, `BTV_INTERNAL_SECRET`(≥32B), `BTV_ENV`, `BTV_GOVERNANCE_URL`(:8000), `BTV_PROXY_UPSTREAM_URL`(api.openai.com), `BTV_RATE_LIMIT_RPM`(60), `BTV_POLICIES_DIR`, `BTV_AUDIT_DIR`, `BTV_TENANT_DATA_DIR`, `BTV_HMAC_KEY`, `BTV_LOG_ENDPOINT`(:3100), `BTV_LOG_VERIFYING_KEY`, `BTV_SIGMA_ENDPOINT`, `PORT`, `GRPC_PORT`, `OTEL_EXPORTER_OTLP_ENDPOINT`.

## Colisões de tipo a atenção
- **Três `TechnicalEvidence`**: btv-types 9596B (constitucional), bindings C-FFI (compacto), kernel 9632B (operacional).
- **Dois `MandateWire`**: btv-types (`ratification_sigs:[SignatureWire;3]`, `expiry_utc:u64`) vs btv-governance (`ratification:RatificationProof`, `expiry_utc:i64`, `mandate_hash`).
- **Dois `Decision`**: btv-types 3 variantes vs kernel 6.
- Serialização: serde_json (HTTP/JSONL), helpers `serde_bytes_64` para `[u8;64]`, Ed25519, HMAC-SHA256, BLAKE3, Merkle SHA-256 (min‖max).
