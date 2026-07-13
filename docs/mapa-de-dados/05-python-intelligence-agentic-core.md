# Mapa de Dados — Python intelligence / agentic / core / observability / security

> Catálogo a **nível de campo** de `intelligence/**`, `agentic/**`, `core/**`, `observability/**`, `security/**`.
> **Role:** INPUT / INTERMEDIATE / OUTPUT / PERSISTED. Parte do [Mapa de Dados](README.md).

## INTELLIGENCE

### llm_async_client.py
`CircuitState`{CLOSED, OPEN, HALF_OPEN}; **LLMRequest**(IN){prompt:str, max_tokens:int=100, temperature:float=0.7, model:str="gpt-4", stream:bool=False, metadata:Dict} → payload OpenAI chat; **LLMResponse**(OUT){content, model, tokens_used:int, latency_ms:float, cached:bool=False, metadata}; **CircuitBreakerStats**{state, failure_count, success_count:int, last_failure_time?:float, last_state_change:float, total_requests:int}; erros LLMError/LLMTimeoutError/LLMCircuitOpenError/LLMRateLimitError; RetryStrategy{max_retries=3, backoff_base=2.0, max_delay=30.0, jitter=True}; CircuitBreaker{failure_threshold=5, timeout=60}; metrics{requests_total/success/failed/cached, retries_total, circuit_breaks}. Cache key=blake2b(`prompt|model|max_tokens|temperature`). Header `Authorization: Bearer`.

### llm_fallback.py
`FallbackPriority`{LOW=1, NORMAL=2, HIGH=3, CRITICAL=4}; **FallbackTask**{request:LLMRequest, priority, timestamp:float, retry_count:int=0}; PriorityQueue max_queue_size=1000, worker_count=5; metrics{tasks_submitted/completed/failed/dropped, queue_full_count}.

### ner_entities.py / ner_detector.py
`NEREntityType`{PERSON_NAME, ADDRESS, PARTIAL_CARD, PARTIAL_DOC, PHONE_NATURAL, DATE_OF_BIRTH, HEALTH_INFO, FINANCIAL_INFO, UNKNOWN}; ENTITY_SEVERITY (PERSON_NAME0.4…HEALTH_INFO0.8); **NERFinding**(frozen){entity_type, text, confidence:float, start?/end?:int} props severity, is_high_risk → to_finding_dict{module:"NER_DETECTOR", rule_id:f"NER_SEMANTIC_{type}",…}; **NERBiasDeclaration**{fpr, fnr:float, calibration_date:int, sample_size:int, model_id, limitations, affected_groups}; **NERInspectionResult**{findings:List[NERFinding], latency_ms:float, model_id, input_len:int} props has_pii, high_risk_findings.

### slm_classifier.py
`IntentLabel`{BENIGN, PII_EXTRACTION, PROMPT_INJECTION, DATA_EXFILTRATION, SOCIAL_ENGINEERING, POLICY_EVASION, EVASION_ATTEMPT, UNKNOWN}; **SLMClassification**(frozen){intent, risk, confidence:float, model_id, latency_ms:float, raw_output=""} prop is_malicious; **SLMBiasDeclaration**{fpr,fnr:float, calibration_date, sample_size:int, model_id, limitations, affected_groups}; **SLMContext**(IN){lang, entropy:float, instruction_density:float, entropy_shift:bool, leet_ratio:float, trust_score:float, domain, violation_count:int}; **MercyAdvice**(frozen){legitimate_probability:float, reasoning, model_id, latency_ms}; **OutputAnalysis**(frozen){leak_detected:bool, leak_type:str, risk:float, recommendation:str, model_id, latency_ms}. Config{_model_path?, _model_id="local-slm", _n_ctx=512, _n_threads=2, _timeout_ms=100, _max_input_tokens=256, _n_gpu_layers=0}. Prompts (consts): CLASSIFICATION/MEDIUM_ZONE/NER_EXTRACTION/ADVANCED_CLASSIFICATION/MERCY_ADVISOR/EXPLAIN/OUTPUT_ANALYSIS/APPEAL_ANALYZER.

### payload_inspector.py
`InjectionSignal`{CLEAN, SUSPICIOUS, CONFIRMED}; `InspectionAction`{ALLOW, INSPECT, BLOCK}; **PayloadInspectionReport**(frozen){action, explain_decision, injection_signal, slm_classification?:SLMClassification, payload_len:int, decided_at_iso, signature, ner_result?:NERInspectionResult} → HMAC-SHA256 sobre `{action,decided,signal}`. Ctor exige `hmac_secret:bytes`.

### threat_classifier.py / misp_ingestor.py / threat_feed.py / policy_generator.py / threat_policy_bridge.py
- TAXONOMY (prompt_injection→AI_ATTACK/BLOCK/9, pii_leakage→DATA_PROTECTION/REDACT/8, …); **Classification**{threat_type, category, recommended_action, severity:int, confidence:float, indicators_matched:int}
- **ThreatEvent**(IN){id, threat_type, severity:int(1-10), source, indicators:List[str], timestamp:int, hash=""} (blake2b)
- **SQLite `threats`** (PERSISTED, `$BTV_THREATS_DB` def data/threats.db): id TEXT PK, threat_type TEXT, severity INTEGER, source TEXT, indicators TEXT(JSON), description TEXT='', mitre_id TEXT='', created_at TEXT, hash TEXT. Índices idx_type/idx_severity/idx_source. `query_threats(threat_type?, min_severity=0, source?, limit=50)`; get_stats{total_threats, by_type, by_source, avg_severity}.
- PolicyGenerator.generate → YAML{id:f"auto-{type}-001", enabled:True, priority, severity, conditions{threat_type,min_severity}, action, source:"intelligence_hub", confidence, auto_generated:True}
- **BridgeSyncResult**(frozen){synced_at:float, threats_processed, policies_generated, policies_deduplicated:int, policies_dir, all_require_review=True, errors:List}; **GeneratedPolicy**(frozen){policy_id, threat_type, severity:int, action, source_threat_id, yaml_content, requires_review=True, enabled=False} → escrita atômica em `data/policies/auto-generated/{id}.yaml`. Policy YAML: enabled:False, requires_review:True, action(BLOCK≥8/ESCALATE≥5/MONITOR_ONLY), source:"intelligence_bridge".

### training/
**TrainingSample**(frozen){text, label, source, confidence:float} (VALID_LABELS: benign, prompt_injection, evasion_attempt, pii_extraction, data_exfiltration, social_engineering); **EvalMetrics**{total_samples, true_positives/negatives, false_positives/negatives:int, label_correct/total:Dict, latencies_ms:List} props fpr/fnr/accuracy/precision/recall/avg_latency_ms/p99_latency_ms → to_bias_declaration; run_fine_tune QLoRA (base phi-4-mini, epochs=3, lora_r=16, lora_alpha=32, lr=2e-4, batch_size=4). risk_map (benign0.1…prompt_injection0.9).

## AGENTIC

### types.py / a2a_channel.py / negotiation_engine.py
- **NegotiationMessage**(frozen){type:Literal[propose/counter/accept/reject/confirm/abort], policy?:dict, reason?, round_number:int, timestamp:float, signature (HMAC)}
- **NegotiationResult**(frozen){status:Literal[confirmed/aborted], shared_policy?:dict, rounds:int, duration_seconds/drift_score:float, abort_reason?, transcript:tuple[NegotiationMessage], explain_decision, timestamp:float, signature}
- `A2AChannel`(Protocol): send/receive; InProcessChannel{_outbox,_inbox:asyncio.Queue}; MCPChannel{remote_url} (stub)
- `NegotiationState`{IDLE, PROPOSED, COUNTERED, ACCEPTED, CONFIRMED, ABORTED}; NegotiationEngine{_own_policy:dict, _sentinel, _guard, _ledger, _max_rounds=10, _timeout=300.0, _hmac_key=b"btv-negotiation-engine-v1", _session_id, _state, _tracker?, _last_drift_score=0.0}. Eventos ledger: `{event:"negotiation.{propose\|counter\|confirmed\|aborted}", session_id, round_number, message_type, status, rounds, duration_seconds, abort_reason, explain_decision}`. Abort reasons: timeout, jailbreak_blocked, peer_abort, goal_drift, incompatible_policy, max_rounds, error.

### negotiation_guard.py / protocol_registry.py / protocol_designer.py
- **SanitizeResult**(frozen){allowed:bool, clean_message?:NegotiationMessage, reason?, explain_decision, timestamp:float, signature}; NegotiationGuard{_persuasion_guard, _ffi_client?, _hmac_key=b"btv-negotiation-guard-v1", _persuasion_threshold=0.5}. _YAML_INJECTION_PATTERNS (regex).
- **ProtocolSpec**(frozen){name, category, requirements_met:frozenset, trust_assumptions:frozenset, overhead, implementation, available:bool, adr?}; **PROTOCOL_REGISTRY** (7): commit_reveal, hmac_evidence, bft_consensus, blake2b_audit (available); tee_attestation, zk_proof, mpc_computation (unavailable).
- **ProtocolPlan**(frozen){selected:tuple[ProtocolSpec], unavailable:tuple, rationale:dict, explain_decision, timestamp:float, signature} → ledger `protocol_designer.select`.

### alignment_degradation_tracker.py / arena_reporter.py / policy_elicitor.py
- **DegradationReport**(frozen){agent_id, degradation_score:float([-1,1]), problematic_collab_rate/solo_rate:float, window_sessions:int, threshold_exceeded:bool, explain_decision, timestamp:float, signature}; window=20, threshold=0.4.
- **Violation**(frozen){event_type, timestamp:float, policy_field, details}; **ArenaReport**(frozen){session_id, utility_score?:float, security_score:float, cost_efficiency:float, evidence_chain:tuple[str] (BLAKE2b), violations:tuple[Violation], negotiation_summary?:NegotiationResult, explanation, timestamp:float, signature}.
- `LLMBackend`(Protocol); AnthropicBackend{_api_key, _model="claude-sonnet-4-6", _max_tokens=1024}; MockBackend; **ElicitedPolicy**(frozen){policy:dict, gaps:tuple[str], confidence:float, source_nl, domain, schema_version, error?, explain_decision, timestamp:float, signature} prop success. KNOWN_DOMAINS(8), _EXPECTED_FIELDS por domínio.

### demo/
`StepKind`(Literal 10 valores); **Step**(frozen){kind:StepKind, actor:str, title, narration, payload:dict, arena_property}; **ScenarioOutcome**(frozen){scenario_id, scenario_title, steps:tuple[Step], arena_report?:ArenaReport}; SCENARIOS{cooperative, red_team, drift, generalisation, leaderboard}; RecordingChannel; EventCallback.

## CORE

### governance_gateway.py
**RefusalConfig**(frozen){enabled=True, min_critical_findings:int=1, require_irreversible_flag=False, persist_to_ledger=True}; **GatewayVerdict**(frozen){verdict_id, action:str(ALLOW\|BLOCK\|INSPECT\|REDACT\|EDUCATE\|LOG\|REFUSE), explain_decision, blocked_at?:str(sanitizer\|inspector\|refusal_gate\|judiciario\|fail_secure), sanitization_level, inspection_action, ethical_action?, decided_at_iso, signature, contestable=True, metadata:dict} → HMAC sobre `{action,decided_at,verdict_id}`. `evaluate(payload:str, ctx:RequestContext, evidence:RustEvidence, signal:InjectionSignal=CLEAN, finding_count=0, critical_count=0, irreversible=False)`. refusal_record ledger: `{type:"refusal_record", verdict_id, critical_count, explain_decision}`.

### tool_call_router.py
**ToolCallResult**(frozen){tool_id, action:str, output:str(vazio se BLOCK), explain_decision:Mapping, is_error:bool, latency_ms:float} prop is_blocked; ToolCallRouter{_sanitizer:ToolOutputSanitizer, _default_signal="Suspicious"}.

## OBSERVABILITY

### metrics.py — métricas Prometheus (nome · tipo · labels)
buildtovalue_decisions_total (Counter[action,profile]), buildtovalue_mercy_applied_total (Counter[profile]), buildtovalue_decision_duration_seconds (Histogram[profile]), buildtovalue_trust_score_lookup_duration_seconds/distribution (Histogram), buildtovalue_appeals_submitted_total (Counter), buildtovalue_appeals_resolved_total (Counter[outcome]), buildtovalue_pending_appeals (Gauge), buildtovalue_ledger_writes_total/duration_seconds, buildtovalue_active_sessions (Gauge), buildtovalue_system_health_score (Gauge), buildtovalue_false_positive_rate (Gauge[profile]), btv_pipeline_stage_duration_seconds (Histogram[stage=rawls\|levinas\|jonas\|gilligan]), btv_rawls_anomalies_total, btv_levinas_care_overrides_total, btv_jonas_risk_escalations_total (Counter[reason]), btv_jonas_bias_expired_total, btv_gilligan_scenarios_total (Counter[scenario=S1..S6]), btv_appeal_sla_compliance_rate (Gauge), btv_appeal_sla_breaches_total, btv_appeal_trust_adjustments_total (Counter[direction]), btv_bias_fnr_divergence_pct/fpr_divergence_pct (Gauge[validator_id]), btv_bias_gate_status (Gauge[validator_id]), btv_trust_score_adjustments_total (Counter[type]), btv_trust_score_current (Gauge[bucket]), btv_benign_refusal_total (Counter[action,mercy_scenario,domain]), btv_benign_refusal_rate (Gauge), btv_action_transition_total (Counter[from_action,to_action]), btv_action_sequence_escalation_total (Counter[pattern]), btv_action_sequence_depth (Histogram). `start_metrics_server(port=9090)`. Thresholds bias FNR: warn 5pp, block 15pp.

### logging.py / tracing.py
JSONFormatter log_data{timestamp, level, logger, message, module, function, line, +trace_id/span_id, exception, verdict_id/session_id/action/profile/trust_score/mercy_score/confidence}; VerdictLogger{verdict_id, session_id, action}. init_tracer(service_name="buildtovalue-governance", version="2.0.0", sampling_rate=0.1). Span attrs evidence.{finding_count,critical_count,composite_risk,…}, context.{agent_id,session_id,user_role,domain}, verdict.{action,confidence,mercy_score,trust_score,rule_id}. Env `ENVIRONMENT`, `OTEL_EXPORTER_OTLP_ENDPOINT`(:4317). Rust↔Python via W3C traceparent/tracestate.

## SECURITY

### keys.py / db.py
**_KeyHolder**{__slots__=("_buf",), _buf:bytearray; borrow()→bytes, zeroize()(ctypes.memset)}; singleton `_KEY_HOLDER`. Erros HmacKeyUnsetError/InsecureHmacKeyError/HmacKeyNotInitializedError. _DEV_FALLBACK=b"btv-dev-key-NOT-FOR-PRODUCTION!!"; _INSECURE_MARKERS. API init_hmac_key/get_hmac_key/rotate_hmac_key/_zeroize_for_tests. Env `BTV_ENV`, `BTV_HMAC_KEY` (removida do environ após leitura). `sqlite_connect_wal(path, timeout=30.0, check_same_thread=True)` → WAL/NORMAL/busy_timeout.

## Chaves HMAC padrão (agentic)
engine `btv-negotiation-engine-v1`, guard `btv-negotiation-guard-v1`, designer `btv-protocol-designer-v1`, tracker `btv-alignment-degradation-tracker-v1`, reporter `btv-arena-reporter-v1`, elicitor `btv-policy-elicitor-v1`. PayloadInspector/GovernanceGateway exigem `hmac_secret` injetado.
