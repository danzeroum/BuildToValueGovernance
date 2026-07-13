# Mapa de Dados — Python `governance/`

> Catálogo de dados a **nível de campo** do maior pacote do repositório (`python/buildtovalue/governance/`, ~90 módulos).
> **Legenda:** Kind = dataclass/class/enum/TypedDict/Protocol/const · Role = **INPUT** (vem de fora) / **INTERMEDIATE** (computado/retido no processamento, mesmo que descartado) / **OUTPUT** (retornado/serializado) / **PERSISTED** (gravado em ledger/SQLite/disco). `frozen` = dataclass imutável.
> Parte do [Mapa de Dados completo](README.md).

## Sumário de subsistemas
- **A** — DTOs base, política, ethical context engine, mercy/ética, trust/perfil/sessão, contestabilidade, goal-drift, ledger/proveniência.
- **B** — agent PDP, capability/budget, contexto/sanitização, RAG/memória, detectores/guards, integridade de modelo, consenso/kill-switch, output/timing/batch.

---

# Parte A — base, política, ética, ledger

## types.py
| Entity | Kind | Fields / Members | Role | Flows |
|---|---|---|---|---|
| `ActionType` | enum(str) | ALLOW, LOG, EDUCATE, REDACT, PENDING_APPROVAL, BLOCK, ESCALATE_HUMAN="escalate_human" | INTERMEDIATE | severidade via ACTION_SEVERITY |
| `ACTION_SEVERITY` | const Dict | ALLOW0 LOG1 EDUCATE2 REDACT3 PENDING_APPROVAL4 BLOCK5 ESCALATE_HUMAN6 | const | ordenação |
| `RequestMetadata` | dataclass | agent_id="unknown", session_id="unknown", user_role="anonymous", domain="general", timestamp, is_first_offense=True, has_prior_violations=False, trust_score=0.5, educational_mode=False, operation_type=None, criticality="MEDIUM", user_history={}, ip_address=None | INPUT | ECE.decide, TechnicalLayer, RecoveryEngine |
| `EthicalContext` | dataclass | user_id, session_id, request_id, timestamp, user_history={}, trust_score=0.5, operation_type, criticality="MEDIUM", is_first_offense=True, has_prior_violations=False, educational_mode=False, domain="general", user_role="anonymous" | INPUT | GovernanceLayer.decide |
| `SimpleFinding` | dataclass | rule_id="", confidence=0.5, severity=0.5, module="" | INTERMEDIATE | duck-type do Finding Rust |
| `SimpleTechnicalEvidence` | dataclass | composite_risk=0.0, finding_count=0, critical_count=0, entropy=0.0, total_chars=0, findings=[], _has_pii=False; @property stats→_Stats, critical→[sev≥0.8] | INTERMEDIATE | adapter do MercyCalculator |
| `Finding` | dataclass | title, description, severity=0.5, confidence=0.5, location, evidence, category | INTERMEDIATE | finding canônico |
| `TechnicalEvidence` | dataclass | finding_count=0, critical_count=0, composite_risk=0.0, findings=[], critical=[], stats=_Stats, hash="", timestamp, ffi_validation_time_ms=0.0, ffi_buffer_size=0 | INPUT | ECE.decide |

## exceptions.py
| `GovernanceError`(base), `SecurityViolation`(model_id, severity="critical"), `IntegrityCheckFailed`(model_id) | class(Exception) | — | — |

## ffi_client.py
| Entity | Kind | Fields / attrs | Role | Flows |
|---|---|---|---|---|
| `FFIError`/`BufferOverflowError`/`DeserializationError`/`BridgeNotAvailableError` | Exception | — | — | fail-secure |
| `BiasDeclaration` | dataclass | false_positive_rate, false_negative_rate, calibration_date=0, test_dataset_size=0, is_valid=False | INTERMEDIATE | parse do JSON do kernel |
| `Finding` | dataclass | title, description, severity=0.5, confidence=0.5, location, evidence, category | INTERMEDIATE | wire FFI |
| `TechnicalEvidence` | dataclass | version, timestamp, audit_trail_id, composite_risk, risk_level="Unknown", finding_count, critical_count, entropy, input_size, executed_modules, processing_time_us, hash, max_severity, bias, findings=[], critical=[], stats={}, categories=[], ffi_validation_time_ms, ffi_buffer_size | INPUT/OUTPUT | `FFIClient.scan()` (deserialize do Rust) |
| `FFIClient` | class | `_btv_kernel`, `bridge_mode`, `_metrics`{calls_total, buffer_overflows, deserialization_errors} | service | ponte PyO3 |

## ffi_types.py
| `FindingWire` TypedDict | title:Required[str], description:Required, severity:Required[float], confidence:Required[float], category:str(opt) | INPUT wire |
| `BiasWire` TypedDict | false_positive_rate, false_negative_rate, calibration_date:int, test_dataset_size:int, is_valid:bool | INPUT wire |

## policy_engine.py
| Entity | Kind | Fields / Members | Role |
|---|---|---|---|
| `PolicyAction` | enum | ALLOW, REDACT, ESCALATE, BLOCK | INTERMEDIATE |
| `PolicySeverity` | enum | LOW, MEDIUM, HIGH, CRITICAL | INTERMEDIATE |
| `PolicyRule` | dataclass frozen | rule_id, description, action, severity, condition_field, condition_operator, condition_value:Any, adr_refs=[] | INTERMEDIATE (do YAML) |
| `PolicyEvalResult` | dataclass frozen | action, triggered_rules:List[str], policy_source, composite_risk, contestable, sla_deadline_iso, hmac_tag, explain; explain_decision() | OUTPUT (HMAC-SHA256) |
| `ModelConfig` | dataclass frozen | manifest_path, expected_hash_env | config |
| `ModelIntegrityConfig` | dataclass frozen | verification_enabled, block_on_failure, models:Dict[str,ModelConfig] | config |
| `AbliterationConfig` | dataclass frozen | refusal_threshold, refusal_threshold_min/max, probe_timeout_ms | config |
| `ArtifactAllowlistConfig` | dataclass frozen | require_artifact_allowlist, allowlist_hash_algorithm, block_on_unknown_artifact | config |
| `PolicyEngine` | class | `_rules`, `_policy_source`, `_governance_config`; @property report_threshold(0.65 clamp 0.50–0.85), rule_count | service |

## policy_loader.py
Funções (sem dataclasses): `load_ethics_committee_pubkey()`→Ed25519PublicKey; `verify_policy_yaml(yaml_bytes, signature_b64)`→bool (fail-secure). Env `BTV_POLICY_PUBKEY_PATH`.

## policy_signer.py
| Entity | Kind | Fields / attrs | Role |
|---|---|---|---|
| consts | const | HMAC_ALGORITHM="sha256", SIGNATURE_VERSION="v1", KEY_ROTATION_DAYS=90 | const |
| `SigningKey` | dataclass | key_id, key_material:bytes, created_at, expires_at, algorithm="sha256", version="v1" | PERSISTED (JSON hex) |
| `PolicySignature` | dataclass | policy_id, signature, key_id, algorithm, version, signed_at, signer, metadata={} | OUTPUT |
| `SignedPolicy` | dataclass | policy:Dict, signature:PolicySignature | OUTPUT (HMAC-SHA256) |
| erros | Exception | PolicySigningError/InvalidSignatureError/ExpiredKeyError/KeyNotFoundError | — |
| `PolicySigner` | class | key_store_path, `keys:Dict[str,SigningKey]`, active_key_id, audit_log, metrics{signatures_created, validations_success/failed, keys_rotated} | service |

## policy_hygiene.py
| `HygieneReport` dataclass frozen | policy_path, length_ratio, trigram_repetition, hygiene_grade:int, issues:tuple, explain_decision, evaluated_at_iso, signature, is_healthy:bool | OUTPUT (HMAC) |
| `PolicyHygieneValidator` class | const `_HMAC_KEY=b"btv-policy-hygiene-v1"` | service |
| consts | BASELINE_LENGTH_CHARS=500, MAX_TRIGRAM_REPETITION=0.30, GRADE_MAX=6 |

## policy_tester.py / policy_tester_runner.py
| `CaseCategory` enum | HARD_BLOCK, PII_CRITICAL, PII_MODERATE, INSTRUCTION_OVERRIDE, BENIGN_TECHNICAL, BENIGN_PERSONAL, EDGE_CASE | INTERMEDIATE |
| `BlindTestCase` dataclass | case_id, input_text, category, expected_action, group, risk_level | INPUT |
| `TestResult` dataclass | case_id, category, expected_action, actual_action, passed, latency_ms, group, error=None | INTERMEDIATE |
| `BlindTestReport` dataclass | policy_name, epoch, total_cases, passed, failed, pass_rate, coverage_pct, equity_ok, ci_gate_passed, duration_ms, results=[], equity_details={}, fingerprint | OUTPUT (sha256 fingerprint) |
| `PolicyTester` class | consts CI_PASS_RATE=0.95, EQUITY_MAX_DIFF=0.10; POSTs /v1/decide | service |
| ⚠️ | `BlindTestCase.category`/`TestResult.category` anotados `TestCategory` (indefinido); valores reais são `CaseCategory` | — |

## safe_expression_evaluator.py
| erros | Exception | SecurityError/ExpressionTimeoutError/DisallowedNodeError/DisallowedFunctionError |
| `EvaluationResult` dataclass | success:bool, value:Any, error, execution_time_ms, nodes_evaluated | OUTPUT |
| `SafeExpressionEvaluator` class | consts ALLOWED_NODES:Set[type], ALLOWED_FUNCTIONS:Set[str], OPERATORS:Dict; attrs timeout, max_length, max_depth, `_cache` (max 100) | service (sandbox AST) |
| `BatchExpressionValidator` class | attr evaluator | service |

## sector_loader.py
| `SectorPatterns` dataclass | sector_id, risk_classification, risk_multiplier:float, patterns:Dict[str,List[str]]={} | INTERMEDIATE (YAML) |
| `SectorLoader` class | const HIGH_RISK_MULTIPLIER=0.7; `_index`, `_cache` | service |

## blind_evaluator.py
| `PolicyEngineProtocol` Protocol | evaluate_blind(input_text, policy_yaml, context)→str | contract |
| `BlindVerdict` dataclass frozen | case_id, action, passed:bool, latency_us:int | OUTPUT |
| `BlindEvaluator` class | const `_FLEXIBLE={EDUCATE,LOG}`; BIAS FPR1.4%/FNR0.9% | service (véu de Rawls, context={}) |

## ethical_context_engine.py
| `EthicalContextEngine` class | attrs profile_manager, contestability_loop, bias_guardian, persuasion_guard, bias_declaration:Dict, `_profile_cache`, metrics{decisions_total, technical_decisions, governance_decisions, mercy_applied, contests_submitted, security_violations, timeouts, cache_hits, avg_technical_time_ms, avg_governance_time_ms}, `_technical:TechnicalLayer`, `_governance:GovernanceLayer`, consensus_validator | service → UnifiedDecision |
| `EthicalContextEngineV2`/`V3` | override decide→v2/v3 | compat |
| `EthicalContextEngineFactory` | static create_* | factory |
| `_DEFAULT_BIAS_DECLARATION` const | model_version="1.1.0-unified", false_positive_rate=0.05, false_negative_rate=0.02, calibration_dataset_size=10000, known_limitations[] | const |

## context_engine.py (legado v1.9.1)
| `EthicalContextEngine` class | `_signing_key_fn`, `_mercy_calc`, `_trust_scores:Dict`, `_violation_counts:Dict`, `_verdict_counter`, `_policy_engine`, report_threshold=0.65 | service → EthicalVerdict (HMAC payload `verdict_id\|blake3_hash\|action\|ts`) |

## context_engine_types.py
| `RequestContext` dataclass | agent_id, session_id, domain="general", user_role="anonymous", ip_jurisdiction="XX", ip_risk="Low", drift_level="None", timestamp, prior_sensitivity_tags=[], cumulative_risk=0.0, active_combinations=[] | INPUT |
| `RustEvidence` dataclass | composite_risk, finding_count, critical_count, entropy, total_chars, policy_action:str, blake3_hash:str, findings_summary=[] | INPUT |
| `EthicalVerdict` dataclass | verdict_id, timestamp, original_action, final_action, mercy_applied, mercy_scenario, mercy_score, trust_score, explanation, hmac_signature, blake3_hash, contestable=True, appeal_deadline(+24h), report_triggered=False | OUTPUT/PERSISTED |

## context_engine_explain.py
Funções: `dp_noise(value, sensitivity=0.1, epsilon=1.0)` (ruído Laplace/DP); `explain_decision(...)`→str.

## ece_technical.py
| `TechnicalLayer` class | `_trust, _mercy, _eval, _metrics, _cache, _pm` | service → TechnicalVerdict |
| `build_technical_eval_context` | ctx dict: finding_count, critical_count, composite_risk, risk_level, trust_score, agent_id, session_id, user_role, domain, has_cpf, has_cnpj, has_pii, max_severity, total_findings, is_high_risk, is_trusted | INTERMEDIATE (→SafeEvaluator) |
| `_RISK_THRESHOLDS` const | (80,CRITICAL),(60,HIGH),(30,MEDIUM) | const |

## ece_governance.py
| `GovernanceLayer` class | `_signer:PolicySigner, _gilligan:GilliganStage, _bias_decl:Dict` | service → EthicalDecision (assina via PolicySigner) |
| funcs | calculate_technical_uncertainty, determine_final_verdict, calculate_governance_confidence, build_mock_decision, build_cot_block_decision | — |

## ece_types.py
| `Rule` dataclass | id, action:str, priority:int, domain, min_risk_level, required_findings, min_trust_score, max_trust_score, condition | INTERMEDIATE |
| `TechnicalVerdict` dataclass | action:ActionType, confidence, rule_id, rationale, mercy_score=0.0, trust_score=0.0, signature:Opt[bytes], context_factors={}, security_evaluation_time_ms, expression_nodes_evaluated | OUTPUT |
| `EthicalDecision` dataclass | verdict:ActionType, adjusted_severity, confidence, context:EthicalContext, mercy_applied, mercy_factor:Opt[MercyFactor], rationale, contributing_factors, contestable=True, appeal_deadline, signature, signed_at, bias_declaration={} | OUTPUT |
| `UnifiedDecision` dataclass | decision_id, timestamp, technical_verdict, ethical_decision, evidence_hash, request_metadata, ethical_context, profile_name, total/technical/governance_time_ms; to_v2_verdict/to_v3_decision/to_audit_dict | OUTPUT/PERSISTED |

## mercy_algorithm.py / mercy_factor.py / mercy_scenarios.py / gilligan.py
| `MercyFactors` dataclass | uncertainty_score, context_justifiability, trust_score, harm_potential, first_offense:bool | INTERMEDIATE |
| `MercyCalculator` class | weights{uncertainty0.30, justifiability0.25, trust0.20, harm0.15, first_offense0.10}, `_violation_history`; scores por domínio dev0.9…legal0.2 | service |
| `MercyFactor` dataclass | technical_uncertainty, first_offense=True, trust_score=0.5, violation_severity, should_apply_mercy=False, mercy_adjustment, rationale | INTERMEDIATE |
| `MercyScenarioResult` dataclass frozen | original_action, final_action, downgrade_levels:int, scenario_id, rationale, mercy_score; @property mercy_applied | OUTPUT |
| `evaluate_scenarios` | S1_CRITICAL_OVERRIDE, S2_HIGH_TRUST_VETERAN, S3_DOMAIN_CONTEXT, S4_UNCERTAIN_DETECTION, S5_REPEAT_LENIENCY, S6_DEFAULT_NO_MERCY | — |
| `GilliganStageResult` dataclass | mercy_score, care_focus:str, factors:Opt[MercyFactors], explanation, passed:bool, error | OUTPUT |
| `GilliganStage` class | consts SOFTEN_THRESHOLD=0.65, MAINTAIN_THRESHOLD=0.35; `_calc:MercyCalculator`; care_focus∈{soften,maintain,block} | service |

## trust_score.py / profile_manager.py / session_manager.py / sensitivity_accumulator.py
| `UserActivity` dataclass | session_id, timestamp:int, action:str, result:str, context | INTERMEDIATE |
| `TrustScoreCalculator` class | weights{base0.20, history0.30, appeals0.20, decay0.15, consistency0.15}, `_session_mgr`, trust_cache, activity_log(deque 200); roles admin0.9…anonymous0.2 | service · SQLite `escrow_ledger`(escrow_id, session_id, amount, delegation_id, status, created_at) |
| consts trust | MAX_SESSIONS=10000, SESSION_TTL_S=1800, ACTIVITY_MAX=200, TRUST_CACHE_TTL_S=300, ESCROW_DB_PATH=env BTV_DB_PATH | const |
| `AgentModuleConfig` dataclass | visual_firewall, channel_authority, oracle_trust_gate, rag_verifier, skill_monitor, liveness_monitor (Opt[Path]) | config |
| `PolicyRule` dataclass | id, name, description, action:str, priority:int, validators=[], categories=[], min_severity=0.0, min_confidence=0.0 | INTERMEDIATE |
| `DomainConfig` dataclass | risk_multiplier=1.0, allowed_findings=[], blocked_findings=[], education_message | config |
| `Profile` dataclass | id, name, description, parent_id, rules=[PolicyRule], domain_config:Dict[str,DomainConfig], version="1.0.0", created_at, updated_at, output_schema | INTERMEDIATE (YAML + herança) |
| `ProfileManager` class | profiles_dir, cache:Dict[str,Profile], metrics{profiles_loaded, cache_hits/misses} | service |
| `SessionManager` class | `_last_seen:OrderedDict[str,float]`, `_max`, `_ttl`, `_op_counter`, evictions | service (LRU+TTL) |
| `SensitivityState` dataclass | tags:Set, tag_counts:Dict(defaultdict), cumulative_risk, active_combinations:List, first_seen, last_seen, request_count | INTERMEDIATE/PERSISTED(mem) |
| `SessionSensitivityAccumulator` class | `_sessions:Dict[str,SensitivityState]`, `_session_mgr`, metrics{accumulations, combinations_detected, evictions} | service |
| `FINDING_TO_SENSITIVITY` const | cpf/cnpj→PII_BRAZILIAN*, email/phone→PII_CONTACT, credit_card→FINANCIAL, ssn→PII_US_GOV, nhs→PII_UK_HEALTH, vat→PII_EU_FISCAL, iban→FINANCIAL_EU, prompt_injection→SECURITY_INJECTION | const |
| consts | COMBINATION_RISK_BOOST=0.15, DANGEROUS_COMBINATIONS(12 pares), MAX_TAGS_PER_SESSION=50 | const |

## contestability/ + escalation
| `ContestabilityLoop` class | sla_hours=24, db_path(env BTV_APPEALS_DB), `appeals:Dict[str,Appeal]`, metrics{appeals_submitted/accepted/rejected/expired, false_positives_confirmed} | service · SQLite `appeals` |
| `_TrustStore` Protocol | adjust(user_id, delta) | contract |
| `AppealStatus` enum | PENDING, UNDER_REVIEW, ACCEPTED, REJECTED, EXPIRED | INTERMEDIATE |
| `Appeal` dataclass | appeal_id, audit_trail_id:int, user_id, timestamp, reason, evidence_provided, status=PENDING, reviewer_notes, resolution_timestamp, sla_deadline(+24h), evidence_hash, grounds:list, mediator_recommendation | PERSISTED (appeals.db) |
| `EthicalVerdict` dataclass | decision:Literal[ALLOW,BLOCK,EDUCATE,CONTEST], explanation, bias_declaration, finding_count, critical_count, hmac_signature:bytes | OUTPUT (HMAC) |
| `VALID_GROUNDS` const | rawls_equity, levinas_protection, gilligan_mercy, jonas_responsibility, technical_error, scope_mismatch, false_positive | const |
| `EscalationLevel` IntEnum | NONE0, WARNING1, CRITICAL2, BREACHED3 | INTERMEDIATE |
| `AppealPriority` IntEnum | LOW0, MEDIUM1, HIGH2, URGENT3 | INTERMEDIATE |
| `EscalationEvent` dataclass frozen | appeal_id, level, timestamp, hours_remaining:float, message | OUTPUT |
| `WebhookTarget` dataclass | url, actions:List[str], enabled=True, timeout_seconds=5, retry_max=2 | config |
| `ContestabilityEscalation` class | `_loop`, `_webhooks`, `_escalation_log`, `_http_post`, metrics{escalations_warning/critical/breached, webhooks_sent/failed} | service |

## explanation_store.py / recovery_engine.py
| `FullExplanation` dataclass | audit_trail_id:int, timestamp, input_hash:int, input_size, evidence_summary:Dict, findings_detail:list[Dict], verdict:Dict, context:Dict, full_rationale:str, decision_factors:Dict | PERSISTED |
| `ExplanationStore` class | db_path, `_local`(thread-local) | service · SQLite `explanations`(audit_trail_id PK, timestamp, input_hash, action, composite_risk, confidence, mercy_applied, full_data JSON, created_at) ret 90d |
| `RecoveryStrategy` enum | ALLOW_WITH_AUDIT, DEGRADE_GRACEFUL, REDIRECT_HUMAN, QUARANTINE_SESSION, MAINTAIN_BLOCK | INTERMEDIATE |
| `RecoveryOutcome` dataclass frozen | strategy, explain_decision, mercy_score, contestable, sla_deadline_iso, session_id, request_id, decided_at_iso, signature, metadata={} | OUTPUT (HMAC) |
| `RecoveryEngine` class | `_secret`, `_mercy:MercyCalculator`, `_violation_counts` | service |

## goal_drift/
| `DriftAction` enum | ALLOW, ESCALATE_HUMAN, BLOCK | INTERMEDIATE |
| `DriftDirection` enum | SECURITY_TO_CONVENIENCE, CONVENIENCE_TO_SECURITY, NONE | INTERMEDIATE |
| `DriftReport` dataclass frozen | session_id, policy_drift_detected, drift_action, drift_score_sequence:tuple, trend_pct:int, asymmetric_pressure:bool, explain_decision, decided_at_iso, signature, drift_direction=NONE, pressure_accumulation_score=0.0 | OUTPUT (HMAC) |
| `_SessionWindow` dataclass | scores:deque[int], actions:deque[str] (maxlen K) | INTERMEDIATE |
| `ModelPerformanceReport` dataclass frozen | model_id, metric, baseline, degradation_pct, degradation_detected, explain_decision, measured_at_iso, signature | OUTPUT |
| `GoalDriftSentinel` class | `_secret_fn`, `_window_k`, `_threshold`, `_sessions`, `_session_mgr`, `_model_metrics`(deque 30) | service · persiste `drift_checkpoint` no DurableLedger |
| consts | DRIFT_WINDOW_K=10, DRIFT_THRESHOLD_PCT=60, DRIFT_SCORE{None0…Critical4} | const |

## durable_ledger.py / delegation_ledger.py / content/feedback provenance / commit_reveal
| `LedgerEntry` dataclass frozen | sequence:int, entry_hash:str, prev_hash:str, payload:Dict(exige explain_decision), hmac_sha256:str, recorded_at_iso:str | PERSISTED (cadeia append-only) |
| `LedgerVerification` dataclass | valid:bool, entries_checked:int, first_invalid_sequence, reason | OUTPUT |
| `DurableLedger` class | `_hmac_key`, `_entries:List[LedgerEntry]`, `_lock`, `_prev_hash_bytes` | service (BLAKE2b chain + HMAC-SHA256) |
| `DelegationRecord` dataclass frozen | record_id, parent_agent, child_agent, scope, capabilities:List, created_at, chain_hash, hmac_sha256, revoked=False | PERSISTED |
| `ChainResult` dataclass frozen | valid, depth:int, chain:List[str], explain | OUTPUT |
| `WorkContract` dataclass frozen | contract_id, contractor, scope_merkle:hex, model_hash:hex, acceptance_criteria_hash, sampling_seed:Opt, created_at, hmac_sha256 | PERSISTED |
| `DelegationLedger` class | `_key_fn`, `_max_depth`(5), `_scope_rank`, `_records`, `_children`, `_parent_of`, `_work_contracts` | service (BLAKE3 Merkle) |
| `ProvenanceReport` dataclass frozen | action:ProvenanceAction, content_hash(BLAKE2b), c2pa_present, c2pa_valid, exif_consistent, classification, explain_decision, decided_at_iso, signature | OUTPUT · ledger `content_provenance_check` |
| `ContentMetadata` dataclass | content_bytes:bytes, classification=INTERNAL, exif_data, c2pa_manifest, source_uri | INPUT |
| `FeedbackEvent` dataclass frozen | user_id, polarity:FeedbackPolarity, target_id, timestamp | INPUT |
| `FeedbackVerdict` dataclass frozen | user_id, risk:FeedbackRisk, flip_ratio:float, burst_detected:bool, explain_decision:dict, ledger_entry:str, decided_at_iso | OUTPUT (ledger HMAC) |
| `CommitEntry` dataclass frozen | commit_id, commit_hash(BLAKE2b), agent_id, committed_at_iso, ttl_seconds, status:CommitStatus, explain_decision, signature | OUTPUT/PERSISTED |
| `RevealResult` dataclass frozen | commit_id, status:RevealStatus, agent_id, revealed_at_iso, explain_decision, signature | OUTPUT |
| `_normalize.py` | `normalize_drift_level`(fail-secure "High"), `normalize_action`(fail-secure "BLOCK") | — |

---

# Parte B — PDP, capability, detectores, integridade, consenso

## agent_pdp.py — contratos PDP canônicos (ADR-029)
| Entity | Kind | Fields / Members | Role |
|---|---|---|---|
| `ActionImpact` | enum(str) | SAFE, DESTRUCTIVE, IRREVERSIBLE (default fail-secure IRREVERSIBLE) | INPUT |
| `AgentVerdict` | enum(str) | ALLOW, EDUCATE, PENDING_APPROVAL, BLOCK | OUTPUT |
| `AgentAction` | dataclass | name, impact=IRREVERSIBLE, capabilities:List[str]=[] | INPUT |
| `AgentContext` | dataclass | profile_id="default", sector_id="general", session_trust_score=0.5, agent_metadata={} | INPUT |
| `AgentDecisionRequest` | dataclass | agent_id, session_id, action:AgentAction, parameters_hash(64-hex BLAKE3), schema_version="1.0", request_id(uuid), parameters_preview={}, context:AgentContext, timestamp_utc, parent_verdict_id, delegation_depth=0 | INPUT (post_init zera preview se IRREVERSIBLE) |
| `BiasSummary` | dataclass | false_positive_rate_pct, false_negative_rate_pct, calibration_date, known_limitations="" | OUTPUT |
| `VerdictEnvelope` | dataclass | request_id, verdict, verdict_code:int, explain_decision, bias_declaration:BiasSummary, contestable, appeal_deadline_utc, policy_version_applied, evidence_id, hmac_sha256, timestamp_utc, approval_id | OUTPUT/PERSISTED (verify_hmac constant-time; @property is_blocked) |

## agent_budget.py / privacy_budget.py / approval_workflow.py
| `BudgetLimits` dataclass | max_tokens=1_000_000, max_cost_usd=10.0, max_api_calls=500, max_tools_per_request=20 | INPUT |
| `BudgetStatus` dataclass | agent_id, session_id, tokens_used/remaining, cost_used/remaining_usd, api_calls_used/remaining | OUTPUT |
| `AccountTier` enum | OPERATIONAL, RESERVE, UNTOUCHABLE | INPUT |
| `ResourceHierarchy` dataclass frozen | accounts:Dict[str,AccountTier], daily_operational_limit_brl:Decimal, human_sig_required_above_brl:Decimal | INPUT |
| `AgentBudget` class | `_resource_hierarchy`, `_default:BudgetLimits`, `_agents`, `_usage:Dict[(agent,session),_Usage]` | service (EDUCATE@80%, BLOCK@100%) |
| `SensitiveDataType` enum | GPS_LOCATION, HEALTH_DATA, FINANCIAL="FINANCIAL_DATA", BIOMETRIC | INPUT |
| `BudgetStatus`(privacy) enum | OK, WARNING(≥70%), CRITICAL(≥90%), EXHAUSTED(100%→BLOCK) | OUTPUT |
| `BudgetCheckResult` dataclass frozen | status, data_type, window, used:int, limit:int, explain_decision, decided_at_iso, signature | OUTPUT/PERSISTED |
| `PrivacyBudgetTracker` class | `_secret`, `_db_path`, `_limits`, `_lock` | PERSISTED · SQLite `privacy_usage`(id, agent_id, session_id, data_type, recorded_at) |
| `ApprovalStatus` enum | PENDING, APPROVED, DENIED, EXPIRED | OUTPUT |
| `ApprovalTicket` dataclass | ticket_id, request_id, agent_id, action_name, reason, status, created_at, timeout_s, approver_id, resolved_at, hmac_sha256 | OUTPUT (in-mem) |
| `ApprovalWorkflow` class | `_timeout`, `_triggers`, `_expired_action`, `_key`, `_tickets` | service (HITL) |

## capability_registry.py / capability_enforcer.py
| `CapabilityResult` dataclass frozen | allowed:bool, missing:FrozenSet[str], explain | OUTPUT |
| `CapabilityRegistry` class | `_defaults:Set`, `_agents`(grants−revoked), `_revoked`, `_hierarchy` | INPUT |
| `CapabilityEnforcer` class | `_registry`, `_hmac_key` | service → GateResult; SimpleFinding(rule_id="CAPABILITY_EXCEEDED", sev=0.9) |

## context_sanitizer.py / tool_sanitizer.py / tool_call_guard.py
| `SanitizationLevel` enum | CLEAN, NORMALIZED, CORRECTED, SUSPICIOUS, REJECTED | OUTPUT |
| `SanitizationReport` dataclass frozen | level, explain_decision, changes:tuple, sanitized:Opt[RequestContext], decided_at_iso, signature | OUTPUT (HMAC; is_safe()) |
| `ContextSanitizer` class | `_secret` | service (fail-secure→REJECTED) |
| `SanitizerDecision` enum | ALLOW, BLOCK | OUTPUT |
| `SanitizedOutput` dataclass frozen | sanitized_output, decision, is_error:bool, removed_tokens_count:int, explain_decision:Mapping | OUTPUT |
| `ToolOutputClassifier` (abstract) | classify(text)→(bool,float,str) | INPUT (injetado) |
| `ToolOutputSanitizer` class | `_classifier`, `_timeout_ms=10`, `_fail_secure=True` | service (Stage-2) |
| `ToolPolicy` dataclass frozen | allowed_tools=[], blocked_tools=[], max_params_size_bytes=10000, required_capabilities:Dict={} | INPUT (YAML) |
| `ToolCallGuard` class | `_global_blocked`, `_blocked_re`, `_default`, `_agents:Dict[str,ToolPolicy]` | service · ledger `tool_output_audit`(tool, output_blake3, agent_id, session_id, explain_decision) |

## RAG / memória
| `IntegrityResult` dataclass frozen | valid:bool, reason, blake3_hash, hmac_signature, gate_result:GateResult | OUTPUT |
| `MemoryProvenanceRecord` dataclass frozen | chunk_blake3, source_channel, inserted_by_agent_id, inserted_at_iso, hmac_signature | OUTPUT/PERSISTED · ledger `rag_provenance` |
| `RagIntegrityVerifier` class | `_max_chunk`(4000), `_drift_thresh`(0.3), `_require_hash`, `_injection_check`, `_key`, `_contradiction_detector` | service |
| `ContradictionFinding` dataclass frozen | entity, existing_value, new_value, existing_source, explain_decision | OUTPUT (password/network/credential) |
| `InconsistencyType` enum | DIRECT_CONTRADICTION, TEMPORAL_VIOLATION, SOURCE_CONFLICT, ENTITY_DUPLICATION | OUTPUT |
| `ConsistencyReport` dataclass frozen | consistent, inconsistency_type, severity, conflicting_key, existing_value, new_value, flagged_for_review, explain_decision, decided_at_iso, signature | OUTPUT/PERSISTED |
| `MemoryFact` dataclass | entity_key, attribute, value, source, timestamp_iso, event_references:List | INPUT (ledger `memory_fact`) |
| `MemoryConsistencyValidator` class | `_ledger`, `_secret` | service |

## Detectores / guards
| `BotVerdict` enum | BOT_SUSPECT, NOT_BOT, INSUFFICIENT_DATA | OUTPUT |
| `BotSignal` dataclass frozen | session_id, verdict, std_dev_ms:Opt, sample_count:int, explain_decision | OUTPUT (BiasDecl FPR~0.8%/FNR~12%) |
| `BotDetector` class | `_threshold`(50ms std), `_min_samples`(5), `_sessions:dict[str,_SessionIntervals]`, `_session_mgr` | service |
| `DataClassification` enum | PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED | INPUT |
| `GateResult` dataclass | verdict:AgentVerdict, evidence_id:Opt, explain, gate:str; @property allowed/blocked | OUTPUT (DTO comum) |
| gates | message_gate/indexing_gate/rag_gate/training_gate/lora_deploy_gate → AgentDecisionRequest (G1–G5) | INTERMEDIATE |
| `VendorId` enum | OPENAI, ANTHROPIC, GOOGLE, AZURE | INPUT |
| `VendorConfig` dataclass | vendor_id, has_dpa=False, has_zdr=False, data_residency="US" | INPUT |
| `RefusalProbeQuestion` dataclass | probe_id, category(HARMFUL/BENIGN), prompt, expected_refuses:bool | INPUT |
| `AbliterationResult` dataclass | model_id, is_abliterated, confidence, refusal_rate, false_refusal_rate, probe_count, explanation, timestamp, contestable=True, appeal_deadline(+24h), probe_ids_failed=[] | OUTPUT |
| `AbliterationDetector` class | `_probes`, `_probe_timeout_ms`, `_refusal_threshold`(0.80), `_benign_threshold`(0.30) | service (fail-secure→abliterated) |
| `LeakageResult` dataclass frozen | leaked, confidence, action:ActionType, explain, hmac_sha256, sanitized_output | OUTPUT |
| `OutputLeakageDetector` class | `_indicators`, `_structural_re`, `_ngram_size`(3), `_threshold`(0.35), `_key` | service (4 camadas) |
| `FactCheckerProtocol` Protocol | model_id, model_family; check_claim(claim,context)→(bool,float) | INPUT (injetado) |
| `BiasDeclarationV2` dataclass frozen | model_id, model_family, checker_model_id, checker_model_family, declared_at_iso, known_limitations=(), false_positive_rate=0.05, false_negative_rate=0.02, calibration_date | INPUT |
| `ClaimFlag` dataclass frozen | claim_text, suspicion:ClaimSuspicion, position:int, reason | INTERMEDIATE |
| `AnnotatedCoT` dataclass frozen | cot_original, cot_hash_sha256, flags:Tuple[ClaimFlag], annotation_time_iso, checker_model_id, hmac_sha256, persuasion_score | OUTPUT |
| `PersuasionGuard` class | `_bias_declaration`, `_hmac_key`, `_fact_checker`, `_status` | service (raise se UNAVAILABLE) |
| `ThreatLevel` enum | LOW, MEDIUM, HIGH, CRITICAL | OUTPUT |
| `ThreatAssessment` dataclass frozen | session_id, threat_level, escalation_pct:float, burst_detected, pattern_match, explain, instruction_density=0.0, hmac_sha256 | OUTPUT |
| `ConversationThreatGraph` class | `_window`(10), `_burst_thresh`(3), `_esc_pct`(50), `_turns:Dict[str,Deque]`, `_key`, `_mgr` | service |
| `CircuitState` enum | CLOSED, OPEN, HALF_OPEN | STATE |
| `CorrelationResult` dataclass frozen | allowed, conflict:Opt, circuit_state, explain | OUTPUT |
| `CrossAgentCorrelator` class | `_fail_thresh`(5), `_window_s`(60), `_cooldown_s`(30), `_active`, `_circuit`, `_degradation_tracker` | service (colusão) |
| `SkillAnomalyFinding` dataclass frozen | skill_id, anomalous_category, baseline_rate, current_rate, explain_decision | OUTPUT |
| `SkillBehaviorMonitor` class | `_threshold`(0.30), `_session_actions:Dict[str,Counter]` | service · ledger `skill_action` |
| `AutonomyLevel` enum | FULL, RESTRICTED, HIBERNATION | OUTPUT |
| `LivenessStatus` dataclass frozen | agent_id, days_inactive:int, autonomy_level, explain_decision | OUTPUT |
| `LivenessMonitor` class | `_key` (RESTRICTED_DAYS=7, HIBERNATION_DAYS=30) | service · ledger `liveness_confirmation` |
| `GuardianVerdict` dataclass | allowed, model_id, reason, tri_score=1.0, warnings=[] | OUTPUT |
| `DivergenceLevel` enum | OK, WARNING, BLOCK | OUTPUT |
| `BiasGuardian` class | fail_on_unknown:bool | service (compute_cas covertness) |
| `FirewallVerdict` enum | ALLOW, BLOCK | OUTPUT |
| `FirewallResult` dataclass frozen | verdict, matched_pattern, sanitized_text, explain, reasoning_check:Opt[ReasoningGuardResult] | OUTPUT |
| `VisualInputFirewall` class | stateless | service (high-impact→ESCALATE) |
| `ReasoningGuardResult` dataclass frozen | allowed, attack_vector(MM_PLAN_SCOPE_ESCALATION/CROSS_MODAL_SYNTHESIS/None), explain | OUTPUT (**fail-open**) |
| `VisualReasoningGuard` class | `_threshold`(0.5) | service |

## Integridade de modelo
| `ModelStatus` enum | LEGITIMATE, ABLITERATED, SUSPICIOUS, UNKNOWN | INPUT/OUT |
| `KnownModel` dataclass | model_id, family, status, aliases=[], detection_date, notes, tamper_resistance_index=1.0 | INPUT (registries LEGITIMATE_MODELS/ABLITERATED_MODELS) |
| `IntegrityVerifier` class | `_policy_engine`, detector:AbliterationDetector, `_manifest_verifier` | service (manifest→blacklist→whitelist→behavioral) |
| `ManifestAppealResult` dataclass | appeal_id, model_id, accepted, new_expected_hash(64-hex), explanation, timestamp, contestable=False | OUTPUT |
| `ModelIntegrityContestabilityFlow` class | `_loop:ContestabilityLoop` | PERSISTED (Appeal grounds=[technical_error]) |
| `ManifestVerificationResult` dataclass frozen | model_id, manifest_path, is_valid, explanation, contestable=True | OUTPUT |
| `ManifestHashVerifier` class | stateless (SHA-256 vs env expected_hash_env) | service |
| `AlignmentManifest` dataclass frozen | agent_id, golden_rules:tuple, created_at, signature(HMAC), version=1, supersedes | OUTPUT/PERSISTED · ledger `alignment_manifest_created`/`manifest_revocation` |
| `AlignmentManifestVerifier` class | stateless | service |

## Consenso / kill-switch / oracle / output / timing / batch
| `Reversibility` enum | REVERSIBLE, IRREVERSIBLE | INPUT |
| `ConsensusOutcome` enum | UNANIMOUS_BLOCK, MAJORITY_BLOCK, UNANIMOUS_ALLOW, DIVERGENT, TIMEOUT, FAST_PATH | OUTPUT |
| `RolloutResult` dataclass frozen | run_index, action:ActionType, confidence, rationale, duration_ms | INTERMEDIATE |
| `ConsensusDecision` dataclass frozen | outcome, final_action:ActionType, rollout_results:Tuple, consensus_time_ms, divergence_detected, escalation_reason, hmac_sha256, decided_at_iso, n_runs=3 | OUTPUT |
| `ConsensusValidator` class | `_judge_fn`, `_hmac_key`, `_metrics`{total_calls, fast_path_calls, consensus_calls, divergent_count, timeout_count, block_majority_count} | service async (N=3, threshold=2, HARD_CAP_MS=40) |
| `VoteResult` enum | PENDING, ISOLATED, EXPIRED, REJECTED | OUTPUT |
| `KillSwitchProposal` dataclass frozen | proposal_id, target_agent_id, proposer_id, proposed_at_iso, ttl_seconds, authorized_voters:FrozenSet, threshold:float, explain_decision, signature | OUTPUT/PERSISTED · ledger `kill_switch_proposal` |
| `KillSwitchVoteRecord` dataclass frozen | vote_id, proposal_id, target_agent_id, voter_id, voted_at_iso, result, votes_cast, votes_needed, explain_decision, signature | OUTPUT/PERSISTED · ledger `kill_switch_vote` |
| `MultiPartyKillSwitch` class | `_ledger`, `_voters:frozenset`, `_secret`, `_ttl`(3600), `_threshold`(2/3), `_proposals`, `_votes` | PERSISTED (ledger é fonte de verdade) |
| `OracleEntry` dataclass frozen | oracle_id, hmac_key:bytes, valid_until:datetime, revoked=False | INPUT/PERSISTED |
| `OracleRegistry` class | `_entries:Dict[str,OracleEntry]` | service (ledger `oracle_revocation`) |
| `OracleVerdict` dataclass frozen | claim, verified, oracle_id, confidence, hmac_signature, explain_decision | OUTPUT (ledger `oracle_verification`) |
| `OracleTrustGate` class | `_registry:OracleRegistry` | service |
| `SchemaViolation` dataclass | path, rule, message | OUTPUT |
| `SchemaValidationResult` dataclass | valid, violations:List, latency_ms, schema_used | OUTPUT |
| `OutputSchemaValidator` class | stateless (subset JSON-Schema) | service |
| `ResponseTimeConfig` / `RateLimitConfig` dataclass | min/max/target_time_ms, jitter_enabled, jitter_percent · max_requests=100, window_seconds=60 | INPUT |
| `ResponseTimeNormalizer` / `RateLimiter` / `ConstantTimeOps` / `TimingSafeErrorHandler` class | metrics{requests_normalized/allowed/denied…} | service |
| `BatchItem` dataclass frozen | item_id, payload:Dict | INPUT |
| `BatchItemResult` dataclass frozen | item_id, action:str, confidence, explain_decision:Dict, error, processing_time_ms | OUTPUT/PERSISTED |
| `BatchMetrics` dataclass | total, processed, failed, blocked_by_error, total_time_ms | OUTPUT |
| `BatchResult` dataclass | results:Tuple[BatchItemResult], metrics:BatchMetrics, batch_id, completed_at_iso | OUTPUT |
| `BatchProcessor` class | `_decision_fn`, `_ledger`, `_item_timeout_s`(0.05), `_max_concurrency`(8) | service async (timeout→BLOCK) |
| `SyntheticCase` dataclass frozen | case_id, group:TestGroup, input_text, expected, pattern_epoch, policy_version | OUTPUT |
| `SyntheticDatasetGenerator` class | `_policy_yaml`, `_pattern_epoch`, `_target_count`=200, `_bias`, `_seed`(SHA-256) | service |
| `pattern_registry_client` | funcs get_current_epoch(env BTV_PATTERN_EPOCH → gateway /health/bias), epoch_changed | INPUT |

---

## Observações transversais (dados)
- **`GateResult`** (chatbot_gates) é o DTO de saída comum, produzido/consumido por agent_budget, capability_enforcer, tool_call_guard, rag_integrity_verifier, liveness_monitor, visual_input_firewall.
- **Persistência via `DurableLedger.append(dict)`** com discriminador `type`: `tool_output_audit`, `rag_provenance`, `memory_fact`, `skill_action`, `liveness_confirmation`, `alignment_manifest_created`/`manifest_revocation`, `oracle_verification`/`oracle_revocation`, `kill_switch_proposal`/`kill_switch_vote`, `content_provenance_check`, `commit_reveal_*`, `drift_checkpoint`, batch `decision_id`. `privacy_budget` usa SQLite próprio (`privacy_usage`).
- **DTOs assinados por HMAC** (integridade/contestabilidade): PolicyEvalResult, HygieneReport, PolicySignature, EthicalVerdict, LedgerEntry, DriftReport, ModelPerformanceReport, RecoveryOutcome, DelegationRecord/WorkContract, ProvenanceReport, CommitEntry/RevealResult, FeedbackVerdict, VerdictEnvelope, BudgetCheckResult, SanitizationReport, ConsistencyReport, AnnotatedCoT, ThreatAssessment, LeakageResult, ConsensusDecision, KillSwitch*, AlignmentManifest, IntegrityResult/MemoryProvenanceRecord.
- **Único guard fail-open:** `VisualReasoningGuard` (allowed=True em erro). Todos os demais são fail-secure.
- **Duplicações de tipo a atenção:** dois `TechnicalEvidence` (types.py vs ffi_client.py), dois `EthicalVerdict` (context_engine_types vs contestability/_types), `BiasDeclaration` em ffi_client/synthetic_dataset/persuasion(V2). Sempre desambiguar por arquivo.
- **Tabelas SQLite:** `escrow_ledger`, `appeals`, `explanations`, `privacy_usage`. **Cadeia em memória:** `DurableLedger._entries` (BLAKE2b + HMAC).
