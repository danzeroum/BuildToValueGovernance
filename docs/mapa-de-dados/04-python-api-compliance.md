# Mapa de Dados — Python API + Compliance

> Catálogo a **nível de campo** de `python/buildtovalue/api/**` e `compliance/**`.
> **Role:** INPUT (body/param) / INTERMEDIATE / OUTPUT (response) / PERSISTED (DB/ledger/arquivo). Parte do [Mapa de Dados](README.md).

## A · `api/_models.py` — modelos Pydantic
| Model | Campos (name:type + constraints/defaults) | Role |
|---|---|---|
| **DecideRequest** | input_text:str="" (max 50000), finding_count:int=0, critical_count:int=0, composite_risk:float=0.0, action:str="ALLOW", hard_blocked:bool=False, matched_policies:List[str]=[], session_id?, trust_score?:float, is_first_offense?:bool, profile?, entropy:float=0.0, total_chars:int=0, blake3_hash:str="", max_finding_confidence:float=0.0, ip_risk:str="Low", ip_jurisdiction:str="XX", drift_level:str="None", llm_output?, verdict_id?, source?, channel?, agent_policies?:List[str] | INPUT |
| **BiasDeclaration** | equity_score:float=0.0, pii_redacted:bool=False, long_term_impact:str="low", mercy_applied:bool=False, explain:str="" | OUTPUT nested |
| **DecideResponse** | verdict_id, action, original_action, mercy_applied:bool, mercy_scenario:str="", mercy_score:float=0.0, trust_score:float, adjusted_risk:float, rationale, contestable:bool, appeal_deadline_hours:int, signature, latency_ms:float, bias_declaration:BiasDeclaration, slm_used:bool=False, slm_intent?, slm_risk?:float, risk_classification?, compliance_violations?:List[dict], compliance_rate?:float, schema_violations?:list | OUTPUT |
| **MultiDecideRequest/Response** | prompt:str, agent_ids:List[str]=[], session_id? / verdicts:List[DecideResponse] | IN/OUT |
| **AppealSubmitRequest** | audit_trail_id:int, user_id:str(min 1), reason:str(min 20), evidence?, evidence_hash?, grounds:List[str]=[] | INPUT |
| **AppealResponse** | appeal_id, audit_trail_id:int, user_id, timestamp:int, reason, evidence_provided?, status:AppealStatusEnum, reviewer_notes?, resolution_timestamp?:int, sla_deadline:int, is_overdue:bool, evidence_hash?, grounds:List[str], mediator_recommendation? | OUTPUT |
| **AppealPageResponse** | data:List[AppealResponse], pagination:PaginationMeta{page,limit,total,pages:int} | OUTPUT |
| **AppealResolveRequest** | accepted:bool, reviewer_notes:str(min 10), reviewer_id:str(min 1), mediator_recommendation? | INPUT |
| **AppealMetricsResponse** | appeals_submitted/accepted/rejected:int, sla_violations:int, pending_appeals:int, sla_compliance_rate:float, appeal_success_rate:float | OUTPUT |
| **RiskClassifyRequest** | agent_id, sector, capabilities:List[str]=[], deployment_context:dict={} | INPUT |
| **ComplianceRequest** | framework, evidence:dict={}, verdict:dict={} | INPUT |
| **ThreatIngestRequest** | id, threat_type, severity:int, source:str="manual", indicators:List[str]=[], description:str="", mitre_id:str="" | INPUT |
| **ThreatQueryRequest** | threat_type?, min_severity:int=0, source?, limit:int=50 | INPUT |
| **FRIARequest** | agent_id, sector, capabilities:List[str]=[], deployment_context:dict={} | INPUT |
| **ROPARequest** | controller/dpo_name/dpo_contact:str="Not specified", start_ts?/end_ts?:int | INPUT |
| **Art20Request** | start_ts?/end_ts?:int, include_decisions:bool=True, max_decisions:int=500 | INPUT |
| **DocumentExportRequest** | type:str="" (ropa\|fria\|art20), data:dict={}, format:str="json" | INPUT |
| **AppealStatusEnum** | pending, under_review, accepted, rejected, expired | — |

## B · `_lifespan.py` — singletons em `app.state`
risk_classifier(RiskClassifier), ffi_client(FFI ou None), contestability_loop, ethical_engine(signing_key_fn=get_hmac_key), sensitivity_accumulator, trust_calculator, goal_drift_sentinel, durable_ledger(hmac_key snapshot), cross_agent(CrossAgentCorrelator), delegation_ledger, profile_manager?, sector_loader, output_validator, slm?(SLMClassifier), ner?(NERDetector), limiter. Side-effects: init_hmac_key, init_db, init_threats_db, hydrate_from_sqlite, init_auth, _init_users_db. Env `BTV_KERNEL_WORKERS=4`, `BTV_POLICY_DIR`, `BTV_APPEALS_DB`.

## C · Schemas SQLite
**`_db.py`** (`$BTV_DB_PATH` def data/trust.db):
- `sessions`: session_id TEXT PK, trust_score REAL DEFAULT 0.5, offenses INTEGER DEFAULT 0, total_requests INTEGER DEFAULT 0, created_at/updated_at TEXT, last_entropy REAL DEFAULT 0.0, last_action TEXT DEFAULT ''
- `agent_pubkeys`: agent_id TEXT PK, public_key_hex TEXT, registered_at TEXT, revoked_at TEXT, registration_proof TEXT

**`routes/auth.py`** (`$BTV_USERS_DB` def data/users.db):
- `users`: username TEXT PK, password_hash TEXT (bcrypt rounds=12), role TEXT DEFAULT 'viewer', created_at TEXT. Seed `admin` de `$BTV_ADMIN_PASSWORD` (min 12) só se vazia.

**`security/db.py`**: `sqlite_connect_wal(path, timeout=30.0)` → journal_mode=WAL, synchronous=NORMAL, busy_timeout=30000.

Outras tabelas (fora deste arquivo mas relacionadas): `escrow_ledger`, `appeals`, `explanations`, `privacy_usage`, `threats` (ver mapas 03/05).

## D · Endpoints FastAPI (por arquivo)
- **decide.py**: `POST /v1/decide` (DecideRequest→DecideResponse, `require_api_key`+get_decide_singletons); `POST /v1/multi-decide` (MultiDecideRequest→MultiDecideResponse). Deltas de trust: ALLOW/LOG +0.02, EDUCATE −0.05, BLOCK −0.15. NamedTuples internos (INT): `_DecideCtx`, `_AdjSignals{risk,finding_count,critical_count,action}`, `_SLMMeta{used,intent,risk,justifiability}`, `_ComplianceMeta{risk_class,violations,rate}`.
- **appeals.py**: `POST /v1/appeals`(201, JWT), `GET /v1/appeals/metrics`, `GET /v1/appeals/{id}`, `GET /v1/appeals`(query status?/user_id?/page(ge1)/limit(1-100)/sort_by/order), `POST /v1/appeals/{id}/resolve`(JWT, 409 se resolvido).
- **auth.py** (/v1/auth): LoginRequest{username(min1),password(min1)}→LoginResponse{token,refresh_token,username,role,expires_in:int}; UserInfo{username,role}. JWT claims: sub, role, iat, exp. Consts HS256, JWT_EXPIRY=28800s, REFRESH=604800s. `POST /login`(limit 10/min), `POST /refresh`, `GET /me`.
- **agent_decide.py**: `POST /v1/agent/decide`. AgentActionModel{name, impact:str="Irreversible", capabilities:List[str]}; AgentContextModel{profile_id="default", sector_id="general", session_trust_score:float=0.5, agent_metadata:Dict}; AgentDecideRequest{agent_id(min1), session_id(min1), action, parameters_hash(len 64), schema_version="1.0", request_id(uuid4), parameters_preview:Dict, context, parent_verdict_id?, delegation_depth:int=0}; VerdictEnvelopeResponse{request_id, verdict, verdict_code:int, explain_decision, bias_false_positive_rate_pct/false_negative_rate_pct:float, contestable, appeal_deadline_utc, policy_version_applied, evidence_id, hmac_sha256, timestamp_utc, approval_id?}. verdict_code: ALLOW→200, EDUCATE/PENDING_APPROVAL→202, BLOCK→403.
- **agents.py** (10 rotas): AgentRegisterRequest{public_key_hex(len64), registration_proof?}; OracleRegisterRequest{hmac_key_hex, valid_until_iso, description=""}; A2ACorrelateRequest{agent_id, action}; A2AScanRequest{src, dst, payload}; DelegationRecordRequest{parent_agent, child_agent, scope, capabilities?:List}; DelegationRevokeRequest{record_id}. Store `_ORACLE_REGISTRY_STORE:Dict`.
- **compliance.py** (8 rotas): `POST /check`(→artifacts+rate), `GET /frameworks`, `GET /report/{framework}`, `POST /classify-risk`, `POST /fria/generate`, `POST /ropa/generate`, `POST /art20/report`, `POST /documents/export`. Singletons COMPLIANCE_PLUGINS={LGPD,EU_AI_ACT}.
- **compliance_eval.py**: `POST /v1/compliance/evaluate` (EvaluateRequest{agent_metadata:Dict, frameworks?:List}→ComplianceEvalResult.to_dict()).
- **health.py**: `GET /health`{status, service, version="2.3.0", sessions_tracked, persistence, slm_loaded, ethical_engine, trust_calculator_singleton, goal_drift_sentinel, appeals_pending}; `GET /v1/trust/{session_id}`{session_id, trust_score, offenses, total_requests}.
- **fleet.py**: `GET /v1/fleet`→FleetResponse{agents:List[FleetAgent]}; FleetAgent{id, name, owner="—", bundle="default", model, risk="medium", status="online", blockRate:float, decisions24h:int, trust:float=0.5, fria:bool, friaDate?, jurisdictions:List, capabilities:List, description}.
- **metrics.py**: `GET /v1/metrics?range=`→MetricsResponse{range, total_decisions:int, block_rate:float, trust_avg:float, heatmap:List[List[int]] 7×24, top_vectors:List[VectorCount{name,count}], activity:List[ActivityItem{action,label,risk,ago_s}]}.
- **ledger.py** (/v1/ledger): `GET /query`(params session_id?/verdict_id?/action?/start_ts?/end_ts?/page(ge1)/limit(1-1000))→LedgerResult.to_dict(); `GET /stats`{exists, entry_count, ledger_file}.
- **intelligence.py**: bridge `POST /sync?min_severity=1`, `GET /status`; hub `POST /ingest`, `/ingest/batch`, `/query`, `GET /threat/{id}`, `/stats`.
- **slm_ner.py**: `GET /v1/slm/metrics`, `/v1/slm/bias`, `POST /v1/scan/semantic`, `GET /v1/ner/metrics`.
- **webhooks.py** (/v1/webhooks): `GET /status`, `POST /reload`, `POST /test`.

## E · `webhook_dispatcher.py`
WebhookTarget(frozen){url, actions:List[str], enabled=True, timeout_seconds:float=5.0, retry_max:int=2}; WebhookPayload(frozen){verdict_id, action, risk:float, findings:int, critical:int, hard_blocked, mercy_applied:bool, profile, session_id, timestamp:float}; to_dict() adiciona `event:"btv.decision"`; WebhookResult{url, success:bool, status_code?, attempts:int, error?}. Headers: Content-Type, User-Agent: BuildToValue-Webhook/1.0, X-BTV-Event: decision.

## F · `ledger_reader.py` (READ-ONLY `data/ledger/decisions.jsonl`)
REQUIRED_FIELDS (entrada JSONL escrita pelo Rust `validate.rs`): ts, session, profile, policy_action, final_action, mercy, risk, findings, critical, hard_blocked, verdict_id, latency_ms. LedgerQuery(frozen){session_id?, verdict_id?, action?, start_ts?/end_ts?:int, page:int=1, limit:int=20 (clamp 1-1000)}; LedgerResult(frozen){data:List[Dict], total, page, limit, pages:int, ledger_file}. ⚠️ `ledger_analytics.py` usa `LedgerQuery(page_size=...)` e lê `result.entries`/`result.total_pages` — não existem nesta API (`limit`/`data`/`pages`) → bug em ROPA/Art20.

## G · Helpers e middleware
- **_decide_helpers.py**: `sign_verdict(verdict_id, action, risk)`=HMAC-SHA256 hex de `"{verdict_id}:{action}:{risk:.4f}"`; `_impact_label`, `_build_bias_declaration`, `_appeal_to_response`, `_resolve_domain`, `_resolve_role`.
- **_security_metrics.py**: BTV_AUTH_FAILURES_TOTAL, BTV_RATE_LIMIT_EXCEEDED_TOTAL (Counter), BTV_HTTP_REQUEST_DURATION_SECONDS (Histogram[method,path,status]).
- **plugins.py**: PluginHookContext{hook, request_id, payload:dict}; PluginBase (ABC: pre_auth/post_auth/on_audit_event).
- **auth.py**: `require_api_key` (X-API-Key); 401 `{error:"UNAUTHORIZED", message}`. Env `BTV_API_KEYS`.
- **app.py**: FastAPI(title="BuildToValue Governance", version="0.1.0a1"); middlewares _RequestIdMiddleware(X-BTV-Request-ID), CORS, SecurityHeaders; RFC7807 `{type,title,status,detail}`; 15 routers. Env `BTV_CORS_ORIGINS`, `BTV_SLM_MODEL_PATH`, `BTV_PROBLEM_TYPE_BASE`.

## H · Compliance — modelos/enums
| Entity | Campos |
|---|---|
| `ComplianceLevel` | COMPLIANT, PARTIAL, NON_COMPLIANT, NOT_APPLICABLE |
| `ComplianceArtifact` | framework, article, requirement, status:ComplianceLevel, evidence, recommendation, generated_at |
| `ComplianceReport` | framework, version, total_requirements, compliant, partial, non_compliant:int, artifacts:List, compliance_rate:float, generated_at |
| `CompliancePlugin` (Protocol) | framework_id(), framework_name(), generate_artifacts(ev,verdict), validate_requirements() |
| `ComplianceViolation` (frozen) | framework, article, requirement, policy_name, action, confidence:float, condition, notes="" |
| `ComplianceEvalResult` (frozen) | agent_id, frameworks_evaluated, rules_evaluated:int, violations:List, compliant_count, skipped_count:int, evaluation_time_ms:float, timestamp:int; props violation_count, compliance_rate |
| `RiskLevel` | PROHIBITED, HIGH_RISK, LIMITED_RISK, MINIMAL_RISK |
| `RiskClassification` (frozen) | agent_id, risk_level:RiskLevel, sector, reasons:List, obligations:List, annex_iii:bool, prohibited_detected:List | PROHIBITED_CAPABILITIES(8), LIMITED_RISK_CAPABILITIES(5) |
| `LedgerAggregation` | total_decisions:int, period_start_ts?/end_ts?, action_counts:Dict, risk_distribution:Dict, pii_types_detected:Dict, mercy_count, block_count, hard_block_count, contested_count:int, total_risk_sum:float; props avg_risk, block_rate, mercy_rate |
| `DecisionRecord` | verdict_id, timestamp:int, action, final_action, risk:float, findings, critical:int, mercy, hard_blocked:bool, session, profile, latency_ms:float |
| `ROPAEntry` | activity_name, purpose, legal_basis, data_categories:List, data_subjects, recipients, retention_period, security_measures, cross_border_transfer:bool, record_count:int, period_start/end, pii_types_detected:Dict, risk_distribution:Dict, block_count, mercy_count:int |
| `ROPADocument` | controller, dpo_name, dpo_contact, entries:List[ROPAEntry], generated_at, ledger_hash, total_records_processed:int, period_covered, version="1.0" (+ document_type:"ROPA", legal_basis:"LGPD Art. 37") |
| `FRIASection` | section_id, title, question, auto_answer, manual_required:bool, risk_indicator, article_ref (FRIA-1..FRIA-10) |
| `FRIADocument` | agent_id, risk_level, sector, generated_at, sections:List, summary, total_sections/auto_filled/manual_pending:int, overall_risk |
| `Art20Summary` | total_decisions, automated_decisions, block/allow/educate/redact_decisions, mercy_applied, hard_blocks:int, avg_risk/avg_latency_ms:float |
| `Art20Report` | period_start/end, summary:Art20Summary, decisions:List, methodology, bias_declarations:List, generated_at, version="1.0" |
| `RegulatoryArticle` | framework, article_id, title, text, keywords:List |
| `PolicyCard` | id, name, framework, article, description, severity, action, patterns:List, references:List |
| `Framework` | name, jurisdiction, description, articles:List[RegulatoryArticle] |

`ajl_exporter` report: `report_version:"AJL-1.0", generated_at, system, bias_metrics[], certification_status{eligible,compliance_rate,...}, recommendations[]` (elegível ≥0.95). `roi_engine_v2.calculate_penalties_batch`→`{total_roi_usd:str, count:int}` (penalty_map (pii,LGPD)=50M…). `document_exporter`: export_pdf/export_json (Jinja2 + weasyprint).

## Notas
- **VerdictEnvelopeResponse** (ações estruturadas) ≠ **DecideResponse** (texto). `evidence_id`=uuid4 novo por envelope; `hmac_sha256` assina `"{request_id}|{verdict}|{evidence_id}|{timestamp_utc}"`.
- **Dois ledgers disjuntos**: Rust `decisions.jsonl` (servido por /v1/ledger/*, lido por LedgerReader/LedgerAnalytics/metrics) vs `DurableLedger` in-process (app.state).
