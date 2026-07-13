# Mapa de Dados — SDK TypeScript/Python, integrações, MCP, HTML/dashboard, contratos

> Catálogo a **nível de campo** de `sdk/**`, `spec/**`, dashboards HTML/Streamlit/JS.
> **Role:** IN=request · OUT=response · INT=interno · PER=persistido/config. Parte do [Mapa de Dados](README.md).

## 1 · SDK TypeScript (`sdk/javascript/src`)
**Uniões:** `VerdictAction` = ALLOW\|BLOCK\|INSPECT\|REDACT\|EDUCATE\|LOG · `AppealStatus` = pending\|under_review\|accepted\|rejected\|expired · `AppealGrounds` = rawls_equity\|levinas_protection\|gilligan_mercy\|jonas_responsibility\|technical_error\|scope_mismatch\|false_positive · `GovernanceProfile` = general\|healthcare\|finance\|legal\|research\|education

| Interface | Campos | Role |
|---|---|---|
| `ExplainDecision` | summary:string; rawls/levinas/jonas/gilligan_rationale:string; trust_score:number; mercy_score:number; pipeline_stages:string[] | OUT |
| `Verdict` | verdict_id, action:VerdictAction, original_action, mercy_applied:boolean, finding_count, critical_count:number, composite_risk:number, hard_blocked, contestable:boolean, appeal_deadline_hours:number, signature, rationale, explain:ExplainDecision, jurisdiction_bitmask:number, latency_ms:number | OUT /v1/decide |
| `ValidateVerdict` | Verdict-like + hard_block_term:string\|null, message, matched_policies:string[], max_finding_confidence, entropy, total_chars, blake3_hash, drift_level; sem explain | OUT /v1/validate |
| `Appeal` | appeal_id, verdict_id, user_id, reason, grounds:AppealGrounds[], status, submitted_at/resolved_at/resolution/mediator_recommendation/sla_deadline/evidence_hash:string\|null | OUT |
| `TrustScore` | session_id, trust_score:number, total_requests, offenses:number, calculated_at:string\|null | OUT |
| `SanitizeResult` | sanitized:string, redactions:number, latency_ms:number | OUT |
| `BTVClientOptions` | apiKey:string, gatewayUrl?, timeout?:number, maxRetries?, raiseOnBlock?:boolean | IN |

**client.ts** métodos → endpoints: decide(POST /v1/decide {input,session_id?,profile?,agent_id?}), validate, sanitize({text,session_id?}), appeal(POST /v1/appeals {verdict_id,user_id(def "anonymous"),reason,grounds(def ["false_positive"]),evidence?}), getAppeal, trustScore, health. Consts DEFAULT_GATEWAY=http://localhost:8080, TIMEOUT=30000ms, RETRYABLE={429,500,502,503,504}, header X-API-Key. **errors.ts:** BTVError→BTVAuthError, BTVBlockedError{verdict}, BTVRateLimitError{retryAfter:number\|null}, BTVGatewayError{statusCode}, BTVValidationError{statusCode}.

## 2 · SDK Python (`sdk/python/buildtovalue`)
Enums: VerdictAction(6), DriftLevel{None,Low,Moderate,High,Critical}, AppealStatus(5), AppealGrounds(7). Pydantic models espelham o TS + constraints Field(ge=0,le=1); props: Verdict.is_blocked/is_allowed/explanation, ValidateVerdict.is_blocked/is_allowed, Appeal.is_pending/is_accepted, TrustScore.level. `BTVClient`+`AsyncBTVClient` idênticos: __init__(api_key, gateway_url=http://localhost:8080, timeout=30.0, max_retries=3, raise_on_block=False); mesmos endpoints. `_retry.py`: _RETRYABLE_STATUS={429,500,502,503,504}, base_delay=2.0 (2/4/8s), parse Retry-After. Exceptions espelham TS (retry_after:int\|None, status_code:int).

## 3 · Integrações (`sdk/integrations`)
### Grants — models.py
Enums: GrantCategory(10), GrantStage(7), LinguisticGroup{en-US,pt-BR,es,sw}, ActionImpact{reversible,conditionally_reversible,irreversible}.
- **BiasDeclaration**(frozen){group:LinguisticGroup, fpr?/fnr?:float(0-1), sample_size:int=0, calibration_date?, notes=""} — SW exige fpr/fnr None
- **GrantProposal**{applicant_id, title, description, category=OTHER, stage=DRAFT, budget_usd:float=0.0(0-10M), team_size:int=1, linguistic_group=EN_US, wallet_address?(`^0x[0-9a-fA-F]{40}$`), country_code?, action_impact=IRREVERSIBLE, tags:List, metadata:Dict} → to_session_id() HMAC-SHA256, to_btv_input() JSON minificado
- **GrantVerdict**(frozen){verdict_id, action, hard_blocked, contestable:bool, appeal_deadline_hours:int, composite_risk/trust_score:float, mercy_applied:bool, rationale, rawls/levinas/jonas/gilligan_rationale=""} props can_appeal, is_hard_block, explanation
- **GrantGuardConfig**: block_on={"BLOCK","REDACT"}, raise_on_block=True, use_decide=True, policy_path="data/policies/sectors/grant-eligibility-v1.yaml", agent_id="grant-decision-adapter", session_salt=b"btv-grant-salt", sanitize_max_length=50_000, dry_run=False
- Exceptions: GrantBlockedError{verdict_id,action,rationale,contestable,appeal_deadline_hours,composite_risk?,trust_score?,mercy_applied?,raw_verdict?}, GrantValidationError{field,reason,proposal_ref?}, GrantSanitizationError{stage,detail}, BiasDeclarationError{group,reason}

### Guards de framework
| Classe | Config | Exceção |
|---|---|---|
| `BTVAutoGenGuard` | client, session_id?, profile?, use_decide=False, block_on=frozenset{"BLOCK"}, raise_on_block=False, blocked_reply | BTVBlockedMessageError{verdict_id,action,message} |
| `BTVCrewGuard` | +sanitize_output=True, raise_on_block=True | BTVBlockedTaskError{verdict_id,action,rationale} |
| `BTVGuardrailCallback` (LangChain) | +raise_error=False; hooks on_llm_start/on_llm_end | BTVBlockedByGuardrailError{verdict_id,action,rationale} |
| `BTVQueryEngineGuard` (LlamaIndex) | engine, +sanitize_response=True | BTVBlockedQueryError{verdict_id,action,message} |

## 4 · MCP Server (`sdk/mcp-server/btv_mcp/server.py`) — 8 tools
| Tool | Input (req) | Backing |
|---|---|---|
| validate_input | input_text**; session_id?; profile?(enum6) | client.validate |
| decide | input_text**; session_id?; profile?; agent_id? | client.decide |
| submit_appeal | verdict_id**; reason**(min20); grounds?[7]; user_id? | client.appeal |
| get_trust_score | session_id** | client.trust_score |
| check_compliance | text**; session_id?; profile?(enum4) | client.validate |
| elicit_policy | nl_input**; domain**(enum8) | PolicyElicitor |
| negotiate | policy:object**; session_id? | →select_protocol |
| select_protocol | policy:object**; session_id? | ProtocolDesigner |

Env `BTV_API_KEY`(req), `BTV_GATEWAY_URL`, `BTV_LLM_API_KEY`. Ledgers keyed b"btv-mcp-tier2-v1", b"btv-mcp-elicitor-v1".

## 5 · Contratos (`spec/`)
### openapi.yaml (deltas vs SDK)
- `VerdictAction`: **+REPORT, +REFUSE** (8 vs 6 no SDK)
- `Verdict.verdict_id` pattern `^VRD-[0-9A-HJKMNP-TV-Z]{26}$`; jurisdiction_bitmask BR=0x01,US=0x02,EU=0x04,UK=0x08
- `AppealRequest`(IN): verdict_id, user_id, reason(min20), grounds, evidence?
- `Appeal.mediator_recommendation` enum[accept_appeal,reject_appeal,escalate,educate,null]
- `HealthCheck`{status enum[ok,degraded], uptime_seconds, version}
- `SanitizeResponse`{sanitized, redactions, latency_ms}; `Error`{error, detail?}
- Endpoints: /v1/decide, /v1/validate, /v1/sanitize, /v1/appeals(+/{id},/resolve,/pending,/metrics), /v1/trust/{session_id}, /health, /health/bias{status enum[ok,warning,blocked], validators:{name:{fpr,fnr,divergence_pp,status}}}. Auth X-API-Key.

### agent-pdp-v1.json (JSON-Schema draft-07, `AgentDecisionRequest`, ADR-029)
Required: schema_version(const "1.0"), request_id(uuid), agent_id(min1), session_id(min1), action{name**, impact**(enum Safe/Destructive/Irreversible), capabilities[]}, parameters_hash(`^[0-9a-f]{64}$`), timestamp_utc(date-time). Opt: parameters_preview:object, context{profile_id, sector_id(enum finance/health/legal/general), session_trust_score(0-1), agent_metadata}. additionalProperties:false.

## 6 · HTML / Dashboards
### Streamlit `dashboard/app.py` (env BTV_GATEWAY_URL→8080, BTV_GOVERNANCE_URL→8000)
| Página | Envia | Lê |
|---|---|---|
| Overview | GET {GW}/metrics; GET {GOV}/v1/ledger/recent?limit=10; GET /v1/compliance/report/{lgpd,gdpr,eu_ai_act} | decisions_total, proxy_blocked_total; ledger action/timestamp/policy_id/evidence_hash; compliance_score |
| Validate | POST {GW}/v1/validate {input,session_id} | action, finding_count, critical_count, composite_risk, latency_ms, mercy_applied, hard_blocked |
| Sanitize | POST {GW}/v1/sanitize {text} | sanitized_text, masked_count, masked_types[], latency_ms |
| Trust Score | GET {GOV}/v1/trust/{session_id} | trust_score, offenses, total_requests |
| Compliance | GET /v1/compliance/report/{LGPD,EU_AI_ACT} | compliance_rate, artifacts[{status,article,requirement,evidence,recommendation}] |
| Intelligence | POST /v1/intelligence/{query,ingest}; GET /stats | threats[{id,source,threat_type,severity,indicators[],hash}], stats |
| Audit Ledger | GET /v1/ledger/query {page_size,session_id?,verdict_id?,action?}; /stats | entries[{final_action,ts,verdict_id,risk,findings,critical,latency_ms,mercy}], pagination |
| Appeals | POST /v1/appeals {audit_trail_id,user_id,reason,evidence?}; GET /v1/appeals; /metrics | appeal_id, appeals[{status,user_id,reason,sla_deadline,reviewer_notes}] |
| Webhooks | GET/POST /v1/webhooks/{status,reload,test} | status, targets, dispatched, failed |
| FRIA | POST /v1/compliance/fria/generate {agent_id,sector,capabilities[],deployment_context{safety_component,affects_fundamental_rights}} | risk_level, sections[{section_id,title,risk_indicator,manual_required,question,auto_answer,article_ref}] |

### demo `demo/js/api.js`
Base `/api`, timeout 5000ms; `DemoAuth` JWT em sessionStorage key `btv_demo_token` (Bearer em não-GET). Métodos → health, decide/multiDecide/validate/sanitize/agentDecide, fleet, metrics, trustScore, proxyDecide, ledgerQuery/Stats, appeals*, compliance*, intelligence*, bridgeStatus. Badges de ação: ALLOW,BLOCK,EDUCATE,LOG,REDACT,INSPECT,REPORT,REFUSE,REVIEW.
### `demo/playground/playground.js`
Carrega `scenarios/*.json` (block-451, contestation, sla-24h). Campos: decision(=="BLOCK"), reason, evidence_hash, simulated_time, contestability{endpoint,sla_hours}. Mock — "ledger state not affected".
### `demo/proxy.py`
RUST_ROUTES=[/v1/validate,/v1/sanitize,/v1/decide,/v1/trust/,/v1/proxy/,/health,/metrics]. Injeta X-API-Key. POST /demo-login→{GOV}/v1/auth/login; fail-secure 403 se BTV_DEMO_PASSWORD vazio. POST /deepseek/*→DeepSeek. Cache GET 5s.
### `demo/dpo-ciso/schemas/policy.schema.json`
Props: version, schema_version, schema_type, policy_id, _metadata, metadata, jurisdiction(anyOf string/array/object), bias_declaration, governance, policies:array, rules:array, frameworks:array, thresholds. additionalProperties:true.

## Discrepâncias de dados a atenção
- **VerdictAction**: OpenAPI tem REPORT/REFUSE; SDK TS/Py só 6; demo api.js inclui REVIEW.
- **Sanitize**: SDK/OpenAPI usam `sanitized`/`redactions`; Streamlit lê `sanitized_text`/`masked_count`/`masked_types` (endpoint de forma diferente).
- **Appeals**: OpenAPI/SDK usam `verdict_id`; aba Streamlit posta `audit_trail_id` (dois contratos coexistem).
- **Grants dry-run**: constrói `Verdict` omitindo campos obrigatórios do Pydantic (falharia validação).
