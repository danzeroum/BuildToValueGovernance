# Mapa de Dados — Rust `kernel/`

> Catálogo a **nível de campo/byte** do núcleo de scan (`rust/kernel/src/**`).
> **Role:** INPUT / INTERMEDIATE / OUTPUT / PERSISTED. Parte do [Mapa de Dados](README.md).

## Variáveis de ambiente lidas
| Var | Arquivo | Uso |
|---|---|---|
| `BTV_ENV` | keys.rs | gate fail-closed; `"production"` exige chave real |
| `BTV_HMAC_KEY` | keys.rs | fonte do MAC do kernel → `Zeroizing<Vec<u8>>`; **removida do environ após init** |
| `ENVIRONMENT` | observability/tracing.rs | tag OTEL (default `development`) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | observability/tracing.rs | endpoint OTLP |
| `CARGO_PKG_VERSION` | ffi/bridge | exposto como `VERSION` no Python |

Sentinelas inseguras (consts, `keys.rs`): `DEV_FALLBACK=b"btv-kernel-supply-guard-v1"`; `INSECURE_MARKERS`: NOT-FOR-PRODUCTION, demo-key, btv-dev-key, btv-policy-engine-v1, btv-verdict-hmac-v1, btv-kernel-supply-guard.

## `core/types.rs` — enums, structs, layouts de bytes
| Entity | Kind | Campos / variantes | Role |
|---|---|---|---|
| Consts | const | MAX_FINDINGS=10, MAX_CRITICAL_FINDINGS=3, HASH_SIZE=32, MAX_FINDING_SIZE=512, EVIDENCE_SIZE=9632, MAX_CALIBRATION_DAYS=90 | — |
| `RiskLevel` | enum repr(u8) | Safe=0, Low=1, Medium=2, High=3, Critical=4 | OUTPUT/PERSIST |
| `TechnicalSeverity` | enum repr(u8), serde tag/content | Info=0, Low=1, Medium=2, High=3, Critical(u8 0-255), PolicyViolation=255 | OUTPUT |
| `Action` | enum repr(u8) | Allow=0, Log=1, Block=2, Redact=3 | INTERMEDIATE |
| `ValidatorModule` | enum repr(u8) | Unknown=0, CPF, CNPJ, CreditCard, Luhn, Email, Phone, SSN, Entropy, ZScore, Statistics, Deobfuscator, Network, SessionGuard, OutputGuard, Consent, ConsentRevocation, SensitiveData, InternationalTransfer, DataAccessRequest, DataErasure, BreachNotification, LanguageDetector, NhsNumber, EuVat, Iban, PromptInjection, SqlInjection(27), Jailbreak, DataExfiltration, Xss, Ssti(31) | OUTPUT (índice de bitmask `executed_modules`) |
| `EthicalVerdict` | enum repr(u8) | Pending=0, Allow=1, Educate=2, Redact=3, Block=4, Report=5 | PERSISTED |
| `InputStatistics` | struct repr(C,align8) **32B** | entropy:f32(0-4), z_score:f32(4-8), input_size:u32(8-12), digit_ratio:f32(12-16), letter_ratio:f32(16-20), symbol_ratio:f32(20-24), unique_chars:u16(24-26), pad(26-28), total_chars:u32(28-32) | INTERMEDIATE→OUTPUT |
| `BiasDeclaration` | struct repr(C,align8) **512B** (ADR-063) | false_positive_rate:f32, false_negative_rate:f32, calibration_date:u32(YYYYMMDD), test_dataset_size:u32, affected_groups:[u8;128], known_limitations:[u8;256], _reserved:[u8;112] | OUTPUT/PERSIST |
| `Decision` | enum repr(u8) | Allow=0, Log=1, Deny=2, Block=3, Redact=4, Report=5 (ADR-061) | OUTPUT |
| `ThreatType` | enum | PIILeakage, LanguageDetector, NhsNumber, EuVat, Iban, PromptInjection, ShadowAI, DenialOfWallet, Toxicity, BiasViolation | INPUT |
| `RegulatoryFramework` | enum | LGPD, GDPR, EUAIAct, CCPA, HIPAA, PCIDSS | INPUT |
| `NegotiationDeadlockReason` | enum repr(u8) | MaxRoundsExceeded, TimeoutExpired, ConflictingPolicy, AgentUnreachable | OUTPUT |
| `DeadlockResolutionError` | struct | reason, rounds_completed:u8, agent_ids:[u64;2], explanation:[u8;256] | PERSISTED |
| `AppealRecord` | struct | verdict_id:[u8;16], explanation_hash:[u8;32], bias_declaration_hash:[u8;32], timestamp_utc:u64, appeal_deadline_utc:u64, appeal_url_hash:[u8;32] | PERSISTED |

## `evidence/technical.rs` — TechnicalEvidence (**9632B**, repr(C,align8))
Ordem de memória: METADATA 64B (`version:u32`, `timestamp:u128`, `audit_trail_id:u128`, `processing_time_us:u64`, `input_size:u32`, `original_request_hash:u64`, `_pad_metadata:[u8;8]`) · STATS 32B (`stats:InputStatistics`) · BIAS 512B (`bias:BiasDeclaration`) · FINDINGS 1872B (`findings:[Finding;10]`=1440B, `critical_findings:[Finding;3]`=432B) · COUNTS 16B (`finding_count:u8`, `critical_count:u8`, `risk_level:RiskLevel`, `composite_risk:f32`, `executed_modules:u32` [ADR-017], `_reserved:[u8;5]`) · RESERVED META 7072B (`_reserved_metadata`) · INTEGRITY 32B (`hash:[u8;32]` BLAKE3). Role: OUTPUT + PERSISTED. `must_use`. `to_bytes()`=memcpy 9632B; `from_bytes()` rejeita version 0 ou >3.

**Sub-layout de `_reserved_metadata`:** `[0..8]` pattern_epoch · `[8..24]` tenant_key / `[8..40]` skill_hash · `[40]` bit0 policy_drift_detected · `[41..73]` skill_mac_tag / `[41..164]` frontier region · `[73]` hw_attestation flag; `[74..138]` sig[64]; `[138..170]` hash[32]; `[170..202]` tee_pubkey[32].

## `evidence/finding.rs` — Finding (**144B**, repr(C,align8))
META 8B (`module:ValidatorModule`@0, `severity:TechnicalSeverity`@1-3, `confidence:u8`@3, `position_start:u16`@4-6, `position_end:u16`@6-8) · CLASSIF 64B (`rule_id:[u8;32]`@8-40, `threat_category:[u8;32]`@40-72) · EVIDENCE 64B (`matched_text:[u8;64]`@72-136) · ALIGN (`_padding:[u8;8]`@136-144). Role OUTPUT; `to_bytes()`→144B alimenta BLAKE3.

## `ledger/entry.rs` — LedgerEntry (**384B**, repr(C,align8)) + ActionType
Campos: `entry_id:u64`, `_align_padding:u64`, `audit_trail_id:u128`, `timestamp:u128`, `risk_level:RiskLevel`, `action:ActionType`, `ethical_verdict:EthicalVerdict`, `verdict_id:[u8;32]` (HMAC-SHA256, ADR-043), `_padding_verdict:[u8;5]`, `previous_hash:[u8;32]`, `entry_hash:[u8;32]` (BLAKE3), `merkle_root:[u8;32]`, `protocol_version:u16`, `schema_version:u16`, `producer_id:[u8;32]`, `_reserved:[u8;164]`. **_reserved sub-layout:** `[0..4]`bias_fpr, `[4..8]`bias_fnr, `[8..12]`bias_calibration_date, `[16..48]`regime_hash (ADR-064), `[48..80]`explanation_hash. `ActionType` repr(u8): Allow=0, Log=1, Educate=2, Redact=3, Block=4, Report=5. Role PERSISTED (bincode + WAL).

## `ledger/` — persistência
| Entity | Kind | Campos | Role |
|---|---|---|---|
| `WalConfig` | struct | wal_path:PathBuf(def "ledger.wal"), fsync_enabled:bool(true), max_size_bytes:u64(100MB) | config |
| `WalEntry` | struct serde | seq:u64, timestamp:u128, evidence_snapshot:Vec<u8> (9632B) | PERSISTED (bincode, len-prefix u32) |
| `WriteAheadLog` | struct | file:Mutex<BufWriter<File>>, config, current_seq:Mutex<u64> | writer fsync |
| consts effect_log | const | EFFECT_RING_CAPACITY=64, MAX_FRONTIERS=3, FRONTIER_BYTES=41, FRONTIER_REGION 41..164, FRONTIER_POLL_US=100 | — |
| `Reversibility` | enum repr(u8) | Reversible=0, ReversibleWithCost=1, Irreversible=2 | — |
| `Temporality` | enum repr(u8) | Bufferable=0, Externalized=1 | — |
| `AbortReason` | enum | WalWriteFailed, FrontierTimeout, HandlerFailed, RingFull | — |
| `EffectResult` | enum | Committed, Abort{reason} | OUTPUT |
| `EffectEntry` | struct repr(C) **108B** | action_id:[u8;32], resource_id:[u8;32], reversibility, temporality, _pad:[u8;2], timestamp_ns:u64, hmac:[u8;32] | PERSISTED (WAL-first) |
| `FrontierInner` | struct | resource_ids:[[u8;32];3], epochs:[u64;3], count:usize | INTERMEDIATE |
| `FrontierSet` | struct | inner:Mutex<FrontierInner>, confirmed:[AtomicBool;3] | codifica em `_reserved_metadata[41..164]` |
| `EffectLog` | struct | ring:[EffectEntry;64], head, count, frontiers | ring stack |
| `ChainStatus` | enum | Valid{entry_count}, Empty, TamperedAt{entry_id,expected_hash,actual_hash}, BrokenAt{entry_id}, CorruptAt{byte_offset} | OUTPUT |
| `RecoveryResult` | struct | entries_from_disk:u64, entries_from_wal:u64, recovery_time_ms:f64, chain_status | OUTPUT |
| `DurableLedger` | struct | wal:WalStore, disk_file:Arc<RwLock<File>>, remote_tx:mpsc::Sender<LedgerEntry>, last_entry_id:Arc<RwLock<u64>>, last_entry_hash:Arc<RwLock<[u8;32]>>, session_agg:Mutex<SessionAggregator> | PERSISTED |
| `SessionEvent` | struct Copy | timestamp_us:u64, risk_level, composite_risk:f32, blocked:bool, has_pii:bool | INTERMEDIATE (ring 256) |
| `SessionAggregate` | struct | session_id:u128, event_count, block_count, pii_count:usize, avg_risk:f32, max_risk_level, first/last_event_us:u64 | OUTPUT (Fourth Estate) |
| `RouterError` | enum | InvalidTenantId(String), LedgerInit(anyhow) | OUTPUT |
| `TenantStorageRouter` | struct | base_path:PathBuf, s3_config:S3Config, cache:RwLock<HashMap<String,Arc<DurableLedger>>> | roteamento `{base}/{tenant}/ledger.db` |
| `S3Config` | struct serde | bucket("buildtovalue-ledger"), key_prefix("wal/"), region("us-east-1"), endpoint:Option, force_path_style:bool | config |

## `core/module.rs` — ScanContextFlags (**64B**) + ScanContext
Campos ScanContextFlags: `lang_bitmask:u64`@0, `jurisdiction_bitmask:u64`@8, `capability_mask:u64`@16, `tenant_key:[u8;16]`@24, `pattern_epoch:u64`@40, `lang_scores:[u16;4]`@48, `_reserved:[u8;8]`@56. Bits: LANG_EN..LANG_AR (1<<0..7); JURISDICTION_BR/US/EU/UK (1<<0..3), JURISDICTION_ALL; CAP_PII/INJECTION/DEOBFUSC/OUTPUT/TRUSTED_ROLE (1<<0..4), CAP_ALL=u64::MAX. `ScanContext{stats:InputStatistics, flags}` — stack, `&mut` a todos os módulos. `Module` trait: `scan(&str,&mut ScanContext)→Vec<Finding>`, name, module_id, bias_declaration, explain_decision.

## `core/adapter.rs` / `core/errors.rs`
`MAX_INPUT_BYTES=65536`; `AdaptError{InputTooLarge{size}, Empty}`; `AdaptedInput{blake3_hash:[u8;32], normalized_len:usize}` (INTERMEDIATE→`original_request_hash` 8B + `input_size`). Erros: `EvidenceError{AlreadyFinalized, NotFinalized, InvalidChecksum, VersionMismatch{expected,got}, BufferFull, InvalidUtf8{field}}`.

## `gatekeeper.rs`
`PipelineStage{Deobfuscate,Analyze,Validate}`; `StageEntry{module:Box<dyn Module>, stage}`; `GatekeeperMetrics{scans_total, findings_total, critical_findings:u64, avg_latency_ms, p50/p95/p99/p999_latency_ms:f32}` (OUTPUT via FFI); `Gatekeeper{pipeline:Vec<StageEntry>, metrics, interceptor_chain, latency_ring:Box<[f32;1000]>, ring_pos, ring_len}`. **Temporários intermediários** (descartados): `max_fpr, max_fnr:f32`, `oldest_calibration:u32` (init u32::MAX), `total_test_size:u32` → agregados em `evidence.bias`.

## `batch.rs`
`BatchItemStatus{Ok,Timeout,Error(String)}`; `BatchItem{index, audit_trail_id:u128, evidence:Option<TechnicalEvidence>, status, processing_time_us:u64}`; `BatchResult{items:Vec, total_time_us, succeeded/timed_out/failed:usize}`; `BatchConfig{max_batch_size(100), item_timeout_us(10000), batch_timeout_us(1000000)}`; `BatchError{EmptyBatch, LengthMismatch{inputs,ids}, ExceedsMaxSize{size,max}}`.

## `deobfuscator/` / `interceptor/`
`ChainLayer{depth, decoder:&str, input_len, output_len}` (INT); `ChainResult{final_text:String, layers:Vec<ChainLayer>, is_evasion:bool, elapsed_us:u64}` (INT, descartado após re-scan); `Base64Result{Decoded/DecodedBinary/NotBase64}`, `HexResult{...}`; `LeetspeakDetector.rule_id="DEOBFUSCATOR_LEET_001"`. `InterceptAction{Continue, Modify(String), Block(String)}`; `InterceptResult{action, hook_name}`; `ToolScreenResult{Clean, Suspicious{reason}}` — consts DANGEROUS_PATTERNS (rm -rf, dd if=, mkfs, /etc/passwd, eval(atob, __import__, os.system…), SUSPICIOUS_TOOLS (shell_exec, raw_shell, eval_code…).

## `compliance/`
`DemographicGroup{Gender/Age/Race/Language(String)}`; `BiasMetric{group_a/b, dir:f64, pass_threshold(0.8), compliant, sample_size, timestamp:i64}`; `AJLReport{timestamp, total_metrics, compliant_metrics, compliance_rate, metrics:Vec<BiasMetric>, certification_eligible(≥0.95)}`; `PenaltyCalculator.calculate(ThreatType,Framework)→Option<u64>` (LGPD PII 50M, GDPR PII 20M, EUAIAct ShadowAI 30M…).

## `api/` (RFC 7807)
`ValidationResult{Clean, Violation(Finding)}`; `EthicalError` (serde) JSON keys: `type`, `title`, `status:u16`, `detail`, `instance?`, `extensions:BtvExtensions`; `BtvExtensions` keys: `error_code`, `ethical_ground`, `adr_reference`, `verdict_id?`, `audit_log_id?`, `appeal_url`, `contestable_until?`, `metadata?`. Códigos: E120 (bias, 400), E130 (policy, 403), E131 (tenant, 403), E160 (Rawls DIR, 451), E161 (Jonas drift, 451), E429 (z-score, 429). Headers: `X-RateLimit-*`, `X-BTV-Sampling-Mode`, `X-BTV-Verdict-Signature: hmac-sha256=<hex>`.

## `ffi/` — formas de dados
`PyTechnicalEvidence{inner:Arc<TechnicalEvidence>}` (getters version, timestamp, audit_trail_id(str), composite_risk, risk_level(str), finding_count, critical_count, entropy, input_size, executed_modules, processing_time_us, hash(hex), max_severity, bias); `PyBiasDeclaration`, `PyBatchItem{index, evidence, status, processing_time_us}`, `PyBatchResult{items, total_time_us, succeeded/timed_out/failed}`; `RustKernel{gatekeeper:Arc<Mutex<Gatekeeper>>, ledger:Arc<Mutex<DurableLedger>>}` (pymodule `buildtovalue_kernel`); `AccumulatorConfigJson{intervention_threshold(75), temporal_decay_factor(0.95), max_history_size(100)}`. **C-ABI:** `FFIFinding` repr(C) (rule_id, title, description:*c_char, severity:u8, confidence:u8, validator_module, metadata), `FFIValidationResult{findings:*mut FFIFinding, findings_count:usize, error_message:*c_char}`.

**JSON wire (evidence_to_pydict):** version, timestamp, audit_trail_id, composite_risk, risk_level, finding_count, critical_count, entropy, input_size, executed_modules, processing_time_us, hash, bias_fpr, bias_fnr, bias_calibration_date, bias{...}, findings[]{title,category,severity,confidence,description}, critical[]{title,severity,confidence}. Códigos goal-drift FFI: 0 ok, -1 sessão, -2 input.

## `security/`
`FFIBuffer{data:Vec<u8>, checksum:[u8;32] BLAKE3, timestamp:u64, metadata:Option<BufferMetadata>}` (freshness ≤30s); `SupplyGuardResult{Allowed, Blocked(reason)}`; `ChannelTrustLevel{Untrusted=0..Sovereign=4}` (CHANNEL_TABLE 17 canais); `ThreatSignal{pattern_id, category:ThreatCategory{Jailbreak,RlmRecursion,RlmCodeExec,Obfuscation}, severity, confidence:u8}`; `ViolationFinding{violation:IntegrityViolationKind, timestamp_ms, hmac_signature:[u8;32]}`; `SessionToken{token, created_at, expires_at, user_id, nonce:u64}`; `PatternSnapshot{patterns:Vec<CompiledPattern>, epoch:u64}` (ArcSwap); `PatternMatch{category, tier, start, end}`; `GoalDriftBuffer{scores:[u8;10], head, count}` (flag→`_reserved_metadata[40]` bit0); `AccumulatorVerdict{safe:bool, current_score, threshold:f32, trigger_reason:Option<String>}`.

> **Nota:** a maioria dos `validators/**` (cpf, cnpj, email, phone, ssn, nhs, vat, iban, sql/jailbreak/xss/ssti…) e `statistics/**` (entropy, zscore, char_ratio, language, rawls, jonas) são unit structs sem estado — carregam apenas tabelas `&'static` de regex e emitem `Vec<Finding>` (já catalogado). Sua única saída de dados é `Finding`.
