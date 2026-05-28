//! `AuditSink` trait + 4 implementações (audit-sink-local D2).
//!
//! Drainer (D4) serializa chamadas via MPSC antes de chegar aqui, mas os
//! sinks ainda devem ser **`Send + Sync`** e seguros sob acesso
//! concorrente — testes paralelos exercitam o caminho direto e o
//! `MultiAuditSink` pode fan-out para implementações futuras com
//! semântica de concorrência diferente.
//!
//! `#![allow(dead_code)]`: caller de produção (drainer + AppState) chega
//! em commits posteriores desta sprint. Removido após wire final.
#![allow(dead_code)]

use super::event::FairnessAuditEvent;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Contrato comum de todos os sinks de auditoria.
pub trait AuditSink: Send + Sync {
    /// Emite o evento. Implementações **não devem panicar** —
    /// `catch_unwind` no drainer captura, mas evitar panic na fonte é
    /// preferível (operação best-effort, falhas logam via `tracing`).
    fn emit(&self, event: &FairnessAuditEvent);
}

// ─────────────────────────────────────────────────────────────────
// JsonlAuditSink — escrita per-tenant em `{base_dir}/{tenant_id}/events.jsonl`
// ─────────────────────────────────────────────────────────────────

/// Sink que escreve um evento por linha em JSONL particionado por tenant.
///
/// Concorrência: o `Mutex<HashMap<...>>` serializa **abertura e escrita**
/// — duas threads emitindo para tenants diferentes precisam pegar o
/// mesmo lock. Aceitável porque o drainer (D4) já é single-consumer e
/// porque a escrita dentro do lock é rápida (BufWriter agrupa syscalls).
///
/// Alternativa mais escalável (`RwLock<HashMap<String, Mutex<BufWriter>>>`)
/// fica para quando houver evidência de contenção.
pub struct JsonlAuditSink {
    base_dir: PathBuf,
    writers: Mutex<HashMap<String, BufWriter<std::fs::File>>>,
}

impl JsonlAuditSink {
    pub fn new(base_dir: PathBuf) -> Self {
        Self {
            base_dir,
            writers: Mutex::new(HashMap::new()),
        }
    }

    /// Garante o diretório do tenant + abre `events.jsonl` em append-only.
    fn open_writer(&self, tenant_id: &str) -> std::io::Result<BufWriter<std::fs::File>> {
        let dir = self.base_dir.join(tenant_id);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("events.jsonl");
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        Ok(BufWriter::new(file))
    }

    /// Flush manual de todos os writers. Útil para testes que precisam
    /// inspecionar o JSONL imediatamente — em produção o BufWriter
    /// libera no drop ou quando o buffer enche.
    pub fn flush_all(&self) -> std::io::Result<()> {
        let Ok(mut guard) = self.writers.lock() else {
            return Ok(()); // lock poisoned → noop best-effort
        };
        for w in guard.values_mut() {
            w.flush()?;
        }
        Ok(())
    }
}

impl AuditSink for JsonlAuditSink {
    fn emit(&self, event: &FairnessAuditEvent) {
        let Ok(mut guard) = self.writers.lock() else {
            tracing::error!(
                tenant_id = %event.tenant_id,
                "jsonl audit sink: lock poisoned — evento descartado"
            );
            return;
        };

        let writer = match guard.get_mut(&event.tenant_id) {
            Some(w) => w,
            None => {
                let w = match self.open_writer(&event.tenant_id) {
                    Ok(w) => w,
                    Err(e) => {
                        tracing::error!(
                            tenant_id = %event.tenant_id,
                            base_dir = %self.base_dir.display(),
                            error = %e,
                            "jsonl audit sink: falha ao abrir writer — evento descartado"
                        );
                        return;
                    }
                };
                guard.entry(event.tenant_id.clone()).or_insert(w)
            }
        };

        let line = match serde_json::to_string(event) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(
                    event_id = %event.event_id,
                    error = %e,
                    "jsonl audit sink: serialize falhou — evento descartado"
                );
                return;
            }
        };

        if let Err(e) = writeln!(writer, "{line}") {
            tracing::error!(
                event_id = %event.event_id,
                error = %e,
                "jsonl audit sink: writeln falhou — evento perdido"
            );
        }
        // Flush é best-effort por evento; pode buferizar se vier alta
        // taxa. Caller que precisa garantia chama flush_all() em
        // pontos críticos (shutdown, teste).
        let _ = writer.flush();
    }
}

// ─────────────────────────────────────────────────────────────────
// StdoutAuditSink — emite via tracing::info! target btv_audit
// ─────────────────────────────────────────────────────────────────

/// Sink que emite via `tracing::info!(target: "btv_audit", ...)`. Mantém
/// o output estruturado e compatível com coletores (Loki, CloudWatch,
/// journald) que já consomem o formato tracing do gateway. **Não** usar
/// `println!` — bypassa o pipeline de telemetria.
pub struct StdoutAuditSink;

impl AuditSink for StdoutAuditSink {
    fn emit(&self, event: &FairnessAuditEvent) {
        match serde_json::to_string(event) {
            Ok(json) => {
                tracing::info!(target: "btv_audit", event = %json);
            }
            Err(e) => {
                tracing::error!(
                    event_id = %event.event_id,
                    error = %e,
                    "stdout audit sink: serialize falhou"
                );
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────
// MultiAuditSink — fan-out tee
// ─────────────────────────────────────────────────────────────────

/// Fan-out para múltiplos sinks. Emite para todos em sequência;
/// falha de um não impede os demais (cada sink já é best-effort
/// individualmente).
pub struct MultiAuditSink {
    sinks: Vec<Arc<dyn AuditSink>>,
}

impl MultiAuditSink {
    pub fn new(sinks: Vec<Arc<dyn AuditSink>>) -> Self {
        Self { sinks }
    }

    pub fn len(&self) -> usize {
        self.sinks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }
}

impl AuditSink for MultiAuditSink {
    fn emit(&self, event: &FairnessAuditEvent) {
        for sink in &self.sinks {
            sink.emit(event);
        }
    }
}

// ─────────────────────────────────────────────────────────────────
// NullAuditSink — noop
// ─────────────────────────────────────────────────────────────────

/// Sink que descarta tudo. Para testes e tenants opt-out (futuro).
pub struct NullAuditSink;

impl AuditSink for NullAuditSink {
    fn emit(&self, _event: &FairnessAuditEvent) {}
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::fairness_mode::FairnessMode;
    use crate::tenant_status::TenantStatus;
    use tempfile::TempDir;

    fn sample_event(tenant_id: &str, verdict_id: &str) -> FairnessAuditEvent {
        FairnessAuditEvent::new(
            tenant_id.to_string(),
            verdict_id.to_string(),
            1_700_000_000_000,
            FairnessMode::Enforced,
            TenantStatus::Active,
        )
    }

    fn read_file(path: &std::path::Path) -> String {
        std::fs::read_to_string(path).unwrap_or_default()
    }

    // ── JsonlAuditSink ────────────────────────────────────────────

    #[test]
    fn jsonl_sink_writes_per_tenant_directory() {
        let tmp = TempDir::new().unwrap();
        let sink = JsonlAuditSink::new(tmp.path().to_path_buf());
        sink.emit(&sample_event("acme", "VRD-1"));
        sink.emit(&sample_event("globex", "VRD-2"));
        sink.flush_all().unwrap();

        let acme = tmp.path().join("acme").join("events.jsonl");
        let globex = tmp.path().join("globex").join("events.jsonl");
        assert!(acme.exists());
        assert!(globex.exists());
        assert!(read_file(&acme).contains("VRD-1"));
        assert!(read_file(&globex).contains("VRD-2"));
    }

    #[test]
    fn jsonl_sink_appends_one_event_per_line() {
        let tmp = TempDir::new().unwrap();
        let sink = JsonlAuditSink::new(tmp.path().to_path_buf());
        for i in 0..5 {
            sink.emit(&sample_event("acme", &format!("VRD-{i}")));
        }
        sink.flush_all().unwrap();

        let content = read_file(&tmp.path().join("acme").join("events.jsonl"));
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 5);
        // Cada linha deve ser JSON válido independente.
        for line in &lines {
            let parsed: FairnessAuditEvent = serde_json::from_str(line).unwrap();
            assert!(parsed.verdict_id.starts_with("VRD-"));
        }
    }

    #[test]
    fn jsonl_sink_reuses_writer_for_same_tenant() {
        let tmp = TempDir::new().unwrap();
        let sink = JsonlAuditSink::new(tmp.path().to_path_buf());
        sink.emit(&sample_event("t", "V1"));
        sink.emit(&sample_event("t", "V2"));
        // Após dois emits, apenas um writer no HashMap.
        assert_eq!(sink.writers.lock().unwrap().len(), 1);
    }

    #[test]
    fn jsonl_sink_emit_to_unwritable_dir_does_not_panic() {
        // Diretório base não existe (não foi criado). create_dir_all do
        // sink cria — então este teste valida fail-soft de open_writer
        // se o caminho for inválido (ex: arquivo no lugar de diretório).
        let tmp = TempDir::new().unwrap();
        let blocker = tmp.path().join("acme");
        // Cria um ARQUIVO chamado "acme" no path onde o sink esperaria
        // um diretório → create_dir_all/open vão falhar.
        std::fs::write(&blocker, "blocker").unwrap();
        let sink = JsonlAuditSink::new(tmp.path().to_path_buf());
        // emit deve apenas logar erro, não panicar.
        sink.emit(&sample_event("acme", "VRD-1"));
        // Nenhuma entry no HashMap (writer não conseguiu abrir).
        assert!(sink.writers.lock().unwrap().is_empty());
    }

    // ── StdoutAuditSink ───────────────────────────────────────────

    #[test]
    fn stdout_sink_does_not_panic() {
        let sink = StdoutAuditSink;
        sink.emit(&sample_event("acme", "VRD-1"));
    }

    // ── MultiAuditSink ────────────────────────────────────────────

    #[test]
    fn multi_sink_fanout_to_all_inner() {
        let tmp = TempDir::new().unwrap();
        // Mantém referência tipada para o JsonlSink antes de fazer
        // upcast para `dyn AuditSink` — evita downcast/unsafe.
        let jsonl_typed: Arc<JsonlAuditSink> =
            Arc::new(JsonlAuditSink::new(tmp.path().to_path_buf()));
        let stdout: Arc<dyn AuditSink> = Arc::new(StdoutAuditSink);
        let multi = MultiAuditSink::new(vec![
            Arc::clone(&jsonl_typed) as Arc<dyn AuditSink>,
            Arc::clone(&stdout),
        ]);
        assert_eq!(multi.len(), 2);
        assert!(!multi.is_empty());

        multi.emit(&sample_event("acme", "VRD-1"));
        jsonl_typed.flush_all().unwrap();
        let acme = tmp.path().join("acme").join("events.jsonl");
        assert!(acme.exists());
        assert!(read_file(&acme).contains("VRD-1"));
    }

    #[test]
    fn multi_sink_empty_emit_is_noop() {
        let multi = MultiAuditSink::new(vec![]);
        multi.emit(&sample_event("acme", "VRD-1"));
        assert!(multi.is_empty());
    }

    // ── NullAuditSink ─────────────────────────────────────────────

    #[test]
    fn null_sink_is_noop() {
        let sink = NullAuditSink;
        sink.emit(&sample_event("acme", "VRD-1"));
        // Nada para asserir — apenas não panicar.
    }

    // ── trait object safety ──────────────────────────────────────

    #[test]
    fn audit_sink_is_object_safe() {
        let sinks: Vec<Box<dyn AuditSink>> = vec![
            Box::new(NullAuditSink),
            Box::new(StdoutAuditSink),
        ];
        for s in &sinks {
            s.emit(&sample_event("acme", "VRD-1"));
        }
    }
}
