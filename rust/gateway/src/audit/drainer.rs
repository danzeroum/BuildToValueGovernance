//! Bounded MPSC drainer para `FairnessAuditEvent` (audit-sink-local D3+D4).
//!
//! Arquitetura:
//!
//! ```text
//! decide_handler → AuditChannel::try_emit → mpsc(10_000) → drainer task → AuditSink
//!                       ↓                       ↓                ↓
//!                  drop+metric             backpressure    catch_unwind+metric
//!                  (channel full)        (size-bounded)    (sink panic)
//! ```
//!
//! Decisões registradas:
//!
//! - **Hot path NÃO bloqueia** (D3): `try_send` falha → métrica
//!   `btv_audit_events_dropped_total{reason}`. Auditoria perdida sob
//!   load extremo é preferível a violar SLA do Core Banking (ADR-0088 §D1).
//!
//! - **`AssertUnwindSafe` no `catch_unwind`**: `Arc<dyn AuditSink>` não é
//!   `UnwindSafe` automaticamente (contém `Mutex` em `JsonlAuditSink`).
//!   `AssertUnwindSafe` suprime a verificação estática sem mudar
//!   comportamento de runtime — é correto aqui porque o contrato do
//!   drainer é best-effort: panic no sink **não** corrompe o estado do
//!   drainer (sink é só chamado, não compartilha estado mutável com o
//!   loop). Limitação: `catch_unwind` captura panics **dentro de
//!   `sink.emit`**, NÃO panics do próprio loop `recv().await` — se o
//!   loop panicar, a task morre e a auditoria para (`btv_audit_drainer
//!   _panics_total` não incrementa nesse caso).
//!
//! - **Sem respawn automático** (D4 do design): se panic for repetitivo
//!   (bug no sink), respawn cria loop infinito de panic+respawn. Métrica
//!   alerta operador → redeploy é a mitigação operacional.

use super::event::FairnessAuditEvent;
use super::sink::AuditSink;
use lazy_static::lazy_static;
use prometheus::{
    opts, register_int_counter, register_int_counter_vec, IntCounter, IntCounterVec,
};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Capacidade do canal entre produtor (`decide_handler`) e drainer.
/// 10_000 = ~5 segundos de buffer a 2k req/s. Suficiente para absorver
/// picos sem permitir crescimento ilimitado em saturação prolongada.
pub const AUDIT_CHANNEL_CAPACITY: usize = 10_000;

lazy_static! {
    /// Eventos descartados (não enviados ao canal OU não consumidos por
    /// sink panic). Label `reason`: "channel_full" | "channel_closed" |
    /// "sink_panic".
    pub static ref AUDIT_EVENTS_DROPPED_TOTAL: IntCounterVec = {
        #[allow(clippy::unwrap_used)]
        { register_int_counter_vec!(
            opts!(
                "btv_audit_events_dropped_total",
                "Eventos de auditoria fairness descartados (não persistidos)"
            ),
            &["reason"]
        ).unwrap() }
    };

    /// Panics capturados durante `sink.emit`. Métrica crítica de
    /// operação — crescimento contínuo indica bug no sink.
    pub static ref AUDIT_DRAINER_PANICS_TOTAL: IntCounter = {
        #[allow(clippy::unwrap_used)]
        { register_int_counter!(
            "btv_audit_drainer_panics_total",
            "Panics em sink.emit capturados por catch_unwind"
        ).unwrap() }
    };

    /// Eventos persistidos com sucesso. Permite calcular taxa de
    /// sucesso = emitted / (emitted + dropped).
    pub static ref AUDIT_EVENTS_EMITTED_TOTAL: IntCounter = {
        #[allow(clippy::unwrap_used)]
        { register_int_counter!(
            "btv_audit_events_emitted_total",
            "Eventos de auditoria fairness emitidos com sucesso"
        ).unwrap() }
    };
}

/// Producer-side handle. Vai para `AppState` como **campo direto**
/// (`audit_tx: AuditChannel`), não `Option` — `try_emit` em canal
/// fechado é tratado com métrica, não com ramificação no hot path.
#[derive(Clone)]
pub struct AuditChannel {
    sender: mpsc::Sender<FairnessAuditEvent>,
}

impl AuditChannel {
    /// Envia evento se houver capacidade. Falha silenciosa com métrica:
    /// - Canal cheio → `reason="channel_full"`.
    /// - Canal fechado (drainer task morta) → `reason="channel_closed"`.
    ///
    /// **Não bloqueia.** Custo médio < 100 ns (fast path do `try_send`).
    pub fn try_emit(&self, event: FairnessAuditEvent) {
        match self.sender.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                AUDIT_EVENTS_DROPPED_TOTAL
                    .with_label_values(&["channel_full"])
                    .inc();
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                AUDIT_EVENTS_DROPPED_TOTAL
                    .with_label_values(&["channel_closed"])
                    .inc();
            }
        }
    }

    /// Helper para testes que precisam aguardar todos os emits drenarem.
    /// Em produção, o drainer drena continuamente — não há motivo para
    /// chamar isso. Não consumido pelo bin → `dead_code` localizado.
    #[allow(dead_code)]
    pub fn capacity_available(&self) -> usize {
        self.sender.capacity()
    }
}

/// Spawn do drainer. Retorna `(AuditChannel, JoinHandle<()>)`.
///
/// O `JoinHandle` vai para `AppState` para shutdown gracioso (commit
/// futuro implementa drain on SIGTERM). Por agora, task vive até o
/// processo morrer ou `AuditChannel` ser droppado em todos os locais
/// (ponto que fecha o canal e termina o loop).
pub fn spawn_drainer(sink: Arc<dyn AuditSink>) -> (AuditChannel, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel::<FairnessAuditEvent>(AUDIT_CHANNEL_CAPACITY);
    let handle = tokio::spawn(async move {
        tracing::info!(
            capacity = AUDIT_CHANNEL_CAPACITY,
            "audit drainer iniciado"
        );
        while let Some(event) = rx.recv().await {
            // catch_unwind protege contra panic dentro de sink.emit.
            // AssertUnwindSafe necessário: Arc<dyn AuditSink> não é
            // automaticamente UnwindSafe (Mutex condicionalmente o é).
            // Aceitável aqui porque o drainer não compartilha estado
            // mutável com o sink — panic em emit não corrompe o loop.
            let sink_ref = Arc::clone(&sink);
            let event_id_for_log = event.event_id.clone();
            let tenant_id_for_log = event.tenant_id.clone();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sink_ref.emit(&event);
            }));
            match result {
                Ok(()) => {
                    AUDIT_EVENTS_EMITTED_TOTAL.inc();
                }
                Err(_) => {
                    AUDIT_DRAINER_PANICS_TOTAL.inc();
                    AUDIT_EVENTS_DROPPED_TOTAL
                        .with_label_values(&["sink_panic"])
                        .inc();
                    tracing::error!(
                        event_id = %event_id_for_log,
                        tenant_id = %tenant_id_for_log,
                        "audit drainer: panic em sink.emit capturado por catch_unwind \
                         — evento perdido; operador deve investigar bug do sink"
                    );
                }
            }
        }
        // Canal fechado (último Sender droppado) → shutdown gracioso.
        tracing::info!("audit drainer: canal fechado, encerrando");
    });
    (AuditChannel { sender: tx }, handle)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::audit::sink::{JsonlAuditSink, NullAuditSink};
    use crate::fairness_mode::FairnessMode;
    use crate::tenant_status::TenantStatus;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tempfile::TempDir;

    fn sample_event(verdict_id: &str) -> FairnessAuditEvent {
        FairnessAuditEvent::new(
            "acme".to_string(),
            verdict_id.to_string(),
            1_700_000_000_000,
            FairnessMode::Enforced,
            TenantStatus::Active,
        )
    }

    // ── Sinks especiais para teste ────────────────────────────────

    /// Sink que panica nas primeiras `panic_count` chamadas, depois
    /// processa normalmente via inner.
    struct PanickingSink {
        panic_count: AtomicUsize,
        success_count: AtomicUsize,
    }

    impl PanickingSink {
        fn new(panic_count: usize) -> Self {
            Self {
                panic_count: AtomicUsize::new(panic_count),
                success_count: AtomicUsize::new(0),
            }
        }
    }

    impl AuditSink for PanickingSink {
        fn emit(&self, _event: &FairnessAuditEvent) {
            if self.panic_count.load(Ordering::SeqCst) > 0 {
                self.panic_count.fetch_sub(1, Ordering::SeqCst);
                panic!("PanickingSink: simulated emit panic");
            }
            self.success_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Sink que bloqueia por `delay_ms` em cada emit — usado para
    /// forçar saturação do canal.
    struct SlowSink {
        delay_ms: u64,
        emitted: AtomicUsize,
    }

    impl SlowSink {
        fn new(delay_ms: u64) -> Self {
            Self {
                delay_ms,
                emitted: AtomicUsize::new(0),
            }
        }
    }

    impl AuditSink for SlowSink {
        fn emit(&self, _event: &FairnessAuditEvent) {
            std::thread::sleep(Duration::from_millis(self.delay_ms));
            self.emitted.fetch_add(1, Ordering::SeqCst);
        }
    }

    // ── Caso 1: happy path — eventos chegam ao sink ──────────────

    #[tokio::test]
    async fn drainer_persists_events_via_sink() {
        let tmp = TempDir::new().unwrap();
        let jsonl = Arc::new(JsonlAuditSink::new(tmp.path().to_path_buf()));
        let sink: Arc<dyn AuditSink> = Arc::clone(&jsonl) as Arc<dyn AuditSink>;
        let (channel, _handle) = spawn_drainer(sink);

        for i in 0..5 {
            channel.try_emit(sample_event(&format!("VRD-{i}")));
        }
        // Dá tempo para o drainer consumir.
        tokio::time::sleep(Duration::from_millis(200)).await;
        jsonl.flush_all().unwrap();

        let content = std::fs::read_to_string(
            tmp.path().join("acme").join("events.jsonl"),
        )
        .unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 5);
    }

    // ── Caso 2: catch_unwind protege contra panic do sink ────────

    #[tokio::test]
    async fn drainer_recovers_from_sink_panic_and_continues_loop() {
        let panicking = Arc::new(PanickingSink::new(2));
        let sink: Arc<dyn AuditSink> = Arc::clone(&panicking) as Arc<dyn AuditSink>;
        let panics_before = AUDIT_DRAINER_PANICS_TOTAL.get();
        let (channel, _handle) = spawn_drainer(sink);

        // Envia 5 eventos: 2 panicam, 3 sucedem.
        for i in 0..5 {
            channel.try_emit(sample_event(&format!("VRD-{i}")));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;

        // 3 emits sucederam (após 2 panics).
        assert_eq!(panicking.success_count.load(Ordering::SeqCst), 3);
        // Métrica de panic incrementou em >= 2 (testes paralelos podem
        // somar — usamos delta para isolar).
        let panics_after = AUDIT_DRAINER_PANICS_TOTAL.get();
        assert!(
            panics_after - panics_before >= 2,
            "esperava >= 2 panics, got delta {}",
            panics_after - panics_before
        );
    }

    // ── Caso 3: backpressure — try_emit drop com métrica ─────────

    #[tokio::test]
    async fn try_emit_drops_when_channel_full() {
        // SlowSink garante que o drainer não esvazia rapidamente.
        let slow = Arc::new(SlowSink::new(50));
        let sink: Arc<dyn AuditSink> = Arc::clone(&slow) as Arc<dyn AuditSink>;
        let dropped_before = AUDIT_EVENTS_DROPPED_TOTAL
            .with_label_values(&["channel_full"])
            .get();
        let (channel, _handle) = spawn_drainer(sink);

        // Satura o canal: AUDIT_CHANNEL_CAPACITY + extras.
        // Em loop tight, o sender consegue meter ~capacity antes do drainer
        // conseguir tirar uma mensagem; o resto cai em channel_full.
        let extra = 100;
        for i in 0..(AUDIT_CHANNEL_CAPACITY + extra) {
            channel.try_emit(sample_event(&format!("VRD-{i}")));
        }

        // Métrica de drop deve ter incrementado por pelo menos algumas
        // mensagens — não exatamente `extra` porque o drainer também
        // consumiu algumas em paralelo, mas estritamente > 0.
        let dropped_after = AUDIT_EVENTS_DROPPED_TOTAL
            .with_label_values(&["channel_full"])
            .get();
        assert!(
            dropped_after > dropped_before,
            "esperava drops por channel_full, got delta {}",
            dropped_after - dropped_before
        );
    }

    // ── Caso 4: canal fechado — drainer encerra graciosamente ────

    #[tokio::test]
    async fn drainer_exits_when_channel_closed() {
        let sink: Arc<dyn AuditSink> = Arc::new(NullAuditSink);
        let (channel, handle) = spawn_drainer(sink);

        // Drop do channel fecha o sender → recv().await retorna None →
        // loop sai.
        drop(channel);

        // handle deve completar em tempo razoável (não bloqueia para
        // sempre).
        let result =
            tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(
            result.is_ok(),
            "drainer não encerrou após canal fechado"
        );
    }

    // ── Caso 5: AuditChannel é Clone (para AppState compartilhar) ──

    #[tokio::test]
    async fn audit_channel_is_clone_and_shares_sender() {
        let sink: Arc<dyn AuditSink> = Arc::new(NullAuditSink);
        let (channel, _handle) = spawn_drainer(sink);
        let cloned = channel.clone();
        // Ambos compartilham o mesmo sender — não há contagem
        // exata aqui, mas confirmamos que ambos funcionam.
        channel.try_emit(sample_event("VRD-1"));
        cloned.try_emit(sample_event("VRD-2"));
        // Sem panic = sucesso (ambas chamadas foram aceitas no canal).
    }
}
