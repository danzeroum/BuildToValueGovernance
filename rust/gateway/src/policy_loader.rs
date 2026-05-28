//! Filesystem walk + boot step para carregar policies de fairness por tenant
//! (ADR-0089 §D1).
//!
//! NOTE on `dead_code`: o módulo é introduzido neste Commit 4. O caller
//! produção (`main.rs` → `warm_policies().await`) entra no Commit 7 do
//! roadmap (junto com o handler de `/internal/v1/reload-policy` que
//! também usa `load_tenant_policy` para reload sob demanda). Lib tests
//! aqui já exercitam todas as funções. `#![allow(dead_code)]` evita
//! falha em `RUSTFLAGS="-D warnings"`. Remover após Commit 7.
#![allow(dead_code)]
//!
//! Layout esperado:
//!
//! ```text
//! {policies_dir}/
//! ├── {tenant_id}/
//! │   ├── drift_baseline.yaml     (Jonas — ADR-0087)
//! │   └── fairness.yaml           (FairnessMode — ADR-0088)
//! └── ...
//! ```
//!
//! **Invariante de hot path:** este módulo executa APENAS no boot step
//! antes de `axum::serve`. Nenhuma função aqui é chamada por handlers.
//! Carregamento de tenants em paralelo via `futures::join_all`, mas o
//! `spawn` é apenas durante boot, não no hot path (D1 ADR-0088
//! síncrono preservado).
//!
//! **Observabilidade obrigatória (D1 ADR-0089):**
//! - `tracing::info!` por tenant carregado com sucesso (campos estruturados).
//! - `tracing::error!` por falha (nunca silencioso).
//! - Métricas Prometheus `btv_baseline_load_*` registradas no boot.
//!
//! O kernel permanece storage-agnóstico — este módulo lê o filesystem e
//! passa o conteúdo string para `reload_baseline()` do trait
//! `ReloadableGuardrail`.

use crate::fairness_mode::{FairnessMode, FairnessModeRegistry};
use crate::tenant_status::{DegradationCause, TenantStatus, TenantStatusRegistry};
use buildtovalue_kernel::security::tenant_key::validate_tenant_id;
use buildtovalue_kernel::statistics::{JonasMonitor, ReloadableGuardrail};
use futures::future::join_all;
use lazy_static::lazy_static;
use prometheus::{opts, register_int_counter_vec, register_int_gauge, IntCounterVec, IntGauge};
use serde::Deserialize;
use std::path::{Path, PathBuf};

const BASELINE_FILENAME: &str = "drift_baseline.yaml";
const FAIRNESS_FILENAME: &str = "fairness.yaml";

lazy_static! {
    /// Sucessos por boot, contador acumulativo (label tenant_id).
    pub static ref BASELINE_LOAD_SUCCESS_TOTAL: IntCounterVec = {
        #[allow(clippy::unwrap_used)]
        { register_int_counter_vec!(
            opts!("btv_baseline_load_success_total", "Tenants loaded successfully"),
            &["tenant_id"]
        ).unwrap() }
    };

    /// Falhas por boot (labels: tenant_id, cause), para alerta operacional.
    pub static ref BASELINE_LOAD_FAILURES_TOTAL: IntCounterVec = {
        #[allow(clippy::unwrap_used)]
        { register_int_counter_vec!(
            opts!("btv_baseline_load_failures_total", "Baseline load failures per tenant"),
            &["tenant_id", "cause"]
        ).unwrap() }
    };

    /// Tenants atualmente em estado Active após boot.
    pub static ref TENANTS_ACTIVE: IntGauge = {
        #[allow(clippy::unwrap_used)]
        { register_int_gauge!(
            "btv_tenants_active",
            "Tenants em estado Active após boot step"
        ).unwrap() }
    };

    /// Tenants atualmente em estado Degraded.
    pub static ref TENANTS_DEGRADED: IntGauge = {
        #[allow(clippy::unwrap_used)]
        { register_int_gauge!(
            "btv_tenants_degraded",
            "Tenants em estado Degraded (baseline ou fairness.yaml ausente/inválido)"
        ).unwrap() }
    };
}

/// Schema de `fairness.yaml`. Adição não-quebrante: campos novos devem
/// ser `Option<T>` ou ter `#[serde(default)]` (ADR-0082).
#[derive(Debug, Deserialize)]
struct FairnessYaml {
    mode: FairnessMode,
}

/// Resultado do carregamento de um único tenant. Permite agregação no
/// boot step antes de mutar registries.
#[derive(Debug)]
pub struct TenantLoadResult {
    pub tenant_id: String,
    pub status: TenantStatus,
    pub fairness_mode: FairnessMode,
}

/// Carrega o policy de um tenant a partir do seu diretório. Resolve
/// fairness.yaml e drift_baseline.yaml independentemente:
///
/// - Sem `fairness.yaml` → `FairnessMode::Disabled` (default registry).
/// - Sem `drift_baseline.yaml` → `Degraded(MissingBaseline)` apenas se
///   `mode != Disabled`. Tenant com `mode: disabled` não precisa de
///   baseline (Jonas não roda).
/// - YAML malformado → `Degraded(InvalidBaseline | InvalidFairnessYaml)`.
///
/// **Importante:** chamadas `install_baseline` no `JonasMonitor` ocorrem
/// in-place — esta função tem side-effects no monitor. Decisão arquitetural:
/// boot step é o único local com `JonasMonitor::&self` + I/O síncrono;
/// retornar `Result<JonasBaseline, _>` separado obrigaria a passar o
/// monitor de novo em outro loop. Mantemos side-effect localizado aqui
/// com documentação explícita.
pub async fn load_tenant_policy(
    tenant_dir: &Path,
    tenant_id: &str,
    jonas: &JonasMonitor,
) -> TenantLoadResult {
    let fairness_path = tenant_dir.join(FAIRNESS_FILENAME);
    let baseline_path = tenant_dir.join(BASELINE_FILENAME);

    // Step 1: Resolver FairnessMode. Ausente → Disabled (default seguro).
    let (mode, fairness_error): (FairnessMode, Option<String>) =
        match tokio::fs::read_to_string(&fairness_path).await {
            Ok(content) => match serde_yaml::from_str::<FairnessYaml>(&content) {
                Ok(parsed) => (parsed.mode, None),
                Err(e) => (FairnessMode::Disabled, Some(e.to_string())),
            },
            Err(_) => (FairnessMode::Disabled, None), // arquivo ausente é ok
        };

    if let Some(reason) = fairness_error {
        return TenantLoadResult {
            tenant_id: tenant_id.to_string(),
            status: TenantStatus::Degraded {
                cause: DegradationCause::InvalidFairnessYaml { reason },
            },
            fairness_mode: FairnessMode::Disabled,
        };
    }

    // Step 2: Resolver baseline Jonas. Necessário apenas se mode != Disabled.
    if matches!(mode, FairnessMode::Disabled) {
        return TenantLoadResult {
            tenant_id: tenant_id.to_string(),
            status: TenantStatus::Active,
            fairness_mode: mode,
        };
    }

    let baseline_content = match tokio::fs::read_to_string(&baseline_path).await {
        Ok(c) => c,
        Err(_) => {
            return TenantLoadResult {
                tenant_id: tenant_id.to_string(),
                status: TenantStatus::Degraded {
                    cause: DegradationCause::MissingBaseline,
                },
                fairness_mode: mode,
            };
        }
    };

    // Step 3: Instalar no JonasMonitor via trait (kernel-agnostic).
    match jonas.reload_baseline(tenant_id, &baseline_content) {
        Ok(()) => TenantLoadResult {
            tenant_id: tenant_id.to_string(),
            status: TenantStatus::Active,
            fairness_mode: mode,
        },
        Err(e) => TenantLoadResult {
            tenant_id: tenant_id.to_string(),
            status: TenantStatus::Degraded {
                cause: DegradationCause::InvalidBaseline {
                    reason: e.to_string(),
                },
            },
            fairness_mode: mode,
        },
    }
}

/// Walk recursivo de primeiro nível em `policies_dir/`: cada subdiretório
/// é tratado como tenant_id. `tenant_id` é validado via
/// `validate_tenant_id` (ADR-0083 §D1) — diretórios fora do padrão são
/// pulados com log de aviso (não bloqueiam o boot).
fn discover_tenant_dirs(policies_dir: &Path) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let read_dir = match std::fs::read_dir(policies_dir) {
        Ok(rd) => rd,
        Err(e) => {
            tracing::warn!(
                policies_dir = %policies_dir.display(),
                error = %e,
                "policies_dir ausente ou ilegível — boot step prosseguirá sem tenants"
            );
            return out;
        }
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        // `name` é convertido para String imediatamente para liberar o
        // borrow de `path` antes do move em `out.push`.
        let name: String = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if validate_tenant_id(&name).is_err() {
            tracing::warn!(
                dir = %path.display(),
                "diretório em policies/ não é tenant_id válido — ignorado"
            );
            continue;
        }
        out.push((path, name));
    }
    out
}

/// Boot step principal. Carrega todos os tenants declarados em `policies_dir/`
/// em paralelo, aplica resultados nos registries, atualiza métricas e logs.
///
/// **Idempotente:** chamadas repetidas (ex: hot reload) substituem entries
/// existentes via `install`/`mark_*`. Tenants removidos do disco entre
/// chamadas **não** são automaticamente evictados — usar
/// `/internal/v1/tenants/{id}` (Commit 5).
pub async fn warm_policies(
    policies_dir: &Path,
    jonas: &JonasMonitor,
    fairness_modes: &FairnessModeRegistry,
    statuses: &TenantStatusRegistry,
) {
    tracing::info!(
        policies_dir = %policies_dir.display(),
        "iniciando warm_policies (ADR-0089 §D1)"
    );

    let tenant_dirs = discover_tenant_dirs(policies_dir);
    if tenant_dirs.is_empty() {
        tracing::info!("nenhum tenant declarado em policies/ — boot step concluído");
        return;
    }

    // Marca todos como Initializing antes de despachar paralelo — janela
    // existe apenas se boot demorar e o handler começar a aceitar tráfego
    // antes do término (proteção contra race).
    for (_path, id) in &tenant_dirs {
        statuses.mark_initializing(id);
    }

    let futures = tenant_dirs.iter().map(|(path, id)| async move {
        load_tenant_policy(path, id, jonas).await
    });
    let results = join_all(futures).await;

    let mut active_count: i64 = 0;
    let mut degraded_count: i64 = 0;

    for result in results {
        let TenantLoadResult {
            tenant_id,
            status,
            fairness_mode,
        } = result;

        fairness_modes.install(&tenant_id, fairness_mode);
        statuses.set(&tenant_id, status.clone());

        match &status {
            TenantStatus::Active => {
                active_count += 1;
                BASELINE_LOAD_SUCCESS_TOTAL
                    .with_label_values(&[&tenant_id])
                    .inc();
                tracing::info!(
                    tenant_id = %tenant_id,
                    fairness_mode = ?fairness_mode,
                    "tenant carregado com sucesso"
                );
            }
            TenantStatus::Degraded { cause } => {
                degraded_count += 1;
                let cause_label = match cause {
                    DegradationCause::MissingBaseline => "missing_baseline",
                    DegradationCause::InvalidBaseline { .. } => "invalid_baseline",
                    DegradationCause::InvalidFairnessYaml { .. } => "invalid_fairness_yaml",
                    DegradationCause::BaselineHashMismatch { .. } => "baseline_hash_mismatch",
                };
                BASELINE_LOAD_FAILURES_TOTAL
                    .with_label_values(&[&tenant_id, cause_label])
                    .inc();
                tracing::error!(
                    tenant_id = %tenant_id,
                    cause = %cause,
                    fairness_mode = ?fairness_mode,
                    "tenant em estado Degraded — outros tenants não afetados"
                );
            }
            TenantStatus::Initializing => {
                // Não deve acontecer (load_tenant_policy sempre retorna
                // Active ou Degraded), mas é fail-safe se future loaders
                // forem adicionados.
                tracing::warn!(tenant_id = %tenant_id, "tenant ficou em Initializing após load");
            }
        }
    }

    TENANTS_ACTIVE.set(active_count);
    TENANTS_DEGRADED.set(degraded_count);

    tracing::info!(
        active = active_count,
        degraded = degraded_count,
        "warm_policies concluído"
    );
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const VALID_BASELINE_YAML: &str = r#"
version: "1.0.0"
model_id: "test-model"
bins: 10
reference_proportions:
  - 0.05
  - 0.07
  - 0.10
  - 0.13
  - 0.15
  - 0.18
  - 0.15
  - 0.10
  - 0.05
  - 0.02
"#;

    fn tenant_dir(root: &Path, tenant_id: &str) -> PathBuf {
        let dir = root.join(tenant_id);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_file(path: &Path, content: &str) {
        std::fs::write(path, content).unwrap();
    }

    fn fresh_registries() -> (JonasMonitor, FairnessModeRegistry, TenantStatusRegistry) {
        (
            JonasMonitor::new(),
            FairnessModeRegistry::new(),
            TenantStatusRegistry::new(),
        )
    }

    // ── load_tenant_policy ────────────────────────────────────────

    #[tokio::test]
    async fn no_fairness_yaml_yields_disabled_active() {
        let tmp = TempDir::new().unwrap();
        let dir = tenant_dir(tmp.path(), "acme");
        let (jonas, _, _) = fresh_registries();
        let result = load_tenant_policy(&dir, "acme", &jonas).await;
        assert_eq!(result.fairness_mode, FairnessMode::Disabled);
        assert_eq!(result.status, TenantStatus::Active);
    }

    #[tokio::test]
    async fn disabled_mode_does_not_require_baseline() {
        let tmp = TempDir::new().unwrap();
        let dir = tenant_dir(tmp.path(), "acme");
        write_file(&dir.join(FAIRNESS_FILENAME), "mode: disabled\n");
        let (jonas, _, _) = fresh_registries();
        let result = load_tenant_policy(&dir, "acme", &jonas).await;
        assert_eq!(result.fairness_mode, FairnessMode::Disabled);
        assert_eq!(result.status, TenantStatus::Active);
        // Jonas baseline NÃO foi instalado.
        assert!(jonas.metrics("acme").is_none());
    }

    #[tokio::test]
    async fn enforced_with_baseline_yields_active() {
        let tmp = TempDir::new().unwrap();
        let dir = tenant_dir(tmp.path(), "acme");
        write_file(&dir.join(FAIRNESS_FILENAME), "mode: enforced\n");
        write_file(&dir.join(BASELINE_FILENAME), VALID_BASELINE_YAML);
        let (jonas, _, _) = fresh_registries();
        let result = load_tenant_policy(&dir, "acme", &jonas).await;
        assert_eq!(result.fairness_mode, FairnessMode::Enforced);
        assert_eq!(result.status, TenantStatus::Active);
        // Jonas baseline instalado — record agora funciona.
        jonas.record("acme", 0.5, false);
    }

    #[tokio::test]
    async fn enforced_without_baseline_yields_missing_baseline() {
        let tmp = TempDir::new().unwrap();
        let dir = tenant_dir(tmp.path(), "acme");
        write_file(&dir.join(FAIRNESS_FILENAME), "mode: enforced\n");
        let (jonas, _, _) = fresh_registries();
        let result = load_tenant_policy(&dir, "acme", &jonas).await;
        assert_eq!(result.fairness_mode, FairnessMode::Enforced);
        assert_eq!(
            result.status,
            TenantStatus::Degraded {
                cause: DegradationCause::MissingBaseline,
            }
        );
    }

    #[tokio::test]
    async fn invalid_baseline_yields_degraded_with_reason() {
        let tmp = TempDir::new().unwrap();
        let dir = tenant_dir(tmp.path(), "acme");
        write_file(&dir.join(FAIRNESS_FILENAME), "mode: shadow\n");
        write_file(&dir.join(BASELINE_FILENAME), "::not yaml::");
        let (jonas, _, _) = fresh_registries();
        let result = load_tenant_policy(&dir, "acme", &jonas).await;
        match result.status {
            TenantStatus::Degraded {
                cause: DegradationCause::InvalidBaseline { reason },
            } => {
                assert!(!reason.is_empty(), "razão deve carregar contexto do erro");
            }
            other => panic!("expected InvalidBaseline, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn invalid_fairness_yaml_yields_degraded() {
        let tmp = TempDir::new().unwrap();
        let dir = tenant_dir(tmp.path(), "acme");
        write_file(&dir.join(FAIRNESS_FILENAME), "mode: garbage_mode\n");
        write_file(&dir.join(BASELINE_FILENAME), VALID_BASELINE_YAML);
        let (jonas, _, _) = fresh_registries();
        let result = load_tenant_policy(&dir, "acme", &jonas).await;
        match result.status {
            TenantStatus::Degraded {
                cause: DegradationCause::InvalidFairnessYaml { reason },
            } => {
                assert!(!reason.is_empty());
            }
            other => panic!("expected InvalidFairnessYaml, got {other:?}"),
        }
    }

    // ── warm_policies ─────────────────────────────────────────────

    #[tokio::test]
    async fn warm_policies_with_empty_dir_is_noop() {
        let tmp = TempDir::new().unwrap();
        let (jonas, modes, statuses) = fresh_registries();
        warm_policies(tmp.path(), &jonas, &modes, &statuses).await;
        assert_eq!(modes.declared_tenant_count(), 0);
        assert_eq!(statuses.tracked_tenant_count(), 0);
    }

    #[tokio::test]
    async fn warm_policies_with_missing_dir_logs_warn_and_continues() {
        let tmp = TempDir::new().unwrap();
        let nonexistent = tmp.path().join("nope");
        let (jonas, modes, statuses) = fresh_registries();
        warm_policies(&nonexistent, &jonas, &modes, &statuses).await;
        assert_eq!(modes.declared_tenant_count(), 0);
    }

    #[tokio::test]
    async fn warm_policies_loads_multiple_tenants_in_parallel() {
        let tmp = TempDir::new().unwrap();
        // Tenant 1: enforced + baseline válido
        let t1 = tenant_dir(tmp.path(), "acme");
        write_file(&t1.join(FAIRNESS_FILENAME), "mode: enforced\n");
        write_file(&t1.join(BASELINE_FILENAME), VALID_BASELINE_YAML);
        // Tenant 2: shadow + baseline válido
        let t2 = tenant_dir(tmp.path(), "globex");
        write_file(&t2.join(FAIRNESS_FILENAME), "mode: shadow\n");
        write_file(&t2.join(BASELINE_FILENAME), VALID_BASELINE_YAML);
        // Tenant 3: disabled (sem baseline)
        let t3 = tenant_dir(tmp.path(), "legacy");
        write_file(&t3.join(FAIRNESS_FILENAME), "mode: disabled\n");
        // Tenant 4: enforced sem baseline → Degraded
        let t4 = tenant_dir(tmp.path(), "broken");
        write_file(&t4.join(FAIRNESS_FILENAME), "mode: enforced\n");

        let (jonas, modes, statuses) = fresh_registries();
        warm_policies(tmp.path(), &jonas, &modes, &statuses).await;

        assert_eq!(modes.declared_tenant_count(), 4);
        assert_eq!(modes.mode_for("acme"), FairnessMode::Enforced);
        assert_eq!(modes.mode_for("globex"), FairnessMode::Shadow);
        assert_eq!(modes.mode_for("legacy"), FairnessMode::Disabled);
        assert_eq!(modes.mode_for("broken"), FairnessMode::Enforced);

        assert_eq!(statuses.status_for("acme"), TenantStatus::Active);
        assert_eq!(statuses.status_for("globex"), TenantStatus::Active);
        assert_eq!(statuses.status_for("legacy"), TenantStatus::Active);
        assert!(matches!(
            statuses.status_for("broken"),
            TenantStatus::Degraded { .. }
        ));
    }

    #[tokio::test]
    async fn warm_policies_skips_invalid_tenant_id_dirs() {
        let tmp = TempDir::new().unwrap();
        // Diretório com nome inválido (uppercase) — deve ser ignorado.
        let bad = tmp.path().join("UPPERCASE");
        std::fs::create_dir_all(&bad).unwrap();
        write_file(&bad.join(FAIRNESS_FILENAME), "mode: enforced\n");
        // Diretório válido.
        let good = tenant_dir(tmp.path(), "acme");
        write_file(&good.join(FAIRNESS_FILENAME), "mode: disabled\n");

        let (jonas, modes, statuses) = fresh_registries();
        warm_policies(tmp.path(), &jonas, &modes, &statuses).await;

        assert_eq!(modes.declared_tenant_count(), 1, "só acme deve ser carregado");
        assert_eq!(modes.mode_for("acme"), FairnessMode::Disabled);
        // UPPERCASE não tem entry em nenhum registry — defaults aplicam.
        assert_eq!(modes.mode_for("UPPERCASE"), FairnessMode::Disabled);
        assert_eq!(statuses.status_for("UPPERCASE"), TenantStatus::Active);
    }

    #[tokio::test]
    async fn warm_policies_is_idempotent_for_reload() {
        let tmp = TempDir::new().unwrap();
        let t1 = tenant_dir(tmp.path(), "acme");
        write_file(&t1.join(FAIRNESS_FILENAME), "mode: enforced\n");
        write_file(&t1.join(BASELINE_FILENAME), VALID_BASELINE_YAML);

        let (jonas, modes, statuses) = fresh_registries();
        warm_policies(tmp.path(), &jonas, &modes, &statuses).await;
        assert_eq!(modes.mode_for("acme"), FairnessMode::Enforced);

        // Mudar fairness.yaml e re-warm — deve refletir a nova config.
        write_file(&t1.join(FAIRNESS_FILENAME), "mode: shadow\n");
        warm_policies(tmp.path(), &jonas, &modes, &statuses).await;
        assert_eq!(modes.mode_for("acme"), FairnessMode::Shadow);
        assert_eq!(modes.declared_tenant_count(), 1, "reload não cria entry nova");
    }
}
