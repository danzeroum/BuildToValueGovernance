//! `btv-executive` — Poder Executivo constitucional (Paper 5, Theorem 3.5).
//!
//! ## Invariante de contenção
//! O fluxo `Decide → Deliver` é **type-constrained**:
//!
//! ```text
//! context
//!   → EvidenceToken::new          (btv-core, linear)
//!   → ComplianceAuthority::issue  (btv-core, linear)
//!   → Verdict::new(E ⊗ C)         (btv-core, consome ambos)
//!   → LogClient.submit_and_await  (btv-core → HTTP → btv-sigma)
//!   → DeliveryToken::seal(V ⊗ R)  (btv-core, consome ambos)
//!   → DeliveryPayload             (wire format)
//! ```
//!
//! Se **qualquer passo falhar** → `Err(DecisionError)` — nenhum resultado parcial é exposto.
//!
//! ## Limites de importação (enforced pelo CI)
//! - Importa `btv-core` (consome tipos lineares do Legislativo) — CORRETO
//! - Importa `btv-kernel` (infraestrutura de scan) — CORRETO
//! - Importa `btv-types` (wire formats) — CORRETO
//! - NÃO importa `btv-sigma` diretamente — comunica via HTTP
//! - NÃO será importado por `btv-judicial` — o Judiciário verifica via `btv-types`
#![deny(unsafe_code)]
#![deny(unused_must_use)]

mod gatekeeper_bridge;
mod executive;
mod decision;
pub mod error;
pub mod gateway;

pub use executive::{Executive, ExecutiveResult, ScanSummary};
pub use decision::DecisionMaker;
pub use error::DecisionError;
// Re-export wire types consumed by gateway callers
pub use btv_types::{Decision, RiskLevel, DeliveryPayload};
