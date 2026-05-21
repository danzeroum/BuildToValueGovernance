//! Python FFI Entry Point for BuildToValue Governance
//!
//! Este é o ÚNICO módulo PyO3 na crate. Ele consolida todas as
//! funções Python exportadas em um único módulo `buildtovalue_kernel`.

use pyo3::prelude::*;

// Módulos internos
pub mod batch;
pub mod bridge;

// Importar funções públicas dos submódulos
use batch::calculate_penalties_batch;
use bridge::{scan_for_evidence_batch, test_bridge};

/// BuildToValue Kernel Python Module
///
/// Este módulo fornece bindings Python para o sistema BuildToValue Governance.
///
/// # Funções disponíveis:
/// - `calculate_penalties_batch()`: Calcula penalidades em lote
/// - `scan_for_evidence_batch()`: Escaneia evidências em lote
/// - `version()`: Retorna a versão
///
/// # Exemplo:
/// ```python
/// import buildtovalue_kernel as btv
/// print(btv.version())
/// ```
#[pymodule]
#[pyo3(name = "buildtovalue_kernel")]
fn buildtovalue_kernel(py: Python, m: &PyModule) -> PyResult<()> {
    // Metadata do módulo
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("__author__", "BuildToValue Team")?;
    m.add("__description__", "FFI bindings for BuildToValue Governance")?;

    // Constantes
    m.add("PROTOCOL_VERSION", 2u8)?;
    m.add("API_VERSION", "2.2.0")?;

    // Funções principais
    m.add_function(wrap_pyfunction!(calculate_penalties_batch, m)?)?;
    m.add_function(wrap_pyfunction!(scan_for_evidence_batch, m)?)?;
    m.add_function(wrap_pyfunction!(test_bridge, m)?)?;

    // Função de versão
    m.add_function(wrap_pyfunction!(version, m)?)?;

    // Exceções customizadas
    let exceptions = PyModule::new(py, "exceptions")?;
    m.add_submodule(exceptions)?;

    Ok(())
}

/// Retorna a versão atual da biblioteca
#[pyfunction]
fn version() -> String {
    format!("BuildToValue Kernel v{}", env!("CARGO_PKG_VERSION"))
}
