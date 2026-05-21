//! Python FFI Entry Point for BuildToValue Governance
//!
//! Este é o ÚNICO módulo PyO3 na crate. Ele consolida todas as
//! funções Python exportadas em um único módulo `buildtovalue_kernel`.

use pyo3::prelude::*;

// Módulos internos
pub mod batch;
pub mod bridge;

// Importar símbolos públicos dos submódulos
use batch::calculate_penalties_batch;
use bridge::{scan_for_evidence_batch, test_bridge, RustKernel};

/// BuildToValue Kernel Python Module
///
/// # Exemplo:
/// ```python
/// import buildtovalue_kernel as btv
/// kernel = btv.RustKernel()
/// result = kernel.scan_for_evidence_batch(["texto"], [123456])
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

    // Classe RustKernel (API OO usada pelo ffi_client)
    m.add_class::<RustKernel>()?;

    // Funções standalone (API funcional)
    m.add_function(wrap_pyfunction!(calculate_penalties_batch, m)?)?;
    m.add_function(wrap_pyfunction!(scan_for_evidence_batch, m)?)?;
    m.add_function(wrap_pyfunction!(test_bridge, m)?)?;
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
