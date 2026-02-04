//! BuildToValue FFI Bindings (PyO3)

use pyo3::prelude::*;

#[pymodule]
fn buildtovalue_bindings(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    Ok(())
}

#[pyfunction]
fn version() -> String {
    "2.2.0".to_string()
}
