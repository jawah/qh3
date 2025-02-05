use pyo3::exceptions::PyValueError;
use pyo3::pyfunction;
use pyo3::types::PyBytesMethods;
use pyo3::types::{PyBytes, PyString};
use pyo3::Bound;
use pyo3::{PyResult, Python};

use idna::domain_to_ascii;
use idna::domain_to_unicode;

#[pyfunction]
pub fn idna_encode<'a>(py: Python<'a>, text: &str) -> PyResult<Bound<'a, PyBytes>> {
    let idna_domain = match domain_to_ascii(text) {
        Ok(s) => s,
        Err(e) => return Err(PyValueError::new_err(e.to_string())),
    };

    Ok(PyBytes::new(py, idna_domain.as_bytes()))
}

#[pyfunction]
pub fn idna_decode<'a>(py: Python<'a>, src: Bound<'a, PyBytes>) -> PyResult<Bound<'a, PyString>> {
    let decode_res = domain_to_unicode(std::str::from_utf8(src.as_bytes())?);

    if decode_res.1.is_err() {
        return Err(PyValueError::new_err("invalid IDNA input"));
    }

    Ok(PyString::new(py, decode_res.0.as_ref()))
}
