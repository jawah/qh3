use aws_lc_rs::aead::quic::{HeaderProtectionKey, AES_128, AES_256, CHACHA20};

use pyo3::{PyResult, Python};
use pyo3::types::PyBytes;
use pyo3::pymethods;
use pyo3::pyclass;
use crate::CryptoError;

#[pyclass(module = "qh3._hazmat")]
pub struct QUICHeaderProtection {
    hpk: HeaderProtectionKey
}

#[pymethods]
impl QUICHeaderProtection {

    #[new]
    pub fn py_new(key: &PyBytes, algorithm: u16) -> Self {
        QUICHeaderProtection {
            hpk: HeaderProtectionKey::new(
                match algorithm {
                    128 => &AES_128,
                    256 => &AES_256,
                    20 => &CHACHA20,
                    _ => panic!("unsupported")
                },
                &key.as_bytes()
            ).expect("FAILURE")
        }
    }

    pub fn mask<'a>(&self, py: Python<'a>, sample: &PyBytes) -> PyResult<&'a PyBytes> {
        let res = self.hpk.new_mask(&sample.as_bytes());

        return match res {
            Err(_) => Err(CryptoError::new_err("unable to issue mask protection header")),
            Ok(data) => Ok(
                PyBytes::new(
                    py,
                    &data
                )
            )
        }
    }
}
