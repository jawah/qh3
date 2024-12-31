use aws_lc_rs::aead::quic::{HeaderProtectionKey, AES_128, AES_256, CHACHA20};

use crate::CryptoError;
use pyo3::pymethods;
use pyo3::types::PyBytes;
use pyo3::types::PyBytesMethods;
use pyo3::{pyclass, Bound};
use pyo3::{PyResult, Python};

#[pyclass(module = "qh3._hazmat")]
pub struct QUICHeaderProtection {
    hpk: HeaderProtectionKey,
}

#[pymethods]
impl QUICHeaderProtection {
    #[new]
    pub fn py_new(key: Bound<'_, PyBytes>, algorithm: u16) -> PyResult<Self> {
        let inner_hpk = match HeaderProtectionKey::new(
            match algorithm {
                128 => &AES_128,
                256 => &AES_256,
                20 => &CHACHA20,
                _ => return Err(CryptoError::new_err("Algorithm not supported")),
            },
            key.as_bytes(),
        ) {
            Ok(hpk) => hpk,
            Err(_) => {
                return Err(CryptoError::new_err(
                    "Given key is not valid for chosen algorithm",
                ))
            }
        };

        Ok(QUICHeaderProtection { hpk: inner_hpk })
    }

    pub fn mask<'a>(
        &self,
        py: Python<'a>,
        sample: Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let res = self.hpk.new_mask(sample.as_bytes());

        match res {
            Err(_) => Err(CryptoError::new_err(
                "unable to issue mask protection header",
            )),
            Ok(data) => Ok(PyBytes::new(py, &data)),
        }
    }
}
