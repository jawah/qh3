use pyo3::types::PyBytes;
use pyo3::types::PyBytesMethods;
use pyo3::Python;
use pyo3::{pyclass, PyResult};
use pyo3::{pymethods, Bound};

use crate::CryptoError;
use rsa::{sha2::Sha256, Oaep, RsaPrivateKey, RsaPublicKey};

#[pyclass(module = "qh3._hazmat")]
pub struct Rsa {
    public_key: RsaPublicKey,
    private_key: RsaPrivateKey,
}

#[pymethods]
impl Rsa {
    #[new]
    pub fn py_new(key_size: usize) -> PyResult<Self> {
        let mut rng = rand::thread_rng();

        let private_key = match RsaPrivateKey::new(&mut rng, key_size) {
            Ok(key) => key,
            Err(_) => return Err(CryptoError::new_err("Failed to generate RSA private key")),
        };

        let public_key = RsaPublicKey::from(&private_key);

        Ok(Rsa {
            public_key,
            private_key,
        })
    }

    pub fn encrypt<'a>(
        &mut self,
        py: Python<'a>,
        data: Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let payload_to_enc = data.as_bytes();

        let padding = Oaep::new::<Sha256>();
        let mut rng = rand::thread_rng();

        let enc_data = match self.public_key.encrypt(&mut rng, padding, payload_to_enc) {
            Ok(data) => data,
            Err(_) => return Err(CryptoError::new_err("Failed to encrypt data")),
        };

        Ok(PyBytes::new(py, &enc_data))
    }

    pub fn decrypt<'a>(
        &self,
        py: Python<'a>,
        data: Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let payload_to_dec = data.as_bytes();

        let padding = Oaep::new::<Sha256>();

        let dec_data = match self.private_key.decrypt(padding, payload_to_dec) {
            Ok(data) => data,
            Err(_) => return Err(CryptoError::new_err("Failed to decrypt data")),
        };

        Ok(PyBytes::new(py, &dec_data))
    }
}
