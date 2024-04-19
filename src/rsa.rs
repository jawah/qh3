use pyo3::Python;
use pyo3::types::PyBytes;
use pyo3::pymethods;
use pyo3::pyclass;


use rsa::{RsaPrivateKey, RsaPublicKey, Oaep, sha2::Sha256};


#[pyclass(module = "qh3._hazmat")]
pub struct Rsa {
    public_key: RsaPublicKey,
    private_key: RsaPrivateKey,
}

#[pymethods]
impl Rsa {
    #[new]
    pub fn py_new(key_size: usize) -> Self {
        let mut rng = rand::thread_rng();

        let private_key = RsaPrivateKey::new(&mut rng, key_size).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

        Rsa {
            public_key: public_key,
            private_key: private_key,
        }
    }

    pub fn encrypt<'a>(&mut self, py: Python<'a>, data: &PyBytes) -> &'a PyBytes {
        let payload_to_enc = data.as_bytes();

        let padding = Oaep::new::<Sha256>();
        let mut rng = rand::thread_rng();

        let enc_data = self.public_key.encrypt(&mut rng, padding, &payload_to_enc[..]).expect("failed to encrypt");

        return PyBytes::new(
            py,
            &enc_data
        );
    }

    pub fn decrypt<'a>(&self, py: Python<'a>, data: &PyBytes) -> &'a PyBytes {
        let payload_to_dec = data.as_bytes();

        let padding = Oaep::new::<Sha256>();
        let dec_data = self.private_key.decrypt(padding, &payload_to_dec).expect("failed to decrypt");

        return PyBytes::new(
            py,
            &dec_data
        );
    }
}
