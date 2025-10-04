use aws_lc_rs::{agreement, error};

use aws_lc_rs::kem;
use aws_lc_rs::kem::ML_KEM_768;
use rustls::crypto::SharedSecret;

use crate::CryptoError;
use pyo3::types::PyBytes;
use pyo3::types::PyBytesMethods;
use pyo3::Python;
use pyo3::{pyclass, PyResult};
use pyo3::{pymethods, Bound};

const X25519_LEN: usize = 32;
const KYBER_CIPHERTEXT_LEN: usize = 1088;
const X25519_KYBER_COMBINED_PUBKEY_LEN: usize = X25519_LEN + 1184;
const X25519_KYBER_COMBINED_CIPHERTEXT_LEN: usize = X25519_LEN + KYBER_CIPHERTEXT_LEN;
const X25519_KYBER_COMBINED_SHARED_SECRET_LEN: usize = X25519_LEN + 32;
const MLKEM768_SECRET_LEN: usize = 32;
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;

struct X25519ML768CombinedSecret([u8; X25519_KYBER_COMBINED_SHARED_SECRET_LEN]);

impl X25519ML768CombinedSecret {
    fn combine(x25519: SharedSecret, kyber: kem::SharedSecret) -> Self {
        let mut out = X25519ML768CombinedSecret([0u8; X25519_KYBER_COMBINED_SHARED_SECRET_LEN]);
        out.0[..MLKEM768_SECRET_LEN].copy_from_slice(kyber.as_ref());
        out.0[MLKEM768_SECRET_LEN..].copy_from_slice(x25519.secret_bytes());
        out
    }
}

#[pyclass(module = "qh3._hazmat")]
pub struct X25519KeyExchange {
    private: agreement::PrivateKey,
}

#[pyclass(module = "qh3._hazmat")]
pub struct ECDHP256KeyExchange {
    private: agreement::PrivateKey,
}

#[pyclass(module = "qh3._hazmat")]
pub struct ECDHP384KeyExchange {
    private: agreement::PrivateKey,
}

#[pyclass(module = "qh3._hazmat")]
pub struct ECDHP521KeyExchange {
    private: agreement::PrivateKey,
}

#[pyclass(module = "qh3._hazmat")]
pub struct X25519ML768KeyExchange {
    x25519_private: agreement::PrivateKey,
    kyber768_decapsulation_key: kem::DecapsulationKey<kem::AlgorithmId>,
    cipher_text: Vec<u8>,
}

#[pymethods]
impl X25519ML768KeyExchange {
    #[new]
    pub fn py_new() -> PyResult<Self> {
        let x25519_pk = match agreement::PrivateKey::generate(&agreement::X25519) {
            Ok(key) => key,
            Err(_) => return Err(CryptoError::new_err("Unable to generate X25519 key")),
        };

        let ml768_dk = match kem::DecapsulationKey::generate(&ML_KEM_768) {
            Ok(key) => key,
            Err(_) => {
                return Err(CryptoError::new_err(
                    "Unable to generate ML_KEM_768 decapsulation key",
                ))
            }
        };

        Ok(X25519ML768KeyExchange {
            x25519_private: x25519_pk,
            kyber768_decapsulation_key: ml768_dk,
            cipher_text: Vec::new(),
        })
    }

    pub fn public_key<'a>(&self, py: Python<'a>) -> PyResult<Bound<'a, PyBytes>> {
        let kyber_pub = match self.kyber768_decapsulation_key.encapsulation_key() {
            Ok(key) => key,
            Err(_) => {
                return Err(CryptoError::new_err(
                    "Unable to generate ML768 encapsulation key",
                ))
            }
        };

        let mut combined_pub_key = Vec::with_capacity(X25519_KYBER_COMBINED_PUBKEY_LEN);

        let raw_ml_encapsulation_key = match kyber_pub.key_bytes() {
            Ok(key) => key,
            Err(_) => {
                return Err(CryptoError::new_err(
                    "Unable to get encapsulation key for ML768 as plain bytes",
                ))
            }
        };

        let raw_x25519_public_key = match self.x25519_private.compute_public_key() {
            Ok(key) => key,
            Err(_) => {
                return Err(CryptoError::new_err(
                    "Unable to get public key for X25519 as plain bytes",
                ))
            }
        };

        combined_pub_key.extend_from_slice(raw_ml_encapsulation_key.as_ref());
        combined_pub_key.extend_from_slice(raw_x25519_public_key.as_ref());

        Ok(PyBytes::new(py, combined_pub_key.as_ref()))
    }

    pub fn shared_ciphertext<'a>(&mut self, py: Python<'a>) -> PyResult<Bound<'a, PyBytes>> {
        if self.cipher_text.is_empty() {
            return Err(CryptoError::new_err(
                "You must receive client share first. Call exchange with client share.",
            ));
        }

        let mut combined_pub_key = Vec::with_capacity(X25519_KYBER_COMBINED_CIPHERTEXT_LEN);

        let raw_x25519_public_key = match self.x25519_private.compute_public_key() {
            Ok(key) => key,
            Err(_) => {
                return Err(CryptoError::new_err(
                    "Unable to get public key for X25519 as plain bytes",
                ))
            }
        };

        combined_pub_key.extend_from_slice(self.cipher_text.as_ref());
        combined_pub_key.extend_from_slice(raw_x25519_public_key.as_ref());

        self.cipher_text = Vec::new();

        Ok(PyBytes::new(py, combined_pub_key.as_ref()))
    }

    pub fn exchange<'a>(
        &mut self,
        py: Python<'a>,
        peer_public_key: Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let cipher_text = peer_public_key.as_bytes();

        // client share received
        if cipher_text.len() == 1216 {
            let (kyber, x25519) = cipher_text.split_at(1184);

            let x25519_peer_public_key =
                agreement::UnparsedPublicKey::new(&agreement::X25519, x25519);

            let x25519_secret = match agreement::agree(
                &self.x25519_private,
                &x25519_peer_public_key,
                error::Unspecified,
                |_key_material| Ok(_key_material.to_vec()),
            ) {
                Ok(key) => key,
                Err(_) => {
                    return Err(CryptoError::new_err(
                        "X25519ML768 exchange failure due to X25519 agreement failure",
                    ))
                }
            };

            let ml768_share = match kem::EncapsulationKey::new(&kem::ML_KEM_768, kyber) {
                Ok(key) => key,
                Err(_) => return Err(CryptoError::new_err("Unable to parse ML768 share")),
            };

            // Bob executes the encapsulation algorithm to to produce their copy of the secret, and associated ciphertext.
            let (ciphertext, bob_secret) = ml768_share.encapsulate().expect("");

            let combined_secret = X25519ML768CombinedSecret::combine(
                SharedSecret::from(&x25519_secret[..]),
                bob_secret,
            );

            self.cipher_text = ciphertext.as_ref().to_vec();

            let key_material = SharedSecret::from(&combined_secret.0[..]);

            Ok(PyBytes::new(py, key_material.secret_bytes()))
        } else {
            let (kyber, x25519) = cipher_text.split_at(MLKEM768_CIPHERTEXT_LEN);

            let x25519_peer_public_key =
                agreement::UnparsedPublicKey::new(&agreement::X25519, x25519);

            let x25519_secret = match agreement::agree(
                &self.x25519_private,
                &x25519_peer_public_key,
                error::Unspecified,
                |_key_material| Ok(_key_material.to_vec()),
            ) {
                Ok(key) => key,
                Err(_) => {
                    return Err(CryptoError::new_err(
                        "X25519ML768 exchange failure due to X25519 agreement failure",
                    ))
                }
            };

            let kyber_secret = match self.kyber768_decapsulation_key.decapsulate(kyber.into()) {
                Ok(secret) => secret,
                Err(_) => {
                    return Err(CryptoError::new_err(
                        "X25519ML768 exchange failure due to decapsulation error",
                    ))
                }
            };

            let combined_secret = X25519ML768CombinedSecret::combine(
                SharedSecret::from(&x25519_secret[..]),
                kyber_secret,
            );

            let key_material = SharedSecret::from(&combined_secret.0[..]);

            Ok(PyBytes::new(py, key_material.secret_bytes()))
        }
    }
}

#[pymethods]
impl X25519KeyExchange {
    #[new]
    pub fn py_new() -> PyResult<Self> {
        let x25519_pk = match agreement::PrivateKey::generate(&agreement::X25519) {
            Ok(key) => key,
            Err(_) => return Err(CryptoError::new_err("Unable to generate X25519 key")),
        };

        Ok(X25519KeyExchange { private: x25519_pk })
    }

    pub fn public_key<'a>(&self, py: Python<'a>) -> PyResult<Bound<'a, PyBytes>> {
        let my_public_key = match self.private.compute_public_key() {
            Ok(key) => key,
            Err(_) => {
                return Err(CryptoError::new_err(
                    "Unable to get public key for X25519 as plain bytes",
                ))
            }
        };

        Ok(PyBytes::new(py, my_public_key.as_ref()))
    }

    pub fn exchange<'a>(
        &self,
        py: Python<'a>,
        peer_public_key: Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let peer_public_key =
            agreement::UnparsedPublicKey::new(&agreement::X25519, peer_public_key.as_bytes());

        let key_material = match agreement::agree(
            &self.private,
            &peer_public_key,
            error::Unspecified,
            |_key_material| Ok(_key_material.to_vec()),
        ) {
            Ok(key) => key,
            Err(_) => return Err(CryptoError::new_err("X25519 exchange failure")),
        };

        Ok(PyBytes::new(py, &key_material))
    }
}

#[pymethods]
impl ECDHP256KeyExchange {
    #[new]
    pub fn py_new() -> PyResult<Self> {
        let ecdh_key = match agreement::PrivateKey::generate(&agreement::ECDH_P256) {
            Ok(key) => key,
            Err(_) => return Err(CryptoError::new_err("Unable to generate ECDH p256 key")),
        };

        Ok(ECDHP256KeyExchange { private: ecdh_key })
    }

    pub fn public_key<'a>(&self, py: Python<'a>) -> PyResult<Bound<'a, PyBytes>> {
        let my_public_key = match self.private.compute_public_key() {
            Ok(key) => key,
            Err(_) => {
                return Err(CryptoError::new_err(
                    "Unable to get public key for ECDHP256KeyExchange",
                ))
            }
        };

        Ok(PyBytes::new(py, my_public_key.as_ref()))
    }

    pub fn exchange<'a>(
        &self,
        py: Python<'a>,
        peer_public_key: Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let peer_public_key =
            agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, peer_public_key.as_bytes());

        let key_material = match agreement::agree(
            &self.private,
            &peer_public_key,
            error::Unspecified,
            |_key_material| Ok(_key_material.to_vec()),
        ) {
            Ok(key) => key,
            Err(_) => return Err(CryptoError::new_err("ECDHP256KeyExchange failure")),
        };

        Ok(PyBytes::new(py, &key_material))
    }
}

#[pymethods]
impl ECDHP384KeyExchange {
    #[new]
    pub fn py_new() -> PyResult<Self> {
        let ecdh_key = match agreement::PrivateKey::generate(&agreement::ECDH_P384) {
            Ok(key) => key,
            Err(_) => return Err(CryptoError::new_err("Unable to generate ECDH p384 key")),
        };

        Ok(ECDHP384KeyExchange { private: ecdh_key })
    }

    pub fn public_key<'a>(&self, py: Python<'a>) -> PyResult<Bound<'a, PyBytes>> {
        let my_public_key = match self.private.compute_public_key() {
            Ok(key) => key,
            Err(_) => {
                return Err(CryptoError::new_err(
                    "Unable to compute ECDH p384 public key",
                ))
            }
        };

        Ok(PyBytes::new(py, my_public_key.as_ref()))
    }

    pub fn exchange<'a>(
        &self,
        py: Python<'a>,
        peer_public_key: Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let peer_public_key =
            agreement::UnparsedPublicKey::new(&agreement::ECDH_P384, peer_public_key.as_bytes());

        let key_material = match agreement::agree(
            &self.private,
            &peer_public_key,
            error::Unspecified,
            |_key_material| Ok(_key_material.to_vec()),
        ) {
            Ok(key) => key,
            Err(_) => return Err(CryptoError::new_err("ECDHP384 exchange failure")),
        };

        Ok(PyBytes::new(py, &key_material))
    }
}

#[pymethods]
impl ECDHP521KeyExchange {
    #[new]
    pub fn py_new() -> PyResult<Self> {
        let ecdh_pk = match agreement::PrivateKey::generate(&agreement::ECDH_P521) {
            Ok(key) => key,
            Err(_) => return Err(CryptoError::new_err("Unable to generate ECDH p521 key")),
        };

        Ok(ECDHP521KeyExchange { private: ecdh_pk })
    }

    pub fn public_key<'a>(&self, py: Python<'a>) -> PyResult<Bound<'a, PyBytes>> {
        let my_public_key = match self.private.compute_public_key() {
            Ok(key) => key,
            Err(_) => {
                return Err(CryptoError::new_err(
                    "Unable to compute ECDH p521 public key",
                ))
            }
        };

        Ok(PyBytes::new(py, my_public_key.as_ref()))
    }

    pub fn exchange<'a>(
        &self,
        py: Python<'a>,
        peer_public_key: Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let peer_public_key =
            agreement::UnparsedPublicKey::new(&agreement::ECDH_P521, peer_public_key.as_bytes());

        let key_material = match agreement::agree(
            &self.private,
            &peer_public_key,
            error::Unspecified,
            |_key_material| Ok(_key_material.to_vec()),
        ) {
            Ok(key) => key,
            Err(_) => return Err(CryptoError::new_err("ECDHP521 exchange failure")),
        };

        Ok(PyBytes::new(py, &key_material))
    }
}
