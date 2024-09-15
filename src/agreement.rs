use aws_lc_rs::{agreement, error};

use aws_lc_rs::kem;
use aws_lc_rs::unstable::kem::{get_algorithm, AlgorithmId};

use rustls::crypto::{
    SharedSecret,
};

use pyo3::Python;
use pyo3::types::PyBytes;
use pyo3::pymethods;
use pyo3::pyclass;

const X25519_LEN: usize = 32;
const KYBER_CIPHERTEXT_LEN: usize = 1088;
const X25519_KYBER_COMBINED_PUBKEY_LEN: usize = X25519_LEN + 1184;
const X25519_KYBER_COMBINED_CIPHERTEXT_LEN: usize = X25519_LEN + KYBER_CIPHERTEXT_LEN;
const X25519_KYBER_COMBINED_SHARED_SECRET_LEN: usize = X25519_LEN + 32;

struct X25519Kyber768CombinedSecret([u8; X25519_KYBER_COMBINED_SHARED_SECRET_LEN]);

impl X25519Kyber768CombinedSecret {
    fn combine(x25519: SharedSecret, kyber: kem::SharedSecret) -> Self {
        let mut out = X25519Kyber768CombinedSecret([0u8; X25519_KYBER_COMBINED_SHARED_SECRET_LEN]);
        out.0[..X25519_LEN].copy_from_slice(x25519.secret_bytes());
        out.0[X25519_LEN..].copy_from_slice(kyber.as_ref());
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
pub struct X25519Kyber768Draft00KeyExchange {
    x25519_private: agreement::PrivateKey,
    kyber768_decapsulation_key: kem::DecapsulationKey<AlgorithmId>,
}

#[pymethods]
impl X25519Kyber768Draft00KeyExchange {
    #[new]
    pub fn py_new() -> Self {
        X25519Kyber768Draft00KeyExchange {
            x25519_private: agreement::PrivateKey::generate(&agreement::X25519).expect("FAILURE"),
            kyber768_decapsulation_key: kem::DecapsulationKey::generate(get_algorithm(AlgorithmId::Kyber768_R3).expect("Kyber768_R3 not available")).expect("FAILURE")
        }
    }

    pub fn public_key<'a>(&self, py: Python<'a>) -> &'a PyBytes {
        let kyber_pub = self.kyber768_decapsulation_key
            .encapsulation_key()
            .expect("FAILURE");

        let mut combined_pub_key = Vec::with_capacity(X25519_KYBER_COMBINED_PUBKEY_LEN);

        combined_pub_key.extend_from_slice(self.x25519_private.compute_public_key().unwrap().as_ref());
        combined_pub_key.extend_from_slice(kyber_pub.key_bytes().unwrap().as_ref());

        return PyBytes::new(
            py,
            &combined_pub_key.as_ref()
        );
    }

    pub fn exchange<'a>(&self, py: Python<'a>, peer_public_key: &PyBytes) -> &'a PyBytes {
        let cipher_text = peer_public_key.as_bytes();

        if cipher_text.len() != X25519_KYBER_COMBINED_CIPHERTEXT_LEN {
            return PyBytes::new(py, &[]);
        }

        let (x25519, kyber) = cipher_text.split_at(X25519_LEN);

        let x25519_peer_public_key = agreement::UnparsedPublicKey::new(&agreement::X25519, x25519);

        let x25519_secret = agreement::agree(
            &self.x25519_private,
            &x25519_peer_public_key,
            error::Unspecified,
            |_key_material| {
                return Ok(_key_material.to_vec())
            },
        ).expect("FAILURE");

        let kyber_secret = self.kyber768_decapsulation_key
            .decapsulate(kyber.into())
            .expect("FAILURE");

        let combined_secret = X25519Kyber768CombinedSecret::combine(
            SharedSecret::from(&x25519_secret[..]),
            kyber_secret,
        );

        let key_material = SharedSecret::from(&combined_secret.0[..]);

        return PyBytes::new(
            py,
            &key_material.secret_bytes()
        );
    }
}


#[pymethods]
impl X25519KeyExchange {
    #[new]
    pub fn py_new() -> Self {
        X25519KeyExchange {
            private: agreement::PrivateKey::generate(&agreement::X25519).expect("FAILURE"),
        }
    }

    pub fn public_key<'a>(&self, py: Python<'a>) -> &'a PyBytes {
        let my_public_key = self.private.compute_public_key().unwrap();

        return PyBytes::new(
            py,
            &my_public_key.as_ref()
        );
    }

    pub fn exchange<'a>(&self, py: Python<'a>, peer_public_key: &PyBytes) -> &'a PyBytes {
        let peer_public_key = agreement::UnparsedPublicKey::new(&agreement::X25519, peer_public_key.as_bytes());

        let key_material = agreement::agree(
            &self.private,
            &peer_public_key,
            error::Unspecified,
            |_key_material| {
                return Ok(_key_material.to_vec())
            },
        ).expect("FAILURE");

        return PyBytes::new(
            py,
            &key_material
        );
    }
}


#[pymethods]
impl ECDHP256KeyExchange {
    #[new]
    pub fn py_new() -> Self {
        ECDHP256KeyExchange {
            private: agreement::PrivateKey::generate(&agreement::ECDH_P256).expect("FAILURE")
        }
    }

    pub fn public_key<'a>(&self, py: Python<'a>) -> &'a PyBytes {
        let my_public_key = self.private.compute_public_key().unwrap();

        return PyBytes::new(
            py,
            &my_public_key.as_ref()
        );
    }

    pub fn exchange<'a>(&self, py: Python<'a>, peer_public_key: &PyBytes) -> &'a PyBytes {
        let peer_public_key = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, peer_public_key.as_bytes());

        let key_material = agreement::agree(
            &self.private,
            &peer_public_key,
            error::Unspecified,
            |_key_material| {
                return Ok(_key_material.to_vec());
            },
        ).expect("FAILURE");

        return PyBytes::new(
            py,
            &key_material
        );
    }
}


#[pymethods]
impl ECDHP384KeyExchange {
    #[new]
    pub fn py_new() -> Self {
        ECDHP384KeyExchange {
            private: agreement::PrivateKey::generate(&agreement::ECDH_P384).expect("FAILURE")
        }
    }

    pub fn public_key<'a>(&self, py: Python<'a>) -> &'a PyBytes {
        let my_public_key = self.private.compute_public_key().unwrap();

        return PyBytes::new(
            py,
            &my_public_key.as_ref()
        );
    }

    pub fn exchange<'a>(&self, py: Python<'a>, peer_public_key: &PyBytes) -> &'a PyBytes {
        let peer_public_key = agreement::UnparsedPublicKey::new(&agreement::ECDH_P384, peer_public_key.as_bytes());

        let key_material = agreement::agree(
            &self.private,
            &peer_public_key,
            error::Unspecified,
            |_key_material| {
                return Ok(_key_material.to_vec());
            },
        ).expect("FAILURE");

        return PyBytes::new(
            py,
            &key_material
        );
    }
}


#[pymethods]
impl ECDHP521KeyExchange {
    #[new]
    pub fn py_new() -> Self {
        ECDHP521KeyExchange {
            private: agreement::PrivateKey::generate(&agreement::ECDH_P521).expect("FAILURE")
        }
    }

    pub fn public_key<'a>(&self, py: Python<'a>) -> &'a PyBytes {
        let my_public_key = self.private.compute_public_key().unwrap();

        return PyBytes::new(
            py,
            &my_public_key.as_ref()
        );
    }

    pub fn exchange<'a>(&self, py: Python<'a>, peer_public_key: &PyBytes) -> &'a PyBytes {
        let peer_public_key = agreement::UnparsedPublicKey::new(&agreement::ECDH_P521, peer_public_key.as_bytes());

        let key_material = agreement::agree(
            &self.private,
            &peer_public_key,
            error::Unspecified,
            |_key_material| {
                return Ok(_key_material.to_vec());
            },
        ).expect("FAILURE");

        return PyBytes::new(
            py,
            &key_material
        );
    }
}

