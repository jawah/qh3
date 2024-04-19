use aws_lc_rs::{agreement, error};

use pyo3::Python;
use pyo3::types::PyBytes;
use pyo3::pymethods;
use pyo3::pyclass;


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

