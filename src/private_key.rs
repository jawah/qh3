use aws_lc_rs::signature::{
    EcdsaKeyPair as InternalEcPrivateKey, Ed25519KeyPair as InternalEd25519PrivateKey, KeyPair,
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, ECDSA_P521_SHA512_ASN1_SIGNING,
};
use dsa::SigningKey as InternalDsaPrivateKey;
use rsa::{RsaPrivateKey as InternalRsaPrivateKey, RsaPublicKey as InternalRsaPublicKey};

use rsa::pkcs1v15::SigningKey as InternalRsaPkcsSigningKey;
use rsa::pss::SigningKey as InternalRsaPssSigningKey;

use rsa::sha2::{Sha256, Sha384, Sha512};
use rsa::signature::SignatureEncoding;
use rsa::signature::Signer;

use pkcs8::DecodePrivateKey;
use pkcs8::EncodePublicKey;

use aws_lc_rs::rand::SystemRandom;

use crate::verify::{verify_signature, PublicKeyAlgorithm};
use crate::CryptoError;
use pyo3::exceptions::PyException;
use pyo3::pyfunction;
use pyo3::pymethods;
use pyo3::types::PyBytes;
use pyo3::types::PyBytesMethods;
use pyo3::{pyclass, Bound};
use pyo3::{PyResult, Python};

pyo3::create_exception!(_hazmat, SignatureError, PyException);

#[pyclass(module = "qh3._hazmat")]
pub struct EcPrivateKey {
    inner: InternalEcPrivateKey,
    curve: u32,
}

#[pyclass(module = "qh3._hazmat")]
pub struct Ed25519PrivateKey {
    inner: InternalEd25519PrivateKey,
}

#[pyclass(module = "qh3._hazmat")]
pub struct DsaPrivateKey {
    inner: InternalDsaPrivateKey,
}

#[pyclass(module = "qh3._hazmat")]
pub struct RsaPrivateKey {
    inner: InternalRsaPrivateKey,
}

#[pymethods]
impl Ed25519PrivateKey {
    #[new]
    pub fn py_new(pkcs8: Bound<'_, PyBytes>) -> PyResult<Self> {
        let pk = match InternalEd25519PrivateKey::from_pkcs8(pkcs8.as_bytes()) {
            Ok(key) => key,
            Err(_) => return Err(CryptoError::new_err("Invalid Ed25519 PrivateKey")),
        };

        Ok(Ed25519PrivateKey { inner: pk })
    }

    pub fn sign<'a>(&self, py: Python<'a>, data: Bound<'_, PyBytes>) -> Bound<'a, PyBytes> {
        let signature = self.inner.sign(data.as_bytes());

        PyBytes::new(py, signature.as_ref())
    }

    pub fn public_key<'a>(&self, py: Python<'a>) -> Bound<'a, PyBytes> {
        PyBytes::new(py, self.inner.public_key().as_ref())
    }
}

#[pymethods]
impl EcPrivateKey {
    #[new]
    pub fn py_new(der_key: Bound<'_, PyBytes>, curve_type: u32, is_pkcs8: bool) -> PyResult<Self> {
        let signing_algorithm = match curve_type {
            256 => &ECDSA_P256_SHA256_ASN1_SIGNING,
            384 => &ECDSA_P384_SHA384_ASN1_SIGNING,
            521 => &ECDSA_P521_SHA512_ASN1_SIGNING,
            _ => {
                return Err(CryptoError::new_err(
                    "Unsupported curve type in EcPrivateKey",
                ))
            }
        };

        if is_pkcs8 {
            // PKCS8 DER
            let pk = match InternalEcPrivateKey::from_pkcs8(signing_algorithm, der_key.as_bytes()) {
                Ok(key) => key,
                Err(e) => return Err(CryptoError::new_err(format!("invalid ec key: {}", e))),
            };

            Ok(EcPrivateKey {
                inner: pk,
                curve: curve_type,
            })
        } else {
            // SEC1 DER
            let pk = match InternalEcPrivateKey::from_private_key_der(
                signing_algorithm,
                der_key.as_bytes(),
            ) {
                Ok(key) => key,
                Err(e) => return Err(CryptoError::new_err(format!("invalid sec1 key: {}", e))),
            };

            Ok(EcPrivateKey {
                inner: pk,
                curve: curve_type,
            })
        }
    }

    pub fn sign<'a>(
        &self,
        py: Python<'a>,
        data: Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let rng = SystemRandom::new();
        let signature = match self.inner.sign(&rng, data.as_bytes()) {
            Ok(signature) => signature,
            Err(_) => return Err(CryptoError::new_err("Ec signature could not be issued")),
        };

        Ok(PyBytes::new(py, signature.as_ref()))
    }

    pub fn public_key<'a>(&self, py: Python<'a>) -> Bound<'a, PyBytes> {
        PyBytes::new(py, self.inner.public_key().as_ref())
    }

    #[getter]
    pub fn curve_type(&self) -> u32 {
        self.curve
    }
}

#[pymethods]
impl DsaPrivateKey {
    #[new]
    pub fn py_new(pkcs8: Bound<'_, PyBytes>) -> PyResult<Self> {
        let pk = match InternalDsaPrivateKey::from_pkcs8_der(pkcs8.as_bytes()) {
            Ok(key) => key,
            Err(_) => return Err(CryptoError::new_err("Invalid Dsa PrivateKey")),
        };

        Ok(DsaPrivateKey { inner: pk })
    }

    pub fn sign<'a>(&self, py: Python<'a>, data: Bound<'_, PyBytes>) -> Bound<'a, PyBytes> {
        let signature = self.inner.sign(data.as_bytes());

        PyBytes::new(py, &signature.to_bytes())
    }

    pub fn public_key<'a>(&self, py: Python<'a>) -> Bound<'a, PyBytes> {
        PyBytes::new(
            py,
            self.inner
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
        )
    }
}

#[pymethods]
impl RsaPrivateKey {
    #[new]
    pub fn py_new(pkcs8: Bound<'_, PyBytes>) -> PyResult<Self> {
        let pk = match InternalRsaPrivateKey::from_pkcs8_der(pkcs8.as_bytes()) {
            Ok(key) => key,
            Err(_) => return Err(CryptoError::new_err("Invalid Rsa PrivateKey")),
        };

        Ok(RsaPrivateKey { inner: pk })
    }

    pub fn sign<'a>(
        &self,
        py: Python<'a>,
        data: Bound<'_, PyBytes>,
        is_pss_padding: bool,
        hash_size: u32,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let private_key = self.inner.clone();

        match is_pss_padding {
            true => match hash_size {
                256 => {
                    let signer = InternalRsaPssSigningKey::<Sha256>::new(private_key);
                    Ok(PyBytes::new(py, &signer.sign(data.as_bytes()).to_vec()))
                }
                384 => {
                    let signer = InternalRsaPssSigningKey::<Sha384>::new(private_key);
                    Ok(PyBytes::new(py, &signer.sign(data.as_bytes()).to_vec()))
                }
                512 => {
                    let signer = InternalRsaPssSigningKey::<Sha512>::new(private_key);
                    Ok(PyBytes::new(py, &signer.sign(data.as_bytes()).to_vec()))
                }
                _ => Err(CryptoError::new_err(
                    "unsupported hash size for RSA signing",
                )),
            },
            false => match hash_size {
                256 => {
                    let signer = InternalRsaPkcsSigningKey::<Sha256>::new(private_key);
                    Ok(PyBytes::new(py, &signer.sign(data.as_bytes()).to_vec()))
                }
                384 => {
                    let signer = InternalRsaPkcsSigningKey::<Sha384>::new(private_key);
                    Ok(PyBytes::new(py, &signer.sign(data.as_bytes()).to_vec()))
                }
                512 => {
                    let signer = InternalRsaPkcsSigningKey::<Sha512>::new(private_key);
                    Ok(PyBytes::new(py, &signer.sign(data.as_bytes()).to_vec()))
                }
                _ => Err(CryptoError::new_err(
                    "unsupported hash size for RSA signing",
                )),
            },
        }
    }

    pub fn public_key<'a>(&self, py: Python<'a>) -> Bound<'a, PyBytes> {
        let public_key: InternalRsaPublicKey = self.inner.to_public_key();

        PyBytes::new(
            py,
            &public_key.to_public_key_der().as_ref().unwrap().to_vec(),
        )
    }
}

#[pyfunction]
#[allow(unreachable_code)]
pub fn verify_with_public_key(
    public_key_raw: Bound<'_, PyBytes>,
    algorithm: u32,
    message: Bound<'_, PyBytes>,
    signature: Bound<'_, PyBytes>,
) -> PyResult<()> {
    let sig_algorithm = match algorithm {
        0x0804 | 0x0809 => PublicKeyAlgorithm::RsaPssSha256,
        0x0805 | 0x080A => PublicKeyAlgorithm::RsaPssSha384,
        0x0806 | 0x080B => PublicKeyAlgorithm::RsaPssSha512,
        0x0201 => PublicKeyAlgorithm::RsaPkcsSha1,
        0x0401 => PublicKeyAlgorithm::RsaPkcsSha256,
        0x0501 => PublicKeyAlgorithm::RsaPkcsSha384,
        0x0601 => PublicKeyAlgorithm::RsaPkcsSha512,
        0x0807 => PublicKeyAlgorithm::Ed25519,
        0x0403 => PublicKeyAlgorithm::EcdsaP256WithSha256,
        0x0503 => PublicKeyAlgorithm::EcdsaP384WithSha384,
        0x0603 => PublicKeyAlgorithm::EcdsaP521WithSha512,
        _ => {
            return Err(CryptoError::new_err(format!(
                "unsupported signature algorithm {}",
                algorithm
            )))
        }
    };

    verify_signature(
        public_key_raw.as_bytes(),
        sig_algorithm,
        message.as_bytes(),
        signature.as_bytes(),
    )
}
