use aws_lc_rs::signature::{
    EcdsaKeyPair as InternalEcPrivateKey, Ed25519KeyPair as InternalEd25519PrivateKey, KeyPair,
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, ECDSA_P521_SHA512_ASN1_SIGNING,
};
use dsa::SigningKey as InternalDsaPrivateKey;
use rsa::{RsaPrivateKey as InternalRsaPrivateKey, RsaPublicKey as InternalRsaPublicKey};

use rsa::pkcs1v15::{Signature as RsaPkcsSignature, SigningKey as InternalRsaPkcsSigningKey};
use rsa::pss::{Signature as RsaPssSignature, SigningKey as InternalRsaPssSigningKey};

use rsa::pkcs1v15::VerifyingKey as RsaPkcsVerifyingKey;
use rsa::pss::VerifyingKey as RsaPssVerifyingKey;
use rsa::sha2::{Sha256, Sha384, Sha512};
use rsa::signature::SignatureEncoding;
use rsa::signature::Signer;
use rsa::signature::Verifier;

use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};

use pkcs8::DecodePrivateKey;
use pkcs8::DecodePublicKey;
use pkcs8::EncodePublicKey;

use aws_lc_rs::error::Unspecified;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature;
use aws_lc_rs::signature::UnparsedPublicKey;

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
    pub fn py_new(pkcs8: Bound<'_, PyBytes>, curve_type: u32) -> PyResult<Self> {
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

        let pk = match InternalEcPrivateKey::from_pkcs8(signing_algorithm, pkcs8.as_bytes()) {
            Ok(key) => key,
            Err(_) => return Err(CryptoError::new_err("Invalid Ec PrivateKey")),
        };

        Ok(EcPrivateKey {
            inner: pk,
            curve: curve_type,
        })
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
    let pss_rsae_blind_signature = 0x0804..0x0806;
    let pss_pss_blind_signature = 0x0809..0x080B;
    let pkcs115_blind_signature = [0x0401, 0x0501, 0x0601];

    let public_key_bytes = public_key_raw.as_bytes();

    // Can't get RSA signature to work using UnparsedPublicKey, I could have missed something...?
    if pss_rsae_blind_signature.contains(&algorithm)
        || pss_pss_blind_signature.contains(&algorithm)
        || pkcs115_blind_signature.contains(&algorithm)
    {
        let rsa_parsed_public_key =
            match InternalRsaPublicKey::from_public_key_der(public_key_bytes) {
                Ok(public_key) => public_key,
                Err(_) => return Err(CryptoError::new_err("Invalid RSA public key")),
            };

        return match algorithm {
            0x0804 | 0x0809 => {
                let alt_verifier = RsaPssVerifyingKey::<Sha256>::new(rsa_parsed_public_key);

                let res = alt_verifier.verify(
                    message.as_bytes(),
                    match &RsaPssSignature::try_from(signature.as_bytes()) {
                        Ok(signature) => signature,
                        Err(_) => return Err(CryptoError::new_err("Invalid RSA PSS signature")),
                    },
                );

                return match res {
                    Err(_) => Err(SignatureError::new_err("signature mismatch (rsa)")),
                    _ => Ok(()),
                };
            }
            0x0805 | 0x080A => {
                let alt_verifier = RsaPssVerifyingKey::<Sha384>::new(rsa_parsed_public_key);

                let res = alt_verifier.verify(
                    message.as_bytes(),
                    match &RsaPssSignature::try_from(signature.as_bytes()) {
                        Ok(signature) => signature,
                        Err(_) => return Err(CryptoError::new_err("Invalid RSA PSS signature")),
                    },
                );

                return match res {
                    Err(_) => Err(SignatureError::new_err("signature mismatch (rsa)")),
                    _ => Ok(()),
                };
            }
            0x0806 | 0x080B => {
                let alt_verifier = RsaPssVerifyingKey::<Sha512>::new(rsa_parsed_public_key);

                let res = alt_verifier.verify(
                    message.as_bytes(),
                    match &RsaPssSignature::try_from(signature.as_bytes()) {
                        Ok(signature) => signature,
                        Err(_) => return Err(CryptoError::new_err("Invalid RSA PSS signature")),
                    },
                );

                return match res {
                    Err(_) => Err(SignatureError::new_err("signature mismatch (rsa)")),
                    _ => Ok(()),
                };
            }

            0x0401 => {
                let alt_verifier = RsaPkcsVerifyingKey::<Sha256>::new(rsa_parsed_public_key);

                let res = alt_verifier.verify(
                    message.as_bytes(),
                    match &RsaPkcsSignature::try_from(signature.as_bytes()) {
                        Ok(signature) => signature,
                        Err(_) => return Err(CryptoError::new_err("Invalid RSA PKCS signature")),
                    },
                );

                return match res {
                    Err(_) => Err(SignatureError::new_err("signature mismatch (rsa)")),
                    _ => Ok(()),
                };
            }
            0x0501 => {
                let alt_verifier = RsaPkcsVerifyingKey::<Sha384>::new(rsa_parsed_public_key);

                let res = alt_verifier.verify(
                    message.as_bytes(),
                    match &RsaPkcsSignature::try_from(signature.as_bytes()) {
                        Ok(signature) => signature,
                        Err(_) => return Err(CryptoError::new_err("Invalid RSA PKCS signature")),
                    },
                );

                return match res {
                    Err(_) => Err(SignatureError::new_err("signature mismatch (rsa)")),
                    _ => Ok(()),
                };
            }
            0x0601 => {
                let alt_verifier = RsaPkcsVerifyingKey::<Sha512>::new(rsa_parsed_public_key);

                let res = alt_verifier.verify(
                    message.as_bytes(),
                    match &RsaPkcsSignature::try_from(signature.as_bytes()) {
                        Ok(signature) => signature,
                        Err(_) => return Err(CryptoError::new_err("Invalid RSA PKCS signature")),
                    },
                );

                return match res {
                    Err(_) => Err(SignatureError::new_err("signature mismatch (rsa)")),
                    _ => Ok(()),
                };
            }

            _ => Err(CryptoError::new_err("unsupported signature algorithm")),
        };
    }

    if algorithm == 0x0807 {
        let ed25519_verifier: Ed25519VerifyingKey =
            match Ed25519VerifyingKey::from_public_key_der(public_key_bytes) {
                Ok(public_key) => public_key,
                Err(_) => return Err(CryptoError::new_err("Invalid Ed25519 public key")),
            };

        let res = ed25519_verifier.verify(
            message.as_bytes(),
            &Ed25519Signature::from_bytes(signature.as_bytes()[0..64].try_into()?),
        );

        return match res {
            Err(_) => Err(SignatureError::new_err("signature mismatch (ed25519)")),
            _ => Ok(()),
        };
    }

    let public_key = UnparsedPublicKey::new(
        match algorithm {
            0x0403 => &signature::ECDSA_P256_SHA256_ASN1,
            0x0503 => &signature::ECDSA_P384_SHA384_ASN1,
            0x0603 => &signature::ECDSA_P521_SHA512_ASN1,
            _ => return Err(CryptoError::new_err("unsupported signature algorithm")),
        },
        public_key_bytes,
    );

    let res = public_key.verify(message.as_bytes(), signature.as_bytes());

    match res {
        Err(Unspecified) => Err(SignatureError::new_err("signature mismatch (ecdsa)")),
        _ => Ok(()),
    }
}
