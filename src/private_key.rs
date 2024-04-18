use rsa::{RsaPrivateKey as InternalRsaPrivateKey, RsaPublicKey as InternalRsaPublicKey};
use dsa::{SigningKey as InternalDsaPrivateKey};
use aws_lc_rs::signature::{
    EcdsaKeyPair as InternalEcPrivateKey,
    KeyPair,
    ECDSA_P256_SHA256_ASN1_SIGNING,
    ECDSA_P384_SHA384_ASN1_SIGNING,
    ECDSA_P521_SHA512_ASN1_SIGNING,
    Ed25519KeyPair as InternalEd25519PrivateKey,
};

use rsa::pkcs1v15::{SigningKey as InternalRsaPkcsSigningKey, Signature as RsaPkcsSignature};
use rsa::pss::{Signature as RsaPssSignature, SigningKey as InternalRsaPssSigningKey};

use rsa::sha2::{Sha256, Sha512, Sha384};
use rsa::signature::Signer;
use rsa::signature::SignatureEncoding;
use rsa::pss::{VerifyingKey as RsaPssVerifyingKey};
use rsa::pkcs1v15::{VerifyingKey as RsaPkcsVerifyingKey};
use rsa::signature::Verifier;

use ed25519_dalek::{VerifyingKey as Ed25519VerifyingKey, Signature as Ed25519Signature};

use pkcs8::DecodePrivateKey;
use pkcs8::EncodePublicKey;
use pkcs8::DecodePublicKey;

use aws_lc_rs::signature::{UnparsedPublicKey};
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::signature;
use aws_lc_rs::rand::SystemRandom;

use pyo3::{PyResult, Python};
use pyo3::types::PyBytes;
use pyo3::pymethods;
use pyo3::pyfunction;
use pyo3::pyclass;
use pyo3::exceptions::PyException;

pyo3::create_exception!(_hazmat, SignatureError, PyException);


#[pyclass(module = "qh3._hazmat")]
pub struct EcPrivateKey {
    inner: InternalEcPrivateKey,
    curve: u32
}

#[pyclass(module = "qh3._hazmat")]
pub struct Ed25519PrivateKey {
    inner: InternalEd25519PrivateKey
}

#[pyclass(module = "qh3._hazmat")]
pub struct DsaPrivateKey {
    inner: InternalDsaPrivateKey
}

#[pyclass(module = "qh3._hazmat")]
pub struct RsaPrivateKey {
    inner: InternalRsaPrivateKey
}

#[pymethods]
impl Ed25519PrivateKey {
    #[new]
    pub fn py_new(pkcs8: &PyBytes) -> Self {
        Ed25519PrivateKey {
            inner: InternalEd25519PrivateKey::from_pkcs8(&pkcs8.as_bytes()).expect("FAILURE")
        }
    }

    pub fn sign<'a>(&self, py: Python<'a>, data: &PyBytes) -> &'a PyBytes {
        let signature = self.inner.sign(&data.as_bytes());

        return PyBytes::new(
            py,
            &signature.as_ref()
        );
    }

    pub fn public_key<'a>(&self, py: Python<'a>) -> &'a PyBytes {
        return PyBytes::new(
            py,
            &self.inner.public_key().as_ref()
        );
    }
}


#[pymethods]
impl EcPrivateKey {
    #[new]
    pub fn py_new(pkcs8: &PyBytes, curve_type: u32) -> Self {
        let signing_algorithm = match curve_type {
            256 => &ECDSA_P256_SHA256_ASN1_SIGNING,
            384 => &ECDSA_P384_SHA384_ASN1_SIGNING,
            521 => &ECDSA_P521_SHA512_ASN1_SIGNING,
            _ => panic!("unsupported"),
        };

        return EcPrivateKey {
            inner: InternalEcPrivateKey::from_pkcs8(&signing_algorithm, &pkcs8.as_bytes()).expect("FAILURE"),
            curve: curve_type
        }
    }

    pub fn sign<'a>(&self, py: Python<'a>, data: &PyBytes) -> &'a PyBytes {
        let rng = SystemRandom::new();
        let signature = self.inner.sign(&rng, &data.as_bytes());

        return PyBytes::new(
            py,
            &signature.unwrap().as_ref()
        );
    }

    pub fn public_key<'a>(&self, py: Python<'a>) -> &'a PyBytes {
        return PyBytes::new(
            py,
            &self.inner.public_key().as_ref()
        );
    }

    #[getter]
    pub fn curve_type(&self) -> u32 {
        return self.curve;
    }
}


#[pymethods]
impl DsaPrivateKey {
    #[new]
    pub fn py_new(pkcs8: &PyBytes) -> Self {
        return DsaPrivateKey {
            inner: InternalDsaPrivateKey::from_pkcs8_der(&pkcs8.as_bytes()).expect("FAILURE")
        }
    }

    pub fn sign<'a>(&self, py: Python<'a>, data: &PyBytes) -> &'a PyBytes {
        let signature = self.inner.sign(&data.as_bytes());

        return PyBytes::new(
            py,
            &signature.to_bytes()
        );
    }

    pub fn public_key<'a>(&self, py: Python<'a>) -> &'a PyBytes {
        return PyBytes::new(
            py,
            &self.inner.verifying_key().to_public_key_der().expect("FAILURE").as_bytes()
        );
    }
}


#[pymethods]
impl RsaPrivateKey {
    #[new]
    pub fn py_new(pkcs8: &PyBytes) -> Self {
        return RsaPrivateKey {
            inner: InternalRsaPrivateKey::from_pkcs8_der(&pkcs8.as_bytes()).expect("FAILURE")
        }
    }

    pub fn sign<'a>(&self, py: Python<'a>, data: &PyBytes, is_pss_padding: bool, hash_size: u32) -> &'a PyBytes {

        let private_key = self.inner.clone();

        match is_pss_padding {
            true => match hash_size {
                256 => {
                    let signer = InternalRsaPssSigningKey::<Sha256>::new(private_key);
                    return PyBytes::new(
                        py,
                        &signer.sign(&data.as_bytes()).to_vec()
                    );
                },
                384 => {
                    let signer = InternalRsaPssSigningKey::<Sha384>::new(private_key);
                    return PyBytes::new(
                        py,
                        &signer.sign(&data.as_bytes()).to_vec()
                    );
                },
                512 => {
                    let signer = InternalRsaPssSigningKey::<Sha512>::new(private_key);
                    return PyBytes::new(
                        py,
                        &signer.sign(&data.as_bytes()).to_vec()
                    );
                },
                _ => panic!("unsupported")
            },
            false => match hash_size {
                256 => {
                    let signer = InternalRsaPkcsSigningKey::<Sha256>::new(private_key);
                    return PyBytes::new(
                        py,
                        &signer.sign(&data.as_bytes()).to_vec()
                    );
                },
                384 => {
                    let signer = InternalRsaPkcsSigningKey::<Sha384>::new(private_key);
                    return PyBytes::new(
                        py,
                        &signer.sign(&data.as_bytes()).to_vec()
                    );
                },
                512 => {
                    let signer = InternalRsaPkcsSigningKey::<Sha512>::new(private_key);
                    return PyBytes::new(
                        py,
                        &signer.sign(&data.as_bytes()).to_vec()
                    );
                },
                _ => panic!("unsupported")
            }
        };
    }

    pub fn public_key<'a>(&self, py: Python<'a>) -> &'a PyBytes {
        let public_key: InternalRsaPublicKey = self.inner.to_public_key();

        return PyBytes::new(
            py,
            &public_key.to_public_key_der().as_ref().unwrap().to_vec()
        )
    }
}


#[pyfunction]
#[allow(unreachable_code)]
pub fn verify_with_public_key(public_key_raw: &PyBytes, algorithm: u32, message: &PyBytes, signature: &PyBytes) -> PyResult<()> {

    let pss_rsae_blind_signature = 0x0804..0x0806;
    let pss_pss_blind_signature = 0x0809..0x080B;
    let pkcs115_blind_signature = [0x0401, 0x0501, 0x0601];

    let public_key_bytes = public_key_raw.as_bytes();

    // Can't get RSA signature to work using UnparsedPublicKey, I could have missed something...?
    if pss_rsae_blind_signature.contains(&algorithm) || pss_pss_blind_signature.contains(&algorithm) || pkcs115_blind_signature.contains(&algorithm) {
        let rsa_parsed_public_key = InternalRsaPublicKey::from_public_key_der(&public_key_bytes).expect("FAILURE");

        return match algorithm {
            0x0804 | 0x0809 => {
                let alt_verifier = RsaPssVerifyingKey::<Sha256>::new(rsa_parsed_public_key);

                let res = alt_verifier.verify(&message.as_bytes(), &RsaPssSignature::try_from(signature.as_bytes()).expect("FAILURE"));

                return match res {
                    Err(_) => Err(SignatureError::new_err("signature mismatch (rsa)")),
                    _ => Ok(())
                }
            },
            0x0805 | 0x080A => {
                let alt_verifier = RsaPssVerifyingKey::<Sha384>::new(rsa_parsed_public_key);

                let res = alt_verifier.verify(&message.as_bytes(), &RsaPssSignature::try_from(signature.as_bytes()).expect("FAILURE"));

                return match res {
                    Err(_) => Err(SignatureError::new_err("signature mismatch (rsa)")),
                    _ => Ok(())
                }
            },
            0x0806 | 0x080B => {
                let alt_verifier = RsaPssVerifyingKey::<Sha512>::new(rsa_parsed_public_key);

                let res = alt_verifier.verify(&message.as_bytes(), &RsaPssSignature::try_from(signature.as_bytes()).expect("FAILURE"));

                return match res {
                    Err(_) => Err(SignatureError::new_err("signature mismatch (rsa)")),
                    _ => Ok(())
                }
            },

            0x0401 => {
                let alt_verifier = RsaPkcsVerifyingKey::<Sha256>::new(rsa_parsed_public_key);

                let res = alt_verifier.verify(&message.as_bytes(), &RsaPkcsSignature::try_from(signature.as_bytes()).expect("FAILURE"));

                return match res {
                    Err(_) => Err(SignatureError::new_err("signature mismatch (rsa)")),
                    _ => Ok(())
                }
            },
            0x0501 => {
                let alt_verifier = RsaPkcsVerifyingKey::<Sha384>::new(rsa_parsed_public_key);

                let res = alt_verifier.verify(&message.as_bytes(), &RsaPkcsSignature::try_from(signature.as_bytes()).expect("FAILURE"));

                return match res {
                    Err(_) => Err(SignatureError::new_err("signature mismatch (rsa)")),
                    _ => Ok(())
                }
            },
            0x0601 => {
                let alt_verifier = RsaPkcsVerifyingKey::<Sha512>::new(rsa_parsed_public_key);

                let res = alt_verifier.verify(&message.as_bytes(), &RsaPkcsSignature::try_from(signature.as_bytes()).expect("FAILURE"));

                return match res {
                    Err(_) => Err(SignatureError::new_err("signature mismatch (rsa)")),
                    _ => Ok(())
                }
            },

            _ => panic!("unreachable statement")
        };
    }

    if algorithm == 0x0807 {
        let ed25519_verifier: Ed25519VerifyingKey = Ed25519VerifyingKey::from_public_key_der(&public_key_bytes).expect("FAILURE");
        let res = ed25519_verifier.verify(&message.as_bytes(), &Ed25519Signature::from_bytes(signature.as_bytes()[0..64].try_into().unwrap()));

        return match res {
            Err(_) => Err(SignatureError::new_err("signature mismatch (ed25519)")),
            _ => Ok(())
        };
    }

    let public_key = UnparsedPublicKey::new(
        match algorithm {
            0x0403 => &signature::ECDSA_P256_SHA256_ASN1,
            0x0503 => &signature::ECDSA_P384_SHA384_ASN1,
            0x0603 => &signature::ECDSA_P521_SHA512_ASN1,
            _ => panic!("unsupported algorithm")
        },
        public_key_bytes
    );

    let res = public_key.verify(&message.as_bytes(), &signature.as_bytes());

    return match res {
        Err(Unspecified) => Err(SignatureError::new_err("signature mismatch (ecdsa)")),
        _ => Ok(())
    }
}
