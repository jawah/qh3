use pyo3::types::PyBytes;
use pyo3::types::PyBytesMethods;
use pyo3::Python;
use pyo3::{pyclass, PyResult};
use pyo3::{pymethods, Bound};

use pkcs8::{der::Encode, DecodePrivateKey, Error, PrivateKeyInfo as InternalPrivateKeyInfo};
use rsa::{
    pkcs1::DecodeRsaPrivateKey,
    pkcs8::{EncodePrivateKey, LineEnding, ObjectIdentifier},
    RsaPrivateKey,
};

use crate::CryptoError;
use rustls_pemfile::{read_one_from_slice, Item};

#[pyclass(module = "qh3._hazmat", eq, eq_int)]
#[derive(Clone, Copy, PartialEq)]
#[allow(non_camel_case_types)]
pub enum KeyType {
    ECDSA_P256,
    ECDSA_P384,
    ECDSA_P521,
    ED25519,
    DSA,
    RSA,
}

#[pyclass(module = "qh3._hazmat")]
pub struct PrivateKeyInfo {
    cert_type: KeyType,
    der_encoded: Vec<u8>,
}

impl TryFrom<InternalPrivateKeyInfo<'_>> for PrivateKeyInfo {
    type Error = Error;

    fn try_from(pkcs8: InternalPrivateKeyInfo<'_>) -> Result<PrivateKeyInfo, Error> {
        let der_document = pkcs8.to_der().unwrap();

        let rsa_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1")
            .as_bytes()
            .to_vec();
        let dsa_oid = ObjectIdentifier::new_unwrap("1.2.840.10040.4.1")
            .as_bytes()
            .to_vec();

        if rsa_oid == pkcs8.algorithm.oid.as_bytes().to_vec() {
            return Ok(PrivateKeyInfo {
                der_encoded: der_document.clone(),
                cert_type: KeyType::RSA,
            });
        }

        if dsa_oid == pkcs8.algorithm.oid.as_bytes().to_vec() {
            return Ok(PrivateKeyInfo {
                der_encoded: der_document.clone(),
                cert_type: KeyType::DSA,
            });
        }

        Ok(PrivateKeyInfo {
            der_encoded: der_document.clone(),
            cert_type: KeyType::ED25519,
        })
    }
}

#[pymethods]
impl PrivateKeyInfo {
    #[new]
    #[pyo3(signature = (raw_pem_content, password=None))]
    pub fn py_new(
        raw_pem_content: Bound<'_, PyBytes>,
        password: Option<Bound<'_, PyBytes>>,
    ) -> PyResult<Self> {
        let pem_content = raw_pem_content.as_bytes();
        let decoded_bytes = std::str::from_utf8(pem_content)?;

        let is_encrypted = decoded_bytes.contains("ENCRYPTED");
        let item = read_one_from_slice(pem_content);

        match item.unwrap().unwrap().0 {
            Item::Pkcs1Key(key) => {
                if is_encrypted {
                    return Err(CryptoError::new_err(
                        "RSA Pkcs1Key is encrypted, please decrypt it prior to passing it.",
                    ));
                }

                let rsa_key: RsaPrivateKey =
                    match RsaPrivateKey::from_pkcs1_der(key.secret_pkcs1_der()) {
                        Ok(rsa_key) => rsa_key,
                        Err(_) => return Err(CryptoError::new_err("RSA private key is invalid.")),
                    };

                let pkcs8_pem = match rsa_key.to_pkcs8_pem(LineEnding::LF) {
                    Ok(pem) => pem,
                    Err(_) => {
                        return Err(CryptoError::new_err("malformed/invalid RSA private key?"))
                    }
                };

                let pkcs8_pem: &str = pkcs8_pem.as_ref();

                Ok(PrivateKeyInfo::from_pkcs8_pem(pkcs8_pem).unwrap())
            }
            Item::Pkcs8Key(_key) => {
                if is_encrypted {
                    return match PrivateKeyInfo::from_pkcs8_encrypted_pem(
                        decoded_bytes,
                        password.unwrap().as_bytes(),
                    ) {
                        Ok(key) => Ok(key),
                        Err(_) => Err(CryptoError::new_err(
                            "unable to decrypt Pkcs8 private key. invalid password?",
                        )),
                    };
                }

                Ok(PrivateKeyInfo::from_pkcs8_pem(decoded_bytes).unwrap())
            }
            Item::Sec1Key(key) => {
                if is_encrypted {
                    return Err(CryptoError::new_err(
                        "Sec1key encrypted is encrypted, please decrypt it prior to passing it.",
                    ));
                }

                let sec1_der = key.secret_sec1_der().to_vec();

                Ok(PrivateKeyInfo {
                    cert_type: match sec1_der.len() {
                        32..=121 => KeyType::ECDSA_P256,
                        132..=167 => KeyType::ECDSA_P384,
                        200..=400 => KeyType::ECDSA_P521,
                        _ => return Err(CryptoError::new_err("unsupported sec1key")),
                    },
                    der_encoded: sec1_der,
                })
            }
            _ => Err(CryptoError::new_err("unsupported key type")),
        }
    }

    pub fn get_type(&self) -> KeyType {
        self.cert_type
    }

    pub fn public_bytes<'a>(&self, py: Python<'a>) -> Bound<'a, PyBytes> {
        PyBytes::new(py, &self.der_encoded)
    }
}
