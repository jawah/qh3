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

const RSA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const DSA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10040.4.1");
const SECP_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

#[pyclass(module = "qh3._hazmat", eq, eq_int)]
#[derive(Clone, Copy, PartialEq)]
#[allow(non_camel_case_types)]
pub enum KeyType {
    ECDSA_P256, // R1 -- prime
    ECDSA_P384, // R1 -- prime
    ECDSA_P521, // R1 -- prime
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
        let der_document = pkcs8.to_der()?;

        match pkcs8.algorithm.oid {
            RSA_OID => Ok(PrivateKeyInfo {
                der_encoded: der_document.clone(),
                cert_type: KeyType::RSA,
            }),
            DSA_OID => Ok(PrivateKeyInfo {
                der_encoded: der_document.clone(),
                cert_type: KeyType::DSA,
            }),
            SECP_KEY => {
                let params_any = pkcs8
                    .algorithm
                    .parameters
                    .ok_or(Error::KeyMalformed)?
                    .decode_as::<ObjectIdentifier>()
                    .map_err(|_| Error::KeyMalformed)?;

                // either compare to hard-coded OID strings:
                let cert_type = match params_any.to_string().as_str() {
                    // prime256v1 / secp256r1
                    "1.2.840.10045.3.1.7" => KeyType::ECDSA_P256,
                    // secp384r1
                    "1.3.132.0.34" => KeyType::ECDSA_P384,
                    // secp521r1
                    "1.3.132.0.35" => KeyType::ECDSA_P521,
                    _ => return Err(Error::ParametersMalformed),
                };

                Ok(PrivateKeyInfo {
                    der_encoded: der_document.clone(),
                    cert_type,
                })
            }
            ED25519_OID => Ok(PrivateKeyInfo {
                der_encoded: der_document.clone(),
                cert_type: KeyType::ED25519,
            }),
            _ => Err(Error::KeyMalformed),
        }
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

        if item.is_err() {
            return Err(CryptoError::new_err("Given PEM key is malformed"));
        }

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

                let decoded = PrivateKeyInfo::from_pkcs8_pem(decoded_bytes);

                if decoded.is_err() {
                    return Err(CryptoError::new_err(
                        "Given PEM key is unsupported. e.g. SECP256K1 are unsupported.",
                    ));
                }

                Ok(decoded.unwrap())
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
