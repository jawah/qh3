use pyo3::Python;
use pyo3::types::PyBytes;
use pyo3::pymethods;
use pyo3::pyclass;

use pkcs8::{der::Encode, DecodePrivateKey, Error, PrivateKeyInfo as InternalPrivateKeyInfo};
use rsa::{
    pkcs1::DecodeRsaPrivateKey,
    pkcs8::{LineEnding, EncodePrivateKey, ObjectIdentifier},
    RsaPrivateKey,
};

use rustls_pemfile::{Item, read_one_from_slice};


#[pyclass(module = "qh3._hazmat")]
#[derive(Clone, Copy)]
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

        let rsa_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1").as_bytes().to_vec();
        let dsa_oid = ObjectIdentifier::new_unwrap("1.2.840.10040.4.1").as_bytes().to_vec();

        if rsa_oid == pkcs8.algorithm.oid.as_bytes().to_vec() {
            return Ok(
                PrivateKeyInfo{
                    der_encoded: der_document.clone(),
                    cert_type: KeyType::RSA
                }
            );
        }

        if dsa_oid == pkcs8.algorithm.oid.as_bytes().to_vec() {
            return Ok(
                PrivateKeyInfo{
                    der_encoded: der_document.clone(),
                    cert_type: KeyType::DSA
                }
            );
        }

        return Ok(
            PrivateKeyInfo{
                der_encoded: der_document.clone(),
                cert_type: KeyType::ED25519
            }
        );
    }
}

#[pymethods]
impl PrivateKeyInfo {
    #[new]
    pub fn py_new(raw_pem_content: &PyBytes, password: Option<&PyBytes>) -> Self {
        let pem_content = raw_pem_content.as_bytes();
        let decoded_bytes = std::str::from_utf8(pem_content).unwrap();

        let is_encrypted = decoded_bytes.contains("ENCRYPTED");
        let item = read_one_from_slice(&pem_content);

        match item.unwrap().unwrap().0 {
            Item::Pkcs1Key(key) => {
                if is_encrypted {
                    panic!("unsupported");
                }

                let rsa_key: RsaPrivateKey = RsaPrivateKey::from_pkcs1_der(&key.secret_pkcs1_der()).unwrap();

                let pkcs8_pem = rsa_key
                    .to_pkcs8_pem(LineEnding::LF).expect("FAILURE");

                let pkcs8_pem: &str = pkcs8_pem.as_ref();

                return PrivateKeyInfo::from_pkcs8_pem(&pkcs8_pem).unwrap();
            },
            Item::Pkcs8Key(_key) => {
                if is_encrypted {
                    return PrivateKeyInfo::from_pkcs8_encrypted_pem(&decoded_bytes, password.unwrap().as_bytes()).unwrap();
                }

                return PrivateKeyInfo::from_pkcs8_pem(&decoded_bytes).unwrap();
            },
            Item::Sec1Key(key) => {
                if is_encrypted {
                    panic!("unsupported");
                }

                let sec1_der = key.secret_sec1_der().to_vec();

                return PrivateKeyInfo {
                    cert_type: match sec1_der.len() {
                        32..=121 => KeyType::ECDSA_P256,
                        132..=167 => KeyType::ECDSA_P384,
                        200..=400 => KeyType::ECDSA_P521,
                        _ => panic!("unsupported sec1 key"),
                    },
                    der_encoded: sec1_der,
                }
            },
            _ => panic!("unsupported"),
        };

    }

    pub fn get_type(&self) -> KeyType {
        return self.cert_type;
    }

    pub fn public_bytes<'a>(&self, py: Python<'a>) -> &'a PyBytes {
        return PyBytes::new(
            py,
            &self.der_encoded
        );
    }
}
