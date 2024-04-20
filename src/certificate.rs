use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{ServerCertVerifier};
use rustls::{CertificateError, Error, RootCertStore};
use rustls::pki_types::{CertificateDer, UnixTime, ServerName};

use pyo3::{PyResult, Python};
use pyo3::types::{PyBytes, PyList, PyTuple};
use pyo3::pymethods;
use pyo3::pyclass;
use pyo3::ToPyObject;

use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

use std::sync::Arc;

use pyo3::exceptions::PyException;

use crate::CryptoError;

pyo3::create_exception!(_hazmat, SelfSignedCertificateError, PyException);
pyo3::create_exception!(_hazmat, InvalidNameCertificateError, PyException);
pyo3::create_exception!(_hazmat, ExpiredCertificateError, PyException);
pyo3::create_exception!(_hazmat, UnacceptableCertificateError, PyException);


#[pyclass(name = "Extension", module = "qh3._hazmat", frozen)]
pub struct Extension {
    oid: String,
    value: Vec<u8>,
}

#[pyclass(name = "Subject", module = "qh3._hazmat", frozen)]
pub struct Subject {
    oid: String,
    value: Vec<u8>
}

#[pyclass(name = "Certificate", module = "qh3._hazmat", frozen)]
pub struct Certificate {
    version: u8,
    serial_number: String,
    raw_serial_number: Vec<u8>,
    not_valid_before: i64,
    not_valid_after: i64,
    extensions: Vec<Extension>,
    subject: Vec<Subject>,
    issuer: Vec<Subject>,
    public_bytes: Vec<u8>,
    public_key: Vec<u8>,
}

#[pymethods]
impl Certificate {
    #[new]
    pub fn py_new(certificate_der: &PyBytes) -> PyResult<Self> {
        let res = X509Certificate::from_der(certificate_der.as_bytes());

        match res {
            Ok((rem, cert)) => {
                assert!(rem.is_empty());

                let mut subject = Vec::new();
                let mut issuer = Vec::new();
                let mut extensions: Vec<Extension> = Vec::new();

                for extension in cert.iter_extensions() {
                    match extension.parsed_extension() {
                        ParsedExtension::AuthorityInfoAccess(aia) => {
                            for ext_endpoint in &aia.accessdescs {
                                extensions.push(
                                    Extension {
                                        oid: ext_endpoint.access_method.to_string(),
                                        value: ext_endpoint.access_location.to_string().into(),
                                    }
                                )

                            }
                        },
                        ParsedExtension::SubjectAlternativeName(san) => {
                            for name in &san.general_names {
                                extensions.push(
                                    Extension {
                                        oid: "2.5.29.17".to_string(),
                                        value: name.to_string().into(),
                                    }
                                )
                            }
                        }
                        _ => ()
                    }
                }

                for item in cert.subject.iter() {
                    for sub_item in item.iter() {
                        subject.push(
                            Subject {
                                oid: sub_item.attr_type().to_string(),
                                value: sub_item.attr_value().data.to_vec()
                            }
                        )
                    }
                }

                for item in cert.issuer.iter() {
                    for sub_item in item.iter() {
                        issuer.push(
                            Subject {
                                oid: sub_item.attr_type().to_string(),
                                value: sub_item.attr_value().data.to_vec()
                            }
                        )
                    }
                }

                return Ok(
                    Certificate {
                        version: match cert.version() {
                            X509Version::V1 => 0,
                            X509Version::V2 => 1,
                            X509Version::V3 => 2,
                            _ => 0xFF
                        },
                        serial_number: cert.raw_serial_as_string(),
                        raw_serial_number: cert.raw_serial().to_vec(),
                        not_valid_before: cert.validity.not_before.timestamp(),
                        not_valid_after: cert.validity.not_after.timestamp(),
                        extensions: extensions,
                        subject: subject,
                        issuer: issuer,
                        public_bytes: certificate_der.as_bytes().to_vec(),
                        public_key: match cert.public_key().parsed() {
                            Ok(PublicKey::EC(pts)) => {
                                pts.data().to_vec()
                            },
                            Ok(PublicKey::DSA(cert_decoded)) => {
                                cert_decoded.to_vec()
                            },
                            _ => cert.public_key().raw.to_vec()
                        },
                    }
                )
            },
            _ => Err(CryptoError::new_err("x509 parsing failed")),
        }

    }

    #[getter]
    pub fn serial_number(&self) -> &String {
        return &self.serial_number;
    }

    pub fn raw_serial_number<'a>(&self, py: Python<'a>) -> &'a PyBytes {
        return PyBytes::new(
            py,
            &self.raw_serial_number
        )
    }

    #[getter]
    pub fn not_valid_before(&self) -> i64 {
        return self.not_valid_before;
    }

    #[getter]
    pub fn not_valid_after(&self) -> i64 {
        return self.not_valid_after;
    }

    #[getter]
    pub fn version(&self) -> u8 {
        return self.version;
    }

    #[getter]
    pub fn subject<'a>(&self, py: Python<'a>) -> &'a PyList {
        let values = PyList::empty(py);

        for item in &self.subject {
            let oid_short = match item.oid.as_str() {
                "2.5.4.3" => "CN".to_string(),
                "2.5.4.7" => "L".to_string(),
                "2.5.4.8" => "ST".to_string(),
                "2.5.4.10" => "O".to_string(),
                "2.5.4.11" => "OU".to_string(),
                "2.5.4.6" => "C".to_string(),
                "2.5.4.9" => "STREET".to_string(),
                "0.9.2342.19200300.100.1.25" => "DC".to_string(),
                "0.9.2342.19200300.100.1.1" => "UID".to_string(),
                _ => "".to_string()
            };

            let _ = values.append(
                PyTuple::new(
                    py,
                    [
                        item.oid.to_object(py),
                        oid_short.to_object(py),
                        PyBytes::new(
                            py,
                            &item.value
                        ).into()
                    ]
                )
            );
        }

        return values;
    }

    #[getter]
    pub fn issuer<'a>(&self, py: Python<'a>) -> &'a PyList {
        let values = PyList::empty(py);

        for item in &self.issuer {

            let oid_short = match item.oid.as_str() {
                "2.5.4.3" => "CN",
                "2.5.4.7" => "L",
                "2.5.4.8" => "ST",
                "2.5.4.10" => "O",
                "2.5.4.11" => "OU",
                "2.5.4.6" => "C",
                "2.5.4.9" => "STREET",
                "0.9.2342.19200300.100.1.25" => "DC",
                "0.9.2342.19200300.100.1.1" => "UID",
                _ => ""
            };

            let _ = values.append(
                PyTuple::new(
                    py,
                    [
                        item.oid.to_object(py),
                        oid_short.to_object(py),
                        PyBytes::new(
                            py,
                            &item.value
                        ).into()
                    ]
                )
            );
        }

        return values;
    }

    pub fn get_subject_alt_names<'a>(&self, py: Python<'a>) -> &'a PyList {
        let values = PyList::empty(py);

        for item in &self.extensions {
            if item.oid == "2.5.29.17" {
                let _ = values.append(
                    PyBytes::new(
                        py,
                        &item.value
                    )
                );
            }
        }

        return values;
    }

    pub fn get_ocsp_endpoints<'a>(&self, py: Python<'a>) -> &'a PyList {
        let values = PyList::empty(py);

        for item in &self.extensions {
            if item.oid == "1.3.6.1.5.5.7.48.1" {
                let _ = values.append(
                    PyBytes::new(
                        py,
                        &item.value
                    )
                );
            }
        }

        return values;
    }

    pub fn get_issuer_endpoints<'a>(&self, py: Python<'a>) -> &'a PyList {
        let values = PyList::empty(py);

        for item in &self.extensions {
            if item.oid == "1.3.6.1.5.5.7.48.2" {
                let _ = values.append(
                    PyBytes::new(
                        py,
                        &item.value
                    )
                );
            }
        }

        return values;
    }

    pub fn public_bytes<'a>(&self, py: Python<'a>) -> &'a PyBytes {
        return PyBytes::new(
            py,
            &self.public_bytes
        )
    }

    pub fn public_key<'a>(&self, py: Python<'a>) -> &'a PyBytes {
        return PyBytes::new(
            py,
            &self.public_key
        );
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.serial_number == other.serial_number
    }
}


#[pyclass(name = "ServerVerifier", module = "qh3._hazmat")]
pub struct ServerVerifier {
    inner: Arc<WebPkiServerVerifier>
}

#[pymethods]
impl ServerVerifier {

    #[new]
    pub fn py_new(authorities: Vec<&PyBytes>) -> PyResult<Self> {
        let mut root_cert_store = RootCertStore::empty();

        root_cert_store.add_parsable_certificates(authorities.into_iter().map(|ca| CertificateDer::from(ca.as_bytes())));
        let res = WebPkiServerVerifier::builder(Arc::new(root_cert_store)).build();

        match res {
            Ok(store) => {
                Ok(
                    ServerVerifier {
                        inner: store
                    }
                )
            },
            Err(_) => Err(CryptoError::new_err("Unable to create the X509 trust store"))
        }
    }

    #[allow(unreachable_code)]
    pub fn verify(&mut self, peer: &PyBytes, intermediaries: Vec<&PyBytes>, server_name: String) -> PyResult<()> {
        let peer_der = CertificateDer::from(peer.as_bytes());
        let mut intermediaries_der = Vec::new();

        for intermediary in intermediaries {
            intermediaries_der.push(CertificateDer::from(intermediary.as_bytes()));
        }

        let parsed_name_res = ServerName::try_from(server_name);

        return match parsed_name_res {
            Ok(parsed_name) => {
                let res = self.inner.verify_server_cert(
                    &peer_der,
                    &intermediaries_der,
                    &parsed_name,
                    &[],
                    UnixTime::now(),
                );

                return match res {
                    Ok(_) => Ok(()),
                    Err(Error::InvalidCertificate(err)) => {
                        match err {
                            CertificateError::UnknownIssuer => Err(SelfSignedCertificateError::new_err("unable to get local issuer certificate")),
                            CertificateError::NotValidForName => Err(InvalidNameCertificateError::new_err("invalid server name for certificate")),
                            CertificateError::Expired => Err(ExpiredCertificateError::new_err("server certificate expired")),
                            CertificateError::NotValidYet => Err(ExpiredCertificateError::new_err("server certificate is not yet valid")),
                            _ => Err(UnacceptableCertificateError::new_err("the server certificate is unacceptable"))
                        }
                    },
                    Err(_) => Err(CryptoError::new_err("the x509 certificate store encountered an error"))
                }
            },
            Err(_) => {
                return Err(InvalidNameCertificateError::new_err("unparseable server name"));
            }
        }

    }
}
