// OCSP Response Parser and Request Builder
// This module is created for Niquests
// qh3 has no use for it and we won't implement it for this package
use pyo3::{PyResult, Python};
use pyo3::types::PyBytes;
use pyo3::pymethods;
use pyo3::pyclass;

use der::{Decode, Encode};
use pyo3::exceptions::PyValueError;
use x509_ocsp::{OcspResponse, BasicOcspResponse, SingleResponse, OcspResponseStatus as InternalOcspResponseStatus, CertStatus as InternalCertStatus, OcspRequest as InternalOcspRequest, Request};
use x509_ocsp::builder::OcspRequestBuilder;
use x509_cert::Certificate;

use sha1::Sha1;

#[pyclass(module = "qh3._hazmat")]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum ReasonFlags {
    unspecified = 0,
    key_compromise = 1,
    ca_compromise = 2,
    affiliation_changed = 3,
    superseded = 4,
    cessation_of_operation = 5,
    certificate_hold = 6,
    privilege_withdrawn = 9,
    aa_compromise = 10,
    remove_from_crl = 8,
}

#[pyclass(module = "qh3._hazmat")]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum OCSPResponseStatus {
    SUCCESSFUL = 0,
    MALFORMED_REQUEST = 1,
    INTERNAL_ERROR = 2,
    TRY_LATER = 3,
    SIG_REQUIRED = 5,
    UNAUTHORIZED = 6,
}

#[pyclass(module = "qh3._hazmat")]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum OCSPCertStatus {
    GOOD = 0,
    REVOKED = 1,
    UNKNOWN = 2,
}


#[pyclass(module = "qh3._hazmat")]
#[allow(non_camel_case_types)]
pub struct OCSPResponse {
    next_update: u64,
    response_status: OCSPResponseStatus,
    certificate_status: OCSPCertStatus,
    revocation_reason: Option<ReasonFlags>,
}

#[pymethods]
impl OCSPResponse {
    #[new]
    pub fn py_new(raw_response: &PyBytes) -> PyResult<Self> {
        let ocsp_res: OcspResponse = OcspResponse::from_der(&raw_response.as_bytes()).unwrap();

        if !ocsp_res.response_bytes.is_some() {
            return Err(PyValueError::new_err("OCSP Server did not provide answers"));
        }

        let inner_resp: BasicOcspResponse = BasicOcspResponse::from_der(&ocsp_res.response_bytes.unwrap().response.as_bytes()).unwrap();

        if inner_resp.tbs_response_data.responses.len() == 0 {
            return Err(PyValueError::new_err("OCSP Server did not provide answers"));
        }

        let first_resp_for_cert: &SingleResponse = &inner_resp.tbs_response_data.responses[0];

        return Ok(
            OCSPResponse {
                next_update: first_resp_for_cert.next_update.unwrap().0.to_unix_duration().as_secs(),
                response_status: match ocsp_res.response_status {
                    InternalOcspResponseStatus::Successful => OCSPResponseStatus::SUCCESSFUL,
                    InternalOcspResponseStatus::MalformedRequest => OCSPResponseStatus::MALFORMED_REQUEST,
                    InternalOcspResponseStatus::InternalError => OCSPResponseStatus::INTERNAL_ERROR,
                    InternalOcspResponseStatus::TryLater => OCSPResponseStatus::TRY_LATER,
                    InternalOcspResponseStatus::SigRequired => OCSPResponseStatus::SIG_REQUIRED,
                    InternalOcspResponseStatus::Unauthorized => OCSPResponseStatus::UNAUTHORIZED
                },
                certificate_status: match first_resp_for_cert.cert_status {
                    InternalCertStatus::Good(..) => OCSPCertStatus::GOOD,
                    InternalCertStatus::Revoked(_) => OCSPCertStatus::REVOKED,
                    InternalCertStatus::Unknown(_) => OCSPCertStatus::UNKNOWN,
                },
                revocation_reason: match first_resp_for_cert.cert_status {
                    InternalCertStatus::Revoked(info) => match info.revocation_reason {
                        Some(reason) => match reason as u8 {
                            0 => Some(ReasonFlags::unspecified),
                            1 => Some(ReasonFlags::key_compromise),
                            2 => Some(ReasonFlags::ca_compromise),
                            3 => Some(ReasonFlags::affiliation_changed),
                            4 => Some(ReasonFlags::superseded),
                            5 => Some(ReasonFlags::cessation_of_operation),
                            6 => Some(ReasonFlags::certificate_hold),
                            8 => Some(ReasonFlags::remove_from_crl),
                            9 => Some(ReasonFlags::privilege_withdrawn),
                            10 => Some(ReasonFlags::aa_compromise),
                            _ => None
                        },
                        _ => None
                    },
                    InternalCertStatus::Good(_) | InternalCertStatus::Unknown(_) => None
                }
            }
        )
    }

    #[getter]
    pub fn next_update(&self) -> u64 {
        return self.next_update;
    }

    #[getter]
    pub fn response_status(&self) -> OCSPResponseStatus {
        return self.response_status;
    }

    #[getter]
    pub fn certificate_status(&self) -> OCSPCertStatus {
        return self.certificate_status;
    }

    #[getter]
    pub fn revocation_reason(&self) -> Option<ReasonFlags> {
        return self.revocation_reason;
    }
}


#[pyclass(module = "qh3._hazmat")]
pub struct OCSPRequest {
    inner_request: Vec<u8>
}

#[pymethods]
impl OCSPRequest {
    #[new]
    pub fn py_new(peer_certificate: &PyBytes, issuer_certificate: &PyBytes) -> PyResult<Self> {
        let issuer = Certificate::from_der(&issuer_certificate.as_bytes()).unwrap();
        let cert = Certificate::from_der(&peer_certificate.as_bytes()).unwrap();

        let req: InternalOcspRequest = OcspRequestBuilder::default()
            .with_request(Request::from_cert::<Sha1>(&issuer, &cert).unwrap())
            .build();

        return match req.to_der() {
            Ok(raw_der) => Ok(
                OCSPRequest {
                    inner_request: raw_der
                }
            ),
            Err(_) => Err(PyValueError::new_err("unable to generate the request"))
        };
    }

    pub fn public_bytes<'a>(&self, py: Python<'a>) -> &'a PyBytes {
        return PyBytes::new(
            py,
            &self.inner_request
        );
    }
}
