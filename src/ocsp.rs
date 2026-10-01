// OCSP Response Parser and Request Builder
// This module is created for Niquests
// qh3 has no use for it and we won't implement it for this package
use pyo3::pymethods;
use pyo3::types::PyBytesMethods;
use pyo3::types::{PyBytes, PyType};
use pyo3::{pyclass, Bound};
use pyo3::{PyResult, Python};

use der::oid::AssociatedOid;
use der::{Decode, Encode};
use pyo3::exceptions::PyValueError;
use x509_cert::Certificate;
use x509_ocsp::builder::OcspRequestBuilder;
use x509_ocsp::{
    BasicOcspResponse, CertStatus as InternalCertStatus, OcspRequest as InternalOcspRequest,
    OcspResponse, OcspResponseStatus as InternalOcspResponseStatus, Request,
};

use bincode::{serialize, Options};
use serde::{Deserialize, Serialize};
use sha1::Sha1;

use crate::chain::is_parent;
use crate::verify::{context_for_verify, verify_signature};
use x509_parser::certificate::X509Certificate;
use x509_parser::nom::AsBytes;
use x509_parser::prelude::AlgorithmIdentifier;
use x509_parser::prelude::FromDer;

#[pyclass(module = "qh3._hazmat", eq, eq_int, from_py_object)]
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Debug)]
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

#[pyclass(module = "qh3._hazmat", eq, eq_int, from_py_object)]
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq)]
#[allow(non_camel_case_types)]
pub enum OCSPResponseStatus {
    SUCCESSFUL = 0,
    MALFORMED_REQUEST = 1,
    INTERNAL_ERROR = 2,
    TRY_LATER = 3,
    SIG_REQUIRED = 5,
    UNAUTHORIZED = 6,
}

#[pyclass(module = "qh3._hazmat", eq, eq_int, from_py_object)]
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq)]
#[allow(non_camel_case_types)]
pub enum OCSPCertStatus {
    GOOD = 0,
    REVOKED = 1,
    UNKNOWN = 2,
}

#[pyclass(module = "qh3._hazmat", from_py_object)]
#[derive(Clone, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub struct OCSPResponse {
    next_update: u64,
    response_status: OCSPResponseStatus,
    certificate_status: OCSPCertStatus,
    revocation_reason: Option<ReasonFlags>,
    raw: Vec<u8>,
}

fn parse_response(raw: &[u8]) -> PyResult<(InternalOcspResponseStatus, BasicOcspResponse)> {
    let response = OcspResponse::from_der(raw)
        .map_err(|_| PyValueError::new_err("OCSP DER given is invalid"))?;
    let response_bytes = response
        .response_bytes
        .ok_or_else(|| PyValueError::new_err("OCSP Server did not provide answers"))?;
    if response_bytes.response_type != BasicOcspResponse::OID {
        return Err(PyValueError::new_err("Unsupported OCSP response type"));
    }
    let basic = BasicOcspResponse::from_der(response_bytes.response.as_bytes())
        .map_err(|_| PyValueError::new_err("Failed to parse basic OCSP response"))?;
    if basic.tbs_response_data.responses.is_empty() {
        return Err(PyValueError::new_err("OCSP Server did not provide answers"));
    }
    Ok((response.response_status, basic))
}

fn parse_certificate<'a>(der: &'a [u8], description: &str) -> PyResult<X509Certificate<'a>> {
    match X509Certificate::from_der(der) {
        Ok(([], certificate)) => Ok(certificate),
        _ => Err(PyValueError::new_err(format!(
            "Invalid DER for OCSP {} certificate",
            description
        ))),
    }
}

impl OCSPResponse {
    fn from_der(raw: &[u8], raise_on_missing_nextupdate: bool) -> PyResult<Self> {
        let (response_status, inner_resp) = parse_response(raw)?;
        let first_resp_for_cert = inner_resp
            .tbs_response_data
            .responses
            .first()
            .ok_or_else(|| PyValueError::new_err("OCSP Server did not provide answers"))?;

        if raise_on_missing_nextupdate && first_resp_for_cert.next_update.is_none() {
            return Err(PyValueError::new_err("OCSP response is missing nextUpdate"));
        }

        Ok(OCSPResponse {
            // nextUpdate is optional in RFC 6960. Existing consumers require
            // an integer, so use thisUpdate as a conservative cache deadline
            // when its absence is allowed: grant no additional cache lifetime.
            // Keep the fallback nonzero because consumers treat zero as
            // "no expiry". The signed DER remains unchanged.
            next_update: first_resp_for_cert
                .next_update
                .map(|time| time.0.to_unix_duration().as_secs())
                .unwrap_or_else(|| {
                    first_resp_for_cert
                        .this_update
                        .0
                        .to_unix_duration()
                        .as_secs()
                        .max(1)
                }),
            response_status: match response_status {
                InternalOcspResponseStatus::Successful => OCSPResponseStatus::SUCCESSFUL,
                InternalOcspResponseStatus::MalformedRequest => {
                    OCSPResponseStatus::MALFORMED_REQUEST
                }
                InternalOcspResponseStatus::InternalError => OCSPResponseStatus::INTERNAL_ERROR,
                InternalOcspResponseStatus::TryLater => OCSPResponseStatus::TRY_LATER,
                InternalOcspResponseStatus::SigRequired => OCSPResponseStatus::SIG_REQUIRED,
                InternalOcspResponseStatus::Unauthorized => OCSPResponseStatus::UNAUTHORIZED,
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
                        _ => None,
                    },
                    _ => None,
                },
                InternalCertStatus::Good(_) | InternalCertStatus::Unknown(_) => None,
            },
            raw: raw.to_vec(),
        })
    }
}

#[pymethods]
impl OCSPResponse {
    #[new]
    #[pyo3(signature = (raw_response, *, raise_on_missing_nextupdate=true))]
    pub fn py_new(
        raw_response: Bound<'_, PyBytes>,
        raise_on_missing_nextupdate: bool,
    ) -> PyResult<Self> {
        Self::from_der(raw_response.as_bytes(), raise_on_missing_nextupdate)
    }

    #[getter]
    pub fn next_update(&self) -> u64 {
        self.next_update
    }

    #[getter]
    pub fn response_status(&self) -> OCSPResponseStatus {
        self.response_status
    }

    #[getter]
    pub fn certificate_status(&self) -> OCSPCertStatus {
        self.certificate_status
    }

    #[getter]
    pub fn revocation_reason(&self) -> Option<ReasonFlags> {
        self.revocation_reason
    }

    pub fn authenticate_for(&self, issuer_der: Bound<'_, PyBytes>) -> PyResult<bool> {
        let issuer = parse_certificate(issuer_der.as_bytes(), "issuer")?;
        let (_, inner_resp) = parse_response(&self.raw)?;

        // applying some trick to get that signature algorithm matching
        // the x509_parser inner struct.
        let der_bytes = inner_resp.signature_algorithm.to_der().map_err(|_| {
            PyValueError::new_err("Unable to encode OCSP response signature algorithm")
        })?;

        // Convert to AlgorithmIdentifier
        let (_, algorithm) = AlgorithmIdentifier::from_der(der_bytes.as_slice()).map_err(|_| {
            PyValueError::new_err("Unable to extract ocsp response signature algorithm identifier")
        })?;
        let signed_data = inner_resp
            .tbs_response_data
            .to_der()
            .map_err(|_| PyValueError::new_err("Unable to encode OCSP response signed data"))?;
        let signature = inner_resp
            .signature
            .as_bytes()
            .ok_or_else(|| PyValueError::new_err("OCSP response signature is not byte-aligned"))?;

        // this branch handle the case where the issuer CA
        // does not have EKU OCSP signing, they probably issued
        // one or many intermediate to be capable of signing OCSP
        // responses.
        if let Some(certs) = &inner_resp.certs {
            let der_blobs: Vec<Vec<u8>> = certs
                .iter()
                .map(|crt| crt.to_der())
                .collect::<Result<_, _>>()
                .map_err(|_| PyValueError::new_err("Unable to encode OCSP signer certificate"))?;

            let extra_chain: Vec<X509Certificate<'_>> = der_blobs
                .iter()
                .map(|der| parse_certificate(der, "signer"))
                .collect::<PyResult<_>>()?;

            // Find the OCSP signer certificate that chains up to the issuer
            let mut ocsp_signer = None;

            // Try to find which certificate is signed by the issuer
            for (idx, cert) in extra_chain.iter().enumerate() {
                if is_parent(cert, &issuer).is_ok() {
                    // Verify the complete chain if there are intermediate certs
                    if idx > 0 {
                        // Build the chain from ocsp_signer to issuer
                        let mut chain_tip = cert;
                        let mut certs_to_check: Vec<_> = extra_chain
                            .iter()
                            .enumerate()
                            .filter(|(i, _)| *i != idx)
                            .collect();

                        // Try to build the chain
                        while !certs_to_check.is_empty() {
                            let mut found = false;
                            for i in (0..certs_to_check.len()).rev() {
                                let (_, candidate) = certs_to_check[i];
                                if is_parent(chain_tip, candidate).is_ok() {
                                    chain_tip = candidate;
                                    certs_to_check.remove(i);
                                    found = true;
                                    break;
                                }
                            }
                            if !found {
                                break; // Can't build complete chain
                            }
                        }

                        // Verify the chain is complete to issuer
                        if is_parent(chain_tip, &issuer).is_err() {
                            continue; // This wasn't the right OCSP signer
                        }
                    }
                    ocsp_signer = Some(cert);
                    break;
                }
            }

            let immediate_issuer = match ocsp_signer {
                Some(cert) => cert,
                None => return Ok(false),
            };

            let ctx_verify = match context_for_verify(&algorithm, immediate_issuer) {
                Some(ctx) => ctx,
                None => {
                    return Err(PyValueError::new_err(
                        "Unable to verify ocsp response signature (algorithm unsupported)",
                    ))
                }
            };

            Ok(verify_signature(
                ctx_verify.1.as_bytes(),
                ctx_verify.0,
                &signed_data,
                signature,
            )
            .is_ok())
        } else {
            // simplest case, the issuer can directly sign those! (most common)
            let ctx_verify = match context_for_verify(&algorithm, &issuer) {
                Some(ctx) => ctx,
                None => {
                    return Err(PyValueError::new_err(
                        "Unable to verify ocsp response signature (algorithm unsupported)",
                    ))
                }
            };

            Ok(verify_signature(
                ctx_verify.1.as_bytes(),
                ctx_verify.0,
                &signed_data,
                signature,
            )
            .is_ok())
        }
    }

    pub fn serialize<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let encoded = serialize(self)
            .map_err(|_| PyValueError::new_err("Unable to serialize OCSP response"))?;
        Ok(PyBytes::new(py, &encoded))
    }

    #[classmethod]
    pub fn deserialize(_cls: Bound<'_, PyType>, encoded: Bound<'_, PyBytes>) -> PyResult<Self> {
        // Keep the existing bincode layout, but bound decoding by the input
        // length and revalidate the DER instead of trusting cached metadata.
        let response: Self = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(encoded.as_bytes().len() as u64)
            .reject_trailing_bytes()
            .deserialize(encoded.as_bytes())
            .map_err(|_| PyValueError::new_err("Invalid serialized OCSP response"))?;
        // Restore responses that were explicitly accepted with the opt-out.
        Self::from_der(&response.raw, false)
    }
}

#[pyclass(module = "qh3._hazmat")]
pub struct OCSPRequest {
    inner_request: Vec<u8>,
}

#[pymethods]
impl OCSPRequest {
    #[new]
    pub fn py_new(
        peer_certificate: Bound<'_, PyBytes>,
        issuer_certificate: Bound<'_, PyBytes>,
    ) -> PyResult<Self> {
        let issuer = Certificate::from_der(issuer_certificate.as_bytes())
            .map_err(|_| PyValueError::new_err("Invalid DER for OCSP issuer certificate"))?;
        let cert = Certificate::from_der(peer_certificate.as_bytes())
            .map_err(|_| PyValueError::new_err("Invalid DER for OCSP peer certificate"))?;

        let request = Request::from_cert::<Sha1>(&issuer, &cert)
            .map_err(|_| PyValueError::new_err("Unable to build OCSP request"))?;

        let req: InternalOcspRequest = OcspRequestBuilder::default().with_request(request).build();

        match req.to_der() {
            Ok(raw_der) => Ok(OCSPRequest {
                inner_request: raw_der,
            }),
            Err(_) => Err(PyValueError::new_err("unable to generate the request")),
        }
    }

    pub fn public_bytes<'a>(&self, py: Python<'a>) -> Bound<'a, PyBytes> {
        PyBytes::new(py, &self.inner_request)
    }
}
