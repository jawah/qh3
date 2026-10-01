use crate::verify::{context_for_verify, verify_signature};
use crate::{CryptoError, ReasonFlags};
use bincode::{serialize, Options};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::PyBytesMethods;
use pyo3::types::{PyBytes, PyType};
use pyo3::{pyclass, pymethods, Bound, PyResult, Python};
use serde::{Deserialize, Serialize};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;
use x509_parser::prelude::ReasonCode as InternalCode;
use x509_parser::revocation_list::CertificateRevocationList as InternalCrl;

#[pyclass(module = "qh3._hazmat", from_py_object)]
#[derive(Clone, Serialize, Deserialize)]
pub struct RevokedCertificate {
    serial_number: String,
    reason: ReasonFlags,
    expired_at: i64,
}

#[pymethods]
impl RevokedCertificate {
    #[getter]
    pub fn serial_number(&self) -> &String {
        &self.serial_number
    }

    #[getter]
    pub fn reason(&self) -> ReasonFlags {
        self.reason
    }

    #[getter]
    pub fn expired_at(&self) -> i64 {
        self.expired_at
    }

    pub fn __repr__(&self) -> String {
        format!(
            "<RevokedCertificate S/N \"{}\" reason={:?}>",
            self.serial_number, self.reason
        )
    }
}

#[pyclass(module = "qh3._hazmat", from_py_object)]
#[derive(Clone, Serialize, Deserialize)]
pub struct CertificateRevocationList {
    container: Vec<RevokedCertificate>,
    issuer: String,
    last_updated_at: i64,
    next_update_at: i64,
    tbs_inner: Vec<u8>,
    signature: Vec<u8>,
    raw: Vec<u8>,
}

impl CertificateRevocationList {
    fn from_der(raw: &[u8], raise_on_missing_nextupdate: bool) -> PyResult<Self> {
        match InternalCrl::from_der(raw) {
            Ok(([], crl)) => {
                if raise_on_missing_nextupdate && crl.next_update().is_none() {
                    return Err(PyValueError::new_err("CRL is missing nextUpdate"));
                }
                let mut revoked_list = Vec::new();

                for revoked in crl.iter_revoked_certificates() {
                    let reason = revoked.reason_code().unwrap_or_default().1;

                    revoked_list.push(RevokedCertificate {
                        serial_number: revoked.raw_serial_as_string(),
                        reason: match reason {
                            InternalCode::Unspecified => ReasonFlags::unspecified,
                            InternalCode::AACompromise => ReasonFlags::aa_compromise,
                            InternalCode::AffiliationChanged => ReasonFlags::affiliation_changed,
                            InternalCode::CACompromise => ReasonFlags::ca_compromise,
                            InternalCode::CertificateHold => ReasonFlags::certificate_hold,
                            InternalCode::KeyCompromise => ReasonFlags::key_compromise,
                            InternalCode::CessationOfOperation => {
                                ReasonFlags::cessation_of_operation
                            }
                            InternalCode::Superseded => ReasonFlags::superseded,
                            InternalCode::PrivilegeWithdrawn => ReasonFlags::privilege_withdrawn,
                            InternalCode::RemoveFromCRL => ReasonFlags::remove_from_crl,
                            _ => ReasonFlags::unspecified,
                        },
                        expired_at: revoked.revocation_date.timestamp(),
                    });
                }

                Ok(CertificateRevocationList {
                    container: revoked_list,
                    issuer: format!("{}", crl.issuer()),
                    last_updated_at: crl.last_update().timestamp(),
                    // Match OCSP's opt-out: use the signed thisUpdate without
                    // granting extra cache lifetime. Keep the fallback nonzero
                    // because downstream consumers treat zero as "no expiry".
                    next_update_at: crl
                        .next_update()
                        .map(|time| time.timestamp())
                        .unwrap_or_else(|| crl.last_update().timestamp().max(1)),
                    tbs_inner: crl.tbs_cert_list.as_ref().to_vec(),
                    signature: crl.signature_value.data.to_vec(),
                    raw: raw.to_vec(),
                })
            }
            _ => Err(CryptoError::new_err("unable to parse crl")),
        }
    }
}

#[pymethods]
impl CertificateRevocationList {
    #[new]
    #[pyo3(signature = (crl_der, *, raise_on_missing_nextupdate=true))]
    pub fn py_new(
        crl_der: Bound<'_, PyBytes>,
        raise_on_missing_nextupdate: bool,
    ) -> PyResult<Self> {
        Self::from_der(crl_der.as_bytes(), raise_on_missing_nextupdate)
    }

    pub fn authenticate_for(&self, issuer_der: Bound<'_, PyBytes>) -> PyResult<bool> {
        let issuer = match X509Certificate::from_der(issuer_der.as_bytes()) {
            Ok(([], issuer)) => issuer,
            _ => {
                return Err(PyValueError::new_err(
                    "Invalid DER for CRL issuer certificate",
                ))
            }
        };

        match InternalCrl::from_der(self.raw.as_ref()) {
            Ok(([], crl)) => {
                if crl.signature_value.unused_bits != 0 {
                    return Err(PyValueError::new_err("CRL signature is not byte-aligned"));
                }
                let pubkey_info = match context_for_verify(&crl.signature_algorithm, &issuer) {
                    Some(info) => info,
                    _ => return Ok(false),
                };

                Ok(verify_signature(
                    pubkey_info.1.as_ref(),
                    pubkey_info.0,
                    crl.tbs_cert_list.as_ref(),
                    crl.signature_value.data.as_ref(),
                )
                .is_ok())
            }
            _ => Err(PyValueError::new_err("Invalid DER for CRL")),
        }
    }

    pub fn is_revoked(&self, serial_number: String) -> Option<RevokedCertificate> {
        for revoked in &self.container {
            if revoked.serial_number == serial_number {
                return Some(revoked.clone());
            }
        }

        None
    }

    #[getter]
    pub fn next_update_at(&self) -> i64 {
        self.next_update_at
    }

    #[getter]
    pub fn last_updated_at(&self) -> i64 {
        self.last_updated_at
    }

    #[getter]
    pub fn issuer(&self) -> String {
        self.issuer.clone()
    }

    pub fn __len__(&self) -> usize {
        self.container.len()
    }

    pub fn serialize<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let encoded =
            serialize(self).map_err(|_| PyValueError::new_err("Unable to serialize CRL"))?;
        Ok(PyBytes::new(py, &encoded))
    }

    #[classmethod]
    pub fn deserialize(_cls: Bound<'_, PyType>, encoded: Bound<'_, PyBytes>) -> PyResult<Self> {
        let crl: Self = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(encoded.as_bytes().len() as u64)
            .reject_trailing_bytes()
            .deserialize(encoded.as_bytes())
            .map_err(|_| PyValueError::new_err("Invalid serialized CRL"))?;

        // Retain the existing cache layout, but derive revocations, expiry, and
        // signature data from the original DER instead of trusting cached fields.
        // An opt-out accepted at construction also survives a cache round-trip.
        Self::from_der(&crl.raw, false)
            .map_err(|_| PyValueError::new_err("Invalid DER in serialized CRL"))
    }
}
