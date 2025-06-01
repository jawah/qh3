use crate::{CryptoError, ReasonFlags};
use bincode::{deserialize, serialize};
use pyo3::prelude::PyBytesMethods;
use pyo3::types::{PyBytes, PyType};
use pyo3::{pyclass, pymethods, Bound, PyResult, Python};
use serde::{Deserialize, Serialize};
use x509_parser::prelude::FromDer;
use x509_parser::prelude::ReasonCode as InternalCode;
use x509_parser::revocation_list::CertificateRevocationList as InternalCrl;
use x509_parser::time::ASN1Time;

#[pyclass(module = "qh3._hazmat")]
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

#[pyclass(module = "qh3._hazmat")]
#[derive(Clone, Serialize, Deserialize)]
pub struct CertificateRevocationList {
    container: Vec<RevokedCertificate>,
    issuer: String,
    last_updated_at: i64,
    next_update_at: i64,
}

#[pymethods]
impl CertificateRevocationList {
    #[new]
    pub fn py_new(crl: Bound<'_, PyBytes>) -> PyResult<Self> {
        match InternalCrl::from_der(crl.as_bytes()) {
            Ok((_rem, crl)) => {
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
                    next_update_at: crl.next_update().unwrap_or(ASN1Time::now()).timestamp() + 3600,
                })
            }
            Err(_) => Err(CryptoError::new_err("unable to parse crl")),
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
        Ok(PyBytes::new(py, &serialize(&self).unwrap()))
    }

    #[classmethod]
    pub fn deserialize(_cls: Bound<'_, PyType>, encoded: Bound<'_, PyBytes>) -> PyResult<Self> {
        Ok(deserialize(encoded.as_bytes()).unwrap())
    }
}
