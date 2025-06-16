use crate::SignatureError;
use pyo3::types::PyBytes;
use pyo3::types::PyBytesMethods;
use pyo3::{pyfunction, Bound, PyErr, PyResult, Python};

use crate::verify::{context_for_verify, verify_signature};
use x509_parser::nom::AsBytes;
use x509_parser::prelude::*;

/// Given a leaf certificate and a candidate issuer certificate, verify that
/// `parent`'s public key actually signed `child`'s TBS bytes under the declared
/// signature algorithm. Supports the most common OIDs.
/// Returns `Ok(())` if the signature is valid, or an Err(CryptoError) otherwise.
fn is_parent(child: &X509Certificate<'_>, parent: &X509Certificate<'_>) -> Result<(), PyErr> {
    let tbs = child.tbs_certificate.as_ref(); // the “to be signed” bytes
    let sig = child.signature_value.data.as_bytes(); // signature BIT STRING

    let context_verify = match context_for_verify(&child.signature_algorithm, parent) {
        Some(ctx) => ctx,
        None => {
            return Err(SignatureError::new_err(
                "unable to extract context for cert signature verify",
            ))
        }
    };

    verify_signature(context_verify.1.as_ref(), context_verify.0, tbs, sig)
}

/// This function safely rebuild a certificate chain
/// Beware that intermediates MUST NOT contain any
/// trust anchor (self-signed).
#[pyfunction]
pub fn rebuild_chain<'py>(
    py: Python<'py>,
    leaf: Bound<'py, PyBytes>,
    intermediates: Vec<Bound<'py, PyBytes>>,
) -> PyResult<Vec<Bound<'py, PyBytes>>> {
    // 1. Parse the leaf certificate
    let mut current = X509Certificate::from_der(leaf.as_bytes()).unwrap().1;

    // 2. Create the pool of intermediate certificates
    // We need to ensure the data lives as long as 'py
    let mut pool: Vec<X509Certificate<'_>> = intermediates
        .iter()
        .map(|intermediate| {
            X509Certificate::from_der(intermediate.as_bytes())
                .unwrap()
                .1
        })
        .collect();

    // 3. Initialize chain with the leaf DER
    let mut chain: Vec<Bound<'py, PyBytes>> = Vec::new();
    chain.push(leaf.clone());

    // 4. Loop: for the current cert, try every remaining candidate for a valid sig
    loop {
        let mut found_index = None;
        for (idx, cand_cert) in pool.iter().enumerate() {
            // If signature verifies, treat cand_cert as the parent
            if is_parent(&current, cand_cert).is_ok() {
                found_index = Some(idx);
                break;
            }
        }

        if let Some(i) = found_index {
            let parent_cert = pool.remove(i);
            chain.push(PyBytes::new(py, intermediates[i].as_bytes()));
            current = parent_cert; // climb up one level
        } else {
            // No parent found—stop
            break;
        }
    }

    Ok(chain)
}
