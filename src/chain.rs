use x509_parser::prelude::*;
use aws_lc_rs::signature::{
    UnparsedPublicKey,
    RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512,
    ECDSA_P256_SHA256_ASN1,
    ECDSA_P384_SHA384_ASN1,
    ECDSA_P521_SHA512_ASN1,
};
use pyo3::{pyfunction, Bound, PyErr, PyResult, Python};
use pyo3::types::PyBytes;
use pyo3::types::PyBytesMethods;
use x509_parser::asn1_rs::oid;
use x509_parser::nom::AsBytes;
use crate::CryptoError;


/// Given a leaf certificate and a candidate issuer certificate, verify that
/// `parent`'s public key actually signed `child`'s TBS bytes under the declared
/// signature algorithm. Supports the most common OIDs.
/// Returns `Ok(())` if the signature is valid, or an Err(CryptoError) otherwise.
fn verify_signature(
    child: &X509Certificate<'_>,
    parent: &X509Certificate<'_>,
) -> Result<(), PyErr> {
    let tbs = child.tbs_certificate.as_ref();       // the “to be signed” bytes
    let sig = child.signature_value.data.as_bytes();       // signature BIT STRING
    let alg_oid = child.signature_algorithm.algorithm.clone();

    let pubkey_spki = parent.tbs_certificate.subject_pki.raw;

    if alg_oid == oid!(1.2.840.113549.1.1.11) {
        // sha256WithRSAEncryption
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, pubkey_spki)
            .verify(tbs, sig)
            .map_err(|e| CryptoError::new_err(format!("RSA+SHA256 verify failed: {:?}", e)))
    } else if alg_oid == oid!(1.2.840.113549.1.1.12) {
        // sha384WithRSAEncryption
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA384, pubkey_spki)
            .verify(tbs, sig)
            .map_err(|e| CryptoError::new_err(format!("RSA+SHA384 verify failed: {:?}", e)))
    } else if alg_oid == oid!(1.2.840.113549.1.1.13) {
        // sha512WithRSAEncryption
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA512, pubkey_spki)
            .verify(tbs, sig)
            .map_err(|e| CryptoError::new_err(format!("RSA+SHA512 verify failed: {:?}", e)))
    } else if alg_oid == oid!(1.2.840.10045.4.3.2) {
        // ecdsa-with-SHA256 (P-256)
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, pubkey_spki)
            .verify(tbs, sig)
            .map_err(|e| CryptoError::new_err(format!("ECDSA P-256+SHA256 verify failed: {:?}", e)))
    } else if alg_oid == oid!(1.2.840.10045.4.3.3) {
        // ecdsa-with-SHA384 (P-384)
        UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, pubkey_spki)
            .verify(tbs, sig)
            .map_err(|e| CryptoError::new_err(format!("ECDSA P-384+SHA384 verify failed: {:?}", e)))
    } else if alg_oid == oid!(1.2.840.10045.4.3.4) {
        // ecdsa-with-SHA512 (P-521)
        UnparsedPublicKey::new(&ECDSA_P521_SHA512_ASN1, pubkey_spki)
            .verify(tbs, sig)
            .map_err(|e| CryptoError::new_err(format!("ECDSA P-521+SHA512 verify failed: {:?}", e)))
    } else {
        Err(CryptoError::new_err(format!("Unsupported signature OID: {}", alg_oid)))
    }
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
            X509Certificate::from_der(intermediate.as_bytes()).unwrap().1
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
            if verify_signature(&current, cand_cert).is_ok() {
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