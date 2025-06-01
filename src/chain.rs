use crate::CryptoError;
use aws_lc_rs::signature::{
    UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, ECDSA_P521_SHA512_ASN1,
};
use dsa::signature::Verifier;
use pkcs8::DecodePublicKey;
use pyo3::types::PyBytes;
use pyo3::types::PyBytesMethods;
use pyo3::{pyfunction, Bound, PyErr, PyResult, Python};
use rsa::pkcs1v15::Signature as RsaPkcsSignature;
use rsa::pkcs1v15::VerifyingKey as RsaPkcsVerifyingKey;
use rsa::sha2::{Sha256, Sha384, Sha512};
use rsa::RsaPublicKey as InternalRsaPublicKey;
use x509_parser::asn1_rs::{oid, Oid};
use x509_parser::nom::AsBytes;
use x509_parser::prelude::*;

const RSA_SHA256: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .11);
const RSA_SHA384: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .12);
const RSA_SHA512: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .13);
const ECDSA_SHA256: Oid<'static> = oid!(1.2.840 .10045 .4 .3 .2);
const ECDSA_SHA384: Oid<'static> = oid!(1.2.840 .10045 .4 .3 .3);
const ECDSA_SHA512: Oid<'static> = oid!(1.2.840 .10045 .4 .3 .4);

/// Given a leaf certificate and a candidate issuer certificate, verify that
/// `parent`'s public key actually signed `child`'s TBS bytes under the declared
/// signature algorithm. Supports the most common OIDs.
/// Returns `Ok(())` if the signature is valid, or an Err(CryptoError) otherwise.
fn verify_signature(
    child: &X509Certificate<'_>,
    parent: &X509Certificate<'_>,
) -> Result<(), PyErr> {
    let tbs = child.tbs_certificate.as_ref(); // the “to be signed” bytes
    let sig = child.signature_value.data.as_bytes(); // signature BIT STRING
    let alg_oid = child.signature_algorithm.algorithm.clone();

    let pubkey_spki = parent.tbs_certificate.subject_pki.raw;

    let is_rsa_based = alg_oid == RSA_SHA256 || alg_oid == RSA_SHA384 || alg_oid == RSA_SHA512;

    if is_rsa_based {
        let rsa_parsed_public_key = match InternalRsaPublicKey::from_public_key_der(pubkey_spki) {
            Ok(public_key) => public_key,
            Err(_) => return Err(CryptoError::new_err("Invalid RSA public key")),
        };

        if alg_oid == RSA_SHA256 {
            let alt_verifier = RsaPkcsVerifyingKey::<Sha256>::new(rsa_parsed_public_key);

            alt_verifier
                .verify(
                    tbs,
                    match &RsaPkcsSignature::try_from(sig) {
                        Ok(signature) => signature,
                        Err(_) => return Err(CryptoError::new_err("Invalid RSA PKCS signature")),
                    },
                )
                .map_err(|e| CryptoError::new_err(format!("RSA+SHA256 verify failed: {:?}", e)))
        } else if alg_oid == RSA_SHA384 {
            let alt_verifier = RsaPkcsVerifyingKey::<Sha384>::new(rsa_parsed_public_key);

            alt_verifier
                .verify(
                    tbs,
                    match &RsaPkcsSignature::try_from(sig) {
                        Ok(signature) => signature,
                        Err(_) => return Err(CryptoError::new_err("Invalid RSA PKCS signature")),
                    },
                )
                .map_err(|e| CryptoError::new_err(format!("RSA+SHA256 verify failed: {:?}", e)))
        } else if alg_oid == RSA_SHA512 {
            let alt_verifier = RsaPkcsVerifyingKey::<Sha512>::new(rsa_parsed_public_key);

            alt_verifier
                .verify(
                    tbs,
                    match &RsaPkcsSignature::try_from(sig) {
                        Ok(signature) => signature,
                        Err(_) => return Err(CryptoError::new_err("Invalid RSA PKCS signature")),
                    },
                )
                .map_err(|e| CryptoError::new_err(format!("RSA+SHA256 verify failed: {:?}", e)))
        } else {
            Err(CryptoError::new_err(format!(
                "Unsupported signature OID: {}",
                alg_oid
            )))
        }
    } else if alg_oid == ECDSA_SHA256 {
        // ecdsa-with-SHA256 (P-256)
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, pubkey_spki)
            .verify(tbs, sig)
            .map_err(|e| CryptoError::new_err(format!("ECDSA P-256+SHA256 verify failed: {:?}", e)))
    } else if alg_oid == ECDSA_SHA384 {
        // ecdsa-with-SHA384 (P-384)
        UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, pubkey_spki)
            .verify(tbs, sig)
            .map_err(|e| CryptoError::new_err(format!("ECDSA P-384+SHA384 verify failed: {:?}", e)))
    } else if alg_oid == ECDSA_SHA512 {
        // ecdsa-with-SHA512 (P-521)
        UnparsedPublicKey::new(&ECDSA_P521_SHA512_ASN1, pubkey_spki)
            .verify(tbs, sig)
            .map_err(|e| CryptoError::new_err(format!("ECDSA P-521+SHA512 verify failed: {:?}", e)))
    } else {
        Err(CryptoError::new_err(format!(
            "Unsupported signature OID: {}",
            alg_oid
        )))
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
