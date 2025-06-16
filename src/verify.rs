use aws_lc_rs::error::Unspecified;
use aws_lc_rs::signature;
use aws_lc_rs::signature::UnparsedPublicKey;
use pyo3::PyErr;

use x509_parser::asn1_rs::{oid, Oid};
use x509_parser::certificate::X509Certificate;
use x509_parser::signature_algorithm::RsaSsaPssParams;

use rsa::pkcs1v15::Signature as RsaPkcsSignature;
use rsa::pss::Signature as RsaPssSignature;

use rsa::RsaPublicKey as InternalRsaPublicKey;

use rsa::pkcs1v15::VerifyingKey as RsaPkcsVerifyingKey;
use rsa::pss::VerifyingKey as RsaPssVerifyingKey;
use rsa::sha2::{Sha256, Sha384, Sha512};
use rsa::signature::Verifier;

use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};

use crate::{CryptoError, SignatureError};
use pkcs8::DecodePublicKey;
use sha1::Sha1;
use x509_parser::x509::AlgorithmIdentifier;

const RSA_PSS: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .10);

const RSA_PSS_SHA256_PARAMETER: Oid<'static> = oid!(2.16.840 .1 .101 .3 .4 .2 .1);
const RSA_PSS_SHA384_PARAMETER: Oid<'static> = oid!(2.16.840 .1 .101 .3 .4 .2 .2);
const RSA_PSS_SHA512_PARAMETER: Oid<'static> = oid!(2.16.840 .1 .101 .3 .4 .2 .3);

const RSA_PKCS_SHA1: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .5);
const RSA_PKCS_SHA256: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .11);
const RSA_PKCS_SHA384: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .12);
const RSA_PKCS_SHA512: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .13);

const ECDSA_SHA256: Oid<'static> = oid!(1.2.840 .10045 .4 .3 .2);
const ECDSA_SHA384: Oid<'static> = oid!(1.2.840 .10045 .4 .3 .3);
const ECDSA_SHA512: Oid<'static> = oid!(1.2.840 .10045 .4 .3 .4);

const ED25519: Oid<'static> = oid!(1.3.101 .112);

const CURVE_P256: Oid<'static> = oid!(1.2.840 .10045 .3 .1 .7);
const CURVE_P384: Oid<'static> = oid!(1.3.132 .0 .34);
const CURVE_P521: Oid<'static> = oid!(1.3.132 .0 .35);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyAlgorithm {
    RsaPssSha1 = 0,
    RsaPssSha256 = 1,
    RsaPssSha384 = 2,
    RsaPssSha512 = 3,

    RsaPkcsSha1 = 4,
    RsaPkcsSha256 = 5,
    RsaPkcsSha384 = 6,
    RsaPkcsSha512 = 7,

    Ed25519 = 8,

    EcdsaP256WithSha256 = 9,
    EcdsaP256WithSha384 = 10,
    EcdsaP256WithSha512 = 11,

    EcdsaP384WithSha256 = 12,
    EcdsaP384WithSha384 = 13,
    EcdsaP384WithSha512 = 14,

    EcdsaP521WithSha256 = 15,
    EcdsaP521WithSha384 = 16,
    EcdsaP521WithSha512 = 17,
}

pub fn context_for_verify(
    signature_algorithm: &AlgorithmIdentifier,
    issuer: &X509Certificate,
) -> Option<(PublicKeyAlgorithm, Vec<u8>)> {
    let signature_oid = &signature_algorithm.algorithm;

    let algo = if signature_oid == &RSA_PSS {
        let params = signature_algorithm.parameters.as_ref()?;

        let params = RsaSsaPssParams::try_from(params).unwrap();

        let hash_oid = params.hash_algorithm_oid();

        if hash_oid == &RSA_PSS_SHA256_PARAMETER {
            PublicKeyAlgorithm::RsaPssSha256
        } else if hash_oid == &RSA_PSS_SHA384_PARAMETER {
            PublicKeyAlgorithm::RsaPssSha384
        } else if hash_oid == &RSA_PSS_SHA512_PARAMETER {
            PublicKeyAlgorithm::RsaPssSha512
        } else {
            PublicKeyAlgorithm::RsaPssSha1
        }
    } else if signature_oid == &RSA_PKCS_SHA1 {
        PublicKeyAlgorithm::RsaPkcsSha1
    } else if signature_oid == &RSA_PKCS_SHA256 {
        PublicKeyAlgorithm::RsaPkcsSha256
    } else if signature_oid == &RSA_PKCS_SHA384 {
        PublicKeyAlgorithm::RsaPkcsSha384
    } else if signature_oid == &RSA_PKCS_SHA512 {
        PublicKeyAlgorithm::RsaPkcsSha512
    } else if signature_oid == &ECDSA_SHA256
        || signature_oid == &ECDSA_SHA384
        || signature_oid == &ECDSA_SHA512
    {
        // we actually want the curve from the parent (aka. issuer)
        let params = issuer
            .tbs_certificate
            .subject_pki
            .algorithm
            .parameters
            .as_ref()?;

        if let Ok(curve_oid) = params.as_oid() {
            if curve_oid == CURVE_P256 {
                if signature_oid == &ECDSA_SHA256 {
                    PublicKeyAlgorithm::EcdsaP256WithSha256
                } else if signature_oid == &ECDSA_SHA384 {
                    PublicKeyAlgorithm::EcdsaP256WithSha384
                } else {
                    return None;
                }
            } else if curve_oid == CURVE_P384 {
                if signature_oid == &ECDSA_SHA384 {
                    PublicKeyAlgorithm::EcdsaP384WithSha384
                } else if signature_oid == &ECDSA_SHA512 {
                    PublicKeyAlgorithm::EcdsaP384WithSha512
                } else if signature_oid == &ECDSA_SHA256 {
                    PublicKeyAlgorithm::EcdsaP384WithSha256
                } else {
                    return None;
                }
            } else if curve_oid == CURVE_P521 {
                if signature_oid == &ECDSA_SHA512 {
                    PublicKeyAlgorithm::EcdsaP521WithSha512
                } else {
                    return None;
                }
            } else {
                return None;
            }
        } else {
            return None;
        }
    } else if signature_oid == &ED25519 {
        PublicKeyAlgorithm::Ed25519
    } else {
        return None;
    };

    let pubkey_raw = issuer.tbs_certificate.subject_pki.raw.to_vec();

    Some((algo, pubkey_raw))
}

pub fn verify_signature(
    public_key_raw: &[u8],
    algorithm: PublicKeyAlgorithm,
    message: &[u8],
    signature: &[u8],
) -> Result<(), PyErr> {
    if algorithm == PublicKeyAlgorithm::Ed25519 {
        let ed25519_verifier: Ed25519VerifyingKey =
            match Ed25519VerifyingKey::from_public_key_der(public_key_raw) {
                Ok(public_key) => public_key,
                Err(_) => return Err(CryptoError::new_err("Invalid Ed25519 public key")),
            };

        let res = ed25519_verifier.verify(
            message,
            &Ed25519Signature::from_bytes(signature[0..64].try_into()?),
        );

        match res {
            Err(_) => Err(SignatureError::new_err("signature mismatch (ed25519)")),
            _ => Ok(()),
        }
    } else if algorithm == PublicKeyAlgorithm::EcdsaP256WithSha256
        || algorithm == PublicKeyAlgorithm::EcdsaP256WithSha384
        || algorithm == PublicKeyAlgorithm::EcdsaP256WithSha512
        || algorithm == PublicKeyAlgorithm::EcdsaP384WithSha256
        || algorithm == PublicKeyAlgorithm::EcdsaP384WithSha384
        || algorithm == PublicKeyAlgorithm::EcdsaP384WithSha512
        || algorithm == PublicKeyAlgorithm::EcdsaP521WithSha256
        || algorithm == PublicKeyAlgorithm::EcdsaP521WithSha384
        || algorithm == PublicKeyAlgorithm::EcdsaP521WithSha512
    {
        let public_key = UnparsedPublicKey::new(
            match algorithm {
                PublicKeyAlgorithm::EcdsaP256WithSha256 => &signature::ECDSA_P256_SHA256_ASN1,
                PublicKeyAlgorithm::EcdsaP256WithSha384 => &signature::ECDSA_P256_SHA384_ASN1,

                PublicKeyAlgorithm::EcdsaP384WithSha384 => &signature::ECDSA_P384_SHA384_ASN1,
                PublicKeyAlgorithm::EcdsaP384WithSha256 => &signature::ECDSA_P384_SHA256_ASN1,

                PublicKeyAlgorithm::EcdsaP521WithSha256 => &signature::ECDSA_P521_SHA256_ASN1,
                PublicKeyAlgorithm::EcdsaP521WithSha384 => &signature::ECDSA_P521_SHA384_ASN1,
                PublicKeyAlgorithm::EcdsaP521WithSha512 => &signature::ECDSA_P521_SHA512_ASN1,
                _ => return Err(CryptoError::new_err("unsupported signature algorithm")),
            },
            public_key_raw,
        );

        let res = public_key.verify(message, signature);

        match res {
            Err(Unspecified) => Err(SignatureError::new_err(format!(
                "signature mismatch ({:?})",
                algorithm
            ))),
            _ => Ok(()),
        }
    } else if algorithm == PublicKeyAlgorithm::RsaPkcsSha1
        || algorithm == PublicKeyAlgorithm::RsaPkcsSha256
        || algorithm == PublicKeyAlgorithm::RsaPkcsSha384
        || algorithm == PublicKeyAlgorithm::RsaPkcsSha512
    {
        let rsa_parsed_public_key = match InternalRsaPublicKey::from_public_key_der(public_key_raw)
        {
            Ok(public_key) => public_key,
            Err(e) => {
                return Err(CryptoError::new_err(format!(
                    "Invalid RSA public key {}",
                    e
                )))
            }
        };

        if algorithm == PublicKeyAlgorithm::RsaPkcsSha1 {
            let verifier = RsaPkcsVerifyingKey::<Sha1>::new(rsa_parsed_public_key);

            match verifier.verify(
                message,
                match &RsaPkcsSignature::try_from(signature) {
                    Ok(signature) => signature,
                    Err(_) => return Err(CryptoError::new_err("Invalid RSA PKCS signature")),
                },
            ) {
                Err(_) => Err(SignatureError::new_err("signature mismatch (rsa)")),
                _ => Ok(()),
            }
        } else if algorithm == PublicKeyAlgorithm::RsaPkcsSha256 {
            let verifier = RsaPkcsVerifyingKey::<Sha256>::new(rsa_parsed_public_key);

            match verifier.verify(
                message,
                match &RsaPkcsSignature::try_from(signature) {
                    Ok(signature) => signature,
                    Err(_) => return Err(CryptoError::new_err("Invalid RSA PKCS signature")),
                },
            ) {
                Err(_) => Err(SignatureError::new_err("signature mismatch (rsa)")),
                _ => Ok(()),
            }
        } else if algorithm == PublicKeyAlgorithm::RsaPkcsSha384 {
            let verifier = RsaPkcsVerifyingKey::<Sha384>::new(rsa_parsed_public_key);

            match verifier.verify(
                message,
                match &RsaPkcsSignature::try_from(signature) {
                    Ok(signature) => signature,
                    Err(_) => return Err(CryptoError::new_err("Invalid RSA PKCS signature")),
                },
            ) {
                Err(_) => Err(SignatureError::new_err("signature mismatch (rsa)")),
                _ => Ok(()),
            }
        } else if algorithm == PublicKeyAlgorithm::RsaPkcsSha512 {
            let verifier = RsaPkcsVerifyingKey::<Sha512>::new(rsa_parsed_public_key);

            match verifier.verify(
                message,
                match &RsaPkcsSignature::try_from(signature) {
                    Ok(signature) => signature,
                    Err(_) => return Err(CryptoError::new_err("Invalid RSA PKCS signature")),
                },
            ) {
                Err(_) => Err(SignatureError::new_err("signature mismatch (rsa)")),
                _ => Ok(()),
            }
        } else {
            Err(SignatureError::new_err(
                "unsupported RSA signature algorithm",
            ))
        }
    } else if algorithm == PublicKeyAlgorithm::RsaPssSha1
        || algorithm == PublicKeyAlgorithm::RsaPssSha256
        || algorithm == PublicKeyAlgorithm::RsaPssSha384
        || algorithm == PublicKeyAlgorithm::RsaPssSha512
    {
        let rsa_parsed_public_key = match InternalRsaPublicKey::from_public_key_der(public_key_raw)
        {
            Ok(public_key) => public_key,
            Err(_) => return Err(CryptoError::new_err("Invalid RSA public key")),
        };

        if algorithm == PublicKeyAlgorithm::RsaPssSha1 {
            let verifier = RsaPssVerifyingKey::<Sha1>::new(rsa_parsed_public_key);

            match verifier.verify(
                message,
                match &RsaPssSignature::try_from(signature) {
                    Ok(signature) => signature,
                    Err(_) => return Err(CryptoError::new_err("Invalid RSA PSS signature")),
                },
            ) {
                Err(_) => Err(SignatureError::new_err("signature mismatch (rsa)")),
                _ => Ok(()),
            }
        } else if algorithm == PublicKeyAlgorithm::RsaPssSha256 {
            let verifier = RsaPssVerifyingKey::<Sha256>::new(rsa_parsed_public_key);

            match verifier.verify(
                message,
                match &RsaPssSignature::try_from(signature) {
                    Ok(signature) => signature,
                    Err(_) => return Err(CryptoError::new_err("Invalid RSA PSS signature")),
                },
            ) {
                Err(_) => Err(SignatureError::new_err("signature mismatch (rsa)")),
                _ => Ok(()),
            }
        } else if algorithm == PublicKeyAlgorithm::RsaPssSha384 {
            let verifier = RsaPssVerifyingKey::<Sha384>::new(rsa_parsed_public_key);

            match verifier.verify(
                message,
                match &RsaPssSignature::try_from(signature) {
                    Ok(signature) => signature,
                    Err(_) => return Err(CryptoError::new_err("Invalid RSA PSS signature")),
                },
            ) {
                Err(_) => Err(SignatureError::new_err("signature mismatch (rsa)")),
                _ => Ok(()),
            }
        } else if algorithm == PublicKeyAlgorithm::RsaPssSha512 {
            let verifier = RsaPssVerifyingKey::<Sha512>::new(rsa_parsed_public_key);

            match verifier.verify(
                message,
                match &RsaPssSignature::try_from(signature) {
                    Ok(signature) => signature,
                    Err(_) => return Err(CryptoError::new_err("Invalid RSA PSS signature")),
                },
            ) {
                Err(_) => Err(SignatureError::new_err("signature mismatch (rsa)")),
                _ => Ok(()),
            }
        } else {
            Err(SignatureError::new_err(
                "unsupported RSA signature algorithm",
            ))
        }
    } else {
        Err(SignatureError::new_err("unsupported signature algorithm"))
    }
}
