use pyo3::exceptions::PyException;
use pyo3::prelude::*;

mod aead;
mod agreement;
mod buffer;
mod certificate;
mod headers;
mod hpk;
mod intldomain;
mod ocsp;
mod pkcs8;
mod private_key;
mod rsa;

pub use self::aead::{AeadAes128Gcm, AeadAes256Gcm, AeadChaCha20Poly1305};
pub use self::agreement::{
    ECDHP256KeyExchange, ECDHP384KeyExchange, ECDHP521KeyExchange, X25519KeyExchange,
    X25519ML768KeyExchange,
};
pub use self::buffer::{Buffer, BufferReadError, BufferWriteError};
pub use self::certificate::{
    Certificate, ExpiredCertificateError, InvalidNameCertificateError, SelfSignedCertificateError,
    ServerVerifier, UnacceptableCertificateError,
};
pub use self::headers::{
    DecoderStreamError, DecompressionFailed, EncoderStreamError, QpackDecoder, QpackEncoder,
    StreamBlocked,
};
pub use self::hpk::QUICHeaderProtection;
pub use self::intldomain::{idna_decode, idna_encode};
pub use self::ocsp::{OCSPCertStatus, OCSPRequest, OCSPResponse, OCSPResponseStatus, ReasonFlags};
pub use self::pkcs8::{KeyType, PrivateKeyInfo};
pub use self::private_key::{
    verify_with_public_key, DsaPrivateKey, EcPrivateKey, Ed25519PrivateKey, RsaPrivateKey,
    SignatureError,
};
pub use self::rsa::Rsa;

pyo3::create_exception!(_hazmat, CryptoError, PyException);

#[pymodule(gil_used = false)]
fn _hazmat(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // idna UTS 46
    m.add_function(wrap_pyfunction!(idna_encode, m)?)?;
    m.add_function(wrap_pyfunction!(idna_decode, m)?)?;
    // ls-qpack bridge
    m.add_class::<QpackDecoder>()?;
    m.add_class::<QpackEncoder>()?;
    m.add("StreamBlocked", py.get_type::<StreamBlocked>())?;
    m.add("EncoderStreamError", py.get_type::<EncoderStreamError>())?;
    m.add("DecoderStreamError", py.get_type::<DecoderStreamError>())?;
    m.add("DecompressionFailed", py.get_type::<DecompressionFailed>())?;
    // aead bridge (authenticated encryption)
    m.add_class::<AeadChaCha20Poly1305>()?;
    m.add_class::<AeadAes256Gcm>()?;
    m.add_class::<AeadAes128Gcm>()?;
    // Certificate Store X509 Verification + Certificate Representation
    m.add_class::<ServerVerifier>()?;
    m.add_class::<Certificate>()?;
    m.add(
        "SelfSignedCertificateError",
        py.get_type::<SelfSignedCertificateError>(),
    )?;
    m.add(
        "InvalidNameCertificateError",
        py.get_type::<InvalidNameCertificateError>(),
    )?;
    m.add(
        "ExpiredCertificateError",
        py.get_type::<ExpiredCertificateError>(),
    )?;
    m.add(
        "UnacceptableCertificateError",
        py.get_type::<UnacceptableCertificateError>(),
    )?;
    // RSA specialized for the Retry Token
    m.add_class::<Rsa>()?;
    // Header protection mask
    m.add_class::<QUICHeaderProtection>()?;
    // Private&Public Key Mgmt
    m.add_class::<RsaPrivateKey>()?;
    m.add_class::<DsaPrivateKey>()?;
    m.add_class::<Ed25519PrivateKey>()?;
    m.add_class::<EcPrivateKey>()?;
    m.add_class::<KeyType>()?;
    m.add_class::<PrivateKeyInfo>()?;
    m.add_function(wrap_pyfunction!(verify_with_public_key, m)?)?;
    m.add("SignatureError", py.get_type::<SignatureError>())?;
    // Exchange Key Algorithms
    m.add_class::<X25519KeyExchange>()?;
    m.add_class::<ECDHP256KeyExchange>()?;
    m.add_class::<ECDHP384KeyExchange>()?;
    m.add_class::<ECDHP521KeyExchange>()?;
    m.add_class::<X25519ML768KeyExchange>()?;
    // General Crypto Error
    m.add("CryptoError", py.get_type::<CryptoError>())?;
    // Niquests OCSP helper
    m.add_class::<OCSPResponse>()?;
    m.add_class::<OCSPCertStatus>()?;
    m.add_class::<OCSPResponseStatus>()?;
    m.add_class::<ReasonFlags>()?;
    m.add_class::<OCSPRequest>()?;
    // Buffer
    m.add("BufferReadError", py.get_type::<BufferReadError>())?;
    m.add("BufferWriteError", py.get_type::<BufferWriteError>())?;
    m.add_class::<Buffer>()?;
    Ok(())
}
