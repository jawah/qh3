use pyo3::types::PyBytes;
use pyo3::types::PyBytesMethods;
use pyo3::{pyclass, pymethods, Bound, PyResult, Python};
use rustls::crypto::aws_lc_rs::hpke as rustls_hpke;
use rustls::crypto::hpke::{Hpke, HpkePublicKey, HpkeSealer};

use crate::CryptoError;

/// Select the appropriate HPKE suite from IANA-assigned identifiers.
///
/// We match on (kem_id, kdf_id, aead_id) triples.
/// Only DHKEM(X25519, HKDF-SHA256) = 0x0020 with HKDF-SHA256 = 0x0001 is supported
/// for ECH (mandatory-to-implement per RFC 9849 Section 9).
fn select_suite(kem_id: u16, kdf_id: u16, aead_id: u16) -> PyResult<&'static dyn Hpke> {
    // Only DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 is currently supported
    if kem_id != 0x0020 {
        return Err(CryptoError::new_err(
            "Unsupported HPKE KEM: only DHKEM(X25519, HKDF-SHA256) (0x0020) is supported",
        ));
    }
    if kdf_id != 0x0001 {
        return Err(CryptoError::new_err(
            "Unsupported HPKE KDF: only HKDF-SHA256 (0x0001) is supported",
        ));
    }

    match aead_id {
        0x0001 => Ok(rustls_hpke::DH_KEM_X25519_HKDF_SHA256_AES_128),
        0x0002 => Ok(rustls_hpke::DH_KEM_X25519_HKDF_SHA256_AES_256),
        0x0003 => Ok(rustls_hpke::DH_KEM_X25519_HKDF_SHA256_CHACHA20_POLY1305),
        _ => Err(CryptoError::new_err(
            "Unsupported HPKE AEAD: only AES-128-GCM (0x0001), AES-256-GCM (0x0002), \
             and ChaCha20-Poly1305 (0x0003) are supported",
        )),
    }
}

/// HPKE sender context for Encrypted Client Hello.
///
/// Wraps rustls' HPKE implementation backed by aws-lc-rs.
/// Uses setup_sealer (SetupBaseS) to create a context that can seal
/// multiple messages (needed for HelloRetryRequest re-encryption).
#[pyclass(module = "qh3._hazmat")]
pub struct HpkeContext {
    sealer: Box<dyn HpkeSealer + Send>,
    enc: Vec<u8>,
}

#[pymethods]
impl HpkeContext {
    /// Create a new HPKE sender context (SetupBaseS).
    ///
    /// Arguments:
    ///   kem_id: HPKE KEM identifier (e.g., 0x0020 for DHKEM(X25519, HKDF-SHA256))
    ///   kdf_id: HPKE KDF identifier (e.g., 0x0001 for HKDF-SHA256)
    ///   aead_id: HPKE AEAD identifier (e.g., 0x0001 for AES-128-GCM)
    ///   public_key: The recipient's public key bytes
    ///   info: The info string for HPKE context (for ECH: "tls ech" || 0x00 || ECHConfig)
    #[new]
    pub fn py_new(
        kem_id: u16,
        kdf_id: u16,
        aead_id: u16,
        public_key: Bound<'_, PyBytes>,
        info: Bound<'_, PyBytes>,
    ) -> PyResult<Self> {
        let suite = select_suite(kem_id, kdf_id, aead_id)?;
        let pk = HpkePublicKey(public_key.as_bytes().to_vec());

        let (enc, sealer) = match suite.setup_sealer(info.as_bytes(), &pk) {
            Ok(result) => result,
            Err(_) => {
                return Err(CryptoError::new_err(
                    "HPKE SetupBaseS failed: unable to create sender context",
                ))
            }
        };

        Ok(HpkeContext { sealer, enc: enc.0 })
    }

    /// Return the encapsulated key (enc) produced during SetupBaseS.
    ///
    /// For DHKEM(X25519, HKDF-SHA256), this is 32 bytes.
    /// Sent in the ECH extension's `enc` field in the first ClientHello.
    /// Empty for subsequent ClientHellos after HelloRetryRequest.
    pub fn enc<'a>(&self, py: Python<'a>) -> Bound<'a, PyBytes> {
        PyBytes::new(py, &self.enc)
    }

    /// Encrypt a plaintext with associated data (context.Seal).
    ///
    /// Each call increments the internal HPKE sequence number,
    /// so the first call encrypts the first ClientHello's inner payload,
    /// and a second call (after HRR) uses a fresh nonce automatically.
    pub fn seal<'a>(
        &mut self,
        py: Python<'a>,
        aad: Bound<'_, PyBytes>,
        plaintext: Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let ciphertext = match self.sealer.seal(aad.as_bytes(), plaintext.as_bytes()) {
            Ok(ct) => ct,
            Err(_) => return Err(CryptoError::new_err("HPKE seal failed")),
        };

        Ok(PyBytes::new(py, &ciphertext))
    }
}
