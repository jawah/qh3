use aws_lc_rs::aead::{
    Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305,
};

use pyo3::pyclass;
use pyo3::pymethods;
use pyo3::types::PyBytes;
use pyo3::types::PyBytesMethods;
use pyo3::{Bound, PyResult, Python};

use crate::CryptoError;

#[inline]
fn put_u64(v: u64, bytes: &mut [u8]) {
    let bytes: &mut [u8; 8] = (&mut bytes[..8]).try_into().unwrap();
    *bytes = u64::to_be_bytes(v);
}

pub const NONCE_LEN: usize = 12;

pub struct QuicNonce(pub [u8; NONCE_LEN]);

impl QuicNonce {
    /// Combine an `Iv` and sequence number to produce a unique nonce.
    ///
    /// This is `iv ^ seq` where `seq` is encoded as a 96-bit big-endian integer.
    #[inline]
    pub fn new(iv: &[u8; NONCE_LEN], seq: u64) -> Self {
        let mut nonce = Self([0u8; NONCE_LEN]);
        put_u64(seq, &mut nonce.0[4..]);

        nonce.0.iter_mut().zip(iv.iter()).for_each(|(nonce, iv)| {
            *nonce ^= *iv;
        });

        nonce
    }
}

#[inline]
fn iv_from_pybytes(iv: &Bound<'_, PyBytes>) -> PyResult<[u8; NONCE_LEN]> {
    let bytes = iv.as_bytes();
    if bytes.len() != NONCE_LEN {
        return Err(CryptoError::new_err("Invalid iv length"));
    }
    let mut out = [0u8; NONCE_LEN];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[pyclass(name = "AeadChaCha20Poly1305", module = "qh3._hazmat")]
pub struct AeadChaCha20Poly1305 {
    key: LessSafeKey,
    iv: [u8; NONCE_LEN],
}

#[pyclass(name = "AeadAes256Gcm", module = "qh3._hazmat")]
pub struct AeadAes256Gcm {
    key: LessSafeKey,
    iv: [u8; NONCE_LEN],
}

#[pyclass(name = "AeadAes128Gcm", module = "qh3._hazmat")]
pub struct AeadAes128Gcm {
    key: LessSafeKey,
    iv: [u8; NONCE_LEN],
}

#[pymethods]
impl AeadAes256Gcm {
    #[new]
    pub fn py_new(key: Bound<'_, PyBytes>, iv: Bound<'_, PyBytes>) -> PyResult<Self> {
        let unbound = match UnboundKey::new(&AES_256_GCM, key.as_bytes()) {
            Ok(k) => k,
            Err(_) => return Err(CryptoError::new_err("Invalid AEAD key")),
        };

        let iv = iv_from_pybytes(&iv)?;

        Ok(AeadAes256Gcm {
            key: LessSafeKey::new(unbound),
            iv,
        })
    }

    pub fn decrypt<'a>(
        &mut self,
        py: Python<'a>,
        packet_number: u64,
        data: Bound<'_, PyBytes>,
        associated_data: Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let mut in_out_buffer = data.as_bytes().to_vec();
        let plaintext_len = in_out_buffer.len() - AES_256_GCM.tag_len();

        let aad = Aad::from(associated_data.as_bytes());

        let res = py.detach(|| {
            self.key.open_in_place(
                Nonce::assume_unique_for_key(QuicNonce::new(&self.iv, packet_number).0),
                aad,
                &mut in_out_buffer,
            )
        });

        match res {
            Ok(_) => Ok(PyBytes::new(py, &in_out_buffer[0..plaintext_len])),
            Err(_) => Err(CryptoError::new_err("decryption failed")),
        }
    }

    pub fn encrypt<'a>(
        &mut self,
        py: Python<'a>,
        packet_number: u64,
        data: Bound<'_, PyBytes>,
        associated_data: Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let plaintext = data.as_bytes();
        let plaintext_len = plaintext.len();
        let tag_len = AES_256_GCM.tag_len();

        let aad_bytes = associated_data.as_bytes();
        let nonce = QuicNonce::new(&self.iv, packet_number).0;

        PyBytes::new_with(py, plaintext_len + tag_len, |buffer| {
            buffer[..plaintext_len].copy_from_slice(plaintext);
            let aad = Aad::from(aad_bytes);
            let res = py.detach(|| {
                self.key.seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(nonce),
                    aad,
                    &mut buffer[..plaintext_len],
                )
            });
            match res {
                Ok(tag) => {
                    buffer[plaintext_len..].copy_from_slice(tag.as_ref());
                    Ok(())
                }
                Err(_) => Err(CryptoError::new_err("encryption failed")),
            }
        })
    }
}

#[pymethods]
impl AeadAes128Gcm {
    #[new]
    pub fn py_new(key: Bound<'_, PyBytes>, iv: Bound<'_, PyBytes>) -> PyResult<Self> {
        let unbound = match UnboundKey::new(&AES_128_GCM, key.as_bytes()) {
            Ok(k) => k,
            Err(_) => return Err(CryptoError::new_err("Invalid AEAD key")),
        };

        let iv = iv_from_pybytes(&iv)?;

        Ok(AeadAes128Gcm {
            key: LessSafeKey::new(unbound),
            iv,
        })
    }

    pub fn decrypt<'a>(
        &mut self,
        py: Python<'a>,
        packet_number: u64,
        data: Bound<'_, PyBytes>,
        associated_data: Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let mut in_out_buffer = data.as_bytes().to_vec();
        let plaintext_len = in_out_buffer.len() - AES_128_GCM.tag_len();

        let aad = Aad::from(associated_data.as_bytes());

        let res = py.detach(|| {
            self.key.open_in_place(
                Nonce::assume_unique_for_key(QuicNonce::new(&self.iv, packet_number).0),
                aad,
                &mut in_out_buffer,
            )
        });

        match res {
            Ok(_) => Ok(PyBytes::new(py, &in_out_buffer[0..plaintext_len])),
            Err(_) => Err(CryptoError::new_err("decryption failed")),
        }
    }

    pub fn encrypt<'a>(
        &mut self,
        py: Python<'a>,
        packet_number: u64,
        data: Bound<'_, PyBytes>,
        associated_data: Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let plaintext = data.as_bytes();
        let plaintext_len = plaintext.len();
        let tag_len = AES_128_GCM.tag_len();

        let aad_bytes = associated_data.as_bytes();
        let nonce = QuicNonce::new(&self.iv, packet_number).0;

        PyBytes::new_with(py, plaintext_len + tag_len, |buffer| {
            buffer[..plaintext_len].copy_from_slice(plaintext);
            let aad = Aad::from(aad_bytes);
            let res = py.detach(|| {
                self.key.seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(nonce),
                    aad,
                    &mut buffer[..plaintext_len],
                )
            });
            match res {
                Ok(tag) => {
                    buffer[plaintext_len..].copy_from_slice(tag.as_ref());
                    Ok(())
                }
                Err(_) => Err(CryptoError::new_err("encryption failed")),
            }
        })
    }

    pub fn encrypt_with_nonce<'a>(
        &mut self,
        py: Python<'a>,
        nonce: Bound<'_, PyBytes>,
        data: Bound<'_, PyBytes>,
        associated_data: Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let plaintext = data.as_bytes();
        let plaintext_len = plaintext.len();
        let tag_len = AES_128_GCM.tag_len();

        let aad_bytes = associated_data.as_bytes();
        let nonce_bytes = nonce.as_bytes();

        PyBytes::new_with(py, plaintext_len + tag_len, |buffer| {
            buffer[..plaintext_len].copy_from_slice(plaintext);
            let aad = Aad::from(aad_bytes);
            let res = py.detach(|| {
                self.key.seal_in_place_separate_tag(
                    Nonce::try_assume_unique_for_key(nonce_bytes).unwrap(),
                    aad,
                    &mut buffer[..plaintext_len],
                )
            });
            match res {
                Ok(tag) => {
                    buffer[plaintext_len..].copy_from_slice(tag.as_ref());
                    Ok(())
                }
                Err(_) => Err(CryptoError::new_err("encryption failed")),
            }
        })
    }
}

#[pymethods]
impl AeadChaCha20Poly1305 {
    #[new]
    pub fn py_new(key: Bound<'_, PyBytes>, iv: Bound<'_, PyBytes>) -> PyResult<Self> {
        let iv = iv_from_pybytes(&iv)?;

        Ok(AeadChaCha20Poly1305 {
            key: LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key.as_bytes()).unwrap()),
            iv,
        })
    }

    pub fn decrypt<'a>(
        &mut self,
        py: Python<'a>,
        packet_number: u64,
        data: Bound<'_, PyBytes>,
        associated_data: Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let mut in_out_buffer = data.as_bytes().to_vec();
        let plaintext_len = in_out_buffer.len() - CHACHA20_POLY1305.tag_len();

        let aad = Aad::from(associated_data.as_bytes());

        let res = py.detach(|| {
            self.key.open_in_place(
                Nonce::assume_unique_for_key(QuicNonce::new(&self.iv, packet_number).0),
                aad,
                &mut in_out_buffer,
            )
        });

        match res {
            Ok(_) => Ok(PyBytes::new(py, &in_out_buffer[0..plaintext_len])),
            Err(_) => Err(CryptoError::new_err("decryption failed")),
        }
    }

    pub fn encrypt<'a>(
        &mut self,
        py: Python<'a>,
        packet_number: u64,
        data: Bound<'_, PyBytes>,
        associated_data: Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let plaintext = data.as_bytes();
        let plaintext_len = plaintext.len();
        let tag_len = CHACHA20_POLY1305.tag_len();

        let aad_bytes = associated_data.as_bytes();
        let nonce = QuicNonce::new(&self.iv, packet_number).0;

        PyBytes::new_with(py, plaintext_len + tag_len, |buffer| {
            buffer[..plaintext_len].copy_from_slice(plaintext);
            let aad = Aad::from(aad_bytes);
            let res = py.detach(|| {
                self.key.seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(nonce),
                    aad,
                    &mut buffer[..plaintext_len],
                )
            });
            match res {
                Ok(tag) => {
                    buffer[plaintext_len..].copy_from_slice(tag.as_ref());
                    Ok(())
                }
                Err(_) => Err(CryptoError::new_err("encryption failed")),
            }
        })
    }
}
