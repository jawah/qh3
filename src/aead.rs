use aws_lc_rs::aead::{
    Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305,
};

use pyo3::pyclass;
use pyo3::pymethods;
use pyo3::types::PyBytes;
use pyo3::types::PyBytesMethods;
use pyo3::{Bound, PyResult, Python};

use crate::CryptoError;

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
    pub fn new(iv: &[u8], seq: u64) -> Self {
        let mut nonce = Self([0u8; NONCE_LEN]);
        put_u64(seq, &mut nonce.0[4..]);

        nonce.0.iter_mut().zip(iv.iter()).for_each(|(nonce, iv)| {
            *nonce ^= *iv;
        });

        nonce
    }
}

#[pyclass(name = "AeadChaCha20Poly1305", module = "qh3._hazmat")]
pub struct AeadChaCha20Poly1305 {
    key: LessSafeKey,
    iv: Vec<u8>,
}

#[pyclass(name = "AeadAes256Gcm", module = "qh3._hazmat")]
pub struct AeadAes256Gcm {
    key: LessSafeKey,
    iv: Vec<u8>,
}

#[pyclass(name = "AeadAes128Gcm", module = "qh3._hazmat")]
pub struct AeadAes128Gcm {
    key: LessSafeKey,
    iv: Vec<u8>,
}

#[pymethods]
impl AeadAes256Gcm {
    #[new]
    pub fn py_new(key: Bound<'_, PyBytes>, iv: Bound<'_, PyBytes>) -> PyResult<Self> {
        let unbound = match UnboundKey::new(&AES_256_GCM, key.as_bytes()) {
            Ok(k) => k,
            Err(_) => return Err(CryptoError::new_err("Invalid AEAD key")),
        };

        let iv_as_vec = iv.as_bytes().to_vec();

        if iv_as_vec.len() != NONCE_LEN {
            return Err(CryptoError::new_err("Invalid iv length"));
        }

        Ok(AeadAes256Gcm {
            key: LessSafeKey::new(unbound),
            iv: iv_as_vec,
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

        let res = py.allow_threads(|| {
            self.key.open_in_place(
                Nonce::assume_unique_for_key(QuicNonce::new(self.iv.as_ref(), packet_number).0),
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
        let mut in_out_buffer = Vec::from(data.as_bytes());

        let aad = Aad::from(associated_data.as_bytes());

        let res = py.allow_threads(|| {
            self.key.seal_in_place_append_tag(
                Nonce::assume_unique_for_key(QuicNonce::new(self.iv.as_ref(), packet_number).0),
                aad,
                &mut in_out_buffer,
            )
        });

        match res {
            Ok(_) => Ok(PyBytes::new(py, &in_out_buffer)),
            Err(_) => Err(CryptoError::new_err("encryption failed")),
        }
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

        let iv_as_vec = iv.as_bytes().to_vec();

        if iv_as_vec.len() != NONCE_LEN {
            return Err(CryptoError::new_err("Invalid iv length"));
        }

        Ok(AeadAes128Gcm {
            key: LessSafeKey::new(unbound),
            iv: iv_as_vec,
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

        let res = py.allow_threads(|| {
            self.key.open_in_place(
                Nonce::assume_unique_for_key(QuicNonce::new(self.iv.as_ref(), packet_number).0),
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
        let mut in_out_buffer = Vec::from(data.as_bytes());

        let aad = Aad::from(associated_data.as_bytes());

        let res = py.allow_threads(|| {
            self.key.seal_in_place_append_tag(
                Nonce::assume_unique_for_key(QuicNonce::new(self.iv.as_ref(), packet_number).0),
                aad,
                &mut in_out_buffer,
            )
        });

        match res {
            Ok(_) => Ok(PyBytes::new(py, &in_out_buffer)),
            Err(_) => Err(CryptoError::new_err("encryption failed")),
        }
    }

    pub fn encrypt_with_nonce<'a>(
        &mut self,
        py: Python<'a>,
        nonce: Bound<'_, PyBytes>,
        data: Bound<'_, PyBytes>,
        associated_data: Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let mut in_out_buffer = Vec::from(data.as_bytes());

        let aad = Aad::from(associated_data.as_bytes());
        let nonce_as_ref = nonce.as_bytes();

        let res = py.allow_threads(|| {
            self.key.seal_in_place_append_tag(
                Nonce::try_assume_unique_for_key(nonce_as_ref).unwrap(),
                aad,
                &mut in_out_buffer,
            )
        });

        match res {
            Ok(_) => Ok(PyBytes::new(py, &in_out_buffer)),
            Err(_) => Err(CryptoError::new_err("encryption failed")),
        }
    }
}

#[pymethods]
impl AeadChaCha20Poly1305 {
    #[new]
    pub fn py_new(key: Bound<'_, PyBytes>, iv: Bound<'_, PyBytes>) -> PyResult<Self> {
        let iv_as_vec = iv.as_bytes().to_vec();

        if iv_as_vec.len() != NONCE_LEN {
            return Err(CryptoError::new_err("Invalid iv length"));
        }

        Ok(AeadChaCha20Poly1305 {
            key: LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key.as_bytes()).unwrap()),
            iv: iv_as_vec,
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

        let res = py.allow_threads(|| {
            self.key.open_in_place(
                Nonce::assume_unique_for_key(QuicNonce::new(self.iv.as_ref(), packet_number).0),
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
        let mut in_out_buffer = Vec::from(data.as_bytes());

        let aad = Aad::from(associated_data.as_bytes());

        let res = py.allow_threads(|| {
            self.key.seal_in_place_append_tag(
                Nonce::assume_unique_for_key(QuicNonce::new(self.iv.as_ref(), packet_number).0),
                aad,
                &mut in_out_buffer,
            )
        });

        match res {
            Ok(_) => Ok(PyBytes::new(py, &in_out_buffer)),
            Err(_) => Err(CryptoError::new_err("encryption failed")),
        }
    }
}
