use aws_lc_rs::aead::{Aad, TlsRecordOpeningKey, TlsRecordSealingKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305, TlsProtocolId, Nonce};

use chacha20poly1305::{
    aead::{KeyInit},
    ChaCha20Poly1305, Key as ChaCha20Key, AeadInPlace
};

use pyo3::{PyResult, Python};
use pyo3::types::PyBytes;
use pyo3::pymethods;
use pyo3::pyclass;

use crate::CryptoError;

#[pyclass(name = "AeadChaCha20Poly1305", module = "qh3._hazmat")]
pub struct AeadChaCha20Poly1305 {
    key: Vec<u8>
}

#[pyclass(name = "AeadAes256Gcm", module = "qh3._hazmat")]
pub struct AeadAes256Gcm {
    key: Vec<u8>
}

#[pyclass(name = "AeadAes128Gcm", module = "qh3._hazmat")]
pub struct AeadAes128Gcm {
    key: Vec<u8>
}


#[pymethods]
impl AeadAes256Gcm {
    #[new]
    pub fn py_new(key: &PyBytes) -> Self {
        AeadAes256Gcm { key: key.as_bytes().to_vec() }
    }

    pub fn decrypt<'a>(&mut self, py: Python<'a>, nonce: &PyBytes, data: &PyBytes, associated_data: &PyBytes) -> PyResult<&'a PyBytes> {
        let mut in_out_buffer = data.as_bytes().to_vec();
        let plaintext_len = in_out_buffer.len() - AES_256_GCM.tag_len();

        let opening_key: TlsRecordOpeningKey = TlsRecordOpeningKey::new(&AES_256_GCM, TlsProtocolId::TLS13, &self.key).expect("FAILURE");

        let aad = Aad::from(associated_data.as_bytes());

        let res = opening_key
            .open_in_place(Nonce::try_assume_unique_for_key(nonce.as_bytes()).unwrap(), aad, &mut in_out_buffer);

        return match res {
            Ok(_) => Ok(
                PyBytes::new(
                    py,
                    &in_out_buffer[0..plaintext_len]
                )
            ),
            Err(_) => Err(CryptoError::new_err("decryption failed"))
        };
    }

    pub fn encrypt<'a>(&mut self, py: Python<'a>, nonce: &PyBytes, data: &PyBytes, associated_data: &PyBytes) -> PyResult<&'a PyBytes> {
        let mut in_out_buffer = Vec::from(data.as_bytes());

        let mut sealing_key: TlsRecordSealingKey = TlsRecordSealingKey::new(&AES_256_GCM, TlsProtocolId::TLS13, &self.key).expect("FAILURE");

        let aad = Aad::from(associated_data.as_bytes());

        let res = sealing_key
            .seal_in_place_append_tag(Nonce::try_assume_unique_for_key(nonce.as_bytes()).unwrap(), aad, &mut in_out_buffer);

        return match res {
            Ok(_) => Ok(
                PyBytes::new(
                    py,
                    &in_out_buffer
                )
            ),
            Err(_) => Err(CryptoError::new_err("encryption failed"))
        };
    }
}


#[pymethods]
impl AeadAes128Gcm {
    #[new]
    pub fn py_new(key: &PyBytes) -> Self {
        AeadAes128Gcm { key: key.as_bytes().to_vec() }
    }

    pub fn decrypt<'a>(&mut self, py: Python<'a>, nonce: &PyBytes, data: &PyBytes, associated_data: &PyBytes) -> PyResult<&'a PyBytes> {
        let mut in_out_buffer = data.as_bytes().to_vec();
        let plaintext_len = in_out_buffer.len() - AES_128_GCM.tag_len();

        let opening_key = TlsRecordOpeningKey::new(&AES_128_GCM, TlsProtocolId::TLS13, &self.key).expect("FAILURE");
        let aad = Aad::from(associated_data.as_bytes());

        let res = opening_key
            .open_in_place(Nonce::try_assume_unique_for_key(nonce.as_bytes()).unwrap(), aad, &mut in_out_buffer);

        return match res {
            Ok(_) => Ok(
                PyBytes::new(
                    py,
                    &in_out_buffer[0..plaintext_len]
                )
            ),
            Err(_) => Err(CryptoError::new_err("decryption failed"))
        };
    }

    pub fn encrypt<'a>(&mut self, py: Python<'a>, nonce: &PyBytes, data: &PyBytes, associated_data: &PyBytes) -> PyResult<&'a PyBytes> {
        let mut in_out_buffer = Vec::from(data.as_bytes());

        let mut sealing_key = TlsRecordSealingKey::new(&AES_128_GCM, TlsProtocolId::TLS13, &self.key).expect("FAILURE");

        let aad = Aad::from(associated_data.as_bytes());

        let res = sealing_key
            .seal_in_place_append_tag(Nonce::try_assume_unique_for_key(nonce.as_bytes()).unwrap(), aad, &mut in_out_buffer);

        return match res {
            Ok(_) => Ok(
                PyBytes::new(
                    py,
                    &in_out_buffer
                )
            ),
            Err(_) => Err(CryptoError::new_err("encryption failed"))
        };
    }
}


#[pymethods]
impl AeadChaCha20Poly1305 {
    #[new]
    pub fn py_new(key: &PyBytes) -> Self {
        AeadChaCha20Poly1305 { key: key.as_bytes().to_vec() }
    }

    pub fn decrypt<'a>(&mut self, py: Python<'a>, nonce: &PyBytes, data: &PyBytes, associated_data: &PyBytes) -> PyResult<&'a PyBytes> {
        let mut in_out_buffer = data.as_bytes().to_vec();
        let plaintext_len = in_out_buffer.len() - CHACHA20_POLY1305.tag_len();

        let cipher: ChaCha20Poly1305 = ChaCha20Poly1305::new(ChaCha20Key::from_slice(&self.key));

        let res = cipher.decrypt_in_place(nonce.as_bytes().into(), &associated_data.as_bytes(), &mut in_out_buffer);

        return match res {
            Ok(_) => Ok(
                PyBytes::new(
                    py,
                    &in_out_buffer[0..plaintext_len]
                )
            ),
            Err(_) => Err(CryptoError::new_err("decryption failed"))
        };
    }

    pub fn encrypt<'a>(&mut self, py: Python<'a>, nonce: &PyBytes, data: &PyBytes, associated_data: &PyBytes) -> PyResult<&'a PyBytes> {
        let mut in_out_buffer = Vec::from(data.as_bytes());

        let cipher: ChaCha20Poly1305 = ChaCha20Poly1305::new(ChaCha20Key::from_slice(&self.key));
        let res = cipher.encrypt_in_place(nonce.as_bytes().into(), &associated_data.as_bytes(), &mut in_out_buffer);

        return match res {
            Ok(_) => Ok(
                PyBytes::new(
                    py,
                    &in_out_buffer
                )
            ),
            Err(_) => Err(CryptoError::new_err("encryption failed"))
        };
    }
}
