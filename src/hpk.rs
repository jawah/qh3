use aws_lc_rs::aead::quic::{HeaderProtectionKey, AES_128, AES_256, CHACHA20};

use crate::CryptoError;
use pyo3::pymethods;
use pyo3::types::PyBytes;
use pyo3::types::PyBytesMethods;
use pyo3::{pyclass, Bound};
use pyo3::{PyResult, Python};

const PACKET_NUMBER_LENGTH_MAX: usize = 4;
const SAMPLE_LENGTH: usize = 16;

#[pyclass(module = "qh3._hazmat")]
pub struct QUICHeaderProtection {
    hpk: HeaderProtectionKey,
}

#[pymethods]
impl QUICHeaderProtection {
    #[new]
    pub fn py_new(algorithm: &str, key: Bound<'_, PyBytes>) -> PyResult<Self> {
        let inner_hpk = match HeaderProtectionKey::new(
            match algorithm {
                "aes-128-ecb" => &AES_128,
                "aes-256-ecb" => &AES_256,
                "chacha20" => &CHACHA20,
                _ => return Err(CryptoError::new_err("Algorithm not supported")),
            },
            key.as_bytes(),
        ) {
            Ok(hpk) => hpk,
            Err(_) => {
                return Err(CryptoError::new_err(
                    "Given key is not valid for chosen algorithm",
                ))
            }
        };

        Ok(QUICHeaderProtection { hpk: inner_hpk })
    }

    pub fn apply<'a>(
        &self,
        py: Python<'a>,
        plain_header: &[u8],
        protected_payload: &[u8],
    ) -> PyResult<Bound<'a, PyBytes>> {
        let pn_length = (plain_header[0] & 0x03) as usize + 1;
        let pn_offset = plain_header.len() - pn_length;
        let sample_offset = PACKET_NUMBER_LENGTH_MAX - pn_length;

        let mask = self
            .hpk
            .new_mask(&protected_payload[sample_offset..sample_offset + SAMPLE_LENGTH])
            .map_err(|_| CryptoError::new_err("unable to issue mask protection header"))?;

        // Use PyBytes::new_with to avoid intermediate allocation
        PyBytes::new_with(py, plain_header.len() + protected_payload.len(), |buffer| {
            buffer[..plain_header.len()].copy_from_slice(plain_header);
            buffer[plain_header.len()..].copy_from_slice(protected_payload);

            if buffer[0] & 0x80 != 0 {
                buffer[0] ^= mask[0] & 0x0F;
            } else {
                buffer[0] ^= mask[0] & 0x1F;
            }

            for i in 0..pn_length {
                buffer[pn_offset + i] ^= mask[1 + i];
            }

            Ok(())
        })
    }

    pub fn remove<'a>(
        &self,
        py: Python<'a>,
        packet: &[u8],
        pn_offset: usize,
    ) -> PyResult<(Bound<'a, PyBytes>, u32)> {
        let sample_offset = pn_offset + PACKET_NUMBER_LENGTH_MAX;

        let mask = self
            .hpk
            .new_mask(&packet[sample_offset..sample_offset + SAMPLE_LENGTH])
            .map_err(|_| CryptoError::new_err("unable to issue mask protection header"))?;

        let first_byte = packet[0];
        let first_byte_mask = if first_byte & 0x80 != 0 {
            mask[0] & 0x0F
        } else {
            mask[0] & 0x1F
        };

        let pn_length = ((first_byte ^ first_byte_mask) & 0x03) as usize + 1;
        let mut pn_truncated: u32 = 0;

        let result = PyBytes::new_with(py, pn_offset + pn_length, |buffer| {
            buffer[..pn_offset].copy_from_slice(&packet[..pn_offset]);
            buffer[0] ^= first_byte_mask;

            for i in 0..pn_length {
                let b = packet[pn_offset + i] ^ mask[1 + i];
                buffer[pn_offset + i] = b;
                pn_truncated = (pn_truncated << 8) | (b as u32);
            }

            Ok(())
        })?;

        Ok((result, pn_truncated))
    }

    pub fn mask<'a>(
        &self,
        py: Python<'a>,
        sample: Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let res = self.hpk.new_mask(sample.as_bytes());

        match res {
            Err(_) => Err(CryptoError::new_err(
                "unable to issue mask protection header",
            )),
            Ok(data) => Ok(PyBytes::new(py, &data)),
        }
    }
}
