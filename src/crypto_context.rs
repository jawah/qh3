use aws_lc_rs::aead::quic::{HeaderProtectionKey, AES_128, AES_256, CHACHA20};
use aws_lc_rs::aead::{
    Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305,
};

use pyo3::pymethods;
use pyo3::types::PyBytes;
use pyo3::types::PyBytesMethods;
use pyo3::{pyclass, Bound, Py};
use pyo3::{PyResult, Python};

use crate::utils::write_uint_var;

use crate::aead::{QuicNonce, NONCE_LEN};
use crate::buffer::Buffer;
use crate::utils::decode_packet_number_internal;
use crate::CryptoError;

const PACKET_NUMBER_LENGTH_MAX: usize = 4;
const SAMPLE_LENGTH: usize = 16;

/// Identifies which AEAD algorithm is in use, so we can recreate keys
/// during key phase updates.
#[derive(Clone, Copy)]
enum AeadAlgorithm {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

/// QUIC crypto context that holds both AEAD and Header Protection keys.
#[pyclass(name = "CryptoContext", module = "qh3._hazmat")]
pub struct CryptoContext {
    key: LessSafeKey,
    iv: [u8; NONCE_LEN],
    hpk: HeaderProtectionKey,
    key_phase: u8,
    aead_alg: AeadAlgorithm,
}

#[inline]
fn resolve_aead_algorithm(name: &str) -> PyResult<AeadAlgorithm> {
    match name {
        "aes-128-gcm" => Ok(AeadAlgorithm::Aes128Gcm),
        "aes-256-gcm" => Ok(AeadAlgorithm::Aes256Gcm),
        "chacha20-poly1305" => Ok(AeadAlgorithm::ChaCha20Poly1305),
        _ => Err(CryptoError::new_err("Unsupported AEAD algorithm")),
    }
}

#[inline]
fn make_aead_key(alg: AeadAlgorithm, key_bytes: &[u8]) -> PyResult<LessSafeKey> {
    let static_alg = match alg {
        AeadAlgorithm::Aes128Gcm => &AES_128_GCM,
        AeadAlgorithm::Aes256Gcm => &AES_256_GCM,
        AeadAlgorithm::ChaCha20Poly1305 => &CHACHA20_POLY1305,
    };
    let unbound = UnboundKey::new(static_alg, key_bytes)
        .map_err(|_| CryptoError::new_err("Invalid AEAD key"))?;
    Ok(LessSafeKey::new(unbound))
}

#[pymethods]
impl CryptoContext {
    /// Create a new CryptoContext with both AEAD and HP keys.
    ///
    /// Arguments:
    ///   aead_algorithm: "aes-128-gcm", "aes-256-gcm", or "chacha20-poly1305"
    ///   hp_algorithm: "aes-128-ecb", "aes-256-ecb", or "chacha20"
    ///   key: AEAD key bytes
    ///   iv: 12-byte IV/nonce base
    ///   hp_key: Header protection key bytes
    ///   key_phase: Current key phase (0 or 1)
    #[new]
    pub fn py_new(
        aead_algorithm: &str,
        hp_algorithm: &str,
        key: Bound<'_, PyBytes>,
        iv: Bound<'_, PyBytes>,
        hp_key: Bound<'_, PyBytes>,
        key_phase: u8,
    ) -> PyResult<Self> {
        let aead_alg = resolve_aead_algorithm(aead_algorithm)?;
        let aead_key = make_aead_key(aead_alg, key.as_bytes())?;

        let hp_alg = match hp_algorithm {
            "aes-128-ecb" => &AES_128,
            "aes-256-ecb" => &AES_256,
            "chacha20" => &CHACHA20,
            _ => return Err(CryptoError::new_err("Unsupported HP algorithm")),
        };

        let hpk = HeaderProtectionKey::new(hp_alg, hp_key.as_bytes())
            .map_err(|_| CryptoError::new_err("Invalid HP key"))?;

        let iv_bytes = iv.as_bytes();
        if iv_bytes.len() != NONCE_LEN {
            return Err(CryptoError::new_err("Invalid IV length"));
        }
        let mut iv_arr = [0u8; NONCE_LEN];
        iv_arr.copy_from_slice(iv_bytes);

        Ok(CryptoContext {
            key: aead_key,
            iv: iv_arr,
            hpk,
            key_phase,
            aead_alg,
        })
    }

    #[getter]
    pub fn key_phase(&self) -> u8 {
        self.key_phase
    }

    /// Update only the AEAD key material (for key phase rotation).
    /// The HP key is preserved.
    pub fn update_aead(
        &mut self,
        key: Bound<'_, PyBytes>,
        iv: Bound<'_, PyBytes>,
        key_phase: u8,
    ) -> PyResult<()> {
        self.key = make_aead_key(self.aead_alg, key.as_bytes())?;

        let iv_bytes = iv.as_bytes();
        if iv_bytes.len() != NONCE_LEN {
            return Err(CryptoError::new_err("Invalid IV length"));
        }
        self.iv.copy_from_slice(iv_bytes);
        self.key_phase = key_phase;

        Ok(())
    }

    /// Decrypt a QUIC packet in a single call: HP removal + PN decode + AEAD decrypt.
    ///
    /// Returns (plain_header, payload, packet_number, key_phase_changed).
    /// - If key_phase_changed is true, payload is empty; caller must handle key rotation
    ///   and call decrypt_payload with the new key.
    pub fn decrypt_packet<'a>(
        &self,
        py: Python<'a>,
        packet: &[u8],
        encrypted_offset: usize,
        expected_packet_number: u64,
    ) -> PyResult<(Bound<'a, PyBytes>, Bound<'a, PyBytes>, u64, bool)> {
        let pn_offset = encrypted_offset;
        let sample_offset = pn_offset + PACKET_NUMBER_LENGTH_MAX;

        if packet.len() < sample_offset + SAMPLE_LENGTH {
            return Err(CryptoError::new_err(
                "Packet too short for header protection removal",
            ));
        }

        // 1. HP mask computation
        let mask = self
            .hpk
            .new_mask(&packet[sample_offset..sample_offset + SAMPLE_LENGTH])
            .map_err(|_| CryptoError::new_err("HP mask computation failed"))?;

        // 2. Unmask first byte
        let first_byte = packet[0];
        let first_byte_mask = if first_byte & 0x80 != 0 {
            mask[0] & 0x0F
        } else {
            mask[0] & 0x1F
        };
        let unmasked_first = first_byte ^ first_byte_mask;

        // 3. Recover packet number
        let pn_length = (unmasked_first & 0x03) as usize + 1;
        let mut pn_truncated: u64 = 0;
        for i in 0..pn_length {
            pn_truncated = (pn_truncated << 8) | ((packet[pn_offset + i] ^ mask[1 + i]) as u64);
        }

        // 4. Decode full packet number
        let pn_nbits = (pn_length * 8) as u8;
        let packet_number =
            decode_packet_number_internal(pn_truncated, pn_nbits, expected_packet_number);

        let header_len = pn_offset + pn_length;

        // 5. Key phase check (short header only)
        let key_phase_changed = if first_byte & 0x80 == 0 {
            let kp = (unmasked_first & 4) >> 2;
            kp != self.key_phase
        } else {
            false
        };

        // Build plain_header
        let plain_header = PyBytes::new_with(py, header_len, |buf| {
            buf.copy_from_slice(&packet[..header_len]);
            buf[0] = unmasked_first;
            for i in 0..pn_length {
                buf[pn_offset + i] = packet[pn_offset + i] ^ mask[1 + i];
            }
            Ok(())
        })?;

        if key_phase_changed {
            let empty = PyBytes::new(py, &[]);
            return Ok((plain_header, empty, packet_number, true));
        }

        // 6. AEAD decrypt — to_vec + in-place decrypt + correctly-sized PyBytes output
        let ciphertext = &packet[header_len..];
        let ciphertext_len = ciphertext.len();
        let tag_len = self.key.algorithm().tag_len();

        if ciphertext_len < tag_len {
            return Err(CryptoError::new_err("Ciphertext too short"));
        }

        let plaintext_len = ciphertext_len - tag_len;
        let nonce = QuicNonce::new(&self.iv, packet_number);
        let aad_ref: &[u8] = plain_header.as_bytes();

        let mut in_out_buffer = ciphertext.to_vec();
        let aad = Aad::from(aad_ref);
        let res = py.detach(|| {
            self.key.open_in_place(
                Nonce::assume_unique_for_key(nonce.0),
                aad,
                &mut in_out_buffer,
            )
        });

        match res {
            Ok(_) => {
                let payload = PyBytes::new(py, &in_out_buffer[..plaintext_len]);
                Ok((plain_header, payload, packet_number, false))
            }
            Err(_) => Err(CryptoError::new_err("Decryption failed")),
        }
    }

    /// Decrypt only the payload (AEAD) without HP removal.
    /// Used for key phase change fallback where HP was already removed.
    pub fn decrypt_payload<'a>(
        &self,
        py: Python<'a>,
        ciphertext: &[u8],
        plain_header: Bound<'_, PyBytes>,
        packet_number: u64,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let ciphertext_len = ciphertext.len();
        let tag_len = self.key.algorithm().tag_len();

        if ciphertext_len < tag_len {
            return Err(CryptoError::new_err("Ciphertext too short"));
        }

        let plaintext_len = ciphertext_len - tag_len;
        let nonce = QuicNonce::new(&self.iv, packet_number);
        let aad_ref: &[u8] = plain_header.as_bytes();

        let mut in_out_buffer = ciphertext.to_vec();
        let aad = Aad::from(aad_ref);
        let res = py.detach(|| {
            self.key.open_in_place(
                Nonce::assume_unique_for_key(nonce.0),
                aad,
                &mut in_out_buffer,
            )
        });

        match res {
            Ok(_) => Ok(PyBytes::new(py, &in_out_buffer[..plaintext_len])),
            Err(_) => Err(CryptoError::new_err("Decryption failed")),
        }
    }

    /// Encrypt a QUIC packet in a single call: AEAD encrypt + HP apply.
    ///
    /// Returns the complete protected packet (header + encrypted payload + tag)
    /// with header protection already applied.
    pub fn encrypt_packet<'a>(
        &self,
        py: Python<'a>,
        plain_header: &[u8],
        plain_payload: &[u8],
        packet_number: u64,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let header_len = plain_header.len();
        let payload_len = plain_payload.len();
        let tag_len = self.key.algorithm().tag_len();
        let total_len = header_len + payload_len + tag_len;

        let pn_length = (plain_header[0] & 0x03) as usize + 1;
        let pn_offset = header_len - pn_length;
        let sample_offset = PACKET_NUMBER_LENGTH_MAX - pn_length;

        let nonce = QuicNonce::new(&self.iv, packet_number);

        PyBytes::new_with(py, total_len, |buffer| {
            // Copy header and payload into the output buffer
            buffer[..header_len].copy_from_slice(plain_header);
            buffer[header_len..header_len + payload_len].copy_from_slice(plain_payload);

            // AEAD encrypt payload in-place
            let (header_part, payload_part) = buffer.split_at_mut(header_len);
            let aad = Aad::from(&*header_part);
            let res = py.detach(|| {
                self.key.seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(nonce.0),
                    aad,
                    &mut payload_part[..payload_len],
                )
            });
            match res {
                Ok(tag) => {
                    payload_part[payload_len..].copy_from_slice(tag.as_ref());
                }
                Err(_) => return Err(CryptoError::new_err("Encryption failed")),
            }

            // HP: compute mask from sample in encrypted payload
            let mask = self
                .hpk
                .new_mask(&payload_part[sample_offset..sample_offset + SAMPLE_LENGTH])
                .map_err(|_| CryptoError::new_err("HP mask computation failed"))?;

            // Apply mask to first byte
            if header_part[0] & 0x80 != 0 {
                header_part[0] ^= mask[0] & 0x0F;
            } else {
                header_part[0] ^= mask[0] & 0x1F;
            }

            // Apply mask to PN bytes
            for i in 0..pn_length {
                header_part[pn_offset + i] ^= mask[1 + i];
            }

            Ok(())
        })
    }

    /// Finalize a QUIC packet in-place in the buffer: write header, pad,
    /// AEAD encrypt, and apply HP — all in a single Rust call.
    ///
    /// Arguments:
    ///   buffer: The packet builder's write buffer (must be Owned/mutable)
    ///   packet_start: Offset where this packet begins in the buffer
    ///   packet_size: Current packet size (header_size + payload written so far)
    ///   padding_size: Number of zero-padding bytes to add after payload
    ///   header_size: Size of the reserved header area
    ///   is_long_header: Whether this is a long header packet
    ///   version: QUIC version (used for long headers)
    ///   packet_type: Packet type (0=INITIAL, 1=ZERO_RTT, 2=HANDSHAKE) for long headers
    ///   peer_cid: Destination connection ID
    ///   host_cid: Source connection ID (long headers only)
    ///   peer_token: Token bytes (INITIAL packets only)
    ///   spin_bit: Spin bit value (short headers only)
    ///   packet_number: Packet number
    ///
    /// Returns: sent_bytes (total size of the finalized encrypted packet)
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (buffer, packet_start, packet_size, padding_size, header_size,
                        is_long_header, version, packet_type, peer_cid, host_cid,
                        peer_token, spin_bit, packet_number))]
    pub fn finalize_packet(
        &self,
        py: Python<'_>,
        buffer: Py<Buffer>,
        packet_start: usize,
        packet_size: usize,
        padding_size: usize,
        header_size: usize,
        is_long_header: bool,
        version: u32,
        packet_type: u8,
        peer_cid: &[u8],
        host_cid: &[u8],
        peer_token: &[u8],
        spin_bit: u8,
        packet_number: u64,
    ) -> PyResult<usize> {
        let mut buf_ref = buffer.borrow_mut(py);
        let buf_data = buf_ref.data_mut()?;

        let total_packet_size = packet_size + padding_size;
        let payload_start = packet_start + header_size;
        let payload_end = packet_start + total_packet_size;

        // 1. Write padding zeros
        if padding_size > 0 {
            let pad_start = packet_start + packet_size;
            for i in 0..padding_size {
                buf_data[pad_start + i] = 0;
            }
        }

        // 2. Build header at packet_start
        // PACKET_NUMBER_SEND_SIZE is always 2
        const PN_SEND_SIZE: usize = 2;
        let tag_len = self.key.algorithm().tag_len();

        if is_long_header {
            // Encode first byte for long header
            let long_type_bits = encode_long_type(version, packet_type);
            let first_byte: u8 = 0x80 | 0x40 | (long_type_bits << 4) | (PN_SEND_SIZE as u8 - 1);

            let mut pos = packet_start;
            buf_data[pos] = first_byte;
            pos += 1;

            // Version (4 bytes)
            buf_data[pos..pos + 4].copy_from_slice(&version.to_be_bytes());
            pos += 4;

            // Destination CID
            buf_data[pos] = peer_cid.len() as u8;
            pos += 1;
            buf_data[pos..pos + peer_cid.len()].copy_from_slice(peer_cid);
            pos += peer_cid.len();

            // Source CID
            buf_data[pos] = host_cid.len() as u8;
            pos += 1;
            buf_data[pos..pos + host_cid.len()].copy_from_slice(host_cid);
            pos += host_cid.len();

            // Token (INITIAL only, packet_type == 0)
            if packet_type == 0 {
                let token_len = peer_token.len() as u64;
                pos += write_uint_var(&mut buf_data[pos..], token_len);
                buf_data[pos..pos + peer_token.len()].copy_from_slice(peer_token);
                pos += peer_token.len();
            }

            // Length field: payload_size + PN_SEND_SIZE + tag_len
            // QUIC "length" covers from PN through end of AEAD tag
            let payload_size = total_packet_size - header_size;
            let length = (payload_size + PN_SEND_SIZE + tag_len) as u16;
            // Always encode as 2-byte varint (with 0x4000 prefix)
            buf_data[pos..pos + 2].copy_from_slice(&(length | 0x4000).to_be_bytes());
            pos += 2;

            // Packet number (2 bytes)
            buf_data[pos..pos + 2].copy_from_slice(&(packet_number as u16).to_be_bytes());
        } else {
            // Short header
            let first_byte: u8 =
                0x40 | (spin_bit << 5) | (self.key_phase << 2) | (PN_SEND_SIZE as u8 - 1);

            let mut pos = packet_start;
            buf_data[pos] = first_byte;
            pos += 1;

            // Destination CID
            buf_data[pos..pos + peer_cid.len()].copy_from_slice(peer_cid);
            pos += peer_cid.len();

            // Packet number (2 bytes)
            buf_data[pos..pos + 2].copy_from_slice(&(packet_number as u16).to_be_bytes());
        }

        // 3. AEAD encrypt payload in-place
        let payload_len = payload_end - payload_start;
        let nonce = QuicNonce::new(&self.iv, packet_number);

        // Build AAD from the header we just wrote
        let (header_slice, payload_slice) = buf_data[packet_start..].split_at_mut(header_size);
        let aad = Aad::from(&*header_slice);
        let res = py.detach(|| {
            self.key.seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce.0),
                aad,
                &mut payload_slice[..payload_len],
            )
        });
        match res {
            Ok(tag) => {
                payload_slice[payload_len..payload_len + tag_len].copy_from_slice(tag.as_ref());
            }
            Err(_) => return Err(CryptoError::new_err("Encryption failed")),
        }

        // 4. Apply Header Protection
        let pn_length = PN_SEND_SIZE;
        let pn_offset = header_size - pn_length;
        let sample_offset = PACKET_NUMBER_LENGTH_MAX - pn_length;

        // Recompute header/payload split for HP (need fresh references)
        let buf_slice = &mut buf_data[packet_start..];
        let encrypted_payload = &buf_slice[header_size..];
        let mask = self
            .hpk
            .new_mask(&encrypted_payload[sample_offset..sample_offset + SAMPLE_LENGTH])
            .map_err(|_| CryptoError::new_err("HP mask computation failed"))?;

        // Apply mask to first byte
        if buf_slice[0] & 0x80 != 0 {
            buf_slice[0] ^= mask[0] & 0x0F;
        } else {
            buf_slice[0] ^= mask[0] & 0x1F;
        }

        // Apply mask to PN bytes
        for i in 0..pn_length {
            buf_slice[pn_offset + i] ^= mask[1 + i];
        }

        // 5. Update buffer position
        let sent_bytes = header_size + payload_len + tag_len;
        buf_ref.set_pos(packet_start + sent_bytes);

        Ok(sent_bytes)
    }
}

/// Encode the long header type bits (2 bits) for a given version and packet type.
#[inline]
fn encode_long_type(version: u32, packet_type: u8) -> u8 {
    const QUIC_VERSION_2: u32 = 0x6B3343CF;
    if version == QUIC_VERSION_2 {
        // V2 encoding: INITIAL=1, ZERO_RTT=2, HANDSHAKE=3, RETRY=0
        match packet_type {
            0 => 1, // INITIAL
            1 => 2, // ZERO_RTT
            2 => 3, // HANDSHAKE
            3 => 0, // RETRY
            _ => 0,
        }
    } else {
        // V1 encoding: INITIAL=0, ZERO_RTT=1, HANDSHAKE=2, RETRY=3
        packet_type
    }
}
