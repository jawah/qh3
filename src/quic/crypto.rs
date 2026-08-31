//! Native QUIC packet protection and key storage.

use std::error::Error;
use std::fmt;
use std::time::Duration;

use aws_lc_rs::aead::quic::{HeaderProtectionKey, AES_128, AES_256, CHACHA20};
use aws_lc_rs::aead::{
    Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305,
};
use aws_lc_rs::hkdf::{Algorithm as HkdfAlgorithm, KeyType, Salt, HKDF_SHA256, HKDF_SHA384};

use super::packet_builder::{PacketProtector, ProtectionInput};
use super::types::{Epoch, PacketType, Role};
use crate::aead::{QuicNonce, NONCE_LEN};
use crate::utils::decode_packet_number_internal;

const MAX_PACKET_NUMBER_LEN: usize = 4;
const SAMPLE_LEN: usize = 16;
const QUIC_V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const QUIC_V2_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AeadAlgorithm {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderProtectionAlgorithm {
    Aes128,
    Aes256,
    ChaCha20,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CryptoError {
    InvalidKey,
    InvalidHeaderProtectionKey,
    InvalidIv,
    InvalidKeyPhase,
    MissingKey(Epoch),
    PacketTooShort,
    InvalidHeader,
    HeaderProtection,
    Encrypt,
    Decrypt,
    LengthOverflow,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey => f.write_str("invalid AEAD key"),
            Self::InvalidHeaderProtectionKey => f.write_str("invalid header protection key"),
            Self::InvalidIv => f.write_str("invalid IV length"),
            Self::InvalidKeyPhase => f.write_str("invalid key phase"),
            Self::MissingKey(epoch) => write!(f, "missing {epoch:?} packet key"),
            Self::PacketTooShort => f.write_str("packet too short"),
            Self::InvalidHeader => f.write_str("invalid QUIC header"),
            Self::HeaderProtection => f.write_str("header protection failed"),
            Self::Encrypt => f.write_str("encryption failed"),
            Self::Decrypt => f.write_str("decryption failed"),
            Self::LengthOverflow => f.write_str("packet length overflow"),
        }
    }
}

impl Error for CryptoError {}

pub struct UnprotectedHeader {
    pub header: Vec<u8>,
    pub packet_number: u64,
    pub key_phase: u8,
}

#[derive(Debug)]
pub struct DecryptedPacket {
    pub header: Vec<u8>,
    pub payload: Vec<u8>,
    pub packet_number: u64,
}

/// AEAD and header-protection material for one traffic direction and epoch.
pub struct PacketKey {
    key: LessSafeKey,
    iv: [u8; NONCE_LEN],
    header_key: HeaderProtectionKey,
    key_phase: u8,
    aead_algorithm: AeadAlgorithm,
    hp_algorithm: HeaderProtectionAlgorithm,
    hp_key: Vec<u8>,
    traffic_secret: Option<Vec<u8>>,
    version: u32,
}

impl PacketKey {
    pub fn new(
        aead_algorithm: AeadAlgorithm,
        hp_algorithm: HeaderProtectionAlgorithm,
        key: &[u8],
        iv: &[u8],
        hp_key: &[u8],
        key_phase: u8,
    ) -> Result<Self, CryptoError> {
        if key_phase > 1 {
            return Err(CryptoError::InvalidKeyPhase);
        }
        let mut iv_array = [0; NONCE_LEN];
        if iv.len() != iv_array.len() {
            return Err(CryptoError::InvalidIv);
        }
        iv_array.copy_from_slice(iv);

        Ok(Self {
            key: make_aead_key(aead_algorithm, key)?,
            iv: iv_array,
            header_key: make_header_key(hp_algorithm, hp_key)?,
            key_phase,
            aead_algorithm,
            hp_algorithm,
            hp_key: hp_key.to_vec(),
            traffic_secret: None,
            version: 0x0000_0001,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_traffic_secret(
        aead_algorithm: AeadAlgorithm,
        hp_algorithm: HeaderProtectionAlgorithm,
        key: &[u8],
        iv: &[u8],
        hp_key: &[u8],
        key_phase: u8,
        traffic_secret: &[u8],
        version: u32,
    ) -> Result<Self, CryptoError> {
        let expected_secret_len = match aead_algorithm {
            AeadAlgorithm::Aes256Gcm => 48,
            AeadAlgorithm::Aes128Gcm | AeadAlgorithm::ChaCha20Poly1305 => 32,
        };
        if traffic_secret.len() != expected_secret_len {
            return Err(CryptoError::InvalidKey);
        }
        let mut packet_key = Self::new(aead_algorithm, hp_algorithm, key, iv, hp_key, key_phase)?;
        packet_key.traffic_secret = Some(traffic_secret.to_vec());
        packet_key.version = version;
        Ok(packet_key)
    }

    pub fn key_phase(&self) -> u8 {
        self.key_phase
    }

    pub fn tag_len(&self) -> usize {
        self.key.algorithm().tag_len()
    }

    fn next_key_phase(&self) -> Result<Self, CryptoError> {
        let secret = self
            .traffic_secret
            .as_ref()
            .ok_or(CryptoError::InvalidKeyPhase)?;
        let hash = traffic_secret_hash(self.aead_algorithm);
        let prk = aws_lc_rs::hkdf::Prk::new_less_safe(hash, secret);
        let next_secret = expand_label(&prk, b"quic ku", secret.len())?;
        let next_prk = aws_lc_rs::hkdf::Prk::new_less_safe(hash, &next_secret);
        let prefix: &[u8] = if self.version == 0x6b33_43cf {
            b"quicv2"
        } else {
            b"quic"
        };
        let key_len = match self.aead_algorithm {
            AeadAlgorithm::Aes128Gcm => 16,
            AeadAlgorithm::Aes256Gcm | AeadAlgorithm::ChaCha20Poly1305 => 32,
        };
        let key = expand_label(&next_prk, &[prefix, b" key"].concat(), key_len)?;
        let iv = expand_label(&next_prk, &[prefix, b" iv"].concat(), NONCE_LEN)?;
        let mut next = Self::with_traffic_secret(
            self.aead_algorithm,
            self.hp_algorithm,
            &key,
            &iv,
            &self.hp_key,
            self.key_phase ^ 1,
            &next_secret,
            self.version,
        )?;
        // qh3 intentionally keeps the originally installed HP key across phases.
        next.hp_key.clone_from(&self.hp_key);
        Ok(next)
    }

    pub fn remove_header(
        &self,
        packet: &[u8],
        packet_number_offset: usize,
        expected_packet_number: u64,
    ) -> Result<UnprotectedHeader, CryptoError> {
        let sample_offset = packet_number_offset
            .checked_add(MAX_PACKET_NUMBER_LEN)
            .ok_or(CryptoError::LengthOverflow)?;
        let sample_end = sample_offset
            .checked_add(SAMPLE_LEN)
            .ok_or(CryptoError::LengthOverflow)?;
        let sample = packet
            .get(sample_offset..sample_end)
            .ok_or(CryptoError::PacketTooShort)?;
        let first = *packet.first().ok_or(CryptoError::PacketTooShort)?;
        let mask = self
            .header_key
            .new_mask(sample)
            .map_err(|_| CryptoError::HeaderProtection)?;
        let first_mask = if first & 0x80 == 0 {
            mask[0] & 0x1f
        } else {
            mask[0] & 0x0f
        };
        let unmasked_first = first ^ first_mask;
        let packet_number_len = usize::from(unmasked_first & 0x03) + 1;
        let header_len = packet_number_offset
            .checked_add(packet_number_len)
            .ok_or(CryptoError::LengthOverflow)?;
        let protected_number = packet
            .get(packet_number_offset..header_len)
            .ok_or(CryptoError::PacketTooShort)?;

        let mut truncated = 0_u64;
        let mut header = packet[..header_len].to_vec();
        header[0] = unmasked_first;
        for (index, byte) in protected_number.iter().enumerate() {
            let plain = *byte ^ mask[index + 1];
            header[packet_number_offset + index] = plain;
            truncated = (truncated << 8) | u64::from(plain);
        }

        Ok(UnprotectedHeader {
            header,
            packet_number: decode_packet_number_internal(
                truncated,
                (packet_number_len * 8) as u8,
                expected_packet_number,
            ),
            key_phase: if first & 0x80 == 0 {
                (unmasked_first >> 2) & 1
            } else {
                self.key_phase
            },
        })
    }

    pub fn decrypt_payload(
        &self,
        ciphertext: &[u8],
        header: &[u8],
        packet_number: u64,
    ) -> Result<Vec<u8>, CryptoError> {
        let plaintext_len = ciphertext
            .len()
            .checked_sub(self.tag_len())
            .ok_or(CryptoError::PacketTooShort)?;
        let mut payload = ciphertext.to_vec();
        self.key
            .open_in_place(
                Nonce::assume_unique_for_key(QuicNonce::new(&self.iv, packet_number).0),
                Aad::from(header),
                &mut payload,
            )
            .map_err(|_| CryptoError::Decrypt)?;
        payload.truncate(plaintext_len);
        Ok(payload)
    }

    #[cfg(test)]
    pub fn decrypt_packet(
        &self,
        packet: &[u8],
        packet_number_offset: usize,
        expected_packet_number: u64,
    ) -> Result<DecryptedPacket, CryptoError> {
        let unprotected =
            self.remove_header(packet, packet_number_offset, expected_packet_number)?;
        let ciphertext = packet
            .get(unprotected.header.len()..)
            .ok_or(CryptoError::PacketTooShort)?;
        let payload =
            self.decrypt_payload(ciphertext, &unprotected.header, unprotected.packet_number)?;
        Ok(DecryptedPacket {
            header: unprotected.header,
            payload,
            packet_number: unprotected.packet_number,
        })
    }

    pub fn protect_packet(
        &self,
        mut packet: Vec<u8>,
        header_len: usize,
        packet_number: u64,
    ) -> Result<Vec<u8>, CryptoError> {
        let plain_header = packet.get(..header_len).ok_or(CryptoError::InvalidHeader)?;
        let first = *plain_header.first().ok_or(CryptoError::InvalidHeader)?;
        let packet_number_len = usize::from(first & 0x03) + 1;
        let packet_number_offset = plain_header
            .len()
            .checked_sub(packet_number_len)
            .ok_or(CryptoError::InvalidHeader)?;
        let sample_offset = MAX_PACKET_NUMBER_LEN
            .checked_sub(packet_number_len)
            .ok_or(CryptoError::InvalidHeader)?;
        let protected_payload_len = packet
            .len()
            .checked_sub(header_len)
            .ok_or(CryptoError::InvalidHeader)?
            .checked_add(self.tag_len())
            .ok_or(CryptoError::LengthOverflow)?;
        if protected_payload_len < sample_offset + SAMPLE_LEN {
            return Err(CryptoError::PacketTooShort);
        }
        let total_len = header_len
            .checked_add(protected_payload_len)
            .ok_or(CryptoError::LengthOverflow)?;
        packet.reserve(total_len - packet.len());
        let tag = {
            let (plain_header, plain_payload) = packet.split_at_mut(header_len);
            self.key
                .seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(QuicNonce::new(&self.iv, packet_number).0),
                    Aad::from(&*plain_header),
                    plain_payload,
                )
                .map_err(|_| CryptoError::Encrypt)?
        };
        packet.extend_from_slice(tag.as_ref());

        let sample_start = header_len + sample_offset;
        let sample_end = sample_start + SAMPLE_LEN;
        let mask = self
            .header_key
            .new_mask(&packet[sample_start..sample_end])
            .map_err(|_| CryptoError::HeaderProtection)?;
        packet[0] ^= mask[0] & if first & 0x80 == 0 { 0x1f } else { 0x0f };
        for index in 0..packet_number_len {
            packet[packet_number_offset + index] ^= mask[index + 1];
        }
        Ok(packet)
    }
}

impl PacketProtector for PacketKey {
    type Error = CryptoError;

    fn tag_len(&self) -> usize {
        PacketKey::tag_len(self)
    }

    fn protect(&mut self, input: ProtectionInput) -> Result<Vec<u8>, Self::Error> {
        self.protect_packet(input.packet, input.header_len, input.packet_number)
    }
}

/// Packet crypto boundary intended for the native connection state machine.
pub trait PacketCrypto {
    fn protect(
        &mut self,
        epoch: Epoch,
        packet: Vec<u8>,
        header_len: usize,
        packet_number: u64,
    ) -> Result<Vec<u8>, CryptoError>;
    fn decrypt(
        &mut self,
        epoch: Epoch,
        packet: &[u8],
        packet_number_offset: usize,
        expected_packet_number: u64,
    ) -> Result<DecryptedPacket, CryptoError>;
}

#[derive(Default)]
struct EpochKeys {
    send: Option<PacketKey>,
    receive: Option<PacketKey>,
    previous_receive: Option<PacketKey>,
    previous_receive_expires_at: Option<Duration>,
    receive_largest: Option<u64>,
}

/// Per-epoch, per-direction packet keys owned entirely by the Rust QUIC core.
#[derive(Default)]
pub struct CryptoState {
    initial: EpochKeys,
    zero_rtt: EpochKeys,
    handshake: EpochKeys,
    one_rtt: EpochKeys,
    send_update_unacked: bool,
    send_update_start: Option<u64>,
}

impl CryptoState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_initial(
        version: u32,
        destination_cid: &[u8],
        role: Role,
    ) -> Result<Self, CryptoError> {
        let (client, server) = derive_initial_keys(version, destination_cid)?;
        let mut state = Self::new();
        match role {
            Role::Client => {
                state.install_send(Epoch::Initial, client);
                state.install_receive(Epoch::Initial, server);
            }
            Role::Server => {
                state.install_send(Epoch::Initial, server);
                state.install_receive(Epoch::Initial, client);
            }
        }
        Ok(state)
    }

    pub fn install_send(&mut self, epoch: Epoch, key: PacketKey) {
        self.epoch_mut(epoch).send = Some(key);
        if epoch == Epoch::OneRtt {
            self.send_update_unacked = false;
            self.send_update_start = None;
        }
    }

    pub fn install_receive(&mut self, epoch: Epoch, key: PacketKey) {
        let keys = self.epoch_mut(epoch);
        let retain_previous = epoch == Epoch::OneRtt
            && keys
                .receive
                .as_ref()
                .is_some_and(|current| current.key_phase() != key.key_phase());
        let previous = keys.receive.replace(key);
        keys.previous_receive = retain_previous.then_some(previous).flatten();
        keys.previous_receive_expires_at = None;
        keys.receive_largest = None;
    }

    pub fn discard(&mut self, epoch: Epoch) {
        *self.epoch_mut(epoch) = EpochKeys::default();
    }

    pub fn send_key_phase(&self) -> Option<u8> {
        self.one_rtt.send.as_ref().map(PacketKey::key_phase)
    }

    pub fn has_send_key(&self, epoch: Epoch) -> bool {
        self.epoch(epoch).send.is_some()
    }

    pub fn receive_key_phase(&self) -> Option<u8> {
        self.one_rtt.receive.as_ref().map(PacketKey::key_phase)
    }

    pub fn request_key_update(
        &mut self,
        now: Duration,
        retention: Duration,
    ) -> Result<(), CryptoError> {
        if self.send_update_unacked {
            return Err(CryptoError::InvalidKeyPhase);
        }
        let keys = &mut self.one_rtt;
        let send = keys
            .send
            .as_ref()
            .ok_or(CryptoError::MissingKey(Epoch::OneRtt))?;
        let receive = keys
            .receive
            .as_ref()
            .ok_or(CryptoError::MissingKey(Epoch::OneRtt))?;
        if send.key_phase() != receive.key_phase() {
            return Err(CryptoError::InvalidKeyPhase);
        }
        let next_send = send.next_key_phase()?;
        let next_receive = receive.next_key_phase()?;
        keys.send = Some(next_send);
        keys.previous_receive = keys.receive.replace(next_receive);
        keys.previous_receive_expires_at = Some(add_duration(now, retention));
        keys.receive_largest = None;
        self.send_update_unacked = true;
        self.send_update_start = None;
        Ok(())
    }

    pub fn acknowledge_one_rtt(&mut self, largest_acked: u64) {
        if self
            .send_update_start
            .is_some_and(|start| largest_acked >= start)
        {
            self.send_update_unacked = false;
            self.send_update_start = None;
        }
    }

    pub fn expire_previous_receive(&mut self, now: Duration) {
        if self
            .one_rtt
            .previous_receive_expires_at
            .is_some_and(|deadline| deadline <= now)
        {
            self.one_rtt.previous_receive = None;
            self.one_rtt.previous_receive_expires_at = None;
        }
    }

    pub fn decrypt_one_rtt(
        &mut self,
        packet: &[u8],
        packet_number_offset: usize,
        expected_packet_number: u64,
        now: Duration,
        retention: Duration,
    ) -> Result<DecryptedPacket, CryptoError> {
        self.expire_previous_receive(now);
        let keys = &mut self.one_rtt;
        let current = keys
            .receive
            .as_ref()
            .ok_or(CryptoError::MissingKey(Epoch::OneRtt))?;
        let unprotected =
            current.remove_header(packet, packet_number_offset, expected_packet_number)?;

        if unprotected.key_phase == current.key_phase() {
            let decrypted = decrypt_unprotected(current, packet, &unprotected)?;
            keys.receive_largest =
                Some(keys.receive_largest.map_or(decrypted.packet_number, |pn| {
                    pn.max(decrypted.packet_number)
                }));
            return Ok(decrypted);
        }

        if let Some(previous) = keys
            .previous_receive
            .as_ref()
            .filter(|key| key.key_phase() == unprotected.key_phase)
        {
            if let Ok(decrypted) = decrypt_unprotected(previous, packet, &unprotected) {
                return Ok(decrypted);
            }
        }
        if keys
            .receive_largest
            .is_some_and(|largest| unprotected.packet_number <= largest)
        {
            return Err(CryptoError::InvalidKeyPhase);
        }

        let next_receive = current.next_key_phase()?;
        let decrypted = decrypt_unprotected(&next_receive, packet, &unprotected)?;
        let old_phase = current.key_phase();
        let next_phase = next_receive.key_phase();
        let next_send = match keys.send.as_ref() {
            Some(send) if send.key_phase() == old_phase => Some(send.next_key_phase()?),
            Some(send) if send.key_phase() == next_phase => None,
            Some(_) => return Err(CryptoError::InvalidKeyPhase),
            None => return Err(CryptoError::MissingKey(Epoch::OneRtt)),
        };
        if let Some(send) = next_send {
            keys.send = Some(send);
            self.send_update_unacked = true;
            self.send_update_start = None;
        }
        keys.previous_receive = keys.receive.replace(next_receive);
        keys.previous_receive_expires_at = Some(add_duration(now, retention));
        keys.receive_largest = Some(decrypted.packet_number);
        Ok(decrypted)
    }

    fn epoch(&self, epoch: Epoch) -> &EpochKeys {
        match epoch {
            Epoch::Initial => &self.initial,
            Epoch::ZeroRtt => &self.zero_rtt,
            Epoch::Handshake => &self.handshake,
            Epoch::OneRtt => &self.one_rtt,
        }
    }

    fn epoch_mut(&mut self, epoch: Epoch) -> &mut EpochKeys {
        match epoch {
            Epoch::Initial => &mut self.initial,
            Epoch::ZeroRtt => &mut self.zero_rtt,
            Epoch::Handshake => &mut self.handshake,
            Epoch::OneRtt => &mut self.one_rtt,
        }
    }
}

impl PacketCrypto for CryptoState {
    fn protect(
        &mut self,
        epoch: Epoch,
        packet: Vec<u8>,
        header_len: usize,
        packet_number: u64,
    ) -> Result<Vec<u8>, CryptoError> {
        let protected = self
            .epoch(epoch)
            .send
            .as_ref()
            .ok_or(CryptoError::MissingKey(epoch))?
            .protect_packet(packet, header_len, packet_number)?;
        if epoch == Epoch::OneRtt && self.send_update_unacked && self.send_update_start.is_none() {
            self.send_update_start = Some(packet_number);
        }
        Ok(protected)
    }

    fn decrypt(
        &mut self,
        epoch: Epoch,
        packet: &[u8],
        packet_number_offset: usize,
        expected_packet_number: u64,
    ) -> Result<DecryptedPacket, CryptoError> {
        let keys = self.epoch(epoch);
        let current = keys
            .receive
            .as_ref()
            .ok_or(CryptoError::MissingKey(epoch))?;
        let unprotected =
            current.remove_header(packet, packet_number_offset, expected_packet_number)?;
        let key = if epoch == Epoch::OneRtt && unprotected.key_phase != current.key_phase() {
            keys.previous_receive
                .as_ref()
                .filter(|key| key.key_phase() == unprotected.key_phase)
                .ok_or(CryptoError::InvalidKeyPhase)?
        } else {
            current
        };
        let ciphertext = packet
            .get(unprotected.header.len()..)
            .ok_or(CryptoError::PacketTooShort)?;
        let payload =
            key.decrypt_payload(ciphertext, &unprotected.header, unprotected.packet_number)?;
        Ok(DecryptedPacket {
            header: unprotected.header,
            payload,
            packet_number: unprotected.packet_number,
        })
    }
}

fn decrypt_unprotected(
    key: &PacketKey,
    packet: &[u8],
    unprotected: &UnprotectedHeader,
) -> Result<DecryptedPacket, CryptoError> {
    let ciphertext = packet
        .get(unprotected.header.len()..)
        .ok_or(CryptoError::PacketTooShort)?;
    let payload =
        key.decrypt_payload(ciphertext, &unprotected.header, unprotected.packet_number)?;
    Ok(DecryptedPacket {
        header: unprotected.header.clone(),
        payload,
        packet_number: unprotected.packet_number,
    })
}

fn add_duration(now: Duration, duration: Duration) -> Duration {
    now.checked_add(duration).unwrap_or(Duration::MAX)
}

pub fn derive_initial_keys(
    version: u32,
    destination_cid: &[u8],
) -> Result<(PacketKey, PacketKey), CryptoError> {
    let (salt, label_prefix): (&[u8], &[u8]) = match version {
        0x0000_0001 => (&QUIC_V1_SALT, b"quic"),
        0x6b33_43cf => (&QUIC_V2_SALT, b"quicv2"),
        // Unknown versions use the v1 construction solely to produce an
        // Initial which elicits Version Negotiation from the server.
        _ => (&QUIC_V1_SALT, b"quic"),
    };
    let initial_secret = Salt::new(HKDF_SHA256, salt).extract(destination_cid);
    let client_secret = expand_label(&initial_secret, b"client in", 32)?;
    let server_secret = expand_label(&initial_secret, b"server in", 32)?;
    Ok((
        initial_packet_key(&client_secret, label_prefix)?,
        initial_packet_key(&server_secret, label_prefix)?,
    ))
}

fn initial_packet_key(secret: &[u8], prefix: &[u8]) -> Result<PacketKey, CryptoError> {
    let prk = aws_lc_rs::hkdf::Prk::new_less_safe(HKDF_SHA256, secret);
    let key_label = [prefix, b" key"].concat();
    let iv_label = [prefix, b" iv"].concat();
    let hp_label = [prefix, b" hp"].concat();
    let key = expand_label(&prk, &key_label, 16)?;
    let iv = expand_label(&prk, &iv_label, NONCE_LEN)?;
    let hp = expand_label(&prk, &hp_label, 16)?;
    PacketKey::new(
        AeadAlgorithm::Aes128Gcm,
        HeaderProtectionAlgorithm::Aes128,
        &key,
        &iv,
        &hp,
        0,
    )
}

#[derive(Clone, Copy)]
struct OutputLen(usize);

impl KeyType for OutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

fn expand_label(
    secret: &aws_lc_rs::hkdf::Prk,
    label: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let full_label_len = 6_usize
        .checked_add(label.len())
        .ok_or(CryptoError::LengthOverflow)?;
    if output_len > u16::MAX as usize || full_label_len > u8::MAX as usize {
        return Err(CryptoError::LengthOverflow);
    }
    let mut info = Vec::with_capacity(4 + full_label_len);
    info.extend_from_slice(&(output_len as u16).to_be_bytes());
    info.push(full_label_len as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0); // Empty HKDF context.
    let mut output = vec![0; output_len];
    secret
        .expand(&[&info], OutputLen(output_len))
        .map_err(|_| CryptoError::InvalidKey)?
        .fill(&mut output)
        .map_err(|_| CryptoError::InvalidKey)?;
    Ok(output)
}

fn traffic_secret_hash(algorithm: AeadAlgorithm) -> HkdfAlgorithm {
    match algorithm {
        AeadAlgorithm::Aes256Gcm => HKDF_SHA384,
        AeadAlgorithm::Aes128Gcm | AeadAlgorithm::ChaCha20Poly1305 => HKDF_SHA256,
    }
}

fn make_aead_key(algorithm: AeadAlgorithm, key: &[u8]) -> Result<LessSafeKey, CryptoError> {
    let algorithm = match algorithm {
        AeadAlgorithm::Aes128Gcm => &AES_128_GCM,
        AeadAlgorithm::Aes256Gcm => &AES_256_GCM,
        AeadAlgorithm::ChaCha20Poly1305 => &CHACHA20_POLY1305,
    };
    UnboundKey::new(algorithm, key)
        .map(LessSafeKey::new)
        .map_err(|_| CryptoError::InvalidKey)
}

fn make_header_key(
    algorithm: HeaderProtectionAlgorithm,
    key: &[u8],
) -> Result<HeaderProtectionKey, CryptoError> {
    let algorithm = match algorithm {
        HeaderProtectionAlgorithm::Aes128 => &AES_128,
        HeaderProtectionAlgorithm::Aes256 => &AES_256,
        HeaderProtectionAlgorithm::ChaCha20 => &CHACHA20,
    };
    HeaderProtectionKey::new(algorithm, key).map_err(|_| CryptoError::InvalidHeaderProtectionKey)
}

fn packet_type_epoch(packet_type: PacketType) -> Option<Epoch> {
    match packet_type {
        PacketType::Initial => Some(Epoch::Initial),
        PacketType::ZeroRtt => Some(Epoch::ZeroRtt),
        PacketType::Handshake => Some(Epoch::Handshake),
        PacketType::OneRtt => Some(Epoch::OneRtt),
        PacketType::Retry | PacketType::VersionNegotiation => None,
    }
}

impl PacketProtector for CryptoState {
    type Error = CryptoError;

    fn tag_len(&self) -> usize {
        self.initial
            .send
            .as_ref()
            .or(self.handshake.send.as_ref())
            .or(self.zero_rtt.send.as_ref())
            .or(self.one_rtt.send.as_ref())
            .map_or(16, PacketKey::tag_len)
    }

    fn protect(&mut self, input: ProtectionInput) -> Result<Vec<u8>, Self::Error> {
        let epoch = packet_type_epoch(input.packet_type).ok_or(CryptoError::InvalidHeader)?;
        PacketCrypto::protect(
            self,
            epoch,
            input.packet,
            input.header_len,
            input.packet_number,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn protect(key: &PacketKey, header: &[u8], payload: &[u8], packet_number: u64) -> Vec<u8> {
        let mut packet = Vec::with_capacity(header.len() + payload.len() + key.tag_len());
        packet.extend_from_slice(header);
        packet.extend_from_slice(payload);
        key.protect_packet(packet, header.len(), packet_number)
            .unwrap()
    }

    #[test]
    fn rfc_9001_client_initial_key_material() {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let initial_secret = Salt::new(HKDF_SHA256, &QUIC_V1_SALT).extract(&dcid);
        let client_secret = expand_label(&initial_secret, b"client in", 32).unwrap();
        let prk = aws_lc_rs::hkdf::Prk::new_less_safe(HKDF_SHA256, &client_secret);

        assert_eq!(
            expand_label(&prk, b"quic key", 16).unwrap(),
            [
                0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1,
                0xa2, 0x2d
            ]
        );
        assert_eq!(
            expand_label(&prk, b"quic iv", 12).unwrap(),
            [0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c]
        );
        assert_eq!(
            expand_label(&prk, b"quic hp", 16).unwrap(),
            [
                0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad,
                0xed, 0xd2
            ]
        );
    }

    #[test]
    fn packet_protection_roundtrip_and_bounds_checks() {
        let key = [7; 16];
        let iv = [8; NONCE_LEN];
        let hp = [9; 16];
        let sender = PacketKey::new(
            AeadAlgorithm::Aes128Gcm,
            HeaderProtectionAlgorithm::Aes128,
            &key,
            &iv,
            &hp,
            1,
        )
        .unwrap();
        let receiver = PacketKey::new(
            AeadAlgorithm::Aes128Gcm,
            HeaderProtectionAlgorithm::Aes128,
            &key,
            &iv,
            &hp,
            1,
        )
        .unwrap();
        let header = [0x45, 0xaa, 0xbb, 0x12, 0x34];
        let payload = b"native packet crypto";
        let mut plaintext = Vec::with_capacity(header.len() + payload.len() + sender.tag_len());
        plaintext.extend_from_slice(&header);
        plaintext.extend_from_slice(payload);
        let allocation = plaintext.as_ptr();
        let packet = sender
            .protect_packet(plaintext, header.len(), 0x1234)
            .unwrap();
        assert_eq!(packet.as_ptr(), allocation);
        let decrypted = receiver.decrypt_packet(&packet, 3, 0x1234).unwrap();
        assert_eq!(decrypted.header, header);
        assert_eq!(decrypted.payload, payload);
        assert_eq!(decrypted.packet_number, 0x1234);
        assert_eq!(receiver.key_phase(), 1);

        assert_eq!(
            receiver.decrypt_packet(&[], usize::MAX, 0).unwrap_err(),
            CryptoError::LengthOverflow
        );
        assert_eq!(
            sender.protect_packet(payload.to_vec(), 0, 0).unwrap_err(),
            CryptoError::InvalidHeader
        );
    }

    #[test]
    fn receive_key_update_retains_previous_phase() {
        let make_key = |phase| {
            PacketKey::new(
                AeadAlgorithm::Aes128Gcm,
                HeaderProtectionAlgorithm::Aes128,
                &[phase + 1; 16],
                &[phase + 2; NONCE_LEN],
                &[4; 16],
                phase,
            )
            .unwrap()
        };
        let old_sender = make_key(0);
        let new_sender = make_key(1);
        let mut state = CryptoState::new();
        state.install_receive(Epoch::OneRtt, make_key(0));
        state.install_receive(Epoch::OneRtt, make_key(1));

        let old_header = [0x40, 0xaa, 0x01];
        let new_header = [0x44, 0xaa, 0x02];
        let old_packet = protect(&old_sender, &old_header, &[0; 8], 1);
        let new_packet = protect(&new_sender, &new_header, &[1; 8], 2);
        assert_eq!(
            state
                .decrypt(Epoch::OneRtt, &old_packet, 2, 1)
                .unwrap()
                .payload,
            &[0; 8]
        );
        assert_eq!(
            state
                .decrypt(Epoch::OneRtt, &new_packet, 2, 2)
                .unwrap()
                .payload,
            &[1; 8]
        );
    }

    fn traffic_key(
        aead: AeadAlgorithm,
        hp_algorithm: HeaderProtectionAlgorithm,
        secret: &[u8],
        hp: &[u8],
        phase: u8,
    ) -> PacketKey {
        let prk = aws_lc_rs::hkdf::Prk::new_less_safe(traffic_secret_hash(aead), secret);
        let key_len = if aead == AeadAlgorithm::Aes128Gcm {
            16
        } else {
            32
        };
        let key = expand_label(&prk, b"quic key", key_len).unwrap();
        let iv = expand_label(&prk, b"quic iv", NONCE_LEN).unwrap();
        PacketKey::with_traffic_secret(
            aead,
            hp_algorithm,
            &key,
            &iv,
            hp,
            phase,
            secret,
            0x0000_0001,
        )
        .unwrap()
    }

    #[test]
    fn traffic_secret_key_updates_cover_all_cipher_suites() {
        let suites = [
            (
                AeadAlgorithm::Aes128Gcm,
                HeaderProtectionAlgorithm::Aes128,
                32,
                16,
            ),
            (
                AeadAlgorithm::Aes256Gcm,
                HeaderProtectionAlgorithm::Aes256,
                48,
                32,
            ),
            (
                AeadAlgorithm::ChaCha20Poly1305,
                HeaderProtectionAlgorithm::ChaCha20,
                32,
                32,
            ),
        ];
        for (aead, hp_algorithm, secret_len, hp_len) in suites {
            let secret = vec![7; secret_len];
            let hp = vec![9; hp_len];
            let mut sender = CryptoState::new();
            sender.install_send(
                Epoch::OneRtt,
                traffic_key(aead, hp_algorithm, &secret, &hp, 0),
            );
            sender.install_receive(
                Epoch::OneRtt,
                traffic_key(aead, hp_algorithm, &secret, &hp, 0),
            );
            let mut receiver = CryptoState::new();
            receiver.install_send(
                Epoch::OneRtt,
                traffic_key(aead, hp_algorithm, &secret, &hp, 0),
            );
            receiver.install_receive(
                Epoch::OneRtt,
                traffic_key(aead, hp_algorithm, &secret, &hp, 0),
            );

            sender
                .request_key_update(Duration::ZERO, Duration::from_secs(3))
                .unwrap();
            let header = [0x44, 0xaa, 0x01];
            let packet = protect(sender.one_rtt.send.as_ref().unwrap(), &header, &[1; 8], 1);
            let decrypted = receiver
                .decrypt_one_rtt(&packet, 2, 1, Duration::ZERO, Duration::from_secs(3))
                .unwrap();
            assert_eq!(decrypted.payload, &[1; 8]);
            assert_eq!(receiver.receive_key_phase(), Some(1));
            assert_eq!(receiver.send_key_phase(), Some(1));
        }
    }

    #[test]
    fn local_update_accepts_old_packets_until_retention_expires() {
        let secret = [5; 32];
        let hp = [6; 16];
        let old_sender = traffic_key(
            AeadAlgorithm::Aes128Gcm,
            HeaderProtectionAlgorithm::Aes128,
            &secret,
            &hp,
            0,
        );
        let old_packet = protect(&old_sender, &[0x40, 0xaa, 0x02], &[3; 8], 2);
        let mut receiver = CryptoState::new();
        receiver.install_send(
            Epoch::OneRtt,
            traffic_key(
                AeadAlgorithm::Aes128Gcm,
                HeaderProtectionAlgorithm::Aes128,
                &secret,
                &hp,
                0,
            ),
        );
        receiver.install_receive(
            Epoch::OneRtt,
            traffic_key(
                AeadAlgorithm::Aes128Gcm,
                HeaderProtectionAlgorithm::Aes128,
                &secret,
                &hp,
                0,
            ),
        );
        receiver
            .request_key_update(Duration::from_secs(1), Duration::from_secs(3))
            .unwrap();

        assert_eq!(
            receiver
                .decrypt_one_rtt(
                    &old_packet,
                    2,
                    2,
                    Duration::from_secs(3),
                    Duration::from_secs(3),
                )
                .unwrap()
                .payload,
            &[3; 8]
        );
        assert_eq!(receiver.receive_key_phase(), Some(1));
        assert!(receiver
            .decrypt_one_rtt(
                &old_packet,
                2,
                2,
                Duration::from_secs(4),
                Duration::from_secs(3),
            )
            .is_err());
    }
}
