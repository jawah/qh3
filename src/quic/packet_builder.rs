//! Transactional, crypto-agnostic QUIC packet and UDP datagram construction.
//!
//! The builder owns packet numbers and queued frames.  A failed build does not
//! consume frames, advance a packet number, change accounting, or lose a
//! datagram which would otherwise have been rolled over by that build.

use std::collections::VecDeque;
use std::error::Error;
use std::fmt;

pub use super::types::{DeliveryId, PacketNumberSpace as PacketSpace, PacketType};
use super::types::{FrameType, VarInt, VARINT_MAX};
#[cfg(test)]
use super::wire::QUIC_VERSION_1;
use super::wire::{encode_varint, QUIC_VERSION_2};

const MAX_CID_LEN: usize = 20;
const PN_LEN: usize = 2;
const HP_SAMPLE_OFFSET: usize = 4;
const HP_SAMPLE_LEN: usize = 16;
const INITIAL_DATAGRAM_SIZE: usize = 1280;

impl PacketType {
    fn space(self) -> PacketSpace {
        match self {
            Self::Initial => PacketSpace::Initial,
            Self::Handshake => PacketSpace::Handshake,
            Self::ZeroRtt | Self::OneRtt => PacketSpace::ApplicationData,
            Self::Retry | Self::VersionNegotiation => {
                unreachable!("unprotected packets are rejected before this call")
            }
        }
    }

    fn order(self) -> u8 {
        match self {
            Self::Initial => 0,
            Self::ZeroRtt => 1,
            Self::Handshake => 2,
            Self::OneRtt => 3,
            Self::Retry | Self::VersionNegotiation => 4,
        }
    }

    fn is_long(self) -> bool {
        self != Self::OneRtt
    }
}

/// Action recovery should apply to a frame after loss or acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameAction {
    /// The frame has no delivery callback and is not retransmitted.
    None,
    /// Report acknowledgement or loss, but do not automatically retransmit.
    Notify(DeliveryId),
}

impl FrameAction {
    fn delivery_id(self) -> Option<DeliveryId> {
        match self {
            Self::None => None,
            Self::Notify(id) => Some(id),
        }
    }
}

/// An already encoded frame body.  The builder writes `frame_type` itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueuedFrame {
    pub frame_type: FrameType,
    pub body: Vec<u8>,
    pub action: FrameAction,
}

impl QueuedFrame {
    pub fn new(frame_type: FrameType, body: Vec<u8>, action: FrameAction) -> Self {
        Self {
            frame_type,
            body,
            action,
        }
    }

    fn encoded_len(&self) -> Result<usize, BuildError> {
        varint_len(self.frame_type.value())
            .checked_add(self.body.len())
            .ok_or(BuildError::Capacity)
    }
}

/// An owned plaintext packet supplied to the native QUIC crypto adapter.
pub struct ProtectionInput {
    pub packet: Vec<u8>,
    pub header_len: usize,
    pub packet_number: u64,
    pub packet_type: PacketType,
}

/// Native packet-protection boundary.  The result is the complete protected
/// packet: protected header, ciphertext, and authentication tag.
pub trait PacketProtector {
    type Error: fmt::Display;

    fn tag_len(&self) -> usize;
    fn protect(&mut self, input: ProtectionInput) -> Result<Vec<u8>, Self::Error>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuilderConfig {
    pub version: u32,
    pub source_cid: Vec<u8>,
    pub destination_cid: Vec<u8>,
    pub initial_token: Vec<u8>,
    pub is_client: bool,
    pub spin_bit: bool,
    pub max_datagram_size: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketRequest {
    pub packet_type: PacketType,
    pub key_phase: bool,
    /// Force authenticated PADDING to the end of the available datagram.
    pub pad_to_capacity: bool,
    pub is_pmtu_probe: bool,
}

impl PacketRequest {
    pub fn new(packet_type: PacketType) -> Self {
        Self {
            packet_type,
            key_phase: false,
            pad_to_capacity: false,
            is_pmtu_probe: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameMetadata {
    pub frame_type: FrameType,
    pub payload_offset: usize,
    pub encoded_len: usize,
    pub action: FrameAction,
    pub delivery_id: Option<DeliveryId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketMetadata {
    pub datagram_id: u64,
    pub datagram_offset: usize,
    pub packet_type: PacketType,
    pub packet_space: PacketSpace,
    pub packet_number: u64,
    pub sent_bytes: usize,
    pub in_flight: bool,
    pub is_ack_eliciting: bool,
    pub is_crypto_packet: bool,
    pub is_pmtu_probe: bool,
    pub padding_bytes: usize,
    pub frames: Vec<FrameMetadata>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltDatagram {
    pub id: u64,
    pub bytes: Vec<u8>,
    /// Sum of `sent_bytes` for in-flight packets in this datagram.
    pub flight_bytes: usize,
    /// Recovery metadata for every packet in `bytes`, in wire order.
    pub packets: Vec<PacketMetadata>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildResult {
    /// Metadata for the packet built by this call, once its datagram is
    /// complete. Pending coalesced packets are returned by rollover or flush.
    pub packet: Option<PacketMetadata>,
    pub datagrams: Vec<BuiltDatagram>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildError {
    InvalidConfig(&'static str),
    Capacity,
    Protection(String),
    ProtectedLength { expected: usize, actual: usize },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => f.write_str(message),
            Self::Capacity => f.write_str("packet builder capacity exhausted"),
            Self::Protection(error) => write!(f, "packet protection failed: {error}"),
            Self::ProtectedLength { expected, actual } => {
                write!(f, "protector returned {actual} bytes, expected {expected}")
            }
        }
    }
}

impl Error for BuildError {}

#[derive(Clone, Debug)]
struct PendingDatagram {
    id: u64,
    bytes: Vec<u8>,
    flight_bytes: usize,
    last_type: PacketType,
    packets: Vec<PacketMetadata>,
}

/// Stateful packet builder.  Frames are reserved by peeking into a queue and
/// are removed only in the final, non-fallible commit section of `build`.
pub struct PacketBuilder {
    config: BuilderConfig,
    queues: [VecDeque<QueuedFrame>; 3],
    next_packet_numbers: [u64; 3],
    next_datagram_id: u64,
    pending: Option<PendingDatagram>,
}

impl PacketBuilder {
    pub fn new(config: BuilderConfig) -> Result<Self, BuildError> {
        validate_config(&config)?;

        Ok(Self {
            config,
            queues: std::array::from_fn(|_| VecDeque::new()),
            next_packet_numbers: [0; 3],
            next_datagram_id: 0,
            pending: None,
        })
    }

    /// Restore the next packet number after an enclosing transaction fails.
    pub fn restore_packet_number(
        &mut self,
        space: PacketSpace,
        packet_number: u64,
    ) -> Result<(), BuildError> {
        if packet_number > VARINT_MAX {
            return Err(BuildError::Capacity);
        }
        self.next_packet_numbers[space_index(space)] = packet_number;
        Ok(())
    }

    pub fn set_destination_cid(&mut self, destination_cid: Vec<u8>) -> Result<(), BuildError> {
        if destination_cid.len() > MAX_CID_LEN {
            return Err(BuildError::InvalidConfig(
                "connection IDs cannot exceed 20 bytes",
            ));
        }
        if self.pending.is_some() {
            return Err(BuildError::InvalidConfig(
                "cannot change destination CID with a pending datagram",
            ));
        }
        self.config.destination_cid = destination_cid;
        Ok(())
    }

    pub fn set_initial_token(&mut self, token: Vec<u8>) {
        self.config.initial_token = token;
    }

    pub fn enqueue(&mut self, space: PacketSpace, frame: QueuedFrame) {
        self.queues[space_index(space)].push_back(frame);
    }

    pub fn queued_frames(&self, space: PacketSpace) -> usize {
        self.queues[space_index(space)].len()
    }

    pub fn discard_space(&mut self, space: PacketSpace) {
        self.queues[space_index(space)].clear();
        if self.pending.as_ref().is_some_and(|datagram| {
            datagram
                .packets
                .iter()
                .any(|packet| packet.packet_space == space)
        }) {
            self.pending = None;
        }
    }

    pub fn next_packet_number(&self, space: PacketSpace) -> u64 {
        self.next_packet_numbers[space_index(space)]
    }

    #[cfg(test)]
    pub fn pending_datagram_bytes(&self) -> usize {
        self.pending.as_ref().map_or(0, |d| d.bytes.len())
    }

    /// Build one packet.  Selection stops before the first frame which does not
    /// fit; if even the first frame does not fit, `Capacity` is returned.
    pub fn build<P: PacketProtector>(
        &mut self,
        request: PacketRequest,
        protector: &mut P,
    ) -> Result<BuildResult, BuildError> {
        if matches!(
            request.packet_type,
            PacketType::Retry | PacketType::VersionNegotiation
        ) {
            return Err(BuildError::InvalidConfig(
                "Retry and Version Negotiation packets are not protected",
            ));
        }
        let space = request.packet_type.space();
        let queue_index = space_index(space);
        if self.queues[queue_index].is_empty() {
            return Ok(BuildResult {
                packet: None,
                datagrams: Vec::new(),
            });
        }

        let tag_len = protector.tag_len();
        let header_len = self.header_len(request.packet_type)?;
        let minimum_packet_len = header_len
            .checked_add(tag_len)
            .and_then(|n| {
                self.queues[queue_index]
                    .front()
                    .and_then(|frame| frame.encoded_len().ok())
                    .and_then(|frame_len| n.checked_add(frame_len))
            })
            .ok_or(BuildError::Capacity)?;
        let total_room = usize::MAX;
        let mut must_roll = self.pending.as_ref().is_some_and(|pending| {
            pending.last_type.order() >= request.packet_type.order()
                || pending.last_type == PacketType::OneRtt
        });
        if !must_roll {
            if let Some(pending) = &self.pending {
                let current_room = self
                    .config
                    .max_datagram_size
                    .saturating_sub(pending.bytes.len())
                    .min(total_room);
                must_roll = minimum_packet_len > current_room;
            }
        }
        let pending_len = if must_roll {
            0
        } else {
            self.pending.as_ref().map_or(0, |d| d.bytes.len())
        };
        let datagram_id = if must_roll {
            self.next_datagram_id + 1
        } else {
            self.pending
                .as_ref()
                .map_or(self.next_datagram_id, |d| d.id)
        };
        let available = self
            .config
            .max_datagram_size
            .saturating_sub(pending_len)
            .min(total_room);
        let datagram_capacity = pending_len.saturating_add(available);
        let packet_number = self.next_packet_numbers[queue_index];
        if packet_number > VARINT_MAX {
            return Err(BuildError::Capacity);
        }

        if header_len
            .checked_add(tag_len)
            .ok_or(BuildError::Capacity)?
            >= available
        {
            return Err(BuildError::Capacity);
        }

        let mut plaintext = Vec::with_capacity(available);
        plaintext.resize(header_len, 0);
        let mut frame_metadata = Vec::new();
        let mut selected = 0;
        let mut in_flight = false;
        let mut ack_eliciting = false;
        let mut crypto = false;

        for frame in &self.queues[queue_index] {
            let frame_len = frame.encoded_len()?;
            let payload_len = plaintext.len() - header_len;
            let candidate = header_len
                .checked_add(payload_len)
                .and_then(|n| n.checked_add(frame_len))
                .and_then(|n| n.checked_add(tag_len))
                .ok_or(BuildError::Capacity)?;
            let candidate_in_flight = in_flight || frame_in_flight(frame.frame_type);
            if candidate > available {
                break;
            }

            let offset = payload_len;
            push_varint(&mut plaintext, frame.frame_type.0);
            plaintext.extend_from_slice(&frame.body);
            frame_metadata.push(FrameMetadata {
                frame_type: frame.frame_type,
                payload_offset: offset,
                encoded_len: frame_len,
                action: frame.action,
                delivery_id: frame.action.delivery_id(),
            });
            selected += 1;
            in_flight = candidate_in_flight;
            ack_eliciting |= frame_ack_eliciting(frame.frame_type);
            crypto |= frame.frame_type == FrameType::CRYPTO;
        }
        if selected == 0 {
            return Err(BuildError::Capacity);
        }

        // Ensure enough ciphertext follows the packet number for header
        // protection sampling. PADDING is part of this packet's AEAD plaintext.
        let payload_len = plaintext.len() - header_len;
        let minimum_ciphertext = (HP_SAMPLE_OFFSET - PN_LEN) + HP_SAMPLE_LEN;
        let mut padding = minimum_ciphertext.saturating_sub(payload_len + tag_len);
        let requires_initial_padding =
            request.packet_type == PacketType::Initial && (self.config.is_client || ack_eliciting);
        let target = if request.pad_to_capacity {
            datagram_capacity
        } else if requires_initial_padding {
            INITIAL_DATAGRAM_SIZE.min(datagram_capacity)
        } else {
            0
        };
        if target > pending_len + header_len + payload_len + tag_len {
            padding = padding.max(target - pending_len - header_len - payload_len - tag_len);
        }
        let packet_len = header_len
            .checked_add(payload_len)
            .and_then(|n| n.checked_add(padding))
            .and_then(|n| n.checked_add(tag_len))
            .ok_or(BuildError::Capacity)?;
        if packet_len > available {
            return Err(BuildError::Capacity);
        }
        if padding != 0 {
            plaintext.resize(plaintext.len() + padding, 0);
            in_flight = true;
        }
        let payload_len = plaintext.len() - header_len;
        self.write_header(
            &mut plaintext[..header_len],
            request.packet_type,
            packet_number,
            request.key_phase,
            payload_len,
            tag_len,
        )?;
        let protected = protector
            .protect(ProtectionInput {
                packet: plaintext,
                header_len,
                packet_number,
                packet_type: request.packet_type,
            })
            .map_err(|error| BuildError::Protection(error.to_string()))?;
        if protected.len() != packet_len {
            return Err(BuildError::ProtectedLength {
                expected: packet_len,
                actual: protected.len(),
            });
        }

        let packet = PacketMetadata {
            datagram_id,
            datagram_offset: if must_roll {
                0
            } else {
                self.pending.as_ref().map_or(0, |d| d.bytes.len())
            },
            packet_type: request.packet_type,
            packet_space: space,
            packet_number,
            sent_bytes: packet_len,
            in_flight,
            is_ack_eliciting: ack_eliciting,
            is_crypto_packet: crypto,
            is_pmtu_probe: request.is_pmtu_probe,
            padding_bytes: padding,
            frames: frame_metadata,
        };

        // Nothing above this line mutates transactional builder state.
        let mut datagrams = Vec::new();
        if must_roll {
            datagrams.push(to_built(self.pending.take().expect("rollover has pending")));
            self.next_datagram_id += 1;
        }
        let packet_flight = if in_flight { packet_len } else { 0 };
        if let Some(pending) = &mut self.pending {
            pending.bytes.extend_from_slice(&protected);
            pending.flight_bytes += packet_flight;
            pending.last_type = request.packet_type;
            pending.packets.push(packet.clone());
        } else {
            self.pending = Some(PendingDatagram {
                id: datagram_id,
                bytes: protected,
                flight_bytes: packet_flight,
                last_type: request.packet_type,
                packets: vec![packet.clone()],
            });
        }
        for _ in 0..selected {
            self.queues[queue_index].pop_front();
        }
        self.next_packet_numbers[queue_index] += 1;

        // A short-header packet is always the final packet in a datagram.
        let packet = if request.packet_type == PacketType::OneRtt {
            datagrams.push(to_built(self.pending.take().expect("packet was committed")));
            self.next_datagram_id += 1;
            Some(packet)
        } else {
            None
        };
        Ok(BuildResult { packet, datagrams })
    }

    pub fn flush(&mut self) -> Option<BuiltDatagram> {
        let datagram = self.pending.take().map(to_built);
        if datagram.is_some() {
            self.next_datagram_id += 1;
        }
        datagram
    }

    pub fn set_max_datagram_size(&mut self, size: usize) -> Result<(), BuildError> {
        if size == 0 || self.pending.is_some() {
            return Err(BuildError::InvalidConfig(
                "cannot change datagram size with a pending datagram",
            ));
        }
        self.config.max_datagram_size = size;
        Ok(())
    }

    fn header_len(&self, packet_type: PacketType) -> Result<usize, BuildError> {
        if packet_type.is_long() {
            let mut len = 1 + 4 + 1 + self.config.destination_cid.len();
            len = len
                .checked_add(1 + self.config.source_cid.len())
                .ok_or(BuildError::Capacity)?;
            if packet_type == PacketType::Initial {
                len = len
                    .checked_add(varint_len(self.config.initial_token.len() as u64))
                    .and_then(|n| n.checked_add(self.config.initial_token.len()))
                    .ok_or(BuildError::Capacity)?;
            }
            // Two-byte Length field and two-byte packet number.
            len.checked_add(2 + PN_LEN).ok_or(BuildError::Capacity)
        } else {
            1usize
                .checked_add(self.config.destination_cid.len())
                .and_then(|n| n.checked_add(PN_LEN))
                .ok_or(BuildError::Capacity)
        }
    }

    fn write_header(
        &self,
        header: &mut [u8],
        packet_type: PacketType,
        packet_number: u64,
        key_phase: bool,
        payload_len: usize,
        tag_len: usize,
    ) -> Result<(), BuildError> {
        if header.len() != self.header_len(packet_type)? {
            return Err(BuildError::Capacity);
        }
        let mut offset = 0;
        if packet_type.is_long() {
            let type_bits = long_type_bits(self.config.version, packet_type);
            write_bytes(
                header,
                &mut offset,
                &[0xc0 | (type_bits << 4) | (PN_LEN as u8 - 1)],
            )?;
            write_bytes(header, &mut offset, &self.config.version.to_be_bytes())?;
            write_bytes(
                header,
                &mut offset,
                &[self.config.destination_cid.len() as u8],
            )?;
            write_bytes(header, &mut offset, &self.config.destination_cid)?;
            write_bytes(header, &mut offset, &[self.config.source_cid.len() as u8])?;
            write_bytes(header, &mut offset, &self.config.source_cid)?;
            if packet_type == PacketType::Initial {
                let token_len = VarInt::new(self.config.initial_token.len() as u64)
                    .ok_or(BuildError::Capacity)?;
                let mut encoded = [0; 8];
                let encoded_len =
                    encode_varint(token_len, &mut encoded).unwrap_or_else(|_| unreachable!());
                write_bytes(header, &mut offset, &encoded[..encoded_len])?;
                write_bytes(header, &mut offset, &self.config.initial_token)?;
            }
            let length = PN_LEN
                .checked_add(payload_len)
                .and_then(|n| n.checked_add(tag_len))
                .ok_or(BuildError::Capacity)?;
            if length > 0x3fff {
                return Err(BuildError::Capacity);
            }
            write_bytes(
                header,
                &mut offset,
                &((length as u16) | 0x4000).to_be_bytes(),
            )?;
        } else {
            write_bytes(
                header,
                &mut offset,
                &[0x40
                    | ((self.config.spin_bit as u8) << 5)
                    | ((key_phase as u8) << 2)
                    | (PN_LEN as u8 - 1)],
            )?;
            write_bytes(header, &mut offset, &self.config.destination_cid)?;
        }
        write_bytes(header, &mut offset, &(packet_number as u16).to_be_bytes())?;
        if offset != header.len() {
            return Err(BuildError::Capacity);
        }
        Ok(())
    }
}

fn to_built(pending: PendingDatagram) -> BuiltDatagram {
    BuiltDatagram {
        id: pending.id,
        bytes: pending.bytes,
        flight_bytes: pending.flight_bytes,
        packets: pending.packets,
    }
}

fn validate_config(config: &BuilderConfig) -> Result<(), BuildError> {
    if config.max_datagram_size == 0 {
        return Err(BuildError::InvalidConfig(
            "max_datagram_size must be non-zero",
        ));
    }
    if config.source_cid.len() > MAX_CID_LEN || config.destination_cid.len() > MAX_CID_LEN {
        return Err(BuildError::InvalidConfig(
            "connection IDs cannot exceed 20 bytes",
        ));
    }
    Ok(())
}

fn space_index(space: PacketSpace) -> usize {
    match space {
        PacketSpace::Initial => 0,
        PacketSpace::Handshake => 1,
        PacketSpace::ApplicationData => 2,
    }
}

fn frame_ack_eliciting(frame_type: FrameType) -> bool {
    !matches!(frame_type.value(), 0x00 | 0x02 | 0x03 | 0x1c | 0x1d)
}

fn frame_in_flight(frame_type: FrameType) -> bool {
    !matches!(frame_type.value(), 0x02 | 0x03 | 0x1c | 0x1d)
}

fn long_type_bits(version: u32, packet_type: PacketType) -> u8 {
    match (version == QUIC_VERSION_2, packet_type) {
        (false, PacketType::Initial) => 0,
        (false, PacketType::ZeroRtt) => 1,
        (false, PacketType::Handshake) => 2,
        (true, PacketType::Initial) => 1,
        (true, PacketType::ZeroRtt) => 2,
        (true, PacketType::Handshake) => 3,
        (_, PacketType::OneRtt) => unreachable!("One-RTT has a short header"),
        (_, PacketType::Retry | PacketType::VersionNegotiation) => {
            unreachable!("unprotected packet type")
        }
    }
}

fn varint_len(value: u64) -> usize {
    match value {
        0..=0x3f => 1,
        0x40..=0x3fff => 2,
        0x4000..=0x3fff_ffff => 4,
        _ => 8,
    }
}

fn push_varint(target: &mut Vec<u8>, value: VarInt) {
    let mut encoded = [0; 8];
    let length = encode_varint(value, &mut encoded).unwrap_or_else(|_| unreachable!());
    target.extend_from_slice(&encoded[..length]);
}

fn write_bytes(target: &mut [u8], offset: &mut usize, value: &[u8]) -> Result<(), BuildError> {
    let end = offset
        .checked_add(value.len())
        .ok_or(BuildError::Capacity)?;
    target
        .get_mut(*offset..end)
        .ok_or(BuildError::Capacity)?
        .copy_from_slice(value);
    *offset = end;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestProtector {
        fail: bool,
        bad_len: bool,
        seen: Vec<(PacketType, u64, usize)>,
    }

    impl PacketProtector for TestProtector {
        type Error = &'static str;

        fn tag_len(&self) -> usize {
            16
        }

        fn protect(&mut self, mut input: ProtectionInput) -> Result<Vec<u8>, Self::Error> {
            self.seen.push((
                input.packet_type,
                input.packet_number,
                input.packet.len() - input.header_len,
            ));
            if self.fail {
                return Err("no key");
            }
            input.packet.resize(input.packet.len() + 16, 0xaa);
            if self.bad_len {
                input.packet.pop();
            }
            Ok(input.packet)
        }
    }

    fn protector() -> TestProtector {
        TestProtector {
            fail: false,
            bad_len: false,
            seen: Vec::new(),
        }
    }

    fn config(version: u32) -> BuilderConfig {
        BuilderConfig {
            version,
            source_cid: vec![1; 8],
            destination_cid: vec![2; 8],
            initial_token: Vec::new(),
            is_client: false,
            spin_bit: false,
            max_datagram_size: 1500,
        }
    }

    fn frame(id: u64, frame_type: u64, size: usize) -> QueuedFrame {
        QueuedFrame::new(
            FrameType::try_from(frame_type).unwrap(),
            vec![0; size],
            FrameAction::Notify(DeliveryId(id)),
        )
    }

    #[test]
    fn protection_failure_rolls_back_frame_number_and_accounting() {
        let mut builder = PacketBuilder::new(config(1)).unwrap();
        builder.enqueue(PacketSpace::Handshake, frame(7, 0x06, 4));
        let mut p = protector();
        p.fail = true;
        assert_eq!(
            builder
                .build(PacketRequest::new(PacketType::Handshake), &mut p)
                .unwrap_err(),
            BuildError::Protection("no key".into())
        );
        assert_eq!(builder.queued_frames(PacketSpace::Handshake), 1);
        assert_eq!(builder.next_packet_number(PacketSpace::Handshake), 0);
        assert_eq!(builder.pending_datagram_bytes(), 0);
        assert_eq!(p.seen, [(PacketType::Handshake, 0, 5)]);
    }

    #[test]
    fn builder_fills_the_final_packet_buffer_exactly() {
        let mut builder = PacketBuilder::new(config(QUIC_VERSION_1)).unwrap();
        builder.enqueue(PacketSpace::ApplicationData, frame(1, 0x01, 0));

        let result = builder
            .build(PacketRequest::new(PacketType::OneRtt), &mut protector())
            .unwrap();

        let mut expected = vec![0x41];
        expected.extend_from_slice(&[2; 8]);
        expected.extend_from_slice(&[0, 0, 0x01, 0]);
        expected.extend_from_slice(&[0xaa; 16]);
        assert_eq!(result.datagrams[0].bytes, expected);
        let packet = result.packet.unwrap();
        assert_eq!(packet.frames[0].payload_offset, 0);
        assert_eq!(packet.frames[0].encoded_len, 1);
        assert_eq!(packet.padding_bytes, 1);
    }

    #[test]
    fn bad_protector_length_is_also_a_full_rollback() {
        let mut builder = PacketBuilder::new(config(1)).unwrap();
        builder.enqueue(PacketSpace::ApplicationData, frame(1, 0x01, 0));
        let mut p = protector();
        p.bad_len = true;
        assert!(matches!(
            builder.build(PacketRequest::new(PacketType::OneRtt), &mut p),
            Err(BuildError::ProtectedLength { .. })
        ));
        assert_eq!(builder.queued_frames(PacketSpace::ApplicationData), 1);
        assert_eq!(builder.next_packet_number(PacketSpace::ApplicationData), 0);
    }

    #[test]
    fn rollover_datagram_is_not_lost_on_later_failure() {
        let mut builder = PacketBuilder::new(config(1)).unwrap();
        let mut p = protector();
        builder.enqueue(PacketSpace::Handshake, frame(1, 0x06, 4));
        builder
            .build(PacketRequest::new(PacketType::Handshake), &mut p)
            .unwrap();
        let old_len = builder.pending_datagram_bytes();

        builder.enqueue(PacketSpace::Initial, frame(2, 0x06, 4));
        p.fail = true;
        assert!(builder
            .build(PacketRequest::new(PacketType::Initial), &mut p)
            .is_err());
        assert_eq!(builder.pending_datagram_bytes(), old_len);
        assert_eq!(builder.flush().unwrap().id, 0);
    }

    #[test]
    fn capacity_does_not_reserve_or_consume() {
        let mut cfg = config(1);
        cfg.max_datagram_size = 40;
        let mut builder = PacketBuilder::new(cfg).unwrap();
        builder.enqueue(PacketSpace::Handshake, frame(9, 0x06, 100));
        assert_eq!(
            builder
                .build(PacketRequest::new(PacketType::Handshake), &mut protector())
                .unwrap_err(),
            BuildError::Capacity
        );
        assert_eq!(builder.queued_frames(PacketSpace::Handshake), 1);
        assert_eq!(builder.next_packet_number(PacketSpace::Handshake), 0);
    }

    #[test]
    fn padding_is_authenticated_and_attributed_to_packet() {
        let mut cfg = config(1);
        cfg.is_client = true;
        cfg.max_datagram_size = 1280;
        let mut builder = PacketBuilder::new(cfg).unwrap();
        builder.enqueue(PacketSpace::Initial, frame(1, 0x06, 1));
        let mut p = protector();
        let result = builder
            .build(PacketRequest::new(PacketType::Initial), &mut p)
            .unwrap();
        assert!(result.packet.is_none());
        let datagram = builder.flush().unwrap();
        let packet = &datagram.packets[0];
        assert!(packet.padding_bytes > 1000);
        assert_eq!(packet.sent_bytes, 1280);
        assert_eq!(p.seen[0].2 + 44, 1280); // 28-byte header and 16-byte tag.
        assert_eq!(datagram.bytes.len(), 1280);
        assert_eq!(datagram.flight_bytes, packet.sent_bytes);
    }

    #[test]
    fn header_protection_sample_is_available() {
        let mut builder = PacketBuilder::new(config(QUIC_VERSION_1)).unwrap();
        builder.enqueue(PacketSpace::ApplicationData, frame(1, 0x01, 0));
        let mut p = protector();
        let packet = builder
            .build(PacketRequest::new(PacketType::OneRtt), &mut p)
            .unwrap()
            .packet
            .unwrap();

        // The sample begins four bytes after the PN offset and is 16 bytes.
        assert_eq!(
            p.seen[0].2 + 16,
            (HP_SAMPLE_OFFSET - PN_LEN) + HP_SAMPLE_LEN
        );
        assert_eq!(packet.padding_bytes, 1);
    }

    #[test]
    fn full_coalesced_datagram_rolls_only_after_protection() {
        let mut cfg = config(QUIC_VERSION_1);
        cfg.max_datagram_size = 90;
        let mut builder = PacketBuilder::new(cfg).unwrap();
        let mut p = protector();
        builder.enqueue(PacketSpace::Initial, frame(1, 0x02, 35));
        builder
            .build(PacketRequest::new(PacketType::Initial), &mut p)
            .unwrap();
        builder.enqueue(PacketSpace::Handshake, frame(2, 0x06, 10));

        let result = builder
            .build(PacketRequest::new(PacketType::Handshake), &mut p)
            .unwrap();
        assert_eq!(result.datagrams.len(), 1);
        assert_eq!(result.datagrams[0].id, 0);
        assert_eq!(result.datagrams[0].packets[0].datagram_id, 0);
        assert!(result.packet.is_none());
        assert!(builder.pending_datagram_bytes() > 0);
    }

    #[test]
    fn coalesces_all_packet_types_and_shares_application_numbers() {
        for version in [QUIC_VERSION_1, QUIC_VERSION_2] {
            let mut builder = PacketBuilder::new(config(version)).unwrap();
            let mut p = protector();
            builder.enqueue(PacketSpace::Initial, frame(1, 0x02, 1));
            builder
                .build(PacketRequest::new(PacketType::Initial), &mut p)
                .unwrap();
            builder.enqueue(PacketSpace::ApplicationData, frame(2, 0x01, 1));
            let zero = builder
                .build(PacketRequest::new(PacketType::ZeroRtt), &mut p)
                .unwrap();
            builder.enqueue(PacketSpace::Handshake, frame(3, 0x06, 1));
            builder
                .build(PacketRequest::new(PacketType::Handshake), &mut p)
                .unwrap();
            builder.enqueue(PacketSpace::ApplicationData, frame(4, 0x01, 1));
            let one = builder
                .build(PacketRequest::new(PacketType::OneRtt), &mut p)
                .unwrap();
            assert!(zero.datagrams.is_empty());
            assert!(zero.packet.is_none());
            assert_eq!(one.datagrams.len(), 1);
            assert_eq!(one.datagrams[0].id, 0);
            assert_eq!(one.packet.unwrap().packet_number, 1);
            assert_eq!(one.datagrams[0].packets.len(), 4);
            assert_eq!(
                p.seen.iter().map(|x| x.0).collect::<Vec<_>>(),
                [
                    PacketType::Initial,
                    PacketType::ZeroRtt,
                    PacketType::Handshake,
                    PacketType::OneRtt,
                ]
            );
        }
    }

    #[test]
    fn v1_and_v2_long_header_type_bits_are_correct() {
        let expected = [
            (1, PacketType::Initial, 0),
            (1, PacketType::ZeroRtt, 1),
            (1, PacketType::Handshake, 2),
            (QUIC_VERSION_2, PacketType::Initial, 1),
            (QUIC_VERSION_2, PacketType::ZeroRtt, 2),
            (QUIC_VERSION_2, PacketType::Handshake, 3),
        ];
        for (version, ty, bits) in expected {
            assert_eq!(long_type_bits(version, ty), bits);
        }
    }

    #[test]
    fn selection_commits_only_frames_which_fit() {
        let mut cfg = config(1);
        cfg.max_datagram_size = 80;
        let mut builder = PacketBuilder::new(cfg).unwrap();
        builder.enqueue(PacketSpace::ApplicationData, frame(1, 0x01, 1));
        builder.enqueue(PacketSpace::ApplicationData, frame(2, 0x01, 100));
        let result = builder
            .build(PacketRequest::new(PacketType::OneRtt), &mut protector())
            .unwrap();
        let packet = result.packet.unwrap();
        assert_eq!(packet.frames.len(), 1);
        assert_eq!(packet.frames[0].delivery_id, Some(DeliveryId(1)));
        assert_eq!(builder.queued_frames(PacketSpace::ApplicationData), 1);
    }

    #[test]
    fn packet_number_can_be_queried_and_restored() {
        let mut builder = PacketBuilder::new(config(QUIC_VERSION_1)).unwrap();
        builder.enqueue(PacketSpace::ApplicationData, frame(1, 0x01, 0));
        builder
            .build(PacketRequest::new(PacketType::OneRtt), &mut protector())
            .unwrap();
        assert_eq!(builder.next_packet_number(PacketSpace::ApplicationData), 1);
        builder
            .restore_packet_number(PacketSpace::ApplicationData, 0)
            .unwrap();
        assert_eq!(builder.next_packet_number(PacketSpace::ApplicationData), 0);
    }
}
