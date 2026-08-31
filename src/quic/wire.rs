use std::error::Error;
use std::fmt;
use std::ops::Range;

use super::types::{
    ConnectionError, Epoch, FrameType, PacketType, StreamId, TransportErrorCode, VarInt, VARINT_MAX,
};

pub const QUIC_VERSION_1: u32 = 0x0000_0001;
pub const QUIC_VERSION_2: u32 = 0x6b33_43cf;
const LONG_HEADER_BIT: u8 = 0x80;
const FIXED_BIT: u8 = 0x40;
const MAX_CONNECTION_ID_LEN: usize = 20;
const RETRY_TAG_LEN: usize = 16;
const STREAM_COUNT_MAX: u64 = 1 << 60;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub const fn len(self) -> usize {
        self.end.saturating_sub(self.start)
    }

    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }

    pub fn as_range(self) -> Range<usize> {
        self.start..self.end
    }

    pub fn get(self, input: &[u8]) -> Option<&[u8]> {
        input.get(self.start..self.end)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireError {
    Truncated { offset: usize },
    InvalidVarInt { value: u64 },
    InvalidFixedBit { offset: usize },
    ConnectionIdTooLong { offset: usize, length: usize },
    InvalidVersionNegotiation { offset: usize },
    InvalidPacketLength { offset: usize },
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { offset } => write!(f, "truncated input at offset {offset}"),
            Self::InvalidVarInt { value } => write!(f, "invalid QUIC varint value {value}"),
            Self::InvalidFixedBit { offset } => {
                write!(f, "packet fixed bit is zero at offset {offset}")
            }
            Self::ConnectionIdTooLong { offset, length } => {
                write!(f, "connection ID at offset {offset} is {length} bytes")
            }
            Self::InvalidVersionNegotiation { offset } => {
                write!(f, "invalid version negotiation list at offset {offset}")
            }
            Self::InvalidPacketLength { offset } => {
                write!(f, "invalid packet length at offset {offset}")
            }
        }
    }
}

impl Error for WireError {}

/// Decode one QUIC varint and return its value and encoded length.
pub fn decode_varint(input: &[u8]) -> Result<(VarInt, usize), WireError> {
    let first = *input.first().ok_or(WireError::Truncated { offset: 0 })?;
    let length = 1usize << (first >> 6);
    let bytes = input.get(..length).ok_or(WireError::Truncated {
        offset: input.len(),
    })?;
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok((
        VarInt::new(value).ok_or(WireError::InvalidVarInt { value })?,
        length,
    ))
}

/// Encode a QUIC varint using its shortest representation.
pub fn encode_varint(value: VarInt, output: &mut [u8]) -> Result<usize, WireError> {
    let value = value.into_inner();
    let length = if value < (1 << 6) {
        1
    } else if value < (1 << 14) {
        2
    } else if value < (1 << 30) {
        4
    } else {
        8
    };
    if output.len() < length {
        return Err(WireError::Truncated {
            offset: output.len(),
        });
    }
    for index in 0..length {
        output[length - index - 1] = (value >> (index * 8)) as u8;
    }
    output[0] |= match length {
        1 => 0x00,
        2 => 0x40,
        4 => 0x80,
        8 => 0xc0,
        _ => return Err(WireError::InvalidVarInt { value }),
    };
    Ok(length)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketHeader {
    pub first_byte: u8,
    pub version: Option<u32>,
    pub packet_type: PacketType,
    pub packet: Span,
    pub destination_cid: Span,
    pub source_cid: Span,
    pub token: Span,
    pub retry_integrity_tag: Span,
    /// Packed big-endian u32 values for a Version Negotiation packet.
    pub supported_versions: Span,
    /// Packet number plus protected payload. Empty for Retry and Version Negotiation.
    pub protected_payload: Span,
}

impl PacketHeader {
    pub fn versions<'a>(&self, input: &'a [u8]) -> impl Iterator<Item = u32> + 'a {
        self.supported_versions
            .get(input)
            .unwrap_or_default()
            .chunks_exact(4)
            .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

/// Parse one packet beginning at `offset`. Long packet lengths delimit coalesced packets;
/// short, Retry, and Version Negotiation packets consume the remainder of the datagram.
pub fn parse_packet_header(
    input: &[u8],
    offset: usize,
    short_destination_cid_len: usize,
) -> Result<PacketHeader, WireError> {
    let packet_start = offset;
    let mut cursor = Cursor::at(input, offset)?;
    let first_byte = cursor.byte()?;
    if first_byte & LONG_HEADER_BIT == 0 {
        if first_byte & FIXED_BIT == 0 {
            return Err(WireError::InvalidFixedBit {
                offset: packet_start,
            });
        }
        if short_destination_cid_len > MAX_CONNECTION_ID_LEN {
            return Err(WireError::ConnectionIdTooLong {
                offset: cursor.pos,
                length: short_destination_cid_len,
            });
        }
        let destination_cid = cursor.span(short_destination_cid_len)?;
        return Ok(PacketHeader {
            first_byte,
            version: None,
            packet_type: PacketType::OneRtt,
            packet: Span::new(packet_start, input.len()),
            destination_cid,
            source_cid: Span::new(cursor.pos, cursor.pos),
            token: Span::new(cursor.pos, cursor.pos),
            retry_integrity_tag: Span::new(cursor.pos, cursor.pos),
            supported_versions: Span::new(cursor.pos, cursor.pos),
            protected_payload: Span::new(cursor.pos, input.len()),
        });
    }

    let version = cursor.u32()?;
    let destination_cid = cursor.connection_id()?;
    let source_cid = cursor.connection_id()?;
    let empty = Span::new(cursor.pos, cursor.pos);

    if version == 0 {
        let remaining = input.len() - cursor.pos;
        if remaining == 0 || remaining % 4 != 0 {
            return Err(WireError::InvalidVersionNegotiation { offset: cursor.pos });
        }
        let supported_versions = cursor.span(remaining)?;
        return Ok(PacketHeader {
            first_byte,
            version: Some(version),
            packet_type: PacketType::VersionNegotiation,
            packet: Span::new(packet_start, input.len()),
            destination_cid,
            source_cid,
            token: empty,
            retry_integrity_tag: empty,
            supported_versions,
            protected_payload: Span::new(input.len(), input.len()),
        });
    }
    if first_byte & FIXED_BIT == 0 {
        return Err(WireError::InvalidFixedBit {
            offset: packet_start,
        });
    }

    let encoded_type = (first_byte & 0x30) >> 4;
    let packet_type = if version == QUIC_VERSION_2 {
        match encoded_type {
            0 => PacketType::Retry,
            1 => PacketType::Initial,
            2 => PacketType::ZeroRtt,
            _ => PacketType::Handshake,
        }
    } else {
        match encoded_type {
            0 => PacketType::Initial,
            1 => PacketType::ZeroRtt,
            2 => PacketType::Handshake,
            _ => PacketType::Retry,
        }
    };

    if packet_type == PacketType::Retry {
        let body_len = input
            .len()
            .checked_sub(cursor.pos)
            .filter(|length| *length >= RETRY_TAG_LEN)
            .ok_or(WireError::Truncated { offset: cursor.pos })?;
        let token = cursor.span(body_len - RETRY_TAG_LEN)?;
        let retry_integrity_tag = cursor.span(RETRY_TAG_LEN)?;
        return Ok(PacketHeader {
            first_byte,
            version: Some(version),
            packet_type,
            packet: Span::new(packet_start, cursor.pos),
            destination_cid,
            source_cid,
            token,
            retry_integrity_tag,
            supported_versions: empty,
            protected_payload: Span::new(cursor.pos, cursor.pos),
        });
    }

    let token = if packet_type == PacketType::Initial {
        let length = cursor.varint()?.into_inner();
        cursor.span_usize(length)?
    } else {
        Span::new(cursor.pos, cursor.pos)
    };
    let protected_len_offset = cursor.pos;
    let protected_len = cursor.varint()?.into_inner();
    let protected_payload = cursor.span_usize(protected_len)?;
    if protected_payload.is_empty() {
        return Err(WireError::InvalidPacketLength {
            offset: protected_len_offset,
        });
    }
    Ok(PacketHeader {
        first_byte,
        version: Some(version),
        packet_type,
        packet: Span::new(packet_start, cursor.pos),
        destination_cid,
        source_cid,
        token,
        retry_integrity_tag: Span::new(cursor.pos, cursor.pos),
        supported_versions: Span::new(cursor.pos, cursor.pos),
        protected_payload,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Frame {
    Padding {
        length: usize,
    },
    Ping,
    Ack {
        delay: VarInt,
        ranges: Vec<Range<u64>>,
        ecn: Option<[VarInt; 3]>,
    },
    ResetStream {
        stream_id: StreamId,
        error_code: VarInt,
        final_size: VarInt,
    },
    StopSending {
        stream_id: StreamId,
        error_code: VarInt,
    },
    Crypto {
        offset: VarInt,
        data: Span,
    },
    NewToken {
        token: Span,
    },
    Stream {
        stream_id: StreamId,
        offset: VarInt,
        fin: bool,
        data: Span,
    },
    MaxData {
        maximum: VarInt,
    },
    MaxStreamData {
        stream_id: StreamId,
        maximum: VarInt,
    },
    MaxStreams {
        maximum: VarInt,
        unidirectional: bool,
    },
    DataBlocked {
        limit: VarInt,
    },
    StreamDataBlocked {
        stream_id: StreamId,
        limit: VarInt,
    },
    StreamsBlocked {
        limit: VarInt,
        unidirectional: bool,
    },
    NewConnectionId {
        sequence_number: VarInt,
        retire_prior_to: VarInt,
        connection_id: Span,
        stateless_reset_token: Span,
    },
    RetireConnectionId {
        sequence_number: VarInt,
    },
    PathChallenge {
        data: Span,
    },
    PathResponse {
        data: Span,
    },
    ConnectionClose {
        error_code: VarInt,
        trigger_frame_type: Option<FrameType>,
        reason: Span,
        application: bool,
    },
    HandshakeDone,
    Datagram {
        data: Span,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameRecord {
    pub frame_type: FrameType,
    pub span: Span,
    pub frame: Frame,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PacketFlags {
    pub ack_eliciting: bool,
    pub in_flight: bool,
    pub probing: bool,
    pub has_crypto: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedFrames {
    pub frames: Vec<FrameRecord>,
    pub flags: PacketFlags,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameDecodeError {
    pub connection_error: ConnectionError,
    pub offset: usize,
}

impl fmt::Display for FrameDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at offset {}", self.connection_error, self.offset)
    }
}

impl Error for FrameDecodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.connection_error)
    }
}

pub fn decode_frames(
    input: &[u8],
    epoch: Epoch,
    crypto_frame_required: bool,
) -> Result<DecodedFrames, FrameDecodeError> {
    let mut cursor = Cursor { input, pos: 0 };
    let mut frames = Vec::new();
    let mut flags = PacketFlags {
        probing: !input.is_empty(),
        ..PacketFlags::default()
    };

    while cursor.pos < input.len() {
        let start = cursor.pos;
        let raw_type = cursor.varint().map_err(|_| {
            frame_error(
                None,
                start,
                "malformed frame type",
                TransportErrorCode::FRAME_ENCODING_ERROR,
            )
        })?;
        let frame_type = FrameType(raw_type);
        if !known_frame_type(frame_type) {
            return Err(frame_error(
                Some(frame_type),
                start,
                "unknown frame type",
                TransportErrorCode::FRAME_ENCODING_ERROR,
            ));
        }
        if !frame_allowed(frame_type, epoch) {
            return Err(frame_error(
                Some(frame_type),
                start,
                "frame is not allowed in this epoch",
                TransportErrorCode::PROTOCOL_VIOLATION,
            ));
        }
        let frame = parse_frame(&mut cursor, frame_type, start).map_err(|reason| {
            frame_error(
                Some(frame_type),
                cursor.pos,
                reason,
                TransportErrorCode::FRAME_ENCODING_ERROR,
            )
        })?;
        let value = frame_type.value();
        flags.ack_eliciting |= !matches!(value, 0x00 | 0x02 | 0x03 | 0x1c | 0x1d);
        flags.in_flight |= !matches!(value, 0x02 | 0x03 | 0x1c | 0x1d);
        flags.probing &= matches!(value, 0x00 | 0x18 | 0x1a | 0x1b);
        flags.has_crypto |= value == 0x06;
        frames.push(FrameRecord {
            frame_type,
            span: Span::new(start, cursor.pos),
            frame,
        });
    }

    if frames.is_empty() {
        return Err(frame_error(
            Some(FrameType::PADDING),
            0,
            "packet contains no frames",
            TransportErrorCode::PROTOCOL_VIOLATION,
        ));
    }
    if crypto_frame_required && !flags.has_crypto {
        return Err(frame_error(
            Some(FrameType::PADDING),
            input.len(),
            "packet contains no CRYPTO frame",
            TransportErrorCode::PROTOCOL_VIOLATION,
        ));
    }
    Ok(DecodedFrames { frames, flags })
}

fn parse_frame(
    cursor: &mut Cursor<'_>,
    frame_type: FrameType,
    frame_start: usize,
) -> Result<Frame, &'static str> {
    let value = frame_type.value();
    Ok(match value {
        0x00 => {
            while cursor.input.get(cursor.pos) == Some(&0) {
                cursor.pos += 1;
            }
            Frame::Padding {
                length: cursor.pos - frame_start,
            }
        }
        0x01 => Frame::Ping,
        0x02 | 0x03 => return parse_ack(cursor, value == 0x03),
        0x04 => Frame::ResetStream {
            stream_id: stream_id(cursor.varint()?)?,
            error_code: cursor.varint()?,
            final_size: cursor.varint()?,
        },
        0x05 => Frame::StopSending {
            stream_id: stream_id(cursor.varint()?)?,
            error_code: cursor.varint()?,
        },
        0x06 => {
            let offset = cursor.varint()?;
            let length = cursor.varint()?.into_inner();
            checked_offset_length(offset, length)?;
            Frame::Crypto {
                offset,
                data: cursor.span_usize(length)?,
            }
        }
        0x07 => {
            let length = cursor.varint()?.into_inner();
            Frame::NewToken {
                token: cursor.span_usize(length)?,
            }
        }
        0x08..=0x0f => {
            let stream_id = stream_id(cursor.varint()?)?;
            let offset = if value & 4 != 0 {
                cursor.varint()?
            } else {
                VarInt::ZERO
            };
            let data = if value & 2 != 0 {
                let length = cursor.varint()?.into_inner();
                checked_offset_length(offset, length)?;
                cursor.span_usize(length)?
            } else {
                cursor.remaining_span()
            };
            Frame::Stream {
                stream_id,
                offset,
                fin: value & 1 != 0,
                data,
            }
        }
        0x10 => Frame::MaxData {
            maximum: cursor.varint()?,
        },
        0x11 => Frame::MaxStreamData {
            stream_id: stream_id(cursor.varint()?)?,
            maximum: cursor.varint()?,
        },
        0x12 | 0x13 => {
            let maximum = cursor.varint()?;
            checked_stream_count(maximum)?;
            Frame::MaxStreams {
                maximum,
                unidirectional: value == 0x13,
            }
        }
        0x14 => Frame::DataBlocked {
            limit: cursor.varint()?,
        },
        0x15 => Frame::StreamDataBlocked {
            stream_id: stream_id(cursor.varint()?)?,
            limit: cursor.varint()?,
        },
        0x16 | 0x17 => {
            let limit = cursor.varint()?;
            checked_stream_count(limit)?;
            Frame::StreamsBlocked {
                limit,
                unidirectional: value == 0x17,
            }
        }
        0x18 => {
            let sequence_number = cursor.varint()?;
            let retire_prior_to = cursor.varint()?;
            if retire_prior_to > sequence_number {
                return Err("retire prior to exceeds connection ID sequence number");
            }
            let length = usize::from(cursor.byte()?);
            if !(1..=MAX_CONNECTION_ID_LEN).contains(&length) {
                return Err("connection ID length must be between 1 and 20");
            }
            Frame::NewConnectionId {
                sequence_number,
                retire_prior_to,
                connection_id: cursor.span(length)?,
                stateless_reset_token: cursor.span(16)?,
            }
        }
        0x19 => Frame::RetireConnectionId {
            sequence_number: cursor.varint()?,
        },
        0x1a => Frame::PathChallenge {
            data: cursor.span(8)?,
        },
        0x1b => Frame::PathResponse {
            data: cursor.span(8)?,
        },
        0x1c | 0x1d => {
            let error_code = cursor.varint()?;
            let trigger_frame_type = if value == 0x1c {
                Some(FrameType(cursor.varint()?))
            } else {
                None
            };
            let length = cursor.varint()?.into_inner();
            Frame::ConnectionClose {
                error_code,
                trigger_frame_type,
                reason: cursor.span_usize(length)?,
                application: value == 0x1d,
            }
        }
        0x1e => Frame::HandshakeDone,
        0x30 => Frame::Datagram {
            data: cursor.remaining_span(),
        },
        0x31 => {
            let length = cursor.varint()?.into_inner();
            Frame::Datagram {
                data: cursor.span_usize(length)?,
            }
        }
        _ => return Err("unknown frame type"),
    })
}

fn parse_ack(cursor: &mut Cursor<'_>, with_ecn: bool) -> Result<Frame, &'static str> {
    let largest = cursor.varint()?.into_inner();
    let delay = cursor.varint()?;
    let range_count = cursor.varint()?.into_inner();
    let first_range = cursor.varint()?.into_inner();
    let first_start = largest
        .checked_sub(first_range)
        .ok_or("invalid ACK range")?;

    // Every additional range needs at least two one-byte varints.
    let maximum_encoded = (cursor.input.len() - cursor.pos) / 2;
    let count = usize::try_from(range_count).map_err(|_| "ACK range count is too large")?;
    if count > maximum_encoded {
        return Err("ACK range count exceeds encoded data");
    }
    let mut ranges = Vec::new();
    ranges
        .try_reserve(count + 1)
        .map_err(|_| "ACK range count is too large")?;
    ranges.push(first_start..largest + 1);
    let mut previous_start = first_start;
    for _ in 0..count {
        let gap = cursor.varint()?.into_inner();
        let range_length = cursor.varint()?.into_inner();
        let end = previous_start
            .checked_sub(gap.checked_add(1).ok_or("invalid ACK range")?)
            .ok_or("invalid ACK range")?;
        let start = end
            .checked_sub(range_length.checked_add(1).ok_or("invalid ACK range")?)
            .ok_or("invalid ACK range")?;
        ranges.push(start..end);
        previous_start = start;
    }
    ranges.reverse();
    let ecn = if with_ecn {
        Some([cursor.varint()?, cursor.varint()?, cursor.varint()?])
    } else {
        None
    };
    Ok(Frame::Ack { delay, ranges, ecn })
}

fn checked_offset_length(offset: VarInt, length: u64) -> Result<(), &'static str> {
    offset
        .into_inner()
        .checked_add(length)
        .filter(|sum| *sum <= VARINT_MAX)
        .map(|_| ())
        .ok_or("offset + length exceeds the QUIC varint maximum")
}

fn checked_stream_count(value: VarInt) -> Result<(), &'static str> {
    if value.into_inner() <= STREAM_COUNT_MAX {
        Ok(())
    } else {
        Err("stream count exceeds 2^60")
    }
}

fn stream_id(value: VarInt) -> Result<StreamId, &'static str> {
    StreamId::new(value.into_inner()).ok_or("stream ID exceeds the QUIC varint maximum")
}

fn known_frame_type(frame_type: FrameType) -> bool {
    matches!(frame_type.value(), 0x00..=0x1e | 0x30 | 0x31)
}

fn frame_allowed(frame_type: FrameType, epoch: Epoch) -> bool {
    match frame_type.value() {
        0x00 | 0x01 | 0x1c => true,
        0x02 | 0x03 | 0x06 => matches!(epoch, Epoch::Initial | Epoch::Handshake | Epoch::OneRtt),
        0x04 | 0x05 | 0x08..=0x17 | 0x1d | 0x30 | 0x31 => {
            matches!(epoch, Epoch::ZeroRtt | Epoch::OneRtt)
        }
        0x18..=0x1b => epoch == Epoch::OneRtt,
        0x07 | 0x1e => epoch == Epoch::OneRtt,
        _ => false,
    }
}

fn frame_error(
    frame_type: Option<FrameType>,
    offset: usize,
    reason: &'static str,
    code: TransportErrorCode,
) -> FrameDecodeError {
    FrameDecodeError {
        connection_error: ConnectionError::new(code, frame_type, reason),
        offset,
    }
}

struct Cursor<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn at(input: &'a [u8], pos: usize) -> Result<Self, WireError> {
        if pos > input.len() {
            Err(WireError::Truncated { offset: pos })
        } else {
            Ok(Self { input, pos })
        }
    }

    fn byte(&mut self) -> Result<u8, WireError> {
        let byte = *self
            .input
            .get(self.pos)
            .ok_or(WireError::Truncated { offset: self.pos })?;
        self.pos += 1;
        Ok(byte)
    }

    fn u32(&mut self) -> Result<u32, WireError> {
        let span = self.span(4)?;
        let bytes = &self.input[span.start..span.end];
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn varint(&mut self) -> Result<VarInt, WireError> {
        let (value, length) = decode_varint(
            self.input
                .get(self.pos..)
                .ok_or(WireError::Truncated { offset: self.pos })?,
        )
        .map_err(|error| match error {
            WireError::Truncated { offset } => WireError::Truncated {
                offset: self.pos.saturating_add(offset),
            },
            other => other,
        })?;
        self.pos += length;
        Ok(value)
    }

    fn span(&mut self, length: usize) -> Result<Span, WireError> {
        let end = self
            .pos
            .checked_add(length)
            .filter(|end| *end <= self.input.len())
            .ok_or(WireError::Truncated { offset: self.pos })?;
        let span = Span::new(self.pos, end);
        self.pos = end;
        Ok(span)
    }

    fn span_usize(&mut self, length: u64) -> Result<Span, WireError> {
        self.span(
            usize::try_from(length)
                .map_err(|_| WireError::InvalidPacketLength { offset: self.pos })?,
        )
    }

    fn remaining_span(&mut self) -> Span {
        let span = Span::new(self.pos, self.input.len());
        self.pos = self.input.len();
        span
    }

    fn connection_id(&mut self) -> Result<Span, WireError> {
        let length_offset = self.pos;
        let length = usize::from(self.byte()?);
        if length > MAX_CONNECTION_ID_LEN {
            return Err(WireError::ConnectionIdTooLong {
                offset: length_offset,
                length,
            });
        }
        self.span(length)
    }
}

impl From<WireError> for &'static str {
    fn from(_: WireError) -> Self {
        "failed to parse frame"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_boundaries_round_trip() {
        for value in [
            0,
            63,
            64,
            16_383,
            16_384,
            (1 << 30) - 1,
            1 << 30,
            VARINT_MAX,
        ] {
            let value = VarInt::new(value).unwrap();
            let mut encoded = [0; 8];
            let length = encode_varint(value, &mut encoded).unwrap();
            assert_eq!(decode_varint(&encoded[..length]), Ok((value, length)));
        }
        assert!(encode_varint(VarInt::MAX, &mut [0; 7]).is_err());
        assert!(decode_varint(&[0xc0]).is_err());
    }

    #[test]
    fn parses_v1_initial_with_spans() {
        let packet = [
            0xc0, 0, 0, 0, 1, 2, 0xaa, 0xbb, 1, 0xcc, 2, 0x11, 0x22, 3, 1, 2, 3,
        ];
        let header = parse_packet_header(&packet, 0, 0).unwrap();
        assert_eq!(header.packet_type, PacketType::Initial);
        assert_eq!(header.destination_cid.get(&packet), Some(&[0xaa, 0xbb][..]));
        assert_eq!(header.source_cid.get(&packet), Some(&[0xcc][..]));
        assert_eq!(header.token.get(&packet), Some(&[0x11, 0x22][..]));
        assert_eq!(header.protected_payload.get(&packet), Some(&[1, 2, 3][..]));
    }

    #[test]
    fn parses_v2_retry_and_version_negotiation() {
        let mut retry = vec![0xc0];
        retry.extend_from_slice(&QUIC_VERSION_2.to_be_bytes());
        retry.extend_from_slice(&[1, 1, 1, 2, 9, 8]);
        retry.extend_from_slice(&[7; RETRY_TAG_LEN]);
        let header = parse_packet_header(&retry, 0, 0).unwrap();
        assert_eq!(header.packet_type, PacketType::Retry);
        assert_eq!(header.token.get(&retry), Some(&[9, 8][..]));
        assert_eq!(header.retry_integrity_tag.len(), RETRY_TAG_LEN);

        let negotiation = [
            0x80, 0, 0, 0, 0, 1, 1, 1, 2, 0, 0, 0, 1, 0x6b, 0x33, 0x43, 0xcf,
        ];
        let header = parse_packet_header(&negotiation, 0, 0).unwrap();
        assert_eq!(header.packet_type, PacketType::VersionNegotiation);
        assert_eq!(
            header.versions(&negotiation).collect::<Vec<_>>(),
            vec![1, QUIC_VERSION_2]
        );
    }

    #[test]
    fn parses_short_header_and_rejects_bad_headers() {
        let packet = [0x40, 1, 2, 3, 4];
        let header = parse_packet_header(&packet, 0, 2).unwrap();
        assert_eq!(header.packet_type, PacketType::OneRtt);
        assert_eq!(header.destination_cid, Span::new(1, 3));
        assert_eq!(header.protected_payload, Span::new(3, 5));
        assert!(parse_packet_header(&[0, 1], 0, 1).is_err());
        assert!(parse_packet_header(&[0xc0, 0], 0, 0).is_err());
    }

    #[test]
    fn decodes_all_shape_categories_and_flags() {
        let input = [0x00, 0x00, 0x01, 0x0b, 0x04, 0x03, b'a', b'b', b'c'];
        let decoded = decode_frames(&input, Epoch::OneRtt, false).unwrap();
        assert_eq!(decoded.frames.len(), 3);
        assert_eq!(decoded.frames[0].frame, Frame::Padding { length: 2 });
        assert_eq!(decoded.frames[0].span, Span::new(0, 2));
        assert_eq!(
            decoded.frames[2].frame,
            Frame::Stream {
                stream_id: StreamId::new(4).unwrap(),
                offset: VarInt::ZERO,
                fin: true,
                data: Span::new(6, 9),
            }
        );
        assert!(decoded.flags.ack_eliciting);
        assert!(decoded.flags.in_flight);
        assert!(!decoded.flags.probing);
    }

    #[test]
    fn ack_ranges_are_checked_and_normalized_ascending() {
        // Largest 10, first range 1 => [9, 11), gap 1 and range 2 => [4, 7).
        let decoded = decode_frames(&[0x02, 10, 5, 1, 1, 1, 2], Epoch::Initial, false).unwrap();
        assert_eq!(
            decoded.frames[0].frame,
            Frame::Ack {
                delay: VarInt::new(5).unwrap(),
                ranges: vec![4..7, 9..11],
                ecn: None,
            }
        );
        let error = decode_frames(&[0x02, 0, 0, 0, 1], Epoch::Initial, false).unwrap_err();
        assert_eq!(
            error.connection_error.code,
            TransportErrorCode::FRAME_ENCODING_ERROR
        );
    }

    #[test]
    fn validates_epoch_lengths_counts_and_crypto_requirement() {
        assert_eq!(
            decode_frames(&[0x02, 0, 0, 0, 0], Epoch::ZeroRtt, false)
                .unwrap_err()
                .connection_error
                .code,
            TransportErrorCode::PROTOCOL_VIOLATION
        );
        assert!(decode_frames(&[0x06, 0x3f, 2, 1], Epoch::Initial, false).is_err());
        assert!(decode_frames(
            &[0x12, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
            Epoch::OneRtt,
            false
        )
        .is_err());
        assert!(decode_frames(&[0x01], Epoch::Initial, true).is_err());
        assert!(decode_frames(&[], Epoch::Initial, false).is_err());
    }

    #[test]
    fn malformed_unknown_and_truncated_frames_report_encoding_errors() {
        for payload in [&[0xff][..], &[0x1f][..], &[0x1c, 0, 1][..]] {
            let error = decode_frames(payload, Epoch::OneRtt, false).unwrap_err();
            assert_eq!(
                error.connection_error.code,
                TransportErrorCode::FRAME_ENCODING_ERROR
            );
        }
        let padding = decode_frames(&[0; 1200], Epoch::OneRtt, false).unwrap();
        assert!(!padding.flags.ack_eliciting);
        assert!(padding.flags.probing);
    }

    #[test]
    fn zero_rtt_uses_the_rfc_frame_allowlist() {
        for frame in [
            &[
                0x18, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ][..],
            &[0x19, 0][..],
            &[0x1a, 0, 0, 0, 0, 0, 0, 0, 0][..],
            &[0x1b, 0, 0, 0, 0, 0, 0, 0, 0][..],
        ] {
            assert_eq!(
                decode_frames(frame, Epoch::ZeroRtt, false)
                    .unwrap_err()
                    .connection_error
                    .code,
                TransportErrorCode::PROTOCOL_VIOLATION
            );
        }
        for frame in [
            &[0x00][..],
            &[0x01][..],
            &[0x04, 0, 0, 0][..],
            &[0x05, 1, 0][..],
            &[0x0a, 0, 0][..],
            &[0x10, 0][..],
            &[0x11, 0, 0][..],
            &[0x12, 0][..],
            &[0x14, 0][..],
            &[0x15, 0, 0][..],
            &[0x16, 0][..],
            &[0x31, 0][..],
        ] {
            assert!(decode_frames(frame, Epoch::ZeroRtt, false).is_ok());
        }
    }

    #[test]
    fn decodes_ecn_close_connection_id_and_datagram_spans() {
        let ack = decode_frames(&[0x03, 3, 0, 0, 0, 4, 5, 6], Epoch::OneRtt, false).unwrap();
        assert!(matches!(
            ack.frames[0].frame,
            Frame::Ack { ecn: Some(_), .. }
        ));

        let close =
            decode_frames(&[0x1c, 7, 6, 3, b'b', b'a', b'd'], Epoch::Initial, false).unwrap();
        assert!(matches!(
            close.frames[0].frame,
            Frame::ConnectionClose {
                application: false,
                ..
            }
        ));

        let mut cid = vec![0x18, 2, 1, 4, 1, 2, 3, 4];
        cid.extend_from_slice(&[0; 16]);
        let decoded = decode_frames(&cid, Epoch::OneRtt, false).unwrap();
        assert!(matches!(
            decoded.frames[0].frame,
            Frame::NewConnectionId { .. }
        ));
        cid[1] = 0;
        cid[2] = 1;
        assert!(decode_frames(&cid, Epoch::OneRtt, false).is_err());

        let datagram = decode_frames(&[0x31, 2, 8, 9], Epoch::OneRtt, false).unwrap();
        assert_eq!(
            datagram.frames[0].frame,
            Frame::Datagram {
                data: Span::new(2, 4)
            }
        );
    }
}
