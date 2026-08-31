use std::error::Error;
use std::fmt;

/// The largest value representable by a QUIC variable-length integer.
pub const VARINT_MAX: u64 = (1_u64 << 62) - 1;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VarInt(u64);

impl VarInt {
    pub const MAX: Self = Self(VARINT_MAX);
    pub const ZERO: Self = Self(0);

    pub const fn new(value: u64) -> Option<Self> {
        if value <= VARINT_MAX {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn into_inner(self) -> u64 {
        self.0
    }

    pub fn checked_add(self, rhs: u64) -> Option<Self> {
        self.0.checked_add(rhs).and_then(Self::new)
    }
}

impl From<VarInt> for u64 {
    fn from(value: VarInt) -> Self {
        value.0
    }
}

impl TryFrom<u64> for VarInt {
    type Error = VarIntError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(VarIntError(value))
    }
}

impl fmt::Display for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VarIntError(pub u64);

impl fmt::Display for VarIntError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} exceeds the QUIC varint maximum", self.0)
    }
}

impl Error for VarIntError {}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum Epoch {
    Initial,
    ZeroRtt,
    Handshake,
    OneRtt,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PacketNumberSpace {
    Initial,
    Handshake,
    ApplicationData,
}

impl Epoch {
    pub const fn packet_number_space(self) -> PacketNumberSpace {
        match self {
            Self::Initial => PacketNumberSpace::Initial,
            Self::Handshake => PacketNumberSpace::Handshake,
            Self::ZeroRtt | Self::OneRtt => PacketNumberSpace::ApplicationData,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    VersionNegotiation,
    OneRtt,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Role {
    Client,
    Server,
}

impl Role {
    pub const fn peer(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StreamDirection {
    Bidirectional,
    Unidirectional,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ConnectionState {
    FirstFlight,
    Connected,
    Closing,
    Draining,
    Terminated,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StreamId(VarInt);

impl StreamId {
    pub const fn new(value: u64) -> Option<Self> {
        match VarInt::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub const fn into_inner(self) -> u64 {
        self.0.into_inner()
    }

    pub const fn initiator(self) -> Role {
        if self.into_inner() & 1 == 0 {
            Role::Client
        } else {
            Role::Server
        }
    }

    pub const fn is_unidirectional(self) -> bool {
        self.into_inner() & 2 != 0
    }

    pub const fn index(self) -> u64 {
        self.into_inner() >> 2
    }
}

impl TryFrom<u64> for StreamId {
    type Error = VarIntError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Ok(Self(VarInt::try_from(value)?))
    }
}

impl From<StreamId> for u64 {
    fn from(value: StreamId) -> Self {
        value.into_inner()
    }
}

/// A frame type is a varint so extensions and STREAM flag combinations remain representable.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FrameType(pub VarInt);

impl FrameType {
    pub const PADDING: Self = Self(VarInt::ZERO);
    pub const PING: Self = Self(VarInt(0x01));
    pub const ACK: Self = Self(VarInt(0x02));
    pub const RESET_STREAM: Self = Self(VarInt(0x04));
    pub const STOP_SENDING: Self = Self(VarInt(0x05));
    pub const CRYPTO: Self = Self(VarInt(0x06));
    #[cfg(test)]
    pub const NEW_TOKEN: Self = Self(VarInt(0x07));
    pub const STREAM_BASE: Self = Self(VarInt(0x08));
    pub const STREAM_WITH_OFFSET_LENGTH: Self = Self(VarInt(0x0e));
    pub const STREAM_WITH_OFFSET_LENGTH_FIN: Self = Self(VarInt(0x0f));
    pub const MAX_DATA: Self = Self(VarInt(0x10));
    pub const MAX_STREAM_DATA: Self = Self(VarInt(0x11));
    pub const MAX_STREAMS_BIDI: Self = Self(VarInt(0x12));
    pub const MAX_STREAMS_UNI: Self = Self(VarInt(0x13));
    pub const NEW_CONNECTION_ID: Self = Self(VarInt(0x18));
    pub const RETIRE_CONNECTION_ID: Self = Self(VarInt(0x19));
    pub const PATH_CHALLENGE: Self = Self(VarInt(0x1a));
    pub const PATH_RESPONSE: Self = Self(VarInt(0x1b));
    pub const TRANSPORT_CLOSE: Self = Self(VarInt(0x1c));
    pub const APPLICATION_CLOSE: Self = Self(VarInt(0x1d));
    pub const HANDSHAKE_DONE: Self = Self(VarInt(0x1e));
    pub const DATAGRAM_WITH_LENGTH: Self = Self(VarInt(0x31));

    pub const fn value(self) -> u64 {
        self.0.into_inner()
    }
}

impl TryFrom<u64> for FrameType {
    type Error = VarIntError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Ok(Self(VarInt::try_from(value)?))
    }
}

/// QUIC transport error code, including extension and TLS alert values.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TransportErrorCode(pub VarInt);

impl TransportErrorCode {
    pub const INTERNAL_ERROR: Self = Self(VarInt(0x01));
    pub const FLOW_CONTROL_ERROR: Self = Self(VarInt(0x03));
    pub const STREAM_LIMIT_ERROR: Self = Self(VarInt(0x04));
    pub const STREAM_STATE_ERROR: Self = Self(VarInt(0x05));
    pub const FINAL_SIZE_ERROR: Self = Self(VarInt(0x06));
    pub const FRAME_ENCODING_ERROR: Self = Self(VarInt(0x07));
    pub const CONNECTION_ID_LIMIT_ERROR: Self = Self(VarInt(0x09));
    pub const PROTOCOL_VIOLATION: Self = Self(VarInt(0x0a));
    pub const APPLICATION_ERROR: Self = Self(VarInt(0x0c));
    pub const CRYPTO_BUFFER_EXCEEDED: Self = Self(VarInt(0x0d));

    pub const fn value(self) -> u64 {
        self.0.into_inner()
    }
}

impl TryFrom<u64> for TransportErrorCode {
    type Error = VarIntError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Ok(Self(VarInt::try_from(value)?))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionError {
    pub code: TransportErrorCode,
    pub frame_type: Option<FrameType>,
    pub reason: String,
}

impl ConnectionError {
    pub fn new(
        code: TransportErrorCode,
        frame_type: Option<FrameType>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            code,
            frame_type,
            reason: reason.into(),
        }
    }
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "QUIC error 0x{:x}: {}", self.code.value(), self.reason)?;
        if let Some(frame_type) = self.frame_type {
            write!(f, " (frame 0x{:x})", frame_type.value())?;
        }
        Ok(())
    }
}

impl Error for ConnectionError {}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DeliveryOutcome {
    Acked,
    Discarded,
    Lost,
    ProbeCopy,
    RetireAndRetransmit,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeliveryId(pub u64);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_is_checked() {
        assert_eq!(VarInt::new(VARINT_MAX).unwrap().into_inner(), VARINT_MAX);
        assert!(VarInt::new(VARINT_MAX + 1).is_none());
        assert!(VarInt::MAX.checked_add(1).is_none());
    }

    #[test]
    fn stream_id_parts() {
        let id = StreamId::new(0b1011).unwrap();
        assert_eq!(id.initiator(), Role::Server);
        assert!(id.is_unidirectional());
        assert_eq!(id.index(), 2);
    }

    #[test]
    fn error_display_includes_context() {
        let error = ConnectionError::new(
            TransportErrorCode::FRAME_ENCODING_ERROR,
            Some(FrameType::ACK),
            "bad range",
        );
        assert_eq!(error.to_string(), "QUIC error 0x7: bad range (frame 0x2)");
    }
}
