from __future__ import annotations

from dataclasses import dataclass


class QuicEvent:
    """
    Base class for QUIC events.
    """

    pass


@dataclass(slots=True)
class ConnectionIdIssued(QuicEvent):
    connection_id: bytes


@dataclass(slots=True)
class ConnectionIdRetired(QuicEvent):
    connection_id: bytes


@dataclass(slots=True)
class ConnectionTerminated(QuicEvent):
    """
    The ConnectionTerminated event is fired when the QUIC connection is terminated.
    """

    error_code: int
    "The error code which was specified when closing the connection."

    frame_type: int | None
    "The frame type which caused the connection to be closed, or `None`."

    reason_phrase: str
    "The human-readable reason for which the connection was closed."


@dataclass(slots=True)
class DatagramFrameReceived(QuicEvent):
    """
    The DatagramFrameReceived event is fired when a DATAGRAM frame is received.
    """

    data: bytes
    "The data which was received."


@dataclass(slots=True)
class HandshakeCompleted(QuicEvent):
    """
    The HandshakeCompleted event is fired when the TLS handshake completes.
    """

    alpn_protocol: str | None
    "The protocol which was negotiated using ALPN, or `None`."

    early_data_accepted: bool
    "Whether early (0-RTT) data was accepted by the remote peer."

    session_resumed: bool
    "Whether a TLS session was resumed."


@dataclass(slots=True)
class PingAcknowledged(QuicEvent):
    """
    The PingAcknowledged event is fired when a PING frame is acknowledged.
    """

    uid: int
    "The unique ID of the PING."


@dataclass(slots=True)
class ProtocolNegotiated(QuicEvent):
    """
    The ProtocolNegotiated event is fired when ALPN negotiation completes.
    """

    alpn_protocol: str | None
    "The protocol which was negotiated using ALPN, or `None`."


@dataclass(slots=True)
class StreamDataReceived(QuicEvent):
    """
    The StreamDataReceived event is fired whenever data is received on a
    stream.
    """

    data: bytes
    "The data which was received."

    end_stream: bool
    "Whether the STREAM frame had the FIN bit set."

    stream_id: int
    "The ID of the stream the data was received for."


@dataclass(slots=True)
class StopSendingReceived(QuicEvent):
    """
    The StopSendingReceived event is fired when the remote peer requests
    stopping data transmission on a stream.
    """

    error_code: int
    "The error code that was sent from the peer."

    stream_id: int
    "The ID of the stream that the peer requested stopping data transmission."


@dataclass(slots=True)
class StreamReset(QuicEvent):
    """
    The StreamReset event is fired when the remote peer resets a stream.
    """

    error_code: int
    "The error code that triggered the reset."

    stream_id: int
    "The ID of the stream that was reset."
