from __future__ import annotations

import logging
from enum import Enum, IntEnum

from .._compat import BufferProtocol, as_contiguous_buffer
from .._hazmat import (
    Buffer,
    BufferReadError,
    DecoderStreamError,
    DecompressionFailed,
    EncoderStreamError,
    HeaderTooLarge,
    QpackDecoder,
    QpackEncoder,
    StreamBlocked,
    encode_uint_var,
)
from ..quic.connection import (
    QuicConnection,
    stream_is_client_initiated,
    stream_is_unidirectional,
)
from ..quic.events import (
    DatagramFrameReceived,
    QuicEvent,
    StopSendingReceived,
    StreamDataReceived,
    StreamReset,
)
from ..quic.logger import QuicLoggerTrace
from .events import (
    DatagramReceived,
    DataReceived,
    GoawayReceived,
    H3Event,
    Headers,
    HeadersReceived,
    InformationalHeadersReceived,
    PushPromiseReceived,
    WebTransportStreamDataReceived,
)
from .events import (
    StopSending as H3StopSending,
)
from .events import (
    StreamReset as H3StreamReset,
)
from .exceptions import NoAvailablePushIDError

logger = logging.getLogger("http3")

H3_ALPN = ["h3"]
RESERVED_SETTINGS = (0x0, 0x2, 0x3, 0x4, 0x5)

# Frozenset constants for header validation
_RESPONSE_ALLOWED_PSEUDO = frozenset((b":status",))
_RESPONSE_REQUIRED_PSEUDO = frozenset((b":status",))
_REQUEST_ALLOWED_PSEUDO = frozenset(
    (b":method", b":scheme", b":authority", b":path", b":protocol")
)
_REQUEST_REQUIRED_PSEUDO = frozenset((b":method", b":authority"))
_PUSH_PROMISE_PSEUDO = frozenset((b":method", b":scheme", b":authority", b":path"))
_TRAILERS_PSEUDO: frozenset[bytes] = frozenset()

# Lookup table for uppercase ASCII bytes (A-Z = 65-90)
_HAS_UPPERCASE = bytearray(256)
for _i in range(65, 91):
    _HAS_UPPERCASE[_i] = 1
del _i


class ErrorCode(IntEnum):
    H3_DATAGRAM_ERROR = 0x33
    H3_NO_ERROR = 0x100
    H3_GENERAL_PROTOCOL_ERROR = 0x101
    H3_INTERNAL_ERROR = 0x102
    H3_STREAM_CREATION_ERROR = 0x103
    H3_CLOSED_CRITICAL_STREAM = 0x104
    H3_FRAME_UNEXPECTED = 0x105
    H3_FRAME_ERROR = 0x106
    H3_EXCESSIVE_LOAD = 0x107
    H3_ID_ERROR = 0x108
    H3_SETTINGS_ERROR = 0x109
    H3_MISSING_SETTINGS = 0x10A
    H3_REQUEST_REJECTED = 0x10B
    H3_REQUEST_CANCELLED = 0x10C
    H3_REQUEST_INCOMPLETE = 0x10D
    H3_MESSAGE_ERROR = 0x10E
    H3_CONNECT_ERROR = 0x10F
    H3_VERSION_FALLBACK = 0x110
    QPACK_DECOMPRESSION_FAILED = 0x200
    QPACK_ENCODER_STREAM_ERROR = 0x201
    QPACK_DECODER_STREAM_ERROR = 0x202


class FrameType(IntEnum):
    DATA = 0x0
    HEADERS = 0x1
    PRIORITY = 0x2
    CANCEL_PUSH = 0x3
    SETTINGS = 0x4
    PUSH_PROMISE = 0x5
    GOAWAY = 0x7
    MAX_PUSH_ID = 0xD
    DUPLICATE_PUSH = 0xE
    WEBTRANSPORT_STREAM = 0x41


class HeadersState(Enum):
    INITIAL = 0
    AFTER_HEADERS = 1
    AFTER_TRAILERS = 2


class Setting(IntEnum):
    QPACK_MAX_TABLE_CAPACITY = 0x1
    MAX_FIELD_SECTION_SIZE = 0x6
    QPACK_BLOCKED_STREAMS = 0x7

    # https://datatracker.ietf.org/doc/html/rfc9220#section-5
    ENABLE_CONNECT_PROTOCOL = 0x8
    # https://datatracker.ietf.org/doc/html/rfc9297#section-2.1.1
    H3_DATAGRAM = 0x33
    # Legacy identifier from draft-ietf-masque-h3-datagram-05; kept so we can
    # interop on receive with peers that have not migrated to RFC 9297.
    H3_DATAGRAM_DRAFT05 = 0xFFD277
    # https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http2-02#section-10.1
    ENABLE_WEBTRANSPORT = 0x2B603742

    # Dummy setting to check it is correctly ignored by the peer.
    # https://datatracker.ietf.org/doc/html/rfc9114#section-7.2.4.1
    DUMMY = 0x21


class StreamType(IntEnum):
    CONTROL = 0
    PUSH = 1
    QPACK_ENCODER = 2
    QPACK_DECODER = 3
    WEBTRANSPORT = 0x54


class ProtocolError(Exception):
    """
    Base class for protocol errors.

    These errors are not exposed to the API user, they are handled
    in :meth:`H3Connection.handle_event`.
    """

    error_code = ErrorCode.H3_GENERAL_PROTOCOL_ERROR

    def __init__(self, reason_phrase: str = ""):
        self.reason_phrase = reason_phrase


class QpackDecompressionFailed(ProtocolError):
    error_code = ErrorCode.QPACK_DECOMPRESSION_FAILED


class QpackDecoderStreamError(ProtocolError):
    error_code = ErrorCode.QPACK_DECODER_STREAM_ERROR


class QpackEncoderStreamError(ProtocolError):
    error_code = ErrorCode.QPACK_ENCODER_STREAM_ERROR


class ClosedCriticalStream(ProtocolError):
    error_code = ErrorCode.H3_CLOSED_CRITICAL_STREAM


class FrameError(ProtocolError):
    error_code = ErrorCode.H3_FRAME_ERROR


class FrameUnexpected(ProtocolError):
    error_code = ErrorCode.H3_FRAME_UNEXPECTED


class MessageError(ProtocolError):
    error_code = ErrorCode.H3_MESSAGE_ERROR


class FieldSectionTooLarge(ProtocolError):
    error_code = ErrorCode.H3_EXCESSIVE_LOAD


class MissingSettingsError(ProtocolError):
    error_code = ErrorCode.H3_MISSING_SETTINGS


class SettingsError(ProtocolError):
    error_code = ErrorCode.H3_SETTINGS_ERROR


class StreamCreationError(ProtocolError):
    error_code = ErrorCode.H3_STREAM_CREATION_ERROR


def encode_frame(frame_type: int, frame_data: BufferProtocol) -> bytes:
    frame_data = as_contiguous_buffer(frame_data)
    try:
        # Allocate the final frame once, copying directly from the payload buffer.
        return b"".join(
            (encode_uint_var(frame_type), encode_uint_var(len(frame_data)), frame_data)
        )
    finally:
        if isinstance(frame_data, memoryview):
            frame_data.release()


def encode_settings(settings: dict[int, int]) -> bytes:
    buf = Buffer(capacity=1024)
    for setting, value in settings.items():
        buf.push_uint_var(setting)
        buf.push_uint_var(value)
    return buf.data


def parse_max_push_id(data: bytes) -> int:
    buf = Buffer(data=data)
    max_push_id = buf.pull_uint_var()
    if not buf.eof():
        raise FrameError("MAX_PUSH_ID frame has extra trailing bytes")
    return max_push_id


def parse_settings(data: bytes) -> dict[int, int]:
    buf = Buffer(data=data)
    settings: dict[int, int] = {}
    while not buf.eof():
        setting = buf.pull_uint_var()
        value = buf.pull_uint_var()
        if setting in RESERVED_SETTINGS:
            raise SettingsError(f"Setting identifier 0x{setting:x} is reserved")
        if setting in settings:
            raise SettingsError(f"Setting identifier 0x{setting:x} is included twice")
        settings[setting] = value
    return dict(settings)


def validate_headers(
    headers: Headers,
    allowed_pseudo_headers: frozenset[bytes],
    required_pseudo_headers: frozenset[bytes],
    extract_header: bytes | None = None,
) -> bytes | None:
    after_pseudo_headers = False
    authority: bytes | None = None
    path: bytes | None = None
    scheme: bytes | None = None
    seen_pseudo_headers: set[bytes] = set()

    extracted_header_value: bytes | None = None

    _has_upper = _HAS_UPPERCASE
    for key, value in headers:
        # Fast uppercase check using lookup table instead of regex
        for b in key:
            if _has_upper[b]:
                raise MessageError(f"Header {key!r} contains uppercase letters")

        if extract_header is not None and extracted_header_value is None:
            extracted_header_value = value

        if key and key[0] == 58:  # ord(b":") == 58
            # pseudo-headers
            if after_pseudo_headers:
                raise MessageError(
                    f"Pseudo-header {key!r} is not allowed after regular headers"
                )
            if key not in allowed_pseudo_headers:
                raise MessageError(f"Pseudo-header {key!r} is not valid")
            if key in seen_pseudo_headers:
                raise MessageError(f"Pseudo-header {key!r} is included twice")
            seen_pseudo_headers.add(key)

            # store value
            if key == b":authority":
                authority = value
            elif key == b":path":
                path = value
            elif key == b":scheme":
                scheme = value
        else:
            # regular headers
            after_pseudo_headers = True

    # check required pseudo-headers are present
    if not required_pseudo_headers.issubset(seen_pseudo_headers):
        missing = required_pseudo_headers.difference(seen_pseudo_headers)
        raise MessageError(f"Pseudo-headers {sorted(missing)} are missing")

    if scheme in (b"http", b"https"):
        if not authority:
            raise MessageError("Pseudo-header b':authority' cannot be empty")
        if not path:
            raise MessageError("Pseudo-header b':path' cannot be empty")

    return extracted_header_value


def validate_push_promise_headers(headers: Headers) -> None:
    validate_headers(
        headers,
        allowed_pseudo_headers=_PUSH_PROMISE_PSEUDO,
        required_pseudo_headers=_PUSH_PROMISE_PSEUDO,
    )


def validate_request_headers(headers: Headers) -> None:
    validate_headers(
        headers,
        allowed_pseudo_headers=_REQUEST_ALLOWED_PSEUDO,
        required_pseudo_headers=_REQUEST_REQUIRED_PSEUDO,
    )


def validate_response_headers(headers: Headers) -> int:
    status_code: bytes | None = validate_headers(
        headers,
        allowed_pseudo_headers=_RESPONSE_ALLOWED_PSEUDO,
        required_pseudo_headers=_RESPONSE_REQUIRED_PSEUDO,
        extract_header=b":status",
    )

    try:
        return int(status_code)
    except ValueError:
        raise MessageError(f"Invalid :status value {status_code!r}") from None


def validate_trailers(headers: Headers) -> None:
    validate_headers(
        headers,
        allowed_pseudo_headers=_TRAILERS_PSEUDO,
        required_pseudo_headers=_TRAILERS_PSEUDO,
    )


class H3Stream:
    def __init__(self, stream_id: int) -> None:
        self.blocked = False
        self.blocked_frame_size: int | None = None
        self.buffer = bytearray()
        self.ended = False
        self.frame_size: int | None = None
        self.frame_type: int | None = None
        self.headers_recv_state: HeadersState = HeadersState.INITIAL
        self.headers_send_state: HeadersState = HeadersState.INITIAL
        self.push_id: int | None = None
        self.session_id: int | None = None
        self.stream_id = stream_id
        self.stream_type: int | None = None
        self.receiving_ended = False
        self.sending_ended = False

    def is_ended(self) -> bool:
        return self.sending_ended and self.receiving_ended and not self.blocked

    def finish_sending(self) -> None:
        if self.sending_ended:
            raise FrameUnexpected("stream was already ended")

        self.sending_ended = True


class H3Connection:
    """
    A low-level HTTP/3 connection object.

    :param quic: A :class:`~qh3.connection.QuicConnection` instance.
    """

    def __init__(self, quic: QuicConnection, enable_webtransport: bool = False) -> None:
        self._is_client = quic.configuration.is_client
        # settings
        self._max_table_capacity = 65536
        self._blocked_streams = 100
        self._max_field_section_size = 1048576 if self._is_client else 262144
        # Huffman can use up to 30 bits per decoded octet. Keep a separate
        # bounded allowance for encoded bytes, including the QPACK prefix.
        self._max_encoded_field_section_size = self._max_field_section_size * 4 + 32
        self._enable_webtransport = enable_webtransport

        self._is_done = False
        self._quic = quic
        self._quic_logger: QuicLoggerTrace | None = quic._quic_logger
        self._decoder = QpackDecoder(
            self._max_table_capacity,
            self._blocked_streams,
            max_field_section_size=self._max_field_section_size,
        )
        self._decoder_bytes_received = 0
        self._decoder_bytes_sent = 0
        self._encoder = QpackEncoder()
        self._encoder_bytes_received = 0
        self._encoder_bytes_sent = 0
        self._settings_received = False
        self._stream: dict[int, H3Stream] = {}

        self._max_push_id: int | None = 8 if self._is_client else None
        self._next_push_id: int = 0

        self._local_control_stream_id: int | None = None
        self._local_decoder_stream_id: int | None = None
        self._local_encoder_stream_id: int | None = None

        self._peer_control_stream_id: int | None = None
        self._peer_decoder_stream_id: int | None = None
        self._peer_encoder_stream_id: int | None = None
        self._received_settings: dict[int, int] | None = None
        self._sent_settings: dict[int, int] | None = None

        self._blocked_stream_map: dict[int, H3Stream] = {}

        self._init_connection()

    def create_webtransport_stream(
        self, session_id: int, is_unidirectional: bool = False
    ) -> int:
        """
        Create a WebTransport stream and return the stream ID.

        :param session_id: The WebTransport session identifier.
        :param is_unidirectional: Whether to create a unidirectional stream.
        """
        if is_unidirectional:
            stream_id = self._create_uni_stream(StreamType.WEBTRANSPORT)
            self._quic.send_stream_data(stream_id, encode_uint_var(session_id))
        else:
            stream_id = self._quic.get_next_available_stream_id()
            self._log_stream_type(
                stream_id=stream_id, stream_type=StreamType.WEBTRANSPORT
            )
            self._quic.send_stream_data(
                stream_id,
                encode_uint_var(FrameType.WEBTRANSPORT_STREAM)
                + encode_uint_var(session_id),
            )
        return stream_id

    def handle_event(self, event: QuicEvent) -> list[H3Event]:
        """
        Handle a QUIC event and return a list of HTTP events.

        :param event: The QUIC event to handle.
        """

        if not self._is_done:
            try:
                if isinstance(event, StreamDataReceived):
                    return self._receive_stream_data(event)
                elif isinstance(event, DatagramFrameReceived):
                    return self._receive_datagram(event.data)
                elif isinstance(event, StreamReset):
                    return self._receive_stream_reset(event.stream_id, event.error_code)
                elif isinstance(event, StopSendingReceived):
                    return self._receive_stop_sending(event.stream_id, event.error_code)
            except ProtocolError as exc:
                self._is_done = True
                self._quic.close(
                    error_code=exc.error_code, reason_phrase=exc.reason_phrase
                )

        return []

    def _is_critical_stream(self, stream_id: int) -> bool:
        """
        RFC 9114 6.2: control, QPACK encoder, and QPACK decoder streams are
        critical streams. Closure of any critical stream MUST be treated as
        a connection error of type H3_CLOSED_CRITICAL_STREAM.
        """
        return stream_id in (
            self._peer_control_stream_id,
            self._peer_decoder_stream_id,
            self._peer_encoder_stream_id,
            self._local_control_stream_id,
            self._local_decoder_stream_id,
            self._local_encoder_stream_id,
        )

    def _check_server_critical_stream_end(self, stream: H3Stream) -> None:
        if (
            not self._is_client
            and stream.receiving_ended
            and self._is_critical_stream(stream.stream_id)
        ):
            raise ClosedCriticalStream(
                f"Critical stream {stream.stream_id} closed by peer"
            )

    def _receive_stream_reset(self, stream_id: int, error_code: int) -> list[H3Event]:
        # RFC 9114 6.2.1: a peer-initiated reset of a critical stream is a
        # connection error of type H3_CLOSED_CRITICAL_STREAM.
        if self._is_critical_stream(stream_id):
            raise ClosedCriticalStream(f"Critical stream {stream_id} reset by peer")

        stream = self._stream.get(stream_id)
        if stream is None:
            return [H3StreamReset(stream_id=stream_id, error_code=error_code)]

        # Drop the stream so it cannot accumulate further state and so any
        # future cleanup (e.g. waiting on receiving_ended) is satisfied.
        # Note: RFC 9204 2.2.2.2 Stream Cancellation is OPTIONAL and is
        # only useful when the encoder uses the dynamic table; we omit it.
        stream.receiving_ended = True
        if stream.is_ended():
            self._stream.pop(stream_id, None)
        self._blocked_stream_map.pop(stream_id, None)

        return [H3StreamReset(stream_id=stream_id, error_code=error_code)]

    def _receive_stop_sending(self, stream_id: int, error_code: int) -> list[H3Event]:
        # RFC 9114 6.2.1: a peer-initiated reset of a critical stream is a
        # connection error of type H3_CLOSED_CRITICAL_STREAM.
        if self._is_critical_stream(stream_id):
            raise ClosedCriticalStream(
                f"Critical stream {stream_id} stop-sending by peer"
            )

        stream = self._stream.get(stream_id)
        if stream is not None:
            stream.sending_ended = True
            if stream.is_ended():
                self._stream.pop(stream_id, None)
        # The blocked-stream map references this stream by id; drop it so
        # H3 does not retain state for a stream the application is no
        # longer expected to write to.
        self._blocked_stream_map.pop(stream_id, None)

        return [H3StopSending(stream_id=stream_id, error_code=error_code)]

    def send_datagram(self, flow_id: int, data: bytes) -> None:
        """
        Send a datagram for the specified flow.

        :param flow_id: The flow ID.
        :param data: The HTTP/3 datagram payload.
        """
        self._quic.send_datagram_frame(encode_uint_var(flow_id) + data)

    def send_push_promise(self, stream_id: int, headers: Headers) -> int:
        """
        Send a push promise related to the specified stream.

        Returns the stream ID on which headers and data can be sent.

        :param stream_id: The stream ID on which to send the data.
        :param headers: The HTTP request headers for this push.
        """
        assert not self._is_client, "Only servers may send a push promise."
        if self._max_push_id is None or self._next_push_id >= self._max_push_id:
            raise NoAvailablePushIDError

        # send push promise
        push_id = self._next_push_id
        self._next_push_id += 1
        self._quic.send_stream_data(
            stream_id,
            encode_frame(
                FrameType.PUSH_PROMISE,
                encode_uint_var(push_id) + self._encode_headers(stream_id, headers),
            ),
        )

        #  create push stream
        push_stream_id = self._create_uni_stream(StreamType.PUSH, push_id=push_id)
        self._quic.send_stream_data(push_stream_id, encode_uint_var(push_id))

        return push_stream_id

    def send_data(self, stream_id: int, data: BufferProtocol, end_stream: bool) -> None:
        """
        Send data on the given stream.

        To retrieve datagram which need to be sent over the network call the QUIC
        connection's :meth:`~qh3.connection.QuicConnection.datagrams_to_send`
        method.

        :param stream_id: The stream ID on which to send the data.
        :param data: A C-contiguous buffer, such as bytes, bytearray, memoryview,
            or a CPU-backed Arrow buffer. Its raw bytes are copied by the existing
            framing and send queue; no intermediate bytes conversion is made.
            Do not mutate it during this call. It may be reused after return.
        :param end_stream: Whether to end the stream.
        """
        data = as_contiguous_buffer(data)
        try:
            # check DATA frame is allowed
            stream = self._get_or_create_stream(stream_id)
            if stream.headers_send_state != HeadersState.AFTER_HEADERS:
                raise FrameUnexpected("DATA frame is not allowed in this state")

            # Validate and frame the buffer before committing FIN to stream state.
            data_length = len(data)
            frame = encode_frame(FrameType.DATA, data)
        finally:
            if isinstance(data, memoryview):
                data.release()

        if end_stream:
            stream.finish_sending()

        self._maybe_cleanup_stream(stream)

        # log frame
        if self._quic_logger is not None:
            self._quic_logger.log_event(
                category="http",
                event="frame_created",
                data=self._quic_logger.encode_http3_data_frame(
                    length=data_length, stream_id=stream_id
                ),
            )

        self._quic.send_stream_data(stream_id, frame, end_stream)

    def send_headers(
        self, stream_id: int, headers: Headers, end_stream: bool = False
    ) -> None:
        """
        Send headers on the given stream.

        To retrieve datagram which need to be sent over the network call the QUIC
        connection's :meth:`~qh3.connection.QuicConnection.datagrams_to_send`
        method.

        :param stream_id: The stream ID on which to send the headers.
        :param headers: The HTTP headers to send.
        :param end_stream: Whether to end the stream.
        """
        # check HEADERS frame is allowed
        stream = self._get_or_create_stream(stream_id)
        if stream.headers_send_state == HeadersState.AFTER_TRAILERS:
            raise FrameUnexpected("HEADERS frame is not allowed in this state")

        if end_stream:
            stream.finish_sending()

        frame_data = self._encode_headers(stream_id, headers)

        # log frame
        if self._quic_logger is not None:
            self._quic_logger.log_event(
                category="http",
                event="frame_created",
                data=self._quic_logger.encode_http3_headers_frame(
                    length=len(frame_data), headers=headers, stream_id=stream_id
                ),
            )

        # update state and send headers
        if stream.headers_send_state == HeadersState.INITIAL:
            is_informational_headers = False

            if not self._is_client and not end_stream:
                for k, v in headers:
                    if k == b":status":
                        if int(v) < 200:
                            is_informational_headers = True
                            break
                    elif not k.startswith(b":"):
                        break

            # only the server is allowed to do so!
            if not is_informational_headers:
                stream.headers_send_state = HeadersState.AFTER_HEADERS
        else:
            stream.headers_send_state = HeadersState.AFTER_TRAILERS
        self._quic.send_stream_data(
            stream_id, encode_frame(FrameType.HEADERS, frame_data), end_stream
        )
        self._maybe_cleanup_stream(stream)

    @property
    def received_settings(self) -> dict[int, int] | None:
        """
        Return the received SETTINGS frame, or None.
        """
        return self._received_settings

    @property
    def sent_settings(self) -> dict[int, int] | None:
        """
        Return the sent SETTINGS frame, or None.
        """
        return self._sent_settings

    def _create_uni_stream(self, stream_type: int, push_id: int | None = None) -> int:
        """
        Create an unidirectional stream of the given type.
        """
        stream_id = self._quic.get_next_available_stream_id(is_unidirectional=True)
        self._log_stream_type(
            push_id=push_id, stream_id=stream_id, stream_type=stream_type
        )
        self._quic.send_stream_data(stream_id, encode_uint_var(stream_type))
        return stream_id

    def _decode_headers(
        self,
        stream_id: int,
        frame_data: bytes | None,
        *,
        offset: int = 0,
        length: int | None = None,
    ) -> Headers:
        """
        Decode a HEADERS block and send decoder updates on the decoder stream.

        This is called with frame_data=None when a stream becomes unblocked.
        """
        try:
            if frame_data is None:
                decoder, headers = self._blocked_stream_map[stream_id]._pending  # type: ignore[attr-defined]
                del self._blocked_stream_map[stream_id]._pending  # type: ignore[attr-defined]
            else:
                # todo: investigate why the underlying implementation
                #  seems to ignore bad frames..
                if not frame_data or length == 0:
                    raise DecompressionFailed()
                decoder, headers = self._decoder.feed_header(
                    stream_id, frame_data, offset=offset, length=length
                )
            self._decoder_bytes_sent += len(decoder)
            self._quic.send_stream_data(self._local_decoder_stream_id, decoder)
        except (DecompressionFailed, DecoderStreamError) as exc:
            raise QpackDecompressionFailed() from exc
        except HeaderTooLarge as exc:
            raise FieldSectionTooLarge(str(exc)) from exc

        return headers

    def _encode_headers(self, stream_id: int, headers: Headers) -> bytes:
        """
        Encode a HEADERS block and send encoder updates on the encoder stream.
        """
        try:
            encoder, frame_data = self._encoder.encode(stream_id, headers)
        except EncoderStreamError as exc:
            raise QpackEncoderStreamError() from exc

        self._encoder_bytes_sent += len(encoder)
        self._quic.send_stream_data(self._local_encoder_stream_id, encoder)
        return frame_data

    def _get_or_create_stream(self, stream_id: int) -> H3Stream:
        stream = self._stream.get(stream_id)
        if stream is None:
            stream = H3Stream(stream_id)
            if stream_is_unidirectional(stream_id):
                # The nonexistent half is already ended. Otherwise a peer can
                # leak one H3Stream per completed unknown unidirectional stream.
                if stream_is_client_initiated(stream_id) == self._is_client:
                    stream.receiving_ended = True
                else:
                    stream.sending_ended = True
            self._stream[stream_id] = stream
        return stream

    def _maybe_cleanup_stream(self, stream: H3Stream) -> None:
        if stream.is_ended():
            self._stream.pop(stream.stream_id, None)
            # Defensive: a stream that completes while it was waiting on
            # a QPACK dynamic-table update is no longer of interest.
            self._blocked_stream_map.pop(stream.stream_id, None)

    def _get_local_settings(self) -> dict[int, int]:
        """
        Return the local HTTP/3 settings.
        """
        settings: dict[int, int] = {
            Setting.QPACK_MAX_TABLE_CAPACITY: self._max_table_capacity,
            Setting.MAX_FIELD_SECTION_SIZE: self._max_field_section_size,
            Setting.QPACK_BLOCKED_STREAMS: self._blocked_streams,
            Setting.H3_DATAGRAM: 1,
            Setting.DUMMY: 1,
        }
        if self._enable_webtransport:
            settings[Setting.ENABLE_WEBTRANSPORT] = 1
        return settings

    def _handle_control_frame(
        self, frame_type: int, frame_data: bytes
    ) -> list[H3Event]:
        """
        Handle a frame received on the peer's control stream.
        """
        if frame_type != FrameType.SETTINGS and not self._settings_received:
            raise MissingSettingsError

        if frame_type == FrameType.SETTINGS:
            if self._settings_received:
                raise FrameUnexpected("SETTINGS have already been received")
            settings = parse_settings(frame_data)
            self._validate_settings(settings)
            self._received_settings = settings
            encoder = self._encoder.apply_settings(
                max_table_capacity=settings.get(Setting.QPACK_MAX_TABLE_CAPACITY, 0),
                dyn_table_capacity=settings.get(Setting.QPACK_MAX_TABLE_CAPACITY, 0),
                blocked_streams=settings.get(Setting.QPACK_BLOCKED_STREAMS, 0),
            )
            self._quic.send_stream_data(self._local_encoder_stream_id, encoder)
            self._settings_received = True
        elif frame_type == FrameType.GOAWAY:
            buf = Buffer(data=frame_data)
            goaway_id = buf.pull_uint_var()
            if not buf.eof():
                raise FrameError("GOAWAY frame has extra trailing bytes")
            return [GoawayReceived(stream_id=goaway_id)]
        elif frame_type == FrameType.MAX_PUSH_ID:
            if self._is_client:
                raise FrameUnexpected("Servers must not send MAX_PUSH_ID")
            self._max_push_id = parse_max_push_id(frame_data)
        elif frame_type in (
            FrameType.DATA,
            FrameType.HEADERS,
            FrameType.PUSH_PROMISE,
            FrameType.DUPLICATE_PUSH,
        ):
            raise FrameUnexpected("Invalid frame type on control stream")
        return []

    def _handle_request_or_push_frame(
        self,
        frame_type: int,
        frame_data: bytes | None,
        stream: H3Stream,
        stream_ended: bool,
        *,
        frame_offset: int = 0,
        frame_length: int | None = None,
    ) -> list[H3Event]:
        """
        Handle a frame received on a request or push stream.
        """
        if frame_type == FrameType.DATA:
            # check DATA frame is allowed
            if stream.headers_recv_state is not HeadersState.AFTER_HEADERS:
                raise FrameUnexpected("DATA frame is not allowed in this state")

            if stream_ended or frame_data:
                return [
                    DataReceived(
                        data=frame_data,
                        push_id=stream.push_id,
                        stream_ended=stream_ended,
                        stream_id=stream.stream_id,
                    )
                ]
            return []

        http_events: list[H3Event] = []

        if frame_type == FrameType.HEADERS:
            # check HEADERS frame is allowed
            if stream.headers_recv_state is HeadersState.AFTER_TRAILERS:
                raise FrameUnexpected("HEADERS frame is not allowed in this state")

            # try to decode HEADERS, may raise pylsqpack.StreamBlocked
            headers = self._decode_headers(
                stream.stream_id, frame_data, offset=frame_offset, length=frame_length
            )

            status_code: int | None = None

            # validate headers
            if stream.headers_recv_state is HeadersState.INITIAL:
                if self._is_client:
                    status_code = validate_response_headers(headers)
                else:
                    validate_request_headers(headers)
            else:
                validate_trailers(headers)

            # log frame
            if self._quic_logger is not None:
                if frame_data is None:
                    frame_length = stream.blocked_frame_size
                elif frame_length is None:
                    frame_length = len(frame_data)
                self._quic_logger.log_event(
                    category="http",
                    event="frame_parsed",
                    data=self._quic_logger.encode_http3_headers_frame(
                        length=frame_length,
                        headers=headers,
                        stream_id=stream.stream_id,
                    ),
                )

            # update state and emit headers
            if stream.headers_recv_state is HeadersState.INITIAL:
                # Informational Response MUST be taken as-is without
                # skipping the main response.
                if status_code is None or status_code >= 200 or stream_ended:
                    stream.headers_recv_state = HeadersState.AFTER_HEADERS
            else:
                stream.headers_recv_state = HeadersState.AFTER_TRAILERS
                # Trailers are the final HTTP message element (RFC 9114 4.1).
                # If the QUIC stream has ended, force stream_ended regardless
                # of whether trailing frames (GREASE, etc.) remain in the buffer.
                if stream.receiving_ended:
                    stream_ended = True

            if (
                stream.headers_recv_state is HeadersState.INITIAL
                and status_code is not None
                and status_code < 200
            ):
                http_events.append(
                    InformationalHeadersReceived(
                        headers=headers,
                        stream_id=stream.stream_id,
                    )
                )
            else:
                http_events.append(
                    HeadersReceived(
                        headers=headers,
                        push_id=stream.push_id,
                        stream_id=stream.stream_id,
                        stream_ended=stream_ended,
                    )
                )
        elif frame_type == FrameType.PUSH_PROMISE and stream.push_id is None:
            if not self._is_client:
                raise FrameUnexpected("Clients must not send PUSH_PROMISE")
            frame_buf = Buffer(data=frame_data)
            push_id = frame_buf.pull_uint_var()
            headers = self._decode_headers(
                stream.stream_id, frame_data[frame_buf.tell() :]
            )

            # validate headers
            validate_push_promise_headers(headers)

            # log frame
            if self._quic_logger is not None:
                self._quic_logger.log_event(
                    category="http",
                    event="frame_parsed",
                    data=self._quic_logger.encode_http3_push_promise_frame(
                        length=len(frame_data),
                        headers=headers,
                        push_id=push_id,
                        stream_id=stream.stream_id,
                    ),
                )

            # emit event
            http_events.append(
                PushPromiseReceived(
                    headers=headers, push_id=push_id, stream_id=stream.stream_id
                )
            )
        elif frame_type in (
            FrameType.PRIORITY,
            FrameType.CANCEL_PUSH,
            FrameType.SETTINGS,
            FrameType.PUSH_PROMISE,
            FrameType.GOAWAY,
            FrameType.MAX_PUSH_ID,
            FrameType.DUPLICATE_PUSH,
        ):
            raise FrameUnexpected(
                "Invalid frame type on request stream"
                if stream.push_id is None
                else "Invalid frame type on push stream"
            )

        return http_events

    def _init_connection(self) -> None:
        # send our settings
        self._local_control_stream_id = self._create_uni_stream(StreamType.CONTROL)
        self._sent_settings = self._get_local_settings()
        self._quic.send_stream_data(
            self._local_control_stream_id,
            encode_frame(FrameType.SETTINGS, encode_settings(self._sent_settings)),
        )
        if self._is_client and self._max_push_id is not None:
            self._quic.send_stream_data(
                self._local_control_stream_id,
                encode_frame(FrameType.MAX_PUSH_ID, encode_uint_var(self._max_push_id)),
            )

        # create encoder and decoder streams
        self._local_encoder_stream_id = self._create_uni_stream(
            StreamType.QPACK_ENCODER
        )
        self._local_decoder_stream_id = self._create_uni_stream(
            StreamType.QPACK_DECODER
        )

    def _log_stream_type(
        self, stream_id: int, stream_type: int, push_id: int | None = None
    ) -> None:
        if self._quic_logger is not None:
            type_name = {
                0: "control",
                1: "push",
                2: "qpack_encoder",
                3: "qpack_decoder",
                0x54: "webtransport",  # NOTE: not standardized yet
            }.get(stream_type, "unknown")

            data = {"new": type_name, "stream_id": stream_id}
            if push_id is not None:
                data["associated_push_id"] = push_id

            self._quic_logger.log_event(
                category="http",
                event="stream_type_set",
                data=data,
            )

    def _receive_datagram(self, data: bytes) -> list[H3Event]:
        """
        Handle a datagram.
        """
        buf = Buffer(data=data)
        try:
            flow_id = buf.pull_uint_var()
        except BufferReadError:
            raise ProtocolError("Could not parse flow ID")
        return [DatagramReceived(data=data[buf.tell() :], flow_id=flow_id)]

    def _receive_stream_data(self, event: StreamDataReceived) -> list[H3Event]:
        stream_id = event.stream_id

        stream = self._get_or_create_stream(stream_id)
        if stream_is_unidirectional(stream_id):
            result = self._receive_stream_data_uni(stream, event.data, event.end_stream)
        else:
            result = self._receive_request_or_push_data(
                stream, event.data, event.end_stream
            )
        self._maybe_cleanup_stream(stream)
        return result

    def _receive_request_or_push_data(
        self, stream: H3Stream, data: bytes, stream_ended: bool
    ) -> list[H3Event]:
        """
        Handle data received on a request or push stream.
        """
        http_events: list[H3Event] = []

        s_buffer = stream.buffer
        if stream_ended:
            stream.receiving_ended = True
        if stream.blocked:
            if len(s_buffer) + len(data) > self._max_encoded_field_section_size:
                raise FieldSectionTooLarge("QPACK-blocked stream buffer limit exceeded")
            s_buffer.extend(data)
            return http_events

        s_stream_id = stream.stream_id

        # shortcut for WEBTRANSPORT_STREAM frame fragments
        if (
            stream.frame_type == FrameType.WEBTRANSPORT_STREAM
            and stream.session_id is not None
        ):
            if s_buffer:
                s_buffer.extend(data)
                http_events.append(
                    WebTransportStreamDataReceived(
                        data=bytes(s_buffer),
                        session_id=stream.session_id,
                        stream_id=s_stream_id,
                        stream_ended=stream_ended,
                    )
                )
                s_buffer.clear()
            else:
                http_events.append(
                    WebTransportStreamDataReceived(
                        data=data,
                        session_id=stream.session_id,
                        stream_id=s_stream_id,
                        stream_ended=stream_ended,
                    )
                )
            return http_events

        # shortcut for DATA frame fragments - zero-copy when buffer is empty
        if stream.frame_type == FrameType.DATA and stream.frame_size is not None:
            if not s_buffer:
                data_len = len(data)
                if data_len < stream.frame_size:
                    if stream_ended:
                        raise FrameError("DATA frame truncated by stream end")
                    http_events.append(
                        DataReceived(
                            data=data,
                            push_id=stream.push_id,
                            stream_id=s_stream_id,
                            stream_ended=False,
                        )
                    )
                    stream.frame_size -= data_len
                    return http_events
                if data_len == stream.frame_size:
                    stream.frame_size = None
                    stream.frame_type = None
                    return self._handle_request_or_push_frame(
                        FrameType.DATA, data, stream, stream.receiving_ended
                    )
                # data also contains another frame - use the general parser
            else:
                s_buffer.extend(data)
                buf_len = len(s_buffer)
                if buf_len < stream.frame_size:
                    if stream_ended:
                        raise FrameError("DATA frame truncated by stream end")
                    http_events.append(
                        DataReceived(
                            data=bytes(s_buffer),
                            push_id=stream.push_id,
                            stream_id=s_stream_id,
                            stream_ended=False,
                        )
                    )
                    stream.frame_size -= buf_len
                    s_buffer.clear()
                    return http_events
                # buffer has enough for frame - fall through to general path
                data = b""  # already extended into s_buffer

        # handle lone FIN
        if stream_ended and not s_buffer and not data:
            if stream.headers_recv_state is not HeadersState.INITIAL:
                return [
                    DataReceived(
                        data=b"",
                        push_id=stream.push_id,
                        stream_id=s_stream_id,
                        stream_ended=True,
                    )
                ]
            return []

        buffered = bool(s_buffer)
        if buffered:
            if data:
                s_buffer.extend(data)
            parse_data = bytes(s_buffer)
        else:
            # Buffer borrows these immutable bytes. Only an incomplete suffix
            # needs to be copied into stream.buffer for the next receive call.
            parse_data = data

        buf = Buffer(data=parse_data)
        consumed = 0
        buf_tell = buf.tell
        buf_eof = buf.eof
        buf_pull_uint_var = buf.pull_uint_var
        buf_pull_bytes = buf.pull_bytes
        handle_frame = self._handle_request_or_push_frame

        while not buf_eof():
            # fetch next frame header
            if stream.frame_size is None:
                try:
                    stream.frame_type = buf_pull_uint_var()
                    stream.frame_size = buf_pull_uint_var()
                except BufferReadError:
                    break
                consumed = buf_tell()

                if stream.frame_type in (FrameType.HEADERS, FrameType.PUSH_PROMISE):
                    # PUSH_PROMISE also carries a QUIC-varint push ID (at most
                    # eight bytes) before its QPACK field section.
                    limit = self._max_encoded_field_section_size
                    if stream.frame_type == FrameType.PUSH_PROMISE:
                        limit += 8
                    if stream.frame_size > limit:
                        raise FieldSectionTooLarge(
                            "Encoded field section exceeds the configured limit"
                        )

                # WEBTRANSPORT_STREAM frames last until the end of the stream
                if stream.frame_type == FrameType.WEBTRANSPORT_STREAM:
                    stream.session_id = stream.frame_size
                    stream.frame_size = None

                    frame_data = parse_data[consumed:]
                    s_buffer.clear()

                    self._log_stream_type(
                        stream_id=s_stream_id, stream_type=StreamType.WEBTRANSPORT
                    )

                    if frame_data or stream_ended:
                        http_events.append(
                            WebTransportStreamDataReceived(
                                data=frame_data,
                                session_id=stream.session_id,
                                stream_id=s_stream_id,
                                stream_ended=stream_ended,
                            )
                        )
                    return http_events

                # log frame
                if (
                    self._quic_logger is not None
                    and stream.frame_type == FrameType.DATA
                ):
                    self._quic_logger.log_event(
                        category="http",
                        event="frame_parsed",
                        data=self._quic_logger.encode_http3_data_frame(
                            length=stream.frame_size, stream_id=s_stream_id
                        ),
                    )

            # check how much data is available
            s_frame_size = stream.frame_size
            chunk_size = min(s_frame_size, buf.capacity - consumed)
            if stream.frame_type != FrameType.DATA and chunk_size < s_frame_size:
                break

            # read available data
            frame_type = stream.frame_type
            frame_offset = 0
            if frame_type == FrameType.HEADERS:
                # QPACK retains its own copy if decoding blocks; avoid first
                # making a separate Python bytes object for the encoded block.
                frame_data = parse_data
                frame_offset = consumed
                buf.seek(frame_offset + chunk_size)
            else:
                frame_data = buf_pull_bytes(chunk_size)
            consumed = buf_tell()

            # detect end of frame
            stream.frame_size = s_frame_size - chunk_size
            if not stream.frame_size:
                stream.frame_size = None
                stream.frame_type = None

            try:
                http_events.extend(
                    handle_frame(
                        frame_type,
                        frame_data,
                        stream,
                        stream.receiving_ended and buf_eof(),
                        frame_offset=frame_offset,
                        frame_length=chunk_size,
                    )
                )
            except StreamBlocked:
                stream.blocked = True
                stream.blocked_frame_size = chunk_size
                self._blocked_stream_map[s_stream_id] = stream
                break

            # Trailers are the final HTTP message element (RFC 9114 4.1).
            # Once received, swallow any remaining frames in the buffer.
            if (
                stream.headers_recv_state is HeadersState.AFTER_TRAILERS
                and stream.receiving_ended
            ):
                consumed = buf.capacity
                break

        # Keep only unparsed data, including a partially received frame header.
        if buffered:
            if consumed:
                del s_buffer[:consumed]
        elif consumed < buf.capacity:
            s_buffer.extend(memoryview(parse_data)[consumed:])

        # If the stream ended but no event carried stream_ended=True
        # (e.g. the last frame was GREASE or PUSH_PROMISE after DATA),
        # emit a closing DataReceived so the consumer knows the stream
        # is done. Skip if QPACK-blocked or if trailers already
        # delivered stream_ended.
        if stream_ended and not s_buffer and not stream.blocked:
            if stream.headers_recv_state is HeadersState.AFTER_HEADERS:
                if not http_events or not getattr(
                    http_events[-1], "stream_ended", False
                ):
                    http_events.append(
                        DataReceived(
                            data=b"",
                            push_id=stream.push_id,
                            stream_id=s_stream_id,
                            stream_ended=True,
                        )
                    )

        return http_events

    def _receive_stream_data_uni(
        self, stream: H3Stream, data: bytes, stream_ended: bool
    ) -> list[H3Event]:
        http_events: list[H3Event] = []

        if stream_ended:
            stream.receiving_ended = True
            # Reject FIN before the QPACK fast path can process more input.
            self._check_server_critical_stream_end(stream)

        if (
            data
            and not stream.buffer
            and stream.stream_type
            in (StreamType.QPACK_ENCODER, StreamType.QPACK_DECODER)
        ):
            return self._receive_qpack_data(stream.stream_type, data)

        stream.buffer.extend(data)

        buf = Buffer(data=bytes(stream.buffer))
        consumed = 0

        while (
            stream.stream_type
            in (StreamType.PUSH, StreamType.CONTROL, StreamType.WEBTRANSPORT)
            or not buf.eof()
        ):
            # fetch stream type for unidirectional streams
            if stream.stream_type is None:
                try:
                    stream.stream_type = buf.pull_uint_var()
                except BufferReadError:
                    break
                consumed = buf.tell()

                # check unicity
                if stream.stream_type == StreamType.CONTROL:
                    if self._peer_control_stream_id is not None:
                        raise StreamCreationError("Only one control stream is allowed")
                    self._peer_control_stream_id = stream.stream_id
                elif stream.stream_type == StreamType.QPACK_DECODER:
                    if self._peer_decoder_stream_id is not None:
                        raise StreamCreationError(
                            "Only one QPACK decoder stream is allowed"
                        )
                    self._peer_decoder_stream_id = stream.stream_id
                elif stream.stream_type == StreamType.QPACK_ENCODER:
                    if self._peer_encoder_stream_id is not None:
                        raise StreamCreationError(
                            "Only one QPACK encoder stream is allowed"
                        )
                    self._peer_encoder_stream_id = stream.stream_id

                # FIN can arrive with the type, including a fragmented varint.
                # The peer IDs above remain reserved for this connection's life.
                self._check_server_critical_stream_end(stream)

                # for PUSH, logging is performed once the push_id is known
                if stream.stream_type != StreamType.PUSH:
                    self._log_stream_type(
                        stream_id=stream.stream_id, stream_type=stream.stream_type
                    )

            if stream.stream_type == StreamType.CONTROL:
                if stream_ended:
                    raise ClosedCriticalStream("Closing control stream is not allowed")

                # fetch next frame
                try:
                    frame_type = buf.pull_uint_var()
                    frame_length = buf.pull_uint_var()
                    frame_data = buf.pull_bytes(frame_length)
                except BufferReadError:
                    break
                consumed = buf.tell()

                http_events.extend(self._handle_control_frame(frame_type, frame_data))
            elif stream.stream_type == StreamType.PUSH:
                # fetch push id
                if stream.push_id is None:
                    try:
                        stream.push_id = buf.pull_uint_var()
                    except BufferReadError:
                        break
                    consumed = buf.tell()

                    self._log_stream_type(
                        push_id=stream.push_id,
                        stream_id=stream.stream_id,
                        stream_type=stream.stream_type,
                    )

                # remove processed data from buffer
                del stream.buffer[:consumed]

                return self._receive_request_or_push_data(stream, b"", stream_ended)
            elif stream.stream_type == StreamType.WEBTRANSPORT:
                # fetch session id
                if stream.session_id is None:
                    try:
                        stream.session_id = buf.pull_uint_var()
                    except BufferReadError:
                        break
                    consumed = buf.tell()

                frame_data = bytes(stream.buffer[consumed:])
                stream.buffer.clear()

                if frame_data or stream_ended:
                    http_events.append(
                        WebTransportStreamDataReceived(
                            data=frame_data,
                            session_id=stream.session_id,
                            stream_ended=stream.receiving_ended,
                            stream_id=stream.stream_id,
                        )
                    )
                return http_events
            elif stream.stream_type in (
                StreamType.QPACK_ENCODER,
                StreamType.QPACK_DECODER,
            ):
                # The first receive may also contain the stream-type prefix.
                data = buf.pull_bytes(buf.capacity - buf.tell())
                consumed = buf.tell()
                http_events.extend(self._receive_qpack_data(stream.stream_type, data))
            else:
                # unknown stream type, discard data
                buf.seek(buf.capacity)
                consumed = buf.tell()

        # remove processed data from buffer
        if consumed:
            del stream.buffer[:consumed]

        return http_events

    def _receive_qpack_data(self, stream_type: int, data: bytes) -> list[H3Event]:
        """Feed unframed bytes directly; QPACK handles partial instructions."""
        if stream_type == StreamType.QPACK_DECODER:
            try:
                self._encoder.feed_decoder(data)
            except DecoderStreamError as exc:
                raise QpackDecoderStreamError() from exc
            self._decoder_bytes_received += len(data)
            return []

        try:
            self._decoder.feed_encoder(data)
        except HeaderTooLarge as exc:
            raise FieldSectionTooLarge(str(exc)) from exc
        except EncoderStreamError as exc:
            raise QpackEncoderStreamError() from exc
        self._encoder_bytes_received += len(data)

        unblocked_streams: set[int] = set()
        for blocked_id, blocked_stream in self._blocked_stream_map.items():
            try:
                stream_data, headers = self._decoder.resume_header(blocked_id)
                blocked_stream._pending = (stream_data, headers)  # type: ignore[attr-defined]
                unblocked_streams.add(blocked_id)
            except StreamBlocked:
                continue
            except HeaderTooLarge as exc:
                raise FieldSectionTooLarge(str(exc)) from exc
            except DecoderStreamError as exc:
                raise QpackDecompressionFailed() from exc

        http_events: list[H3Event] = []
        for stream_id in unblocked_streams:
            stream = self._stream[stream_id]

            # resume headers
            http_events.extend(
                self._handle_request_or_push_frame(
                    frame_type=FrameType.HEADERS,
                    frame_data=None,
                    stream=stream,
                    stream_ended=stream.receiving_ended and not stream.buffer,
                )
            )
            stream.blocked = False
            stream.blocked_frame_size = None
            del self._blocked_stream_map[stream_id]

            # resume processing
            if stream.buffer:
                http_events.extend(
                    self._receive_request_or_push_data(
                        stream,
                        b"",
                        stream.receiving_ended,
                    )
                )

        return http_events

    def _validate_settings(self, settings: dict[int, int]) -> None:
        for setting in [
            Setting.ENABLE_CONNECT_PROTOCOL,
            Setting.ENABLE_WEBTRANSPORT,
            Setting.H3_DATAGRAM,
            Setting.H3_DATAGRAM_DRAFT05,
        ]:
            if setting in settings and settings[setting] not in (0, 1):
                raise SettingsError(f"{setting.name} setting must be 0 or 1")

        # Accept either the RFC 9297 identifier (0x33) or the legacy
        # draft-ietf-masque-h3-datagram-05 identifier (0xFFD277) on receive,
        # so we can interop with peers that have not yet migrated.
        h3_datagram = settings.get(Setting.H3_DATAGRAM)
        if h3_datagram is None:
            h3_datagram = settings.get(Setting.H3_DATAGRAM_DRAFT05)

        if h3_datagram == 1 and self._quic._remote_max_datagram_frame_size is None:
            raise SettingsError(
                "H3_DATAGRAM requires max_datagram_frame_size transport parameter"
            )

        if settings.get(Setting.ENABLE_WEBTRANSPORT) == 1 and h3_datagram != 1:
            raise SettingsError("ENABLE_WEBTRANSPORT requires H3_DATAGRAM")
