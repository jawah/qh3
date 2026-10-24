from __future__ import annotations

import pytest

from qh3._hazmat import (
    HeaderTooLarge,
    QpackDecoder,
    QpackEncoder,
    StreamBlocked,
    encode_uint_var,
)
from qh3.h3.connection import (
    ErrorCode,
    FrameType,
    H3Connection,
    Setting,
    encode_frame,
    encode_settings,
)
from qh3.h3.events import HeadersReceived
from qh3.quic.configuration import QuicConfiguration
from qh3.quic.events import StreamDataReceived

from .test_h3 import FakeQuicConnection

REQUEST = [
    (b":method", b"GET"),
    (b":scheme", b"https"),
    (b":authority", b"localhost"),
    (b":path", b"/"),
]
RESPONSE = [(b":status", b"200")]


def block(headers):
    encoder = QpackEncoder()
    instructions, encoded = encoder.encode(0, headers)
    assert instructions == b""
    return encoded


def server():
    quic = FakeQuicConnection(configuration=QuicConfiguration(is_client=False))
    quic._quic_logger = None
    return quic, H3Connection(quic)


def client():
    quic = FakeQuicConnection(configuration=QuicConfiguration(is_client=True))
    quic._quic_logger = None
    return quic, H3Connection(quic)


def prefixed_integer(value, bits, prefix):
    mask = (1 << bits) - 1
    if value < mask:
        return bytes([prefix | value])
    encoded = bytearray([prefix | mask])
    value -= mask
    while value >= 128:
        encoded.append((value & 127) | 128)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def dynamic_entry():
    name, value = b"x-large", b"x" * 4000
    instructions = prefixed_integer(4096, 5, 0x20)
    instructions += prefixed_integer(len(name), 5, 0x40) + name
    instructions += prefixed_integer(len(value), 7, 0) + value
    return instructions


@pytest.mark.parametrize("maximum, allowed", [(65, False), (66, True)])
def test_decoded_field_size_includes_32_bytes_per_field(maximum, allowed):
    headers = [(b"x", b""), (b"y", b"")]
    decoder = QpackDecoder(0, 0, max_field_section_size=maximum)
    if allowed:
        assert decoder.feed_header(0, block(headers))[1] == headers
    else:
        with pytest.raises(HeaderTooLarge):
            decoder.feed_header(0, block(headers))


def test_static_reference_amplification_is_rejected_by_native_decoder():
    # Static index 2 is age: 0, costing 36 decoded field-section bytes.
    encoded = b"\0\0" + b"\xc2" * 8192
    decoder = QpackDecoder(0, 0, max_field_section_size=262144)
    with pytest.raises(HeaderTooLarge):
        decoder.feed_header(0, encoded)
    # Demonstrate the encoded/decoded size mismatch with a bounded test input.
    headers = QpackDecoder(0, 0).feed_header(0, encoded)[1]
    assert len(encoded) < 10_000
    assert sum(len(name) + len(value) + 32 for name, value in headers) > 262144


@pytest.mark.parametrize("blocked", [False, True])
def test_native_dynamic_expansion_budget_survives_blocking(blocked):
    decoder = QpackDecoder(4096, 100, max_field_section_size=262144)
    encoded = b"\x02\0" + b"\x80" * 128
    if blocked:
        with pytest.raises(StreamBlocked):
            decoder.feed_header(0, encoded)
        decoder.feed_encoder(dynamic_entry())
        with pytest.raises(HeaderTooLarge):
            decoder.resume_header(0)
    else:
        decoder.feed_encoder(dynamic_entry())
        with pytest.raises(HeaderTooLarge):
            decoder.feed_header(0, encoded)


@pytest.mark.parametrize("trailer", [False, True])
def test_server_limits_initial_headers_and_trailers(trailer):
    quic, h3 = server()
    assert h3.sent_settings[Setting.MAX_FIELD_SECTION_SIZE] == 262144
    if trailer:
        first = h3.handle_event(
            StreamDataReceived(
                encode_frame(FrameType.HEADERS, block(REQUEST)), False, 0
            )
        )
        assert len(first) == 1 and isinstance(first[0], HeadersReceived)
        encoded = b"\0\0"
    else:
        encoded = block(REQUEST)
    encoded += b"\xc2" * 8192
    assert (
        h3.handle_event(
            StreamDataReceived(encode_frame(FrameType.HEADERS, encoded), True, 0)
        )
        == []
    )
    assert quic.closed[0] == ErrorCode.H3_EXCESSIVE_LOAD


@pytest.mark.parametrize("blocked", [False, True])
def test_server_limits_dynamic_table_expansion(blocked):
    quic, h3 = server()
    assert h3.handle_event(StreamDataReceived(b"\x02", False, 2)) == []
    if not blocked:
        assert h3.handle_event(StreamDataReceived(dynamic_entry(), False, 2)) == []
    prefix = block(REQUEST)
    assert prefix[:2] == b"\0\0"
    encoded = b"\x02\0" + prefix[2:] + b"\x80" * 128
    assert (
        h3.handle_event(
            StreamDataReceived(encode_frame(FrameType.HEADERS, encoded), True, 0)
        )
        == []
    )
    if blocked:
        assert quic.closed is None
        assert h3._stream[0].blocked
        assert h3.handle_event(StreamDataReceived(dynamic_entry(), False, 2)) == []
    assert quic.closed[0] == ErrorCode.H3_EXCESSIVE_LOAD


@pytest.mark.parametrize("split", [None, 1])
def test_oversized_declared_headers_are_rejected_before_buffering(split):
    quic, h3 = server()
    header = encode_uint_var(FrameType.HEADERS) + encode_uint_var(
        h3._max_encoded_field_section_size + 1
    )
    if split:
        assert h3.handle_event(StreamDataReceived(header[:split], False, 0)) == []
        header = header[split:]
    assert h3.handle_event(StreamDataReceived(header, False, 0)) == []
    assert quic.closed[0] == ErrorCode.H3_EXCESSIVE_LOAD
    assert len(h3._stream[0].buffer) < 16


def test_qpack_blocked_stream_buffer_is_bounded():
    quic, h3 = server()
    prefix = block(REQUEST)
    encoded = b"\x02\0" + prefix[2:] + b"\x80"
    assert (
        h3.handle_event(
            StreamDataReceived(encode_frame(FrameType.HEADERS, encoded), False, 0)
        )
        == []
    )
    assert h3._stream[0].blocked
    payload = b"x" * (h3._max_encoded_field_section_size + 1)
    assert h3.handle_event(StreamDataReceived(payload, False, 0)) == []
    assert quic.closed[0] == ErrorCode.H3_EXCESSIVE_LOAD
    assert not h3._stream[0].buffer


def test_valid_server_headers_and_trailers_still_work():
    quic, h3 = server()
    first = h3.handle_event(
        StreamDataReceived(encode_frame(FrameType.HEADERS, block(REQUEST)), False, 0)
    )
    assert first == [HeadersReceived(REQUEST, 0, False)]
    trailers = [(b"x-trailer", b"complete")]
    assert h3.handle_event(
        StreamDataReceived(encode_frame(FrameType.HEADERS, block(trailers)), True, 0)
    ) == [HeadersReceived(trailers, 0, True)]
    assert quic.closed is None


def test_peer_setting_cannot_raise_the_server_receive_limit():
    quic, h3 = server()
    settings = encode_frame(
        FrameType.SETTINGS,
        encode_settings({Setting.MAX_FIELD_SECTION_SIZE: 1 << 40}),
    )
    assert h3.handle_event(StreamDataReceived(b"\0" + settings, False, 2)) == []
    encoded = block(REQUEST) + b"\xc2" * 8192
    assert (
        h3.handle_event(
            StreamDataReceived(encode_frame(FrameType.HEADERS, encoded), True, 0)
        )
        == []
    )
    assert quic.closed[0] == ErrorCode.H3_EXCESSIVE_LOAD


@pytest.mark.parametrize("blocked", [False, True])
def test_malformed_qpack_block_closes_instead_of_leaking_native_exception(blocked):
    quic, h3 = server()
    # Indexed static field 190 does not exist. In the blocked variant, the
    # required insertion delays decoding until the encoder stream arrives.
    encoded = (b"\x02\0" if blocked else b"\0\0") + b"\xff\x7f"
    assert (
        h3.handle_event(
            StreamDataReceived(encode_frame(FrameType.HEADERS, encoded), True, 0)
        )
        == []
    )
    if blocked:
        assert quic.closed is None
        assert (
            h3.handle_event(StreamDataReceived(b"\x02" + dynamic_entry(), False, 2))
            == []
        )
    assert quic.closed[0] == ErrorCode.QPACK_DECOMPRESSION_FAILED


def test_client_accepts_response_above_server_limit():
    quic, h3 = client()
    assert h3.sent_settings[Setting.MAX_FIELD_SECTION_SIZE] == 1024 * 1024
    encoded = block(RESPONSE) + b"\xc2" * 8192
    events = h3.handle_event(
        StreamDataReceived(encode_frame(FrameType.HEADERS, encoded), True, 0)
    )
    assert len(events) == 1 and isinstance(events[0], HeadersReceived)
    size = sum(len(name) + len(value) + 32 for name, value in events[0].headers)
    assert 256 * 1024 < size <= 1024 * 1024
    assert quic.closed is None


@pytest.mark.parametrize("extra_byte", [False, True])
def test_client_decoded_limit_boundary(extra_byte):
    quic, h3 = client()
    # :status: 200 costs 42 bytes; age: 0 costs 36. The final field fills
    # the remaining quota exactly, including its 32-byte field overhead.
    limit = 1024 * 1024
    count = (limit - 42 - 33) // 36
    value_size = limit - 42 - count * 36 - 33
    tail = block([(b"x", b"y" * (value_size + extra_byte))])
    assert tail[:2] == b"\0\0"
    encoded = block(RESPONSE) + b"\xc2" * count + tail[2:]
    events = h3.handle_event(
        StreamDataReceived(encode_frame(FrameType.HEADERS, encoded), True, 0)
    )
    if extra_byte:
        assert events == []
        assert quic.closed[0] == ErrorCode.H3_EXCESSIVE_LOAD
    else:
        assert len(events) == 1 and isinstance(events[0], HeadersReceived)
        assert (
            sum(len(name) + len(value) + 32 for name, value in events[0].headers)
            == limit
        )
        assert quic.closed is None


@pytest.mark.parametrize(
    "kind", ["response", "trailers", "push_promise", "push_response"]
)
@pytest.mark.parametrize("blocked", [False, True])
def test_client_limits_dynamic_expansion_in_all_field_sections(kind, blocked):
    quic, h3 = client()
    assert h3.handle_event(StreamDataReceived(b"\x02", False, 7)) == []
    if not blocked:
        assert h3.handle_event(StreamDataReceived(dynamic_entry(), False, 7)) == []
    if kind == "trailers":
        assert h3.handle_event(
            StreamDataReceived(
                encode_frame(FrameType.HEADERS, block(RESPONSE)), False, 0
            )
        ) == [HeadersReceived(RESPONSE, 0, False)]
        prefix = b"\0\0"
    else:
        prefix = block(REQUEST if kind == "push_promise" else RESPONSE)
    assert prefix[:2] == b"\0\0"
    encoded = b"\x02\0" + prefix[2:] + b"\x80" * 300
    if kind == "push_promise":
        wire = encode_frame(FrameType.PUSH_PROMISE, b"\0" + encoded)
        stream_id = 0
    else:
        wire = encode_frame(FrameType.HEADERS, encoded)
        stream_id = 15 if kind == "push_response" else 0
        if kind == "push_response":
            wire = b"\x01\0" + wire
    assert (
        h3.handle_event(StreamDataReceived(wire, kind != "push_promise", stream_id))
        == []
    )
    if blocked:
        assert quic.closed is None
        assert h3._stream[stream_id].blocked
        assert h3.handle_event(StreamDataReceived(dynamic_entry(), False, 7)) == []
    assert quic.closed[0] == ErrorCode.H3_EXCESSIVE_LOAD


@pytest.mark.parametrize("frame_type", [FrameType.HEADERS, FrameType.PUSH_PROMISE])
def test_client_rejects_oversized_encoded_declaration(frame_type):
    quic, h3 = client()
    limit = 4 * 1024 * 1024 + 32
    if frame_type == FrameType.PUSH_PROMISE:
        limit += 8
    declaration = encode_uint_var(frame_type) + encode_uint_var(limit + 1)
    assert h3.handle_event(StreamDataReceived(declaration, False, 0)) == []
    assert quic.closed[0] == ErrorCode.H3_EXCESSIVE_LOAD
    assert not h3._stream[0].buffer


def test_client_qpack_blocked_buffer_is_bounded():
    quic, h3 = client()
    prefix = block(RESPONSE)
    encoded = b"\x02\0" + prefix[2:] + b"\x80"
    assert (
        h3.handle_event(
            StreamDataReceived(encode_frame(FrameType.HEADERS, encoded), False, 0)
        )
        == []
    )
    assert h3._stream[0].blocked
    payload = b"x" * (4 * 1024 * 1024 + 33)
    assert h3.handle_event(StreamDataReceived(payload, False, 0)) == []
    assert quic.closed[0] == ErrorCode.H3_EXCESSIVE_LOAD
    assert not h3._stream[0].buffer


def test_peer_setting_cannot_raise_the_client_receive_limit():
    quic, h3 = client()
    settings = encode_frame(
        FrameType.SETTINGS, encode_settings({Setting.MAX_FIELD_SECTION_SIZE: 1 << 40})
    )
    assert h3.handle_event(StreamDataReceived(b"\0" + settings, False, 3)) == []
    encoded = block(RESPONSE) + b"\xc2" * 32768
    assert (
        h3.handle_event(
            StreamDataReceived(encode_frame(FrameType.HEADERS, encoded), True, 0)
        )
        == []
    )
    assert quic.closed[0] == ErrorCode.H3_EXCESSIVE_LOAD
