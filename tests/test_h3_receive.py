from __future__ import annotations

import pytest

from qh3.h3 import connection as h3_module
from qh3.h3.connection import (
    ErrorCode,
    FrameType,
    H3Connection,
    HeadersState,
    encode_frame,
)
from qh3.h3.events import DataReceived, HeadersReceived
from qh3.quic.configuration import QuicConfiguration
from qh3.quic.events import StreamDataReceived

from .test_h3 import FakeQuicConnection


def data_receiver():
    quic = FakeQuicConnection(configuration=QuicConfiguration(is_client=True))
    quic._quic_logger = None
    h3 = H3Connection(quic)
    stream = h3._get_or_create_stream(0)
    stream.headers_recv_state = HeadersState.AFTER_HEADERS
    return h3, stream


def receive(h3, data, fin=False):
    return h3.handle_event(StreamDataReceived(data=data, stream_id=0, end_stream=fin))


def test_complete_data_frame_parser_borrows_input(monkeypatch):
    h3, stream = data_receiver()
    body = b"hello" * 200
    wire = encode_frame(FrameType.DATA, body)
    inputs = []
    native_buffer = h3_module.Buffer

    def record_buffer(*args, **kwargs):
        inputs.append(kwargs["data"])
        return native_buffer(*args, **kwargs)

    monkeypatch.setattr(h3_module, "Buffer", record_buffer)
    events = receive(h3, wire, True)
    assert events == [DataReceived(body, 0, True)]
    assert isinstance(events[0].data, bytes)
    assert len(inputs) == 1
    assert inputs[0] is wire
    assert not stream.buffer


@pytest.mark.parametrize("fin", [False, True])
def test_exact_data_completion_reuses_input(fin):
    h3, stream = data_receiver()
    body = b"received payload" * 100
    wire = encode_frame(FrameType.DATA, body)
    header_size = len(wire) - len(body)
    assert receive(h3, wire[:header_size]) == []
    events = receive(h3, body, fin)
    assert events == [DataReceived(body, 0, fin)]
    assert events[0].data is body
    assert stream.frame_size is None
    assert stream.frame_type is None
    assert not stream.buffer
    if not fin:
        assert receive(h3, encode_frame(FrameType.DATA, b"next"), True) == [
            DataReceived(b"next", 0, True)
        ]


@pytest.mark.parametrize(
    "wire, expected",
    [
        (
            encode_frame(FrameType.DATA, b"a" * 70)
            + encode_frame(0x4000, b"ignored")
            + encode_frame(FrameType.DATA, b"last"),
            b"a" * 70 + b"last",
        ),
        # Non-minimal varints are valid and can be split inside either field.
        (b"\x80\x00\x00\x00\x40\x03abc", b"abc"),
        (encode_frame(FrameType.DATA, b""), b""),
    ],
)
def test_frame_headers_and_payloads_split_at_every_boundary(wire, expected):
    for split in range(1, len(wire)):
        h3, stream = data_receiver()
        events = receive(h3, wire[:split])
        events += receive(h3, wire[split:], True)
        assert h3._quic.closed is None
        assert all(isinstance(event, DataReceived) for event in events)
        assert b"".join(event.data for event in events) == expected
        assert events[-1].stream_ended
        assert sum(event.stream_ended for event in events) == 1
        assert not stream.buffer


@pytest.mark.parametrize("split", [1, 2, 3, 4, 5, 6, 7])
def test_only_unparsed_suffix_is_buffered(split):
    h3, stream = data_receiver()
    first = encode_frame(FrameType.DATA, b"first")
    unknown = encode_frame(0x4000, b"ignored")
    partial = unknown[:split]
    assert receive(h3, first + partial) == [DataReceived(b"first", 0, False)]
    header_size = len(unknown) - len(b"ignored")
    assert stream.buffer == (partial if split < header_size else partial[header_size:])
    assert receive(
        h3, unknown[split:] + encode_frame(FrameType.DATA, b"last"), True
    ) == [DataReceived(b"last", 0, True)]
    assert not stream.buffer


def test_data_completion_with_following_frame_uses_general_parser():
    h3, stream = data_receiver()
    stream.frame_type = FrameType.DATA
    stream.frame_size = 3
    assert receive(h3, b"abc" + encode_frame(FrameType.DATA, b"def"), True) == [
        DataReceived(b"abc", 0, False),
        DataReceived(b"def", 0, True),
    ]
    assert not stream.buffer


def test_buffered_data_truncated_by_fin_closes_connection():
    h3, stream = data_receiver()
    stream.frame_type = FrameType.DATA
    stream.frame_size = 6
    stream.buffer.extend(b"ab")
    assert receive(h3, b"c", True) == []
    assert h3._is_done
    assert h3._quic.closed[0] == ErrorCode.H3_FRAME_ERROR


def test_empty_fin_before_headers_does_not_emit_data():
    h3, stream = data_receiver()
    stream.headers_recv_state = HeadersState.INITIAL
    assert receive(h3, b"", True) == []
    assert stream.receiving_ended
    assert h3._quic.closed is None


def test_data_completion_still_validates_header_state():
    h3, stream = data_receiver()
    stream.headers_recv_state = HeadersState.AFTER_TRAILERS
    stream.frame_type = FrameType.DATA
    stream.frame_size = 3
    assert receive(h3, b"abc", True) == []
    assert h3._quic.closed[0] == ErrorCode.H3_FRAME_UNEXPECTED


def test_data_continuation_still_rejects_truncated_fin():
    h3, stream = data_receiver()
    stream.frame_type = FrameType.DATA
    stream.frame_size = 4
    assert receive(h3, b"abc", True) == []
    assert h3._quic.closed[0] == ErrorCode.H3_FRAME_ERROR


def test_coalesced_qpack_blocked_headers_retain_following_data():
    h3, stream = data_receiver()
    stream.headers_recv_state = HeadersState.INITIAL
    for stream_id, data in [
        (3, bytes.fromhex("0004170150000680020000074064091040bcc0000000faceb00c")),
        (7, b"\x02"),
        (11, b"\x03"),
    ]:
        assert h3.handle_event(StreamDataReceived(data, False, stream_id)) == []
    body = b"body arriving with blocked headers"
    data_frame = encode_frame(FrameType.DATA, body)
    assert receive(h3, bytes.fromhex("01040280d910") + data_frame, True) == []
    assert stream.blocked
    assert stream.buffer == data_frame
    events = h3.handle_event(
        StreamDataReceived(
            bytes.fromhex("3fe101c696d07abe941094cb6d0a08017d403971966e32ca98b46f"),
            False,
            7,
        )
    )
    assert isinstance(events[0], HeadersReceived)
    assert not events[0].stream_ended
    assert events[1:] == [DataReceived(body, 0, True)]
    assert not stream.blocked
    assert not stream.buffer
