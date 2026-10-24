from __future__ import annotations

import pytest

from qh3._hazmat import encode_uint_var
from qh3.h3.connection import ErrorCode, H3Connection, StreamType
from qh3.quic.configuration import QuicConfiguration
from qh3.quic.events import StreamDataReceived, StreamReset

from .test_h3 import FakeQuicConnection
from .test_native_connection import (
    CLIENT_ADDR,
    SERVER_ADDR,
    drain_events,
    handshake,
    make_pair,
)


def server():
    quic = FakeQuicConnection(configuration=QuicConfiguration(is_client=False))
    return quic, H3Connection(quic)


class NoQpackInput:
    def feed_encoder(self, data):
        pytest.fail("closed encoder stream reached QPACK")

    def feed_decoder(self, data):
        pytest.fail("closed decoder stream reached QPACK")


@pytest.mark.parametrize("kind", [StreamType.QPACK_ENCODER, StreamType.QPACK_DECODER])
@pytest.mark.parametrize("with_data", [False, True])
def test_server_rejects_qpack_fin_before_processing(kind, with_data):
    quic, h3 = server()
    h3.handle_event(StreamDataReceived(encode_uint_var(kind), False, 2))
    h3._encoder = h3._decoder = NoQpackInput()
    h3.handle_event(StreamDataReceived(b"\x20" if with_data else b"", True, 2))
    assert quic.closed[0] == ErrorCode.H3_CLOSED_CRITICAL_STREAM
    assert h3._is_done
    h3.handle_event(StreamDataReceived(encode_uint_var(kind) + b"\x20", False, 6))
    assert 6 not in h3._stream


@pytest.mark.parametrize(
    "kind", [StreamType.CONTROL, StreamType.QPACK_ENCODER, StreamType.QPACK_DECODER]
)
@pytest.mark.parametrize("split", [0, 1, 2, 3])
def test_server_rejects_fin_with_fragmented_critical_stream_type(kind, split):
    quic, h3 = server()
    prefix = b"\x80\x00\x00" + bytes([kind])
    if split:
        assert h3.handle_event(StreamDataReceived(prefix[:split], False, 2)) == []
    h3._encoder = h3._decoder = NoQpackInput()
    h3.handle_event(StreamDataReceived(prefix[split:] + b"\x20", True, 2))
    assert quic.closed[0] == ErrorCode.H3_CLOSED_CRITICAL_STREAM


@pytest.mark.parametrize(
    "kind", [StreamType.CONTROL, StreamType.QPACK_ENCODER, StreamType.QPACK_DECODER]
)
def test_critical_type_stays_reserved_after_stream_object_cleanup(kind):
    quic, h3 = server()
    h3.handle_event(StreamDataReceived(encode_uint_var(kind), False, 2))
    stream = h3._stream[2]
    stream.sending_ended = stream.receiving_ended = True
    h3._maybe_cleanup_stream(stream)
    assert 2 not in h3._stream
    h3.handle_event(StreamDataReceived(encode_uint_var(kind), False, 6))
    assert quic.closed[0] == ErrorCode.H3_STREAM_CREATION_ERROR


def test_server_rejects_critical_reset():
    quic, h3 = server()
    h3.handle_event(StreamDataReceived(b"\x02", False, 2))
    h3.handle_event(StreamReset(0, 2))
    assert quic.closed[0] == ErrorCode.H3_CLOSED_CRITICAL_STREAM


def test_server_ignores_unknown_stream_fin():
    quic, h3 = server()
    assert h3.handle_event(StreamDataReceived(b"\x21ignored", True, 2)) == []
    assert quic.closed is None
    assert 2 not in h3._stream


@pytest.mark.parametrize("payload", [b"", b"\x21ignored"])
def test_completed_peer_uni_streams_do_not_accumulate(payload):
    quic, h3 = server()
    for index in range(1000):
        assert h3.handle_event(StreamDataReceived(payload, True, 2 + index * 4)) == []
    assert quic.closed is None
    assert not h3._stream


def test_coalesced_encoder_fin_and_reopen_close_the_connection():
    client, quic_server = make_pair()
    client.configuration.probe_datagram_size = False
    _, _, now = handshake(client, quic_server)
    h3 = H3Connection(quic_server)
    client.send_stream_data(2, b"\x02", end_stream=True)
    client.send_stream_data(6, b"\x02\x20")
    datagrams = client.datagrams_to_send(now)
    assert len(datagrams) == 1
    quic_server.receive_datagram(datagrams[0][0], CLIENT_ADDR, now)
    events = drain_events(quic_server)
    assert (
        len([event for event in events if isinstance(event, StreamDataReceived)]) == 2
    )
    for event in events:
        assert h3.handle_event(event) == []
    assert h3._peer_encoder_stream_id == 2
    assert 6 not in h3._stream
    assert quic_server._close_event.error_code == ErrorCode.H3_CLOSED_CRITICAL_STREAM
    for data, _ in quic_server.datagrams_to_send(now + 0.01):
        client.receive_datagram(data, SERVER_ADDR, now + 0.01)
    assert client._close_event.error_code == ErrorCode.H3_CLOSED_CRITICAL_STREAM
