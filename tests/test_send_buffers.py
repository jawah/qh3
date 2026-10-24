from __future__ import annotations

import array

import pytest

from qh3._compat import as_contiguous_buffer
from qh3._hazmat import Buffer, BufferWriteError
from qh3.h3.connection import H3Connection
from qh3.h3.events import DataReceived
from qh3.quic.events import StreamDataReceived

from .test_h3 import h3_fake_client_and_server, h3_transfer
from .test_native_connection import (
    CLIENT_ADDR,
    drain_events,
    handshake,
    make_pair,
    transfer,
)


class NoBytesConversion(bytearray):
    def __bytes__(self):
        raise AssertionError("send must use the buffer protocol")


def payloads():
    return [
        b"abcdefgh",
        bytearray(b"abcdefgh"),
        memoryview(b"abcdefgh"),
        memoryview(bytearray(b"abcdefgh")),
        memoryview(b"--abcdefgh--")[2:-2],
        memoryview(b"abcdefgh").cast("B", (2, 4)),
        array.array("I", [0x01020304, 0x05060708]),
        memoryview(array.array("I", [0x01020304, 0x05060708])),
        NoBytesConversion(b"abcdefgh"),
        bytearray(),
        memoryview(b""),
    ]


@pytest.mark.parametrize("data", payloads())
def test_buffer_push_accepts_contiguous_exporters(data):
    expected = memoryview(data).tobytes()
    buf = Buffer(capacity=len(expected))
    buf.push_bytes(data)
    assert buf.data == expected
    assert buf.tell() == len(expected)


def test_buffer_write_uses_byte_length_and_remains_atomic():
    buf = Buffer(capacity=3)
    buf.push_bytes(b"a")
    with pytest.raises(BufferWriteError):
        buf.push_bytes(array.array("I", [1]))
    assert buf.data == b"a"
    assert buf.tell() == 1


@pytest.mark.parametrize("data", payloads())
@pytest.mark.parametrize("native", [False, True])
def test_quic_sends_buffer_bytes(data, native):
    expected = memoryview(data).tobytes()
    client, server = make_pair()
    _, _, now = handshake(client, server)
    if native:
        client._core.send_stream(0, data, True)
    else:
        client.send_stream_data(0, data, end_stream=True)
    assert client.get_send_buffer_size(0) == len(expected)
    transfer(client, server, CLIENT_ADDR, now)
    assert drain_events(server) == [StreamDataReceived(expected, True, 0)]


def send_h3_buffer(data):
    expected = memoryview(data).tobytes()
    with h3_fake_client_and_server() as (client, server):
        sender = H3Connection(client)
        receiver = H3Connection(server)
        sender.send_headers(
            0,
            [
                (b":method", b"POST"),
                (b":scheme", b"https"),
                (b":authority", b"localhost"),
                (b":path", b"/"),
                (b"content-length", str(len(expected)).encode()),
            ],
        )
        h3_transfer(client, receiver)
        sender.send_data(0, data, end_stream=True)
        received = h3_transfer(client, receiver)
        assert all(
            isinstance(event, DataReceived) and event.stream_id == 0
            for event in received
        )
        assert b"".join(event.data for event in received) == expected
        assert received[-1].stream_ended


@pytest.mark.parametrize("data", payloads())
def test_h3_sends_buffer_bytes(data):
    send_h3_buffer(data)


@pytest.mark.parametrize(
    "phase", ["before_connect", "during_handshake", "connected", "native"]
)
@pytest.mark.parametrize("view", [False, True])
def test_send_copies_into_owned_queue_before_return(phase, view):
    client, server = make_pair()
    source = bytearray(b"original")
    data = memoryview(source) if view else source
    if phase == "during_handshake":
        client.connect(("127.0.0.1", 4434), 1.0)
    elif phase in ("connected", "native"):
        _, _, now = handshake(client, server)
    if phase == "native":
        client._core.send_stream(0, data, True)
    else:
        client.send_stream_data(0, data, end_stream=True)
    if view:
        data.release()
    source[:] = b"changed!"
    source.extend(b"can resize after send")
    if phase in ("before_connect", "during_handshake"):
        _, received, _ = handshake(client, server)
        received = [
            event for event in received if isinstance(event, StreamDataReceived)
        ]
    else:
        transfer(client, server, CLIENT_ADDR, now)
        received = drain_events(server)
    assert received == [StreamDataReceived(b"original", True, 0)]


@pytest.mark.parametrize("data", [b"1234", bytearray(b"1234")])
def test_buffer_view_keeps_original_storage(data):
    view = as_contiguous_buffer(data)
    if isinstance(data, bytes):
        assert view is data
    else:
        assert isinstance(view, memoryview)
        assert view.obj is data


@pytest.mark.parametrize("data", [None, "text", 4, [1, 2, 3]])
def test_non_buffers_rejected_without_allocating_stream(data):
    client, _ = make_pair()
    with pytest.raises(TypeError):
        client.send_stream_data(0, data, end_stream=True)
    assert client.get_next_available_stream_id() == 0
    assert client.get_send_buffer_size() == 0


@pytest.mark.parametrize(
    "data", [memoryview(b"abcdef")[::2], memoryview(b"abcdef")[::-1]]
)
def test_non_contiguous_buffers_are_rejected(data):
    client, server = make_pair()
    _, _, now = handshake(client, server)
    with pytest.raises(BufferError):
        client.send_stream_data(0, data, end_stream=True)
    with pytest.raises(BufferError):
        client._core.send_stream(0, data, True)
    with pytest.raises(BufferError):
        Buffer(capacity=6).push_bytes(data)
    client.send_stream_data(0, b"valid", end_stream=True)
    transfer(client, server, CLIENT_ADDR, now)
    assert drain_events(server) == [StreamDataReceived(b"valid", True, 0)]


def test_invalid_h3_buffer_does_not_commit_fin():
    with h3_fake_client_and_server() as (client, server):
        sender, receiver = H3Connection(client), H3Connection(server)
        sender.send_headers(
            0,
            [
                (b":method", b"POST"),
                (b":scheme", b"https"),
                (b":authority", b"localhost"),
                (b":path", b"/"),
            ],
        )
        h3_transfer(client, receiver)
        with pytest.raises(BufferError):
            sender.send_data(0, memoryview(b"abcdef")[::2], end_stream=True)
        sender.send_data(0, bytearray(b"valid"), end_stream=True)
        received = h3_transfer(client, receiver)
        assert b"".join(event.data for event in received) == b"valid"
        assert received[-1].stream_ended


def test_released_memoryview_is_rejected():
    view = memoryview(b"data")
    view.release()
    client, _ = make_pair()
    with pytest.raises(ValueError):
        client.send_stream_data(0, view)
    with pytest.raises(ValueError):
        Buffer(capacity=4).push_bytes(view)


def test_arrow_buffers():
    pa = pytest.importorskip("pyarrow")
    for data in [pa.py_buffer(b"arrow data"), pa.py_buffer(bytearray(b"mutable"))]:
        send_h3_buffer(data)
        test_quic_sends_buffer_bytes(data, native=True)
        test_quic_sends_buffer_bytes(data, native=False)
