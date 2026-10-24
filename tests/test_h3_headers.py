from __future__ import annotations

import pytest

from qh3._hazmat import DecoderStreamError, QpackDecoder, QpackEncoder
from qh3.h3.connection import (
    FrameType,
    H3Connection,
    StreamType,
    encode_frame,
)
from qh3.h3.events import DataReceived, HeadersReceived
from qh3.quic.configuration import QuicConfiguration
from qh3.quic.events import StreamDataReceived

from .test_h3 import FakeQuicConnection

HEADERS = [(b":status", b"200"), (b"x-name", b"header value")]


def encoded_headers():
    encoder = QpackEncoder()
    instructions, block = encoder.encode(0, HEADERS)
    assert instructions == b""
    return block


@pytest.mark.parametrize("explicit_length", [False, True])
def test_qpack_decodes_a_range_of_existing_bytes(explicit_length):
    block = encoded_headers()
    decoder = QpackDecoder(0, 0)
    data = b"prefix" + block
    kwargs = {"offset": 6}
    if explicit_length:
        data += b"unrelated tail"
        kwargs["length"] = len(block)
    _, headers = decoder.feed_header(0, data, **kwargs)
    assert headers == HEADERS
    assert all(
        isinstance(name, bytes) and isinstance(value, bytes) for name, value in headers
    )


@pytest.mark.parametrize(
    "offset,length", [(9999, None), (9999, 1), (0, 9999), (1, (1 << 64) - 1)]
)
def test_invalid_qpack_range_does_not_change_decoder(offset, length):
    decoder = QpackDecoder(0, 0)
    block = encoded_headers()
    with pytest.raises((ValueError, OverflowError)):
        decoder.feed_header(0, block, offset=offset, length=length)
    assert decoder.feed_header(0, block)[1] == HEADERS


def test_empty_qpack_range_is_rejected():
    decoder = QpackDecoder(0, 0)
    with pytest.raises(DecoderStreamError, match="Empty QPACK"):
        decoder.feed_header(0, b"prefix", offset=6)
    assert decoder.feed_header(0, encoded_headers())[1] == HEADERS


def receiver():
    quic = FakeQuicConnection(configuration=QuicConfiguration(is_client=True))
    quic._quic_logger = None
    return H3Connection(quic)


def test_http3_passes_the_original_header_input_to_qpack():
    h3 = receiver()
    original_decoder = h3._decoder
    calls = []

    class DecoderSpy:
        def feed_header(self, stream_id, data, **kwargs):
            calls.append((data, kwargs))
            return original_decoder.feed_header(stream_id, data, **kwargs)

    h3._decoder = DecoderSpy()
    block = encoded_headers()
    frame = encode_frame(FrameType.HEADERS, block)
    wire = frame + encode_frame(FrameType.DATA, b"body")
    events = h3.handle_event(StreamDataReceived(wire, True, 0))
    assert events == [
        HeadersReceived(HEADERS, 0, False),
        DataReceived(b"body", 0, True),
    ]
    assert len(calls) == 1
    assert calls[0][0] is wire
    assert calls[0][1] == {"offset": len(frame) - len(block), "length": len(block)}


@pytest.mark.parametrize(
    "stream_type", [StreamType.QPACK_ENCODER, StreamType.QPACK_DECODER]
)
def test_established_qpack_stream_feeds_original_bytes(stream_type):
    h3 = receiver()
    stream = h3._get_or_create_stream(
        7 if stream_type == StreamType.QPACK_ENCODER else 11
    )
    stream.stream_type = stream_type
    calls = []

    class QpackSpy:
        def feed_encoder(self, data):
            calls.append(data)

        def feed_decoder(self, data):
            calls.append(data)

    if stream_type == StreamType.QPACK_ENCODER:
        h3._decoder = QpackSpy()
    else:
        h3._encoder = QpackSpy()
    data = b"instruction bytes"
    assert h3.handle_event(StreamDataReceived(data, False, stream.stream_id)) == []
    assert len(calls) == 1 and calls[0] is data
    assert not stream.buffer
    assert (
        h3._encoder_bytes_received
        if stream_type == StreamType.QPACK_ENCODER
        else h3._decoder_bytes_received
    ) == len(data)


@pytest.mark.parametrize("step", [1, 3, 128])
def test_qpack_instruction_fragments_unblock_coalesced_headers(step):
    h3 = receiver()
    # Include a split, non-minimal stream-type varint before the instructions.
    stream_prefix = b"\x80\x00\x00\x02"
    for byte in stream_prefix:
        assert h3.handle_event(StreamDataReceived(bytes([byte]), False, 7)) == []
    header_block = bytes.fromhex("0280d910")
    wire = encode_frame(FrameType.HEADERS, header_block) + encode_frame(
        FrameType.DATA, b"retained"
    )
    assert h3.handle_event(StreamDataReceived(wire, True, 0)) == []
    stream = h3._stream[0]
    assert stream.blocked
    assert stream.blocked_frame_size == len(header_block)
    instructions = bytes.fromhex(
        "3fe101c696d07abe941094cb6d0a08017d403971966e32ca98b46f"
    )
    events = []
    for offset in range(0, len(instructions), step):
        events += h3.handle_event(
            StreamDataReceived(instructions[offset : offset + step], False, 7)
        )
    assert isinstance(events[0], HeadersReceived)
    assert events[0].headers[0] == (b":status", b"200")
    assert events[1:] == [DataReceived(b"retained", 0, True)]
    assert not stream.blocked and not stream.buffer
    assert h3._encoder_bytes_received == len(instructions)


def test_qpack_decoder_stream_handles_fragmented_acknowledgments():
    encoder = QpackEncoder()
    decoder = QpackDecoder(4096, 100)
    decoder.feed_encoder(encoder.apply_settings(4096, 4096, 100))
    h3 = receiver()
    h3._encoder = encoder
    assert h3.handle_event(StreamDataReceived(b"\x03", False, 11)) == []
    acknowledged = 0
    for stream_id in range(0, 40, 4):
        headers = [(b":status", b"200"), (b"x-repeated-header", b"repeated-value")]
        instructions, block = encoder.encode(stream_id, headers)
        decoder.feed_encoder(instructions)
        ack, decoded = decoder.feed_header(stream_id, block)
        assert decoded == headers
        for byte in ack:
            assert h3.handle_event(StreamDataReceived(bytes([byte]), False, 11)) == []
        acknowledged += len(ack)
    assert acknowledged > 0
    assert h3._decoder_bytes_received == acknowledged
    assert h3._quic.closed is None


def test_decoded_headers_remain_owned_after_decoder_reuse():
    decoder = QpackDecoder(0, 0)
    block = encoded_headers()
    first = decoder.feed_header(0, block)[1]
    assert decoder.feed_header(4, block)[1] == HEADERS
    del decoder
    assert first == HEADERS


def test_qpack_unknown_resume_is_an_exception():
    with pytest.raises(DecoderStreamError, match="unknown"):
        QpackDecoder(0, 0).resume_header(0)
