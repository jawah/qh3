from __future__ import annotations

import pytest

from qh3.quic.events import StreamDataReceived, StreamReset
from qh3.quic.packet import QuicErrorCode
from qh3.quic.packet_builder import QuicDeliveryState
from qh3.quic.stream import FinalSizeError, QuicStream


class TestQuicStream:
    def test_receiver_empty(self):
        stream = QuicStream(stream_id=0)
        assert bytes(stream.receiver._buffer) == b""
        assert list(stream.receiver._ranges) == []
        assert stream.receiver._buffer_start == 0

        # empty
        assert stream.receiver.handle_frame(0, b"") == None
        assert bytes(stream.receiver._buffer) == b""
        assert list(stream.receiver._ranges) == []
        assert stream.receiver._buffer_start == 0

    def test_receiver_ordered(self):
        stream = QuicStream(stream_id=0)

        # add data at start
        assert stream.receiver.handle_frame(0, b"01234567") == \
            StreamDataReceived(data=b"01234567", end_stream=False, stream_id=0)
        assert bytes(stream.receiver._buffer) == b""
        assert list(stream.receiver._ranges) == []
        assert stream.receiver._buffer_start == 8
        assert stream.receiver.highest_offset == 8
        assert not stream.receiver.is_finished

        # add more data
        assert stream.receiver.handle_frame(8, b"89012345") == \
            StreamDataReceived(data=b"89012345", end_stream=False, stream_id=0)
        assert bytes(stream.receiver._buffer) == b""
        assert list(stream.receiver._ranges) == []
        assert stream.receiver._buffer_start == 16
        assert stream.receiver.highest_offset == 16
        assert not stream.receiver.is_finished

        # add data and fin
        assert stream.receiver.handle_frame(16, b"67890123", True
            ) == \
            StreamDataReceived(data=b"67890123", end_stream=True, stream_id=0)
        assert bytes(stream.receiver._buffer) == b""
        assert list(stream.receiver._ranges) == []
        assert stream.receiver._buffer_start == 24
        assert stream.receiver.highest_offset == 24
        assert stream.receiver.is_finished

    def test_receiver_unordered(self):
        stream = QuicStream(stream_id=0)

        # add data at offset 8
        assert stream.receiver.handle_frame(8, b"89012345") == \
            None
        assert bytes(stream.receiver._buffer) == b"\x00\x00\x00\x00\x00\x00\x00\x0089012345"
        assert list(stream.receiver._ranges) == [(8, 16)]
        assert stream.receiver._buffer_start == 0
        assert stream.receiver.highest_offset == 16

        # add data at offset 0
        assert stream.receiver.handle_frame(0, b"01234567") == \
            StreamDataReceived(data=b"0123456789012345", end_stream=False, stream_id=0)
        assert bytes(stream.receiver._buffer) == b""
        assert list(stream.receiver._ranges) == []
        assert stream.receiver._buffer_start == 16
        assert stream.receiver.highest_offset == 16

    def test_receiver_offset_only(self):
        stream = QuicStream(stream_id=0)

        # add data at offset 0
        assert stream.receiver.handle_frame(0, b"") == None
        assert bytes(stream.receiver._buffer) == b""
        assert list(stream.receiver._ranges) == []
        assert stream.receiver._buffer_start == 0
        assert stream.receiver.highest_offset == 0

        # add data at offset 8
        assert stream.receiver.handle_frame(8, b"") == None
        assert bytes(stream.receiver._buffer) == b"\x00\x00\x00\x00\x00\x00\x00\x00"
        assert list(stream.receiver._ranges) == []
        assert stream.receiver._buffer_start == 0
        assert stream.receiver.highest_offset == 8

    def test_receiver_already_fully_consumed(self):
        stream = QuicStream(stream_id=0)

        # add data at offset 0
        assert stream.receiver.handle_frame(0, b"01234567") == \
            StreamDataReceived(data=b"01234567", end_stream=False, stream_id=0)
        assert bytes(stream.receiver._buffer) == b""
        assert list(stream.receiver._ranges) == []
        assert stream.receiver._buffer_start == 8

        # add data again at offset 0
        assert stream.receiver.handle_frame(0, b"01234567") == \
            None
        assert bytes(stream.receiver._buffer) == b""
        assert list(stream.receiver._ranges) == []
        assert stream.receiver._buffer_start == 8

        # add data again at offset 0
        assert stream.receiver.handle_frame(0, b"01") == None
        assert bytes(stream.receiver._buffer) == b""
        assert list(stream.receiver._ranges) == []
        assert stream.receiver._buffer_start == 8

    def test_receiver_already_partially_consumed(self):
        stream = QuicStream(stream_id=0)

        assert stream.receiver.handle_frame(0, b"01234567") == \
            StreamDataReceived(data=b"01234567", end_stream=False, stream_id=0)

        assert stream.receiver.handle_frame(0, b"0123456789012345"
            ) == \
            StreamDataReceived(data=b"89012345", end_stream=False, stream_id=0)
        assert bytes(stream.receiver._buffer) == b""
        assert list(stream.receiver._ranges) == []
        assert stream.receiver._buffer_start == 16

    def test_receiver_already_partially_consumed_2(self):
        stream = QuicStream(stream_id=0)

        assert stream.receiver.handle_frame(0, b"01234567") == \
            StreamDataReceived(data=b"01234567", end_stream=False, stream_id=0)

        assert stream.receiver.handle_frame(16, b"abcdefgh") == \
            None

        assert stream.receiver.handle_frame(2, b"23456789012345"
            ) == \
            StreamDataReceived(data=b"89012345abcdefgh", end_stream=False, stream_id=0)
        assert bytes(stream.receiver._buffer) == b""
        assert list(stream.receiver._ranges) == []
        assert stream.receiver._buffer_start == 24

    def test_receiver_fin(self):
        stream = QuicStream(stream_id=0)

        assert stream.receiver.handle_frame(0, b"01234567") == \
            StreamDataReceived(data=b"01234567", end_stream=False, stream_id=0)
        assert stream.receiver.handle_frame(8, b"89012345", True
            ) == \
            StreamDataReceived(data=b"89012345", end_stream=True, stream_id=0)

    def test_receiver_fin_out_of_order(self):
        stream = QuicStream(stream_id=0)

        # add data at offset 8 with FIN
        assert stream.receiver.handle_frame(8, b"89012345", True
            ) == \
            None
        assert stream.receiver.highest_offset == 16
        assert not stream.receiver.is_finished

        # add data at offset 0
        assert stream.receiver.handle_frame(0, b"01234567") == \
            StreamDataReceived(data=b"0123456789012345", end_stream=True, stream_id=0)
        assert stream.receiver.highest_offset == 16
        assert stream.receiver.is_finished

    def test_receiver_fin_then_data(self):
        stream = QuicStream(stream_id=0)
        stream.receiver.handle_frame(0, b"0123", True)

        # data beyond final size
        with pytest.raises(FinalSizeError) as cm:
            stream.receiver.handle_frame(0, b"01234567")
        assert str(cm.value) == "Data received beyond final size"

        # final size would be lowered
        with pytest.raises(FinalSizeError) as cm:
            stream.receiver.handle_frame(0, b"01", True)
        assert str(cm.value) == "Cannot change final size"

    def test_receiver_fin_twice(self):
        stream = QuicStream(stream_id=0)
        assert stream.receiver.handle_frame(0, b"01234567") == \
            StreamDataReceived(data=b"01234567", end_stream=False, stream_id=0)
        assert stream.receiver.handle_frame(8, b"89012345", True
            ) == \
            StreamDataReceived(data=b"89012345", end_stream=True, stream_id=0)

        assert stream.receiver.handle_frame(8, b"89012345", True
            ) == \
            StreamDataReceived(data=b"", end_stream=True, stream_id=0)

    def test_receiver_fin_without_data(self):
        stream = QuicStream(stream_id=0)
        assert stream.receiver.handle_frame(0, b"", True) == \
            StreamDataReceived(data=b"", end_stream=True, stream_id=0)

    def test_receiver_reset(self):
        stream = QuicStream(stream_id=0)
        assert stream.receiver.handle_reset(final_size=4) == \
            StreamReset(error_code=QuicErrorCode.NO_ERROR, stream_id=0)
        assert stream.receiver.is_finished

    def test_receiver_reset_after_fin(self):
        stream = QuicStream(stream_id=0)
        stream.receiver.handle_frame(0, b"0123", True)
        assert stream.receiver.handle_reset(final_size=4) == \
            StreamReset(error_code=QuicErrorCode.NO_ERROR, stream_id=0)

    def test_receiver_reset_twice(self):
        stream = QuicStream(stream_id=0)
        assert stream.receiver.handle_reset(final_size=4) == \
            StreamReset(error_code=QuicErrorCode.NO_ERROR, stream_id=0)
        assert stream.receiver.handle_reset(final_size=4) == \
            StreamReset(error_code=QuicErrorCode.NO_ERROR, stream_id=0)

    def test_receiver_reset_twice_final_size_error(self):
        stream = QuicStream(stream_id=0)
        assert stream.receiver.handle_reset(final_size=4) == \
            StreamReset(error_code=QuicErrorCode.NO_ERROR, stream_id=0)

        with pytest.raises(FinalSizeError) as cm:
            stream.receiver.handle_reset(final_size=5)
        assert str(cm.value) == "Cannot change final size"

    def test_handle_reset_shrinks_final_size(self):
        # RFC 9000 4.5: a RESET_STREAM whose Final Size is below what has
        # already been received MUST be treated as FINAL_SIZE_ERROR.
        stream = QuicStream(stream_id=0)
        stream.receiver.handle_frame(0, b"0123456789")
        assert stream.receiver.highest_offset == 10

        with pytest.raises(FinalSizeError) as cm:
            stream.receiver.handle_reset(final_size=4)
        assert "below already-received" in str(cm.value)
        # State must be unchanged on rejection.
        assert stream.receiver._final_size is None
        assert stream.receiver.highest_offset == 10
        assert not stream.receiver.is_finished

    def test_receiver_stop(self):
        stream = QuicStream()

        # stop is requested
        stream.receiver.stop(QuicErrorCode.NO_ERROR)
        assert stream.receiver.stop_pending

        # stop is sent
        frame = stream.receiver.get_stop_frame()
        assert frame.error_code == QuicErrorCode.NO_ERROR
        assert not stream.receiver.stop_pending

        # stop is acklowledged
        stream.receiver.on_stop_sending_delivery(QuicDeliveryState.ACKED)
        assert not stream.receiver.stop_pending

    def test_receiver_stop_lost(self):
        stream = QuicStream()

        # stop is requested
        stream.receiver.stop(QuicErrorCode.NO_ERROR)
        assert stream.receiver.stop_pending

        # stop is sent
        frame = stream.receiver.get_stop_frame()
        assert frame.error_code == QuicErrorCode.NO_ERROR
        assert not stream.receiver.stop_pending

        # stop is lost
        stream.receiver.on_stop_sending_delivery(QuicDeliveryState.LOST)
        assert stream.receiver.stop_pending

        # stop is sent again
        frame = stream.receiver.get_stop_frame()
        assert frame.error_code == QuicErrorCode.NO_ERROR
        assert not stream.receiver.stop_pending

        # stop is acklowledged
        stream.receiver.on_stop_sending_delivery(QuicDeliveryState.ACKED)
        assert not stream.receiver.stop_pending

    def test_sender_data(self):
        stream = QuicStream()
        assert stream.sender.next_offset == 0

        # nothing to send yet
        frame = stream.sender.get_frame(8)
        assert frame is None

        # write data
        stream.sender.write(b"0123456789012345")
        assert list(stream.sender._pending) == [(0, 16)]
        assert stream.sender.next_offset == 0

        # send a chunk
        f_data, f_fin, f_offset = stream.sender.get_frame(8)
        assert f_data == b"01234567"
        assert not f_fin
        assert f_offset == 0
        assert list(stream.sender._pending) == [(8, 16)]
        assert stream.sender.next_offset == 8

        # send another chunk
        f_data, f_fin, f_offset = stream.sender.get_frame(8)
        assert f_data == b"89012345"
        assert not f_fin
        assert f_offset == 8
        assert list(stream.sender._pending) == []
        assert stream.sender.next_offset == 16

        # nothing more to send
        frame = stream.sender.get_frame(8)
        assert frame is None
        assert list(stream.sender._pending) == []
        assert stream.sender.next_offset == 16

        # first chunk gets acknowledged
        stream.sender.on_data_delivery(QuicDeliveryState.ACKED, 0, 8)
        assert not stream.sender.is_finished

        # second chunk gets acknowledged
        stream.sender.on_data_delivery(QuicDeliveryState.ACKED, 8, 16)
        assert not stream.sender.is_finished

    def test_sender_data_and_fin(self):
        stream = QuicStream()

        # nothing to send yet
        frame = stream.sender.get_frame(8)
        assert frame is None

        # write data and EOF
        stream.sender.write(b"0123456789012345", end_stream=True)
        assert list(stream.sender._pending) == [(0, 16)]
        assert stream.sender.next_offset == 0

        # send a chunk
        f_data, f_fin, f_offset = stream.sender.get_frame(8)
        assert f_data == b"01234567"
        assert not f_fin
        assert f_offset == 0
        assert stream.sender.next_offset == 8

        # send another chunk
        f_data, f_fin, f_offset = stream.sender.get_frame(8)
        assert f_data == b"89012345"
        assert f_fin
        assert f_offset == 8
        assert stream.sender.next_offset == 16

        # nothing more to send
        frame = stream.sender.get_frame(8)
        assert frame is None
        assert stream.sender.next_offset == 16

        # first chunk gets acknowledged
        stream.sender.on_data_delivery(QuicDeliveryState.ACKED, 0, 8)
        assert not stream.sender.is_finished

        # second chunk gets acknowledged
        stream.sender.on_data_delivery(QuicDeliveryState.ACKED, 8, 16)
        assert stream.sender.is_finished

    def test_sender_data_and_fin_ack_out_of_order(self):
        stream = QuicStream()

        # nothing to send yet
        frame = stream.sender.get_frame(8)
        assert frame is None

        # write data and EOF
        stream.sender.write(b"0123456789012345", end_stream=True)
        assert list(stream.sender._pending) == [(0, 16)]
        assert stream.sender.next_offset == 0

        # send a chunk
        frame = stream.sender.get_frame(8)
        f_data, f_fin, f_offset = frame
        assert f_data == b"01234567"
        assert not f_fin
        assert f_offset == 0
        assert stream.sender.next_offset == 8

        # send another chunk
        frame = stream.sender.get_frame(8)
        f_data, f_fin, f_offset = frame
        assert f_data == b"89012345"
        assert f_fin
        assert f_offset == 8
        assert stream.sender.next_offset == 16

        # nothing more to send
        frame = stream.sender.get_frame(8)
        assert frame is None
        assert stream.sender.next_offset == 16

        # second chunk gets acknowledged
        stream.sender.on_data_delivery(QuicDeliveryState.ACKED, 8, 16)
        assert not stream.sender.is_finished

        # first chunk gets acknowledged
        stream.sender.on_data_delivery(QuicDeliveryState.ACKED, 0, 8)
        assert stream.sender.is_finished

    def test_sender_data_lost(self):
        stream = QuicStream()

        # nothing to send yet
        frame = stream.sender.get_frame(8)
        assert frame is None

        # write data and EOF
        stream.sender.write(b"0123456789012345", end_stream=True)
        assert list(stream.sender._pending) == [(0, 16)]
        assert stream.sender.next_offset == 0

        # send a chunk
        assert stream.sender.get_frame(8) == \
            (b"01234567", False, 0)
        assert list(stream.sender._pending) == [(8, 16)]
        assert stream.sender.next_offset == 8

        # send another chunk
        assert stream.sender.get_frame(8) == \
            (b"89012345", True, 8)
        assert list(stream.sender._pending) == []
        assert stream.sender.next_offset == 16

        # nothing more to send
        assert stream.sender.get_frame(8) is None
        assert list(stream.sender._pending) == []
        assert stream.sender.next_offset == 16

        # a chunk gets lost
        stream.sender.on_data_delivery(QuicDeliveryState.LOST, 0, 8)
        assert list(stream.sender._pending) == [(0, 8)]
        assert stream.sender.next_offset == 0

        # send chunk again
        assert stream.sender.get_frame(8) == \
            (b"01234567", False, 0)
        assert list(stream.sender._pending) == []
        assert stream.sender.next_offset == 16

    def test_sender_data_lost_fin(self):
        stream = QuicStream()

        # nothing to send yet
        frame = stream.sender.get_frame(8)
        assert frame is None

        # write data and EOF
        stream.sender.write(b"0123456789012345", end_stream=True)
        assert list(stream.sender._pending) == [(0, 16)]
        assert stream.sender.next_offset == 0

        # send a chunk
        assert stream.sender.get_frame(8) == \
            (b"01234567", False, 0)
        assert list(stream.sender._pending) == [(8, 16)]
        assert stream.sender.next_offset == 8

        # send another chunk
        assert stream.sender.get_frame(8) == \
            (b"89012345", True, 8)
        assert list(stream.sender._pending) == []
        assert stream.sender.next_offset == 16

        # nothing more to send
        assert stream.sender.get_frame(8) is None
        assert list(stream.sender._pending) == []
        assert stream.sender.next_offset == 16

        # a chunk gets lost
        stream.sender.on_data_delivery(QuicDeliveryState.LOST, 8, 16)
        assert list(stream.sender._pending) == [(8, 16)]
        assert stream.sender.next_offset == 8

        # send chunk again
        assert stream.sender.get_frame(8) == \
            (b"89012345", True, 8)
        assert list(stream.sender._pending) == []
        assert stream.sender.next_offset == 16

        # both chunks gets acknowledged
        stream.sender.on_data_delivery(QuicDeliveryState.ACKED, 0, 16)
        assert stream.sender.is_finished

    def test_sender_blocked(self):
        stream = QuicStream()
        max_offset = 12

        # nothing to send yet
        frame = stream.sender.get_frame(8, max_offset)
        assert frame is None
        assert list(stream.sender._pending) == []
        assert stream.sender.next_offset == 0

        # write data, send a chunk
        stream.sender.write(b"0123456789012345")
        f_data, f_fin, f_offset = stream.sender.get_frame(8)
        assert f_data == b"01234567"
        assert not f_fin
        assert f_offset == 0
        assert list(stream.sender._pending) == [(8, 16)]
        assert stream.sender.next_offset == 8

        # send is limited by peer
        f_data, f_fin, f_offset = stream.sender.get_frame(8, max_offset)
        assert f_data == b"8901"
        assert not f_fin
        assert f_offset == 8
        assert list(stream.sender._pending) == [(12, 16)]
        assert stream.sender.next_offset == 12

        # unable to send, blocked
        frame = stream.sender.get_frame(8, max_offset)
        assert frame is None
        assert list(stream.sender._pending) == [(12, 16)]
        assert stream.sender.next_offset == 12

        # write more data, still blocked
        stream.sender.write(b"abcdefgh")
        frame = stream.sender.get_frame(8, max_offset)
        assert frame is None
        assert list(stream.sender._pending) == [(12, 24)]
        assert stream.sender.next_offset == 12

        # peer raises limit, send some data
        max_offset += 8
        f_data, f_fin, f_offset = stream.sender.get_frame(8, max_offset)
        assert f_data == b"2345abcd"
        assert not f_fin
        assert f_offset == 12
        assert list(stream.sender._pending) == [(20, 24)]
        assert stream.sender.next_offset == 20

        # peer raises limit again, send remaining data
        max_offset += 8
        f_data, f_fin, f_offset = stream.sender.get_frame(8, max_offset)
        assert f_data == b"efgh"
        assert not f_fin
        assert f_offset == 20
        assert list(stream.sender._pending) == []
        assert stream.sender.next_offset == 24

        # nothing more to send
        frame = stream.sender.get_frame(8, max_offset)
        assert frame is None

    def test_sender_fin_only(self):
        stream = QuicStream()

        # nothing to send yet
        assert stream.sender.buffer_is_empty
        frame = stream.sender.get_frame(8)
        assert frame is None

        # write EOF
        stream.sender.write(b"", end_stream=True)
        assert not stream.sender.buffer_is_empty
        f_data, f_fin, f_offset = stream.sender.get_frame(8)
        assert f_data == b""
        assert f_fin
        assert f_offset == 0

        # nothing more to send
        assert not stream.sender.buffer_is_empty# FIXME?
        frame = stream.sender.get_frame(8)
        assert frame is None
        assert stream.sender.buffer_is_empty

    def test_sender_fin_only_despite_blocked(self):
        stream = QuicStream()

        # nothing to send yet
        assert stream.sender.buffer_is_empty
        frame = stream.sender.get_frame(8)
        assert frame is None

        # write EOF
        stream.sender.write(b"", end_stream=True)
        assert not stream.sender.buffer_is_empty
        f_data, f_fin, f_offset = stream.sender.get_frame(8)
        assert f_data == b""
        assert f_fin
        assert f_offset == 0

        # nothing more to send
        assert not stream.sender.buffer_is_empty# FIXME?
        frame = stream.sender.get_frame(8)
        assert frame is None
        assert stream.sender.buffer_is_empty

    def test_sender_reset(self):
        stream = QuicStream()

        # reset is requested
        stream.sender.reset(QuicErrorCode.NO_ERROR)
        assert stream.sender.reset_pending

        # reset is sent
        reset = stream.sender.get_reset_frame()
        assert reset[0] == QuicErrorCode.NO_ERROR  # error_code
        assert reset[1] == 0  # final_size
        assert not stream.sender.reset_pending
        assert not stream.sender.is_finished

        # reset is acklowledged
        stream.sender.on_reset_delivery(QuicDeliveryState.ACKED)
        assert not stream.sender.reset_pending
        assert stream.sender.is_finished

    def test_sender_reset_lost(self):
        stream = QuicStream()

        # reset is requested
        stream.sender.reset(QuicErrorCode.NO_ERROR)
        assert stream.sender.reset_pending

        # reset is sent
        reset = stream.sender.get_reset_frame()
        assert reset[0] == QuicErrorCode.NO_ERROR  # error_code
        assert reset[1] == 0  # final_size
        assert not stream.sender.reset_pending

        # reset is lost
        stream.sender.on_reset_delivery(QuicDeliveryState.LOST)
        assert stream.sender.reset_pending
        assert not stream.sender.is_finished

        # reset is sent again
        reset = stream.sender.get_reset_frame()
        assert reset[0] == QuicErrorCode.NO_ERROR  # error_code
        assert reset[1] == 0  # final_size
        assert not stream.sender.reset_pending

        # reset is acklowledged
        stream.sender.on_reset_delivery(QuicDeliveryState.ACKED)
        assert not stream.sender.reset_pending
        assert stream.sender.is_finished
