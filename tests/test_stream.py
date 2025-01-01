from __future__ import annotations

import pytest

from qh3.quic.events import StreamDataReceived, StreamReset
from qh3.quic.packet import QuicErrorCode, QuicStreamFrame
from qh3.quic.packet_builder import QuicDeliveryState
from qh3.quic.stream import FinalSizeError, QuicStream


class TestQuicStream:
    def test_receiver_empty(self):
        stream = QuicStream(stream_id=0)
        assert bytes(stream.receiver._buffer) == b""
        assert list(stream.receiver._ranges) == []
        assert stream.receiver._buffer_start == 0

        # empty
        assert stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"")) == None
        assert bytes(stream.receiver._buffer) == b""
        assert list(stream.receiver._ranges) == []
        assert stream.receiver._buffer_start == 0

    def test_receiver_ordered(self):
        stream = QuicStream(stream_id=0)

        # add data at start
        assert stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"01234567")) == \
            StreamDataReceived(data=b"01234567", end_stream=False, stream_id=0)
        assert bytes(stream.receiver._buffer) == b""
        assert list(stream.receiver._ranges) == []
        assert stream.receiver._buffer_start == 8
        assert stream.receiver.highest_offset == 8
        assert not stream.receiver.is_finished

        # add more data
        assert stream.receiver.handle_frame(QuicStreamFrame(offset=8, data=b"89012345")) == \
            StreamDataReceived(data=b"89012345", end_stream=False, stream_id=0)
        assert bytes(stream.receiver._buffer) == b""
        assert list(stream.receiver._ranges) == []
        assert stream.receiver._buffer_start == 16
        assert stream.receiver.highest_offset == 16
        assert not stream.receiver.is_finished

        # add data and fin
        assert stream.receiver.handle_frame(
                QuicStreamFrame(offset=16, data=b"67890123", fin=True) \
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
        assert stream.receiver.handle_frame(QuicStreamFrame(offset=8, data=b"89012345")) == \
            None
        assert bytes(stream.receiver._buffer) == b"\x00\x00\x00\x00\x00\x00\x00\x0089012345"
        assert list(stream.receiver._ranges) == [range(8, 16)]
        assert stream.receiver._buffer_start == 0
        assert stream.receiver.highest_offset == 16

        # add data at offset 0
        assert stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"01234567")) == \
            StreamDataReceived(data=b"0123456789012345", end_stream=False, stream_id=0)
        assert bytes(stream.receiver._buffer) == b""
        assert list(stream.receiver._ranges) == []
        assert stream.receiver._buffer_start == 16
        assert stream.receiver.highest_offset == 16

    def test_receiver_offset_only(self):
        stream = QuicStream(stream_id=0)

        # add data at offset 0
        assert stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"")) == None
        assert bytes(stream.receiver._buffer) == b""
        assert list(stream.receiver._ranges) == []
        assert stream.receiver._buffer_start == 0
        assert stream.receiver.highest_offset == 0

        # add data at offset 8
        assert stream.receiver.handle_frame(QuicStreamFrame(offset=8, data=b"")) == None
        assert bytes(stream.receiver._buffer) == b"\x00\x00\x00\x00\x00\x00\x00\x00"
        assert list(stream.receiver._ranges) == []
        assert stream.receiver._buffer_start == 0
        assert stream.receiver.highest_offset == 8

    def test_receiver_already_fully_consumed(self):
        stream = QuicStream(stream_id=0)

        # add data at offset 0
        assert stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"01234567")) == \
            StreamDataReceived(data=b"01234567", end_stream=False, stream_id=0)
        assert bytes(stream.receiver._buffer) == b""
        assert list(stream.receiver._ranges) == []
        assert stream.receiver._buffer_start == 8

        # add data again at offset 0
        assert stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"01234567")) == \
            None
        assert bytes(stream.receiver._buffer) == b""
        assert list(stream.receiver._ranges) == []
        assert stream.receiver._buffer_start == 8

        # add data again at offset 0
        assert stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"01")) == None
        assert bytes(stream.receiver._buffer) == b""
        assert list(stream.receiver._ranges) == []
        assert stream.receiver._buffer_start == 8

    def test_receiver_already_partially_consumed(self):
        stream = QuicStream(stream_id=0)

        assert stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"01234567")) == \
            StreamDataReceived(data=b"01234567", end_stream=False, stream_id=0)

        assert stream.receiver.handle_frame(
                QuicStreamFrame(offset=0, data=b"0123456789012345") \
            ) == \
            StreamDataReceived(data=b"89012345", end_stream=False, stream_id=0)
        assert bytes(stream.receiver._buffer) == b""
        assert list(stream.receiver._ranges) == []
        assert stream.receiver._buffer_start == 16

    def test_receiver_already_partially_consumed_2(self):
        stream = QuicStream(stream_id=0)

        assert stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"01234567")) == \
            StreamDataReceived(data=b"01234567", end_stream=False, stream_id=0)

        assert stream.receiver.handle_frame(QuicStreamFrame(offset=16, data=b"abcdefgh")) == \
            None

        assert stream.receiver.handle_frame(
                QuicStreamFrame(offset=2, data=b"23456789012345") \
            ) == \
            StreamDataReceived(data=b"89012345abcdefgh", end_stream=False, stream_id=0)
        assert bytes(stream.receiver._buffer) == b""
        assert list(stream.receiver._ranges) == []
        assert stream.receiver._buffer_start == 24

    def test_receiver_fin(self):
        stream = QuicStream(stream_id=0)

        assert stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"01234567")) == \
            StreamDataReceived(data=b"01234567", end_stream=False, stream_id=0)
        assert stream.receiver.handle_frame(
                QuicStreamFrame(offset=8, data=b"89012345", fin=True) \
            ) == \
            StreamDataReceived(data=b"89012345", end_stream=True, stream_id=0)

    def test_receiver_fin_out_of_order(self):
        stream = QuicStream(stream_id=0)

        # add data at offset 8 with FIN
        assert stream.receiver.handle_frame(
                QuicStreamFrame(offset=8, data=b"89012345", fin=True) \
            ) == \
            None
        assert stream.receiver.highest_offset == 16
        assert not stream.receiver.is_finished

        # add data at offset 0
        assert stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"01234567")) == \
            StreamDataReceived(data=b"0123456789012345", end_stream=True, stream_id=0)
        assert stream.receiver.highest_offset == 16
        assert stream.receiver.is_finished

    def test_receiver_fin_then_data(self):
        stream = QuicStream(stream_id=0)
        stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"0123", fin=True))

        # data beyond final size
        with pytest.raises(FinalSizeError) as cm:
            stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"01234567"))
        assert str(cm.value) == "Data received beyond final size"

        # final size would be lowered
        with pytest.raises(FinalSizeError) as cm:
            stream.receiver.handle_frame(
                QuicStreamFrame(offset=0, data=b"01", fin=True)
            )
        assert str(cm.value) == "Cannot change final size"

    def test_receiver_fin_twice(self):
        stream = QuicStream(stream_id=0)
        assert stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"01234567")) == \
            StreamDataReceived(data=b"01234567", end_stream=False, stream_id=0)
        assert stream.receiver.handle_frame(
                QuicStreamFrame(offset=8, data=b"89012345", fin=True) \
            ) == \
            StreamDataReceived(data=b"89012345", end_stream=True, stream_id=0)

        assert stream.receiver.handle_frame(
                QuicStreamFrame(offset=8, data=b"89012345", fin=True) \
            ) == \
            StreamDataReceived(data=b"", end_stream=True, stream_id=0)

    def test_receiver_fin_without_data(self):
        stream = QuicStream(stream_id=0)
        assert stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"", fin=True)) == \
            StreamDataReceived(data=b"", end_stream=True, stream_id=0)

    def test_receiver_reset(self):
        stream = QuicStream(stream_id=0)
        assert stream.receiver.handle_reset(final_size=4) == \
            StreamReset(error_code=QuicErrorCode.NO_ERROR, stream_id=0)
        assert stream.receiver.is_finished

    def test_receiver_reset_after_fin(self):
        stream = QuicStream(stream_id=0)
        stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"0123", fin=True))
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
        assert list(stream.sender._pending) == [range(0, 16)]
        assert stream.sender.next_offset == 0

        # send a chunk
        frame = stream.sender.get_frame(8)
        assert frame.data == b"01234567"
        assert not frame.fin
        assert frame.offset == 0
        assert list(stream.sender._pending) == [range(8, 16)]
        assert stream.sender.next_offset == 8

        # send another chunk
        frame = stream.sender.get_frame(8)
        assert frame.data == b"89012345"
        assert not frame.fin
        assert frame.offset == 8
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
        assert list(stream.sender._pending) == [range(0, 16)]
        assert stream.sender.next_offset == 0

        # send a chunk
        frame = stream.sender.get_frame(8)
        assert frame.data == b"01234567"
        assert not frame.fin
        assert frame.offset == 0
        assert stream.sender.next_offset == 8

        # send another chunk
        frame = stream.sender.get_frame(8)
        assert frame.data == b"89012345"
        assert frame.fin
        assert frame.offset == 8
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
        assert list(stream.sender._pending) == [range(0, 16)]
        assert stream.sender.next_offset == 0

        # send a chunk
        frame = stream.sender.get_frame(8)
        assert frame.data == b"01234567"
        assert not frame.fin
        assert frame.offset == 0
        assert stream.sender.next_offset == 8

        # send another chunk
        frame = stream.sender.get_frame(8)
        assert frame.data == b"89012345"
        assert frame.fin
        assert frame.offset == 8
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
        assert list(stream.sender._pending) == [range(0, 16)]
        assert stream.sender.next_offset == 0

        # send a chunk
        assert stream.sender.get_frame(8) == \
            QuicStreamFrame(data=b"01234567", fin=False, offset=0)
        assert list(stream.sender._pending) == [range(8, 16)]
        assert stream.sender.next_offset == 8

        # send another chunk
        assert stream.sender.get_frame(8) == \
            QuicStreamFrame(data=b"89012345", fin=True, offset=8)
        assert list(stream.sender._pending) == []
        assert stream.sender.next_offset == 16

        # nothing more to send
        assert stream.sender.get_frame(8) is None
        assert list(stream.sender._pending) == []
        assert stream.sender.next_offset == 16

        # a chunk gets lost
        stream.sender.on_data_delivery(QuicDeliveryState.LOST, 0, 8)
        assert list(stream.sender._pending) == [range(0, 8)]
        assert stream.sender.next_offset == 0

        # send chunk again
        assert stream.sender.get_frame(8) == \
            QuicStreamFrame(data=b"01234567", fin=False, offset=0)
        assert list(stream.sender._pending) == []
        assert stream.sender.next_offset == 16

    def test_sender_data_lost_fin(self):
        stream = QuicStream()

        # nothing to send yet
        frame = stream.sender.get_frame(8)
        assert frame is None

        # write data and EOF
        stream.sender.write(b"0123456789012345", end_stream=True)
        assert list(stream.sender._pending) == [range(0, 16)]
        assert stream.sender.next_offset == 0

        # send a chunk
        assert stream.sender.get_frame(8) == \
            QuicStreamFrame(data=b"01234567", fin=False, offset=0)
        assert list(stream.sender._pending) == [range(8, 16)]
        assert stream.sender.next_offset == 8

        # send another chunk
        assert stream.sender.get_frame(8) == \
            QuicStreamFrame(data=b"89012345", fin=True, offset=8)
        assert list(stream.sender._pending) == []
        assert stream.sender.next_offset == 16

        # nothing more to send
        assert stream.sender.get_frame(8) is None
        assert list(stream.sender._pending) == []
        assert stream.sender.next_offset == 16

        # a chunk gets lost
        stream.sender.on_data_delivery(QuicDeliveryState.LOST, 8, 16)
        assert list(stream.sender._pending) == [range(8, 16)]
        assert stream.sender.next_offset == 8

        # send chunk again
        assert stream.sender.get_frame(8) == \
            QuicStreamFrame(data=b"89012345", fin=True, offset=8)
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
        frame = stream.sender.get_frame(8)
        assert frame.data == b"01234567"
        assert not frame.fin
        assert frame.offset == 0
        assert list(stream.sender._pending) == [range(8, 16)]
        assert stream.sender.next_offset == 8

        # send is limited by peer
        frame = stream.sender.get_frame(8, max_offset)
        assert frame.data == b"8901"
        assert not frame.fin
        assert frame.offset == 8
        assert list(stream.sender._pending) == [range(12, 16)]
        assert stream.sender.next_offset == 12

        # unable to send, blocked
        frame = stream.sender.get_frame(8, max_offset)
        assert frame is None
        assert list(stream.sender._pending) == [range(12, 16)]
        assert stream.sender.next_offset == 12

        # write more data, still blocked
        stream.sender.write(b"abcdefgh")
        frame = stream.sender.get_frame(8, max_offset)
        assert frame is None
        assert list(stream.sender._pending) == [range(12, 24)]
        assert stream.sender.next_offset == 12

        # peer raises limit, send some data
        max_offset += 8
        frame = stream.sender.get_frame(8, max_offset)
        assert frame.data == b"2345abcd"
        assert not frame.fin
        assert frame.offset == 12
        assert list(stream.sender._pending) == [range(20, 24)]
        assert stream.sender.next_offset == 20

        # peer raises limit again, send remaining data
        max_offset += 8
        frame = stream.sender.get_frame(8, max_offset)
        assert frame.data == b"efgh"
        assert not frame.fin
        assert frame.offset == 20
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
        frame = stream.sender.get_frame(8)
        assert frame.data == b""
        assert frame.fin
        assert frame.offset == 0

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
        frame = stream.sender.get_frame(8)
        assert frame.data == b""
        assert frame.fin
        assert frame.offset == 0

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
        assert reset.error_code == QuicErrorCode.NO_ERROR
        assert reset.final_size == 0
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
        assert reset.error_code == QuicErrorCode.NO_ERROR
        assert reset.final_size == 0
        assert not stream.sender.reset_pending

        # reset is lost
        stream.sender.on_reset_delivery(QuicDeliveryState.LOST)
        assert stream.sender.reset_pending
        assert not stream.sender.is_finished

        # reset is sent again
        reset = stream.sender.get_reset_frame()
        assert reset.error_code == QuicErrorCode.NO_ERROR
        assert reset.final_size == 0
        assert not stream.sender.reset_pending

        # reset is acklowledged
        stream.sender.on_reset_delivery(QuicDeliveryState.ACKED)
        assert not stream.sender.reset_pending
        assert stream.sender.is_finished
