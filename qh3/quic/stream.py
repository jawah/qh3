from __future__ import annotations

from .._hazmat import QuicStreamSender, RangeSet
from . import events
from .packet import (
    QuicErrorCode,
    QuicStopSendingFrame,
)
from .packet_builder import QuicDeliveryState


class FinalSizeError(Exception):
    pass


class StreamFinishedError(Exception):
    pass


class QuicStreamReceiver:
    """
    The receive part of a QUIC stream.

    It finishes:
    - immediately for a send-only stream
    - upon reception of a STREAM_RESET frame
    - upon reception of a data frame with the FIN bit set
    """

    __slots__ = (
        "highest_offset",
        "is_finished",
        "stop_pending",
        "_buffer",
        "_buffer_start",
        "_final_size",
        "_ranges",
        "_stream_id",
        "_stop_error_code",
    )

    def __init__(self, stream_id: int | None, readable: bool) -> None:
        self.highest_offset = 0  # the highest offset ever seen
        self.is_finished = False
        self.stop_pending = False

        self._buffer = bytearray()
        self._buffer_start = 0  # the offset for the start of the buffer
        self._final_size: int | None = None
        self._ranges = RangeSet()
        self._stream_id = stream_id
        self._stop_error_code: int | None = None

    def get_stop_frame(self) -> QuicStopSendingFrame:
        self.stop_pending = False
        return QuicStopSendingFrame(
            error_code=self._stop_error_code,
            stream_id=self._stream_id,
        )

    def starting_offset(self) -> int:
        return self._buffer_start

    def handle_frame(
        self, frame_offset: int, frame_data: bytes, frame_fin: bool = False
    ) -> events.StreamDataReceived | None:
        """
        Handle a frame of received data.
        """
        pos = frame_offset - self._buffer_start
        count = len(frame_data)
        frame_end = frame_offset + count

        # we should receive no more data beyond FIN!
        if self._final_size is not None:
            if frame_end > self._final_size:
                raise FinalSizeError("Data received beyond final size")
            elif frame_fin and frame_end != self._final_size:
                raise FinalSizeError("Cannot change final size")
        if frame_fin:
            self._final_size = frame_end
        if frame_end > self.highest_offset:
            self.highest_offset = frame_end

        # fast path: new in-order chunk
        if pos == 0 and count and not self._buffer:
            self._buffer_start += count
            if frame_fin:
                # all data up to the FIN has been received, we're done receiving
                self.is_finished = True
            return events.StreamDataReceived(
                data=frame_data, end_stream=frame_fin, stream_id=self._stream_id
            )

        # discard duplicate data
        if pos < 0:
            frame_data = frame_data[-pos:]
            frame_offset -= pos
            pos = 0
            count = len(frame_data)

        # marked received range
        if frame_end > frame_offset:
            self._ranges.add(frame_offset, frame_end)

        # add new data
        gap = pos - len(self._buffer)
        if gap > 0:
            self._buffer += bytearray(gap)
        self._buffer[pos : pos + count] = frame_data

        # return data from the front of the buffer
        data = self._pull_data()
        end_stream = self._buffer_start == self._final_size
        if end_stream:
            # all data up to the FIN has been received, we're done receiving
            self.is_finished = True
        if data or end_stream:
            return events.StreamDataReceived(
                data=data, end_stream=end_stream, stream_id=self._stream_id
            )
        else:
            return None

    def handle_reset(
        self, *, final_size: int, error_code: int = QuicErrorCode.NO_ERROR
    ) -> events.StreamReset | None:
        """
        Handle an abrupt termination of the receiving part of the QUIC stream.
        """
        if self._final_size is not None and final_size != self._final_size:
            raise FinalSizeError("Cannot change final size")

        # we are done receiving
        self._final_size = final_size
        if final_size > self.highest_offset:
            self.highest_offset = final_size
        self.is_finished = True
        return events.StreamReset(error_code=error_code, stream_id=self._stream_id)

    def on_stop_sending_delivery(self, delivery: QuicDeliveryState) -> None:
        """
        Callback when a STOP_SENDING is ACK'd.
        """
        if delivery != QuicDeliveryState.ACKED:
            self.stop_pending = True

    def stop(self, error_code: int = QuicErrorCode.NO_ERROR) -> None:
        """
        Request the peer stop sending data on the QUIC stream.
        """
        self._stop_error_code = error_code
        self.stop_pending = True

    def _pull_data(self) -> bytes:
        """
        Remove data from the front of the buffer.
        """
        try:
            has_data_to_read = self._ranges[0][0] == self._buffer_start
        except IndexError:
            has_data_to_read = False
        if not has_data_to_read:
            return b""

        r = self._ranges.shift()
        pos = r[1] - r[0]
        data = bytes(self._buffer[:pos])
        del self._buffer[:pos]
        self._buffer_start = r[1]
        return data


class QuicStream:
    __slots__ = (
        "is_blocked",
        "max_stream_data_local",
        "max_stream_data_local_sent",
        "max_stream_data_remote",
        "receiver",
        "sender",
        "stream_id",
    )

    def __init__(
        self,
        stream_id: int | None = None,
        max_stream_data_local: int = 0,
        max_stream_data_remote: int = 0,
        readable: bool = True,
        writable: bool = True,
    ) -> None:
        self.is_blocked = False
        self.max_stream_data_local = max_stream_data_local
        self.max_stream_data_local_sent = max_stream_data_local
        self.max_stream_data_remote = max_stream_data_remote
        self.receiver = QuicStreamReceiver(stream_id=stream_id, readable=readable)
        self.sender = QuicStreamSender(stream_id=stream_id, writable=writable)
        self.stream_id = stream_id

    @property
    def is_finished(self) -> bool:
        return self.receiver.is_finished and self.sender.is_finished
