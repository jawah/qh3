from __future__ import annotations

from enum import IntEnum
from typing import Any, Callable, Sequence

from .._hazmat import Buffer, size_uint_var
from ..tls import Epoch
from .crypto import CryptoPair
from .logger import QuicLoggerTrace
from .packet import (
    NON_ACK_ELICITING_FRAME_TYPES,
    NON_IN_FLIGHT_FRAME_TYPES,
    PACKET_NUMBER_MAX_SIZE,
    QuicFrameType,
    QuicPacketType,
)

# MinPacketSize and MaxPacketSize control the packet sizes for UDP datagrams.
# If MinPacketSize is unset, a default value of 1280 bytes
# will be used during the handshake.
# If MaxPacketSize is unset, a default value of 1452 bytes will be used.
# DPLPMTUD will automatically determine the MTU supported
# by the link-up to the MaxPacketSize,
# except for in the case where MinPacketSize and MaxPacketSize
# are configured to the same value,
# in which case path MTU discovery will be disabled.
# Values above 65355 are invalid.
# 20-bytes for IPv6 overhead.
# 1280 is very conservative
# Chrome tries 1350 at startup
# we should do a rudimentary MTU discovery
# Sending a PING frame 1350
#           THEN       1452
SMALLEST_MAX_DATAGRAM_SIZE = 1200
PACKET_MAX_SIZE = 1280
MTU_PROBE_SIZES = [1350, 1452]

PACKET_LENGTH_SEND_SIZE = 2
PACKET_NUMBER_SEND_SIZE = 2


QuicDeliveryHandler = Callable[..., None]


class QuicDeliveryState(IntEnum):
    ACKED = 0
    LOST = 1


class QuicSentPacket:
    __slots__ = (
        "epoch",
        "in_flight",
        "is_ack_eliciting",
        "is_crypto_packet",
        "is_pmtu_probe",
        "packet_number",
        "packet_type",
        "sent_time",
        "sent_bytes",
        "delivery_handlers",
        "quic_logger_frames",
    )

    def __init__(
        self,
        epoch: Epoch,
        in_flight: bool,
        is_ack_eliciting: bool,
        is_crypto_packet: bool,
        packet_number: int,
        packet_type: QuicPacketType,
        sent_time: float | None = None,
        sent_bytes: int = 0,
        is_pmtu_probe: bool = False,
    ) -> None:
        self.epoch = epoch
        self.in_flight = in_flight
        self.is_ack_eliciting = is_ack_eliciting
        self.is_crypto_packet = is_crypto_packet
        self.is_pmtu_probe = is_pmtu_probe
        self.packet_number = packet_number
        self.packet_type = packet_type
        self.sent_time = sent_time
        self.sent_bytes = sent_bytes
        self.delivery_handlers: list[tuple[QuicDeliveryHandler, Any]] | None = None
        self.quic_logger_frames: list[dict] | None = None

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, QuicSentPacket):
            return NotImplemented
        return (
            self.epoch == other.epoch
            and self.in_flight == other.in_flight
            and self.is_ack_eliciting == other.is_ack_eliciting
            and self.is_crypto_packet == other.is_crypto_packet
            and self.is_pmtu_probe == other.is_pmtu_probe
            and self.packet_number == other.packet_number
            and self.packet_type == other.packet_type
            and self.sent_bytes == other.sent_bytes
        )


class QuicPacketBuilderStop(Exception):
    pass


class QuicPacketBuilder:
    """
    Helper for building QUIC packets.
    """

    __slots__ = (
        "max_flight_bytes",
        "max_total_bytes",
        "quic_logger_frames",
        "_host_cid",
        "_is_client",
        "_peer_cid",
        "_peer_token",
        "_quic_logger",
        "_spin_bit",
        "_version",
        "_datagrams",
        "_datagram_flight_bytes",
        "_datagram_init",
        "_datagram_needs_padding",
        "_packets",
        "_flight_bytes",
        "_total_bytes",
        "_header_size",
        "_packet",
        "_packet_crypto",
        "_packet_long_header",
        "_packet_numbers",
        "_packet_start",
        "_packet_type",
        "_buffer",
        "_buffer_capacity",
        "_flight_capacity",
        "_aead_tag_size",
    )

    def __init__(
        self,
        *,
        host_cid: bytes,
        peer_cid: bytes,
        version: int,
        is_client: bool,
        max_datagram_size: int = PACKET_MAX_SIZE,
        packet_number: int = 0,
        packet_numbers: dict[Epoch, int] | None = None,
        peer_token: bytes = b"",
        quic_logger: QuicLoggerTrace | None = None,
        spin_bit: bool = False,
    ):
        self.max_flight_bytes: int | None = None
        self.max_total_bytes: int | None = None
        self.quic_logger_frames: list[dict] | None = None

        self._host_cid = host_cid
        self._is_client = is_client
        self._peer_cid = peer_cid
        self._peer_token = peer_token
        self._quic_logger = quic_logger
        self._spin_bit = spin_bit
        self._version = version

        # assembled datagrams and packets
        self._datagrams: list[bytes] = []
        self._datagram_flight_bytes = 0
        self._datagram_init = True
        self._datagram_needs_padding = False
        self._packets: list[QuicSentPacket] = []
        self._flight_bytes = 0
        self._total_bytes = 0

        # current packet
        self._header_size = 0
        self._packet: QuicSentPacket | None = None
        self._packet_crypto: CryptoPair | None = None
        self._packet_long_header = False
        self._packet_start = 0
        self._packet_type: QuicPacketType | None = None

        # per-space packet numbers (RFC 9000 §12.3)
        if packet_numbers is not None:
            self._packet_numbers = dict(packet_numbers)
        else:
            self._packet_numbers = {
                Epoch.INITIAL: packet_number,
                Epoch.HANDSHAKE: packet_number,
                Epoch.ONE_RTT: packet_number,
            }

        self._buffer = Buffer(max_datagram_size)
        self._buffer_capacity = max_datagram_size
        self._flight_capacity = max_datagram_size

    @property
    def packet_is_empty(self) -> bool:
        """
        Returns `True` if the current packet is empty.
        """
        assert self._packet is not None
        packet_size = self._buffer.tell() - self._packet_start
        return packet_size <= self._header_size

    @property
    def packet_number(self) -> int:
        """
        Returns the packet number for the next packet.

        .. deprecated:: Use ``packet_numbers`` for per-space access.
        """
        return max(self._packet_numbers.values())

    @property
    def packet_numbers(self) -> dict[Epoch, int]:
        """
        Returns the per-space packet numbers (RFC 9000 12.3).
        """
        return self._packet_numbers

    @property
    def remaining_buffer_space(self) -> int:
        """
        Returns the remaining number of bytes which can be used in
        the current packet.
        """
        return self._buffer_capacity - self._buffer.tell() - self._aead_tag_size

    @property
    def remaining_flight_space(self) -> int:
        """
        Returns the remaining number of bytes which can be used in
        the current packet.
        """
        return self._flight_capacity - self._buffer.tell() - self._aead_tag_size

    def pad_datagram(self) -> None:
        """
        Mark the current datagram as needing to be padded to the full
        path MTU. Used to satisfy RFC 9000 8.2.1 (PATH_CHALLENGE /
        PATH_RESPONSE) and similar requirements.
        """
        self._datagram_needs_padding = True

    def flush(self) -> tuple[list[bytes], list[QuicSentPacket]]:
        """
        Returns the assembled datagrams.
        """
        if self._packet is not None:
            self._end_packet()
        self._flush_current_datagram()

        datagrams = self._datagrams
        packets = self._packets
        self._datagrams = []
        self._packets = []
        return datagrams, packets

    def start_frame(
        self,
        frame_type: int,
        capacity: int = 1,
        handler: QuicDeliveryHandler | None = None,
        handler_args: Sequence[Any] = [],
    ) -> Buffer:
        """
        Starts a new frame.
        """
        buf_pos = self._buffer.tell()
        aead = self._aead_tag_size
        if self._buffer_capacity - buf_pos - aead < capacity or (
            frame_type not in NON_IN_FLIGHT_FRAME_TYPES
            and self._flight_capacity - buf_pos - aead < capacity
        ):
            raise QuicPacketBuilderStop

        self._buffer.push_uint_var(frame_type)
        packet = self._packet
        if frame_type not in NON_ACK_ELICITING_FRAME_TYPES:
            packet.is_ack_eliciting = True
        if frame_type not in NON_IN_FLIGHT_FRAME_TYPES:
            packet.in_flight = True
        if frame_type == QuicFrameType.CRYPTO:
            packet.is_crypto_packet = True
        if handler is not None:
            dh = packet.delivery_handlers
            if dh is None:
                packet.delivery_handlers = [(handler, handler_args)]
            else:
                dh.append((handler, handler_args))
        return self._buffer

    def start_packet(self, packet_type: QuicPacketType, crypto: CryptoPair) -> None:
        """
        Starts a new packet.
        """
        assert packet_type not in {
            QuicPacketType.RETRY,
            QuicPacketType.VERSION_NEGOTIATION,
        }, "Invalid packet type"

        buf = self._buffer

        # finish previous datagram
        if self._packet is not None:
            self._end_packet()

        # if there is too little space remaining, start a new datagram
        # FIXME: the limit is arbitrary!
        packet_start = buf.tell()
        if self._buffer_capacity - packet_start < 128:
            self._flush_current_datagram()
            packet_start = 0

        # initialize datagram if needed
        if self._datagram_init:
            if self.max_total_bytes is not None:
                remaining_total_bytes = self.max_total_bytes - self._total_bytes
                if remaining_total_bytes < self._buffer_capacity:
                    self._buffer_capacity = remaining_total_bytes

            self._flight_capacity = self._buffer_capacity
            if self.max_flight_bytes is not None:
                remaining_flight_bytes = self.max_flight_bytes - self._flight_bytes
                if remaining_flight_bytes < self._flight_capacity:
                    self._flight_capacity = remaining_flight_bytes
            self._datagram_flight_bytes = 0
            self._datagram_init = False
            self._datagram_needs_padding = False

        # calculate header size
        if packet_type != QuicPacketType.ONE_RTT:
            header_size = 11 + len(self._peer_cid) + len(self._host_cid)
            if packet_type == QuicPacketType.INITIAL:
                token_length = len(self._peer_token)
                header_size += size_uint_var(token_length) + token_length
        else:
            header_size = 3 + len(self._peer_cid)

        # check we have enough space
        if packet_start + header_size >= self._buffer_capacity:
            raise QuicPacketBuilderStop

        # determine ack epoch
        if packet_type == QuicPacketType.INITIAL:
            epoch = Epoch.INITIAL
        elif packet_type == QuicPacketType.HANDSHAKE:
            epoch = Epoch.HANDSHAKE
        else:
            epoch = Epoch.ONE_RTT

        self._header_size = header_size
        self._packet = QuicSentPacket(
            epoch,
            False,
            False,
            False,
            self._packet_numbers[epoch],
            packet_type,
        )
        self._packet_crypto = crypto
        self._aead_tag_size = crypto.aead_tag_size
        self._packet_start = packet_start
        self._packet_type = packet_type

        qlf: list[dict] = []
        self._packet.quic_logger_frames = qlf
        self.quic_logger_frames = qlf

        buf.seek(self._packet_start + self._header_size)

    def _end_packet(self) -> None:
        """
        Ends the current packet.
        """
        buf = self._buffer
        buf_pos = buf.tell()
        packet_size = buf_pos - self._packet_start
        if packet_size > self._header_size:
            # padding to ensure sufficient sample size
            padding_size = (
                PACKET_NUMBER_MAX_SIZE
                - PACKET_NUMBER_SEND_SIZE
                + self._header_size
                - packet_size
            )

            # Padding for datagrams containing initial packets; see RFC 9000
            # section 14.1.
            if (
                self._is_client or self._packet.is_ack_eliciting
            ) and self._packet_type == QuicPacketType.INITIAL:
                self._datagram_needs_padding = True

            # For datagrams containing 1-RTT data, we *must* apply the padding
            # inside the packet, we cannot tack bytes onto the end of the
            # datagram.
            if (
                self._datagram_needs_padding
                and self._packet_type == QuicPacketType.ONE_RTT
            ):
                remaining_flight = self._flight_capacity - buf_pos - self._aead_tag_size
                if remaining_flight > padding_size:
                    padding_size = remaining_flight
                self._datagram_needs_padding = False

            if padding_size > 0:
                self._packet.in_flight = True
                # log frame
                if self._quic_logger is not None:
                    self._packet.quic_logger_frames.append(
                        self._quic_logger.encode_padding_frame()
                    )
            else:
                padding_size = 0

            # Write header, pad, encrypt, apply header protection
            self._packet.sent_bytes = self._packet_crypto.finalize_packet(
                buf,
                self._packet_start,
                packet_size,
                padding_size,
                self._header_size,
                self._packet_type != QuicPacketType.ONE_RTT,
                self._version,
                int(self._packet_type),
                self._peer_cid,
                self._host_cid,
                self._peer_token,
                self._spin_bit,
                self._packet.packet_number,
            )

            self._packets.append(self._packet)
            if self._packet.in_flight:
                self._datagram_flight_bytes += self._packet.sent_bytes

            # Short header packets cannot be coalesced, we need a new datagram.
            if self._packet_type == QuicPacketType.ONE_RTT:
                self._flush_current_datagram()

            self._packet_numbers[self._packet.epoch] += 1
        else:
            # "cancel" the packet
            buf.seek(self._packet_start)

        self._packet = None
        self.quic_logger_frames = None

    def _flush_current_datagram(self) -> None:
        datagram_bytes = self._buffer.tell()
        if datagram_bytes:
            # Padding for datagrams containing initial packets; see RFC 9000
            # section 14.1.
            if self._datagram_needs_padding:
                extra_bytes = self._flight_capacity - self._buffer.tell()
                if extra_bytes > 0:
                    self._buffer.push_bytes(bytes(extra_bytes))
                    self._datagram_flight_bytes += extra_bytes
                    datagram_bytes += extra_bytes

            self._datagrams.append(self._buffer.data)
            self._flight_bytes += self._datagram_flight_bytes
            self._total_bytes += datagram_bytes
            self._datagram_init = True
            self._buffer.seek(0)
