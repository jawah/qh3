from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Sequence

from .._compat import DATACLASS_KWARGS
from .._hazmat import Buffer, size_uint_var
from ..tls import Epoch
from .crypto import CryptoPair
from .logger import QuicLoggerTrace
from .packet import (
    NON_ACK_ELICITING_FRAME_TYPES,
    NON_IN_FLIGHT_FRAME_TYPES,
    PACKET_FIXED_BIT,
    PACKET_NUMBER_MAX_SIZE,
    QuicFrameType,
    QuicPacketType,
    encode_long_header_first_byte,
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
PACKET_MAX_SIZE = 1280

PACKET_LENGTH_SEND_SIZE = 2
PACKET_NUMBER_SEND_SIZE = 2


QuicDeliveryHandler = Callable[..., None]


class QuicDeliveryState(IntEnum):
    ACKED = 0
    LOST = 1


@dataclass(**DATACLASS_KWARGS)
class QuicSentPacket:
    epoch: Epoch
    in_flight: bool
    is_ack_eliciting: bool
    is_crypto_packet: bool
    packet_number: int
    packet_type: QuicPacketType
    sent_time: float | None = None
    sent_bytes: int = 0

    delivery_handlers: list[tuple[QuicDeliveryHandler, Any]] = field(
        default_factory=list
    )
    quic_logger_frames: list[dict] = field(default_factory=list)


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
        "_packet_number",
        "_packet_start",
        "_packet_type",
        "_buffer",
        "_buffer_capacity",
        "_flight_capacity",
    )

    def __init__(
        self,
        *,
        host_cid: bytes,
        peer_cid: bytes,
        version: int,
        is_client: bool,
        packet_number: int = 0,
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
        self._packet_number = packet_number
        self._packet_start = 0
        self._packet_type: QuicPacketType | None = None

        self._buffer = Buffer(PACKET_MAX_SIZE)
        self._buffer_capacity = PACKET_MAX_SIZE
        self._flight_capacity = PACKET_MAX_SIZE

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
        """
        return self._packet_number

    @property
    def remaining_buffer_space(self) -> int:
        """
        Returns the remaining number of bytes which can be used in
        the current packet.
        """
        return (
            self._buffer_capacity
            - self._buffer.tell()
            - self._packet_crypto.aead_tag_size
        )

    @property
    def remaining_flight_space(self) -> int:
        """
        Returns the remaining number of bytes which can be used in
        the current packet.
        """
        return (
            self._flight_capacity
            - self._buffer.tell()
            - self._packet_crypto.aead_tag_size
        )

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
        if self.remaining_buffer_space < capacity or (
            frame_type not in NON_IN_FLIGHT_FRAME_TYPES
            and self.remaining_flight_space < capacity
        ):
            raise QuicPacketBuilderStop

        self._buffer.push_uint_var(frame_type)
        if frame_type not in NON_ACK_ELICITING_FRAME_TYPES:
            self._packet.is_ack_eliciting = True
        if frame_type not in NON_IN_FLIGHT_FRAME_TYPES:
            self._packet.in_flight = True
        if frame_type == QuicFrameType.CRYPTO:
            self._packet.is_crypto_packet = True
        if handler is not None:
            self._packet.delivery_handlers.append((handler, handler_args))
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
            epoch=epoch,
            in_flight=False,
            is_ack_eliciting=False,
            is_crypto_packet=False,
            packet_number=self._packet_number,
            packet_type=packet_type,
        )
        self._packet_crypto = crypto
        self._packet_start = packet_start
        self._packet_type = packet_type
        self.quic_logger_frames = self._packet.quic_logger_frames

        buf.seek(self._packet_start + self._header_size)

    def _end_packet(self) -> None:
        """
        Ends the current packet.
        """
        buf = self._buffer
        packet_size = buf.tell() - self._packet_start
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
                if self.remaining_flight_space > padding_size:
                    padding_size = self.remaining_flight_space
                self._datagram_needs_padding = False

            # write padding
            if padding_size > 0:
                buf.push_bytes(bytes(padding_size))
                packet_size += padding_size
                self._packet.in_flight = True

                # log frame
                if self._quic_logger is not None:
                    self._packet.quic_logger_frames.append(
                        self._quic_logger.encode_padding_frame()
                    )

            # write header
            if self._packet_type != QuicPacketType.ONE_RTT:
                length = (
                    packet_size
                    - self._header_size
                    + PACKET_NUMBER_SEND_SIZE
                    + self._packet_crypto.aead_tag_size
                )

                buf.seek(self._packet_start)
                buf.push_uint8(
                    encode_long_header_first_byte(
                        self._version, self._packet_type, PACKET_NUMBER_SEND_SIZE - 1
                    )
                )
                buf.push_uint32(self._version)
                buf.push_uint8(len(self._peer_cid))
                buf.push_bytes(self._peer_cid)
                buf.push_uint8(len(self._host_cid))
                buf.push_bytes(self._host_cid)
                if self._packet_type == QuicPacketType.INITIAL:
                    buf.push_uint_var(len(self._peer_token))
                    buf.push_bytes(self._peer_token)
                buf.push_uint16(length | 0x4000)
                buf.push_uint16(self._packet_number & 0xFFFF)
            else:
                buf.seek(self._packet_start)
                buf.push_uint8(
                    PACKET_FIXED_BIT
                    | (self._spin_bit << 5)
                    | (self._packet_crypto.key_phase << 2)
                    | (PACKET_NUMBER_SEND_SIZE - 1)
                )
                buf.push_bytes(self._peer_cid)
                buf.push_uint16(self._packet_number & 0xFFFF)

            # encrypt in place
            plain = buf.data_slice(self._packet_start, self._packet_start + packet_size)
            buf.seek(self._packet_start)
            buf.push_bytes(
                self._packet_crypto.encrypt_packet(
                    plain[0 : self._header_size],
                    plain[self._header_size : packet_size],
                    self._packet_number,
                )
            )
            self._packet.sent_bytes = buf.tell() - self._packet_start
            self._packets.append(self._packet)
            if self._packet.in_flight:
                self._datagram_flight_bytes += self._packet.sent_bytes

            # Short header packets cannot be coalesced, we need a new datagram.
            if self._packet_type == QuicPacketType.ONE_RTT:
                self._flush_current_datagram()

            self._packet_number += 1
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
