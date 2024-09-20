from __future__ import annotations

from unittest import TestCase

from qh3.quic.crypto import CryptoPair
from qh3.quic.packet import QuicFrameType, QuicPacketType, QuicProtocolVersion
from qh3.quic.packet_builder import (
    QuicPacketBuilder,
    QuicPacketBuilderStop,
    QuicSentPacket,
)
from qh3.tls import Epoch


def datagram_sizes(datagrams: list[bytes]) -> list[int]:
    return [len(x) for x in datagrams]


def create_builder(is_client=False):
    return QuicPacketBuilder(
        host_cid=bytes(8),
        is_client=is_client,
        packet_number=0,
        peer_cid=bytes(8),
        peer_token=b"",
        spin_bit=False,
        version=QuicProtocolVersion.VERSION_1,
    )


def create_crypto():
    crypto = CryptoPair()
    crypto.setup_initial(
        bytes(8), is_client=True, version=QuicProtocolVersion.VERSION_1
    )
    return crypto


class QuicPacketBuilderTest(TestCase):
    def test_long_header_empty(self):
        builder = create_builder()
        crypto = create_crypto()

        builder.start_packet(QuicPacketType.INITIAL, crypto)
        self.assertEqual(builder.remaining_flight_space, 1236)
        self.assertTrue(builder.packet_is_empty)

        # check datagrams
        datagrams, packets = builder.flush()
        self.assertEqual(len(datagrams), 0)
        self.assertEqual(packets, [])

        # check builder
        self.assertEqual(builder.packet_number, 0)

    def test_long_header_padding(self):
        builder = create_builder(is_client=True)
        crypto = create_crypto()

        # INITIAL, fully padded
        builder.start_packet(QuicPacketType.INITIAL, crypto)
        self.assertEqual(builder.remaining_flight_space, 1236)
        buf = builder.start_frame(QuicFrameType.CRYPTO)
        buf.push_bytes(bytes(100))
        self.assertFalse(builder.packet_is_empty)

        # INITIAL, empty
        builder.start_packet(QuicPacketType.INITIAL, crypto)
        self.assertTrue(builder.packet_is_empty)

        # check datagrams
        datagrams, packets = builder.flush()
        self.assertEqual(len(datagrams), 1)
        self.assertEqual(len(datagrams[0]), 1280)
        self.assertEqual(
            packets,
            [
                QuicSentPacket(
                    epoch=Epoch.INITIAL,
                    in_flight=True,
                    is_ack_eliciting=True,
                    is_crypto_packet=True,
                    packet_number=0,
                    packet_type=QuicPacketType.INITIAL,
                    sent_bytes=145,
                )
            ],
        )

        # check builder
        self.assertEqual(builder.packet_number, 1)

    def test_long_header_initial_client_2(self):
        self.maxDiff = None
        builder = create_builder(is_client=True)
        crypto = create_crypto()

        # INITIAL, full length
        builder.start_packet(QuicPacketType.INITIAL, crypto)
        self.assertEqual(builder.remaining_flight_space, 1236)
        buf = builder.start_frame(QuicFrameType.CRYPTO)
        buf.push_bytes(bytes(builder.remaining_flight_space))
        self.assertFalse(builder.packet_is_empty)

        # INITIAL
        builder.start_packet(QuicPacketType.INITIAL, crypto)
        self.assertEqual(builder.remaining_flight_space, 1236)
        buf = builder.start_frame(QuicFrameType.CRYPTO)
        buf.push_bytes(bytes(100))
        self.assertFalse(builder.packet_is_empty)

        # INITIAL, empty
        builder.start_packet(QuicPacketType.INITIAL, crypto)
        self.assertTrue(builder.packet_is_empty)

        # check datagrams
        datagrams, packets = builder.flush()
        self.assertEqual(len(datagrams), 2)
        self.assertEqual(len(datagrams[0]), 1280)
        self.assertEqual(len(datagrams[1]), 1280)
        self.assertEqual(
            packets,
            [
                QuicSentPacket(
                    epoch=Epoch.INITIAL,
                    in_flight=True,
                    is_ack_eliciting=True,
                    is_crypto_packet=True,
                    packet_number=0,
                    packet_type=QuicPacketType.INITIAL,
                    sent_bytes=1280,
                ),
                QuicSentPacket(
                    epoch=Epoch.INITIAL,
                    in_flight=True,
                    is_ack_eliciting=True,
                    is_crypto_packet=True,
                    packet_number=1,
                    packet_type=QuicPacketType.INITIAL,
                    sent_bytes=145,
                ),
            ],
        )

        # check builder
        self.assertEqual(builder.packet_number, 2)

    def test_long_header_initial_server(self):
        builder = create_builder()
        crypto = create_crypto()

        # INITIAL
        builder.start_packet(QuicPacketType.INITIAL, crypto)
        self.assertEqual(builder.remaining_flight_space, 1236)
        buf = builder.start_frame(QuicFrameType.CRYPTO)
        buf.push_bytes(bytes(100))
        self.assertFalse(builder.packet_is_empty)

        # INITIAL, empty
        builder.start_packet(QuicPacketType.INITIAL, crypto)
        self.assertTrue(builder.packet_is_empty)

        # check datagrams
        datagrams, packets = builder.flush()
        self.assertEqual(len(datagrams), 1)
        self.assertEqual(len(datagrams[0]), 1280)
        self.assertEqual(
            packets,
            [
                QuicSentPacket(
                    epoch=Epoch.INITIAL,
                    in_flight=True,
                    is_ack_eliciting=True,
                    is_crypto_packet=True,
                    packet_number=0,
                    packet_type=QuicPacketType.INITIAL,
                    sent_bytes=145,
                )
            ],
        )

        # check builder
        self.assertEqual(builder.packet_number, 1)

    def test_long_header_ping_only(self):
        """
        The payload is too short to provide enough data for header protection,
        so padding needs to be applied.
        """
        builder = create_builder()
        crypto = create_crypto()

        # HANDSHAKE, with only a PING frame
        builder.start_packet(QuicPacketType.HANDSHAKE, crypto)
        builder.start_frame(QuicFrameType.PING)
        self.assertFalse(builder.packet_is_empty)

        # check datagrams
        datagrams, packets = builder.flush()
        self.assertEqual(len(datagrams), 1)
        self.assertEqual(len(datagrams[0]), 45)
        self.assertEqual(
            packets,
            [
                QuicSentPacket(
                    epoch=Epoch.HANDSHAKE,
                    in_flight=True,
                    is_ack_eliciting=True,
                    is_crypto_packet=False,
                    packet_number=0,
                    packet_type=QuicPacketType.HANDSHAKE,
                    sent_bytes=45,
                )
            ],
        )

    def test_long_header_then_short_header(self):
        builder = create_builder()
        crypto = create_crypto()

        # INITIAL, full length
        builder.start_packet(QuicPacketType.INITIAL, crypto)
        self.assertEqual(builder.remaining_flight_space, 1236)
        buf = builder.start_frame(QuicFrameType.CRYPTO)
        buf.push_bytes(bytes(builder.remaining_flight_space))
        self.assertFalse(builder.packet_is_empty)

        # INITIAL, empty
        builder.start_packet(QuicPacketType.INITIAL, crypto)
        self.assertTrue(builder.packet_is_empty)

        # ONE_RTT, full length
        builder.start_packet(QuicPacketType.ONE_RTT, crypto)
        self.assertEqual(builder.remaining_flight_space, 1253)
        buf = builder.start_frame(QuicFrameType.STREAM_BASE)
        buf.push_bytes(bytes(builder.remaining_flight_space))
        self.assertFalse(builder.packet_is_empty)

        # ONE_RTT, empty
        builder.start_packet(QuicPacketType.ONE_RTT, crypto)
        self.assertTrue(builder.packet_is_empty)

        # check datagrams
        datagrams, packets = builder.flush()
        self.assertEqual(len(datagrams), 2)
        self.assertEqual(len(datagrams[0]), 1280)
        self.assertEqual(len(datagrams[1]), 1280)
        self.assertEqual(
            packets,
            [
                QuicSentPacket(
                    epoch=Epoch.INITIAL,
                    in_flight=True,
                    is_ack_eliciting=True,
                    is_crypto_packet=True,
                    packet_number=0,
                    packet_type=QuicPacketType.INITIAL,
                    sent_bytes=1280,
                ),
                QuicSentPacket(
                    epoch=Epoch.ONE_RTT,
                    in_flight=True,
                    is_ack_eliciting=True,
                    is_crypto_packet=False,
                    packet_number=1,
                    packet_type=QuicPacketType.ONE_RTT,
                    sent_bytes=1280,
                ),
            ],
        )

        # check builder
        self.assertEqual(builder.packet_number, 2)

    def test_long_header_initial_client_zero_rtt(self):
        builder = create_builder(is_client=True)
        crypto = create_crypto()

        # INITIAL
        builder.start_packet(QuicPacketType.INITIAL, crypto)
        self.assertEqual(builder.remaining_flight_space, 1236)
        buf = builder.start_frame(QuicFrameType.CRYPTO)
        buf.push_bytes(bytes(613))
        self.assertFalse(builder.packet_is_empty)

        # 0-RTT
        builder.start_packet(QuicPacketType.ZERO_RTT, crypto)
        self.assertEqual(builder.remaining_flight_space, 579)
        buf = builder.start_frame(QuicFrameType.STREAM_BASE)
        buf.push_bytes(bytes(100))
        self.assertFalse(builder.packet_is_empty)

        # check datagrams
        datagrams, packets = builder.flush()
        self.assertEqual(datagram_sizes(datagrams), [1280])
        self.assertEqual(
            packets,
            [
                QuicSentPacket(
                    epoch=Epoch.INITIAL,
                    in_flight=True,
                    is_ack_eliciting=True,
                    is_crypto_packet=True,
                    packet_number=0,
                    packet_type=QuicPacketType.INITIAL,
                    sent_bytes=658,
                ),
                QuicSentPacket(
                    epoch=Epoch.ONE_RTT,
                    in_flight=True,
                    is_ack_eliciting=True,
                    is_crypto_packet=False,
                    packet_number=1,
                    packet_type=QuicPacketType.ZERO_RTT,
                    sent_bytes=144,
                ),
            ],
        )

    def test_long_header_then_long_header(self):
        builder = create_builder()
        crypto = create_crypto()

        # INITIAL
        builder.start_packet(QuicPacketType.INITIAL, crypto)
        self.assertEqual(builder.remaining_flight_space, 1236)
        buf = builder.start_frame(QuicFrameType.CRYPTO)
        buf.push_bytes(bytes(199))
        self.assertFalse(builder.packet_is_empty)

        # HANDSHAKE
        builder.start_packet(QuicPacketType.HANDSHAKE, crypto)
        self.assertEqual(builder.remaining_flight_space, 993)
        buf = builder.start_frame(QuicFrameType.CRYPTO)
        buf.push_bytes(bytes(299))
        self.assertFalse(builder.packet_is_empty)

        # ONE_RTT
        builder.start_packet(QuicPacketType.ONE_RTT, crypto)
        self.assertEqual(builder.remaining_flight_space, 666)
        buf = builder.start_frame(QuicFrameType.CRYPTO)
        buf.push_bytes(bytes(299))
        self.assertFalse(builder.packet_is_empty)

        # check datagrams
        datagrams, packets = builder.flush()
        self.assertEqual(len(datagrams), 1)
        self.assertEqual(len(datagrams[0]), 1280)
        self.assertEqual(
            packets,
            [
                QuicSentPacket(
                    epoch=Epoch.INITIAL,
                    in_flight=True,
                    is_ack_eliciting=True,
                    is_crypto_packet=True,
                    packet_number=0,
                    packet_type=QuicPacketType.INITIAL,
                    sent_bytes=244,
                ),
                QuicSentPacket(
                    epoch=Epoch.HANDSHAKE,
                    in_flight=True,
                    is_ack_eliciting=True,
                    is_crypto_packet=True,
                    packet_number=1,
                    packet_type=QuicPacketType.HANDSHAKE,
                    sent_bytes=343,
                ),
                QuicSentPacket(
                    epoch=Epoch.ONE_RTT,
                    in_flight=True,
                    is_ack_eliciting=True,
                    is_crypto_packet=True,
                    packet_number=2,
                    packet_type=QuicPacketType.ONE_RTT,
                    sent_bytes=693,
                ),
            ],
        )

        # check builder
        self.assertEqual(builder.packet_number, 3)

    def test_short_header_empty(self):
        builder = create_builder()
        crypto = create_crypto()

        builder.start_packet(QuicPacketType.ONE_RTT, crypto)
        self.assertEqual(builder.remaining_flight_space, 1253)
        self.assertTrue(builder.packet_is_empty)

        # check datagrams
        datagrams, packets = builder.flush()
        self.assertEqual(datagrams, [])
        self.assertEqual(packets, [])

        # check builder
        self.assertEqual(builder.packet_number, 0)

    def test_short_header_padding(self):
        builder = create_builder()
        crypto = create_crypto()

        # ONE_RTT, full length
        builder.start_packet(QuicPacketType.ONE_RTT, crypto)
        self.assertEqual(builder.remaining_flight_space, 1253)
        buf = builder.start_frame(QuicFrameType.CRYPTO)
        buf.push_bytes(bytes(builder.remaining_flight_space))
        self.assertFalse(builder.packet_is_empty)

        # check datagrams
        datagrams, packets = builder.flush()
        self.assertEqual(len(datagrams), 1)
        self.assertEqual(len(datagrams[0]), 1280)
        self.assertEqual(
            packets,
            [
                QuicSentPacket(
                    epoch=Epoch.ONE_RTT,
                    in_flight=True,
                    is_ack_eliciting=True,
                    is_crypto_packet=True,
                    packet_number=0,
                    packet_type=QuicPacketType.ONE_RTT,
                    sent_bytes=1280,
                )
            ],
        )

        # check builder
        self.assertEqual(builder.packet_number, 1)

    def test_short_header_max_flight_bytes(self):
        """
        max_flight_bytes limits sent data.
        """
        builder = create_builder()
        builder.max_flight_bytes = 1000

        crypto = create_crypto()

        builder.start_packet(QuicPacketType.ONE_RTT, crypto)
        self.assertEqual(builder.remaining_flight_space, 973)
        buf = builder.start_frame(QuicFrameType.CRYPTO)
        buf.push_bytes(bytes(builder.remaining_flight_space))
        self.assertFalse(builder.packet_is_empty)

        with self.assertRaises(QuicPacketBuilderStop):
            builder.start_packet(QuicPacketType.ONE_RTT, crypto)
            builder.start_frame(QuicFrameType.CRYPTO)

        # check datagrams
        datagrams, packets = builder.flush()
        self.assertEqual(len(datagrams), 1)
        self.assertEqual(len(datagrams[0]), 1000)
        self.assertEqual(
            packets,
            [
                QuicSentPacket(
                    epoch=Epoch.ONE_RTT,
                    in_flight=True,
                    is_ack_eliciting=True,
                    is_crypto_packet=True,
                    packet_number=0,
                    packet_type=QuicPacketType.ONE_RTT,
                    sent_bytes=1000,
                ),
            ],
        )

        # check builder
        self.assertEqual(builder.packet_number, 1)

    def test_short_header_max_flight_bytes_zero(self):
        """
        max_flight_bytes = 0 only allows ACKs and CONNECTION_CLOSE.

        Check CRYPTO is not allowed.
        """
        builder = create_builder()
        builder.max_flight_bytes = 0

        crypto = create_crypto()

        with self.assertRaises(QuicPacketBuilderStop):
            builder.start_packet(QuicPacketType.ONE_RTT, crypto)
            builder.start_frame(QuicFrameType.CRYPTO)

        # check datagrams
        datagrams, packets = builder.flush()
        self.assertEqual(len(datagrams), 0)

        # check builder
        self.assertEqual(builder.packet_number, 0)

    def test_short_header_max_flight_bytes_zero_ack(self):
        """
        max_flight_bytes = 0 only allows ACKs and CONNECTION_CLOSE.

        Check ACK is allowed.
        """
        builder = create_builder()
        builder.max_flight_bytes = 0

        crypto = create_crypto()

        builder.start_packet(QuicPacketType.ONE_RTT, crypto)
        buf = builder.start_frame(QuicFrameType.ACK)
        buf.push_bytes(bytes(64))

        with self.assertRaises(QuicPacketBuilderStop):
            builder.start_packet(QuicPacketType.ONE_RTT, crypto)
            builder.start_frame(QuicFrameType.CRYPTO)

        # check datagrams
        datagrams, packets = builder.flush()
        self.assertEqual(len(datagrams), 1)
        self.assertEqual(len(datagrams[0]), 92)
        self.assertEqual(
            packets,
            [
                QuicSentPacket(
                    epoch=Epoch.ONE_RTT,
                    in_flight=False,
                    is_ack_eliciting=False,
                    is_crypto_packet=False,
                    packet_number=0,
                    packet_type=QuicPacketType.ONE_RTT,
                    sent_bytes=92,
                ),
            ],
        )

        # check builder
        self.assertEqual(builder.packet_number, 1)

    def test_short_header_max_total_bytes_1(self):
        """
        max_total_bytes doesn't allow any packets.
        """
        builder = create_builder()
        builder.max_total_bytes = 11

        crypto = create_crypto()

        with self.assertRaises(QuicPacketBuilderStop):
            builder.start_packet(QuicPacketType.ONE_RTT, crypto)

        # check datagrams
        datagrams, packets = builder.flush()
        self.assertEqual(datagrams, [])
        self.assertEqual(packets, [])

        # check builder
        self.assertEqual(builder.packet_number, 0)

    def test_short_header_max_total_bytes_2(self):
        """
        max_total_bytes allows a short packet.
        """
        builder = create_builder()
        builder.max_total_bytes = 800

        crypto = create_crypto()

        builder.start_packet(QuicPacketType.ONE_RTT, crypto)
        self.assertEqual(builder.remaining_flight_space, 773)
        buf = builder.start_frame(QuicFrameType.CRYPTO)
        buf.push_bytes(bytes(builder.remaining_flight_space))
        self.assertFalse(builder.packet_is_empty)

        with self.assertRaises(QuicPacketBuilderStop):
            builder.start_packet(QuicPacketType.ONE_RTT, crypto)

        # check datagrams
        datagrams, packets = builder.flush()
        self.assertEqual(len(datagrams), 1)
        self.assertEqual(len(datagrams[0]), 800)
        self.assertEqual(
            packets,
            [
                QuicSentPacket(
                    epoch=Epoch.ONE_RTT,
                    in_flight=True,
                    is_ack_eliciting=True,
                    is_crypto_packet=True,
                    packet_number=0,
                    packet_type=QuicPacketType.ONE_RTT,
                    sent_bytes=800,
                )
            ],
        )

        # check builder
        self.assertEqual(builder.packet_number, 1)

    def test_short_header_max_total_bytes_3(self):
        builder = create_builder()
        builder.max_total_bytes = 2000

        crypto = create_crypto()

        builder.start_packet(QuicPacketType.ONE_RTT, crypto)
        self.assertEqual(builder.remaining_flight_space, 1253)
        buf = builder.start_frame(QuicFrameType.CRYPTO)
        buf.push_bytes(bytes(builder.remaining_flight_space))
        self.assertFalse(builder.packet_is_empty)

        builder.start_packet(QuicPacketType.ONE_RTT, crypto)
        self.assertEqual(builder.remaining_flight_space, 693)
        buf = builder.start_frame(QuicFrameType.CRYPTO)
        buf.push_bytes(bytes(builder.remaining_flight_space))
        self.assertFalse(builder.packet_is_empty)

        with self.assertRaises(QuicPacketBuilderStop):
            builder.start_packet(QuicPacketType.ONE_RTT, crypto)

        # check datagrams
        datagrams, packets = builder.flush()
        self.assertEqual(len(datagrams), 2)
        self.assertEqual(len(datagrams[0]), 1280)
        self.assertEqual(len(datagrams[1]), 720)
        self.assertEqual(
            packets,
            [
                QuicSentPacket(
                    epoch=Epoch.ONE_RTT,
                    in_flight=True,
                    is_ack_eliciting=True,
                    is_crypto_packet=True,
                    packet_number=0,
                    packet_type=QuicPacketType.ONE_RTT,
                    sent_bytes=1280,
                ),
                QuicSentPacket(
                    epoch=Epoch.ONE_RTT,
                    in_flight=True,
                    is_ack_eliciting=True,
                    is_crypto_packet=True,
                    packet_number=1,
                    packet_type=QuicPacketType.ONE_RTT,
                    sent_bytes=720,
                ),
            ],
        )

        # check builder
        self.assertEqual(builder.packet_number, 2)

    def test_short_header_ping_only(self):
        """
        The payload is too short to provide enough data for header protection,
        so padding needs to be applied.
        """
        builder = create_builder()
        crypto = create_crypto()

        # HANDSHAKE, with only a PING frame
        builder.start_packet(QuicPacketType.ONE_RTT, crypto)
        builder.start_frame(QuicFrameType.PING)
        self.assertFalse(builder.packet_is_empty)

        # check datagrams
        datagrams, packets = builder.flush()
        self.assertEqual(len(datagrams), 1)
        self.assertEqual(len(datagrams[0]), 29)
        self.assertEqual(
            packets,
            [
                QuicSentPacket(
                    epoch=Epoch.ONE_RTT,
                    in_flight=True,
                    is_ack_eliciting=True,
                    is_crypto_packet=False,
                    packet_number=0,
                    packet_type=QuicPacketType.ONE_RTT,
                    sent_bytes=29,
                )
            ],
        )
