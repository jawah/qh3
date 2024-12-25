from __future__ import annotations

import pytest
import math

from qh3 import tls
from qh3.quic.packet import QuicPacketType
from qh3.quic.packet_builder import QuicSentPacket
from qh3.quic.rangeset import RangeSet
from qh3.quic.recovery import (
    QuicPacketPacer,
    QuicPacketRecovery,
    QuicPacketSpace,
    QuicRttMonitor,
)


def send_probe():
    pass


class TestQuicPacketPacer:
    def setup_method(self):
        self.pacer = QuicPacketPacer()

    def test_no_measurement(self):
        assert self.pacer.next_send_time(now=0.0) is None
        self.pacer.update_after_send(now=0.0)

        assert self.pacer.next_send_time(now=0.0) is None
        self.pacer.update_after_send(now=0.0)

    def test_with_measurement(self):
        assert self.pacer.next_send_time(now=0.0) is None
        self.pacer.update_after_send(now=0.0)

        self.pacer.update_rate(congestion_window=1280000, smoothed_rtt=0.05)
        assert self.pacer.bucket_max == 0.0008
        assert self.pacer.bucket_time == 0.0
        assert self.pacer.packet_time == 0.00005

        # 16 packets
        for i in range(16):
            assert self.pacer.next_send_time(now=1.0) is None
            self.pacer.update_after_send(now=1.0)
        assert self.pacer.next_send_time(now=1.0) == pytest.approx(1.00005)

        # 2 packets
        for i in range(2):
            assert self.pacer.next_send_time(now=1.00005) is None
            self.pacer.update_after_send(now=1.00005)
        assert self.pacer.next_send_time(now=1.00005) == pytest.approx(1.0001)

        # 1 packet
        assert self.pacer.next_send_time(now=1.0001) is None
        self.pacer.update_after_send(now=1.0001)
        assert self.pacer.next_send_time(now=1.0001) == pytest.approx(1.00015)

        # 2 packets
        for i in range(2):
            assert self.pacer.next_send_time(now=1.00015) is None
            self.pacer.update_after_send(now=1.00015)
        assert self.pacer.next_send_time(now=1.00015) == pytest.approx(1.0002)


class TestQuicPacketRecovery:
    def setup_method(self):
        self.INITIAL_SPACE = QuicPacketSpace()
        self.HANDSHAKE_SPACE = QuicPacketSpace()
        self.ONE_RTT_SPACE = QuicPacketSpace()

        self.recovery = QuicPacketRecovery(
            initial_rtt=0.1,
            peer_completed_address_validation=True,
            send_probe=send_probe,
        )
        self.recovery.spaces = [
            self.INITIAL_SPACE,
            self.HANDSHAKE_SPACE,
            self.ONE_RTT_SPACE,
        ]

    def test_discard_space(self):
        self.recovery.discard_space(self.INITIAL_SPACE)

    def test_on_ack_received_ack_eliciting(self):
        packet = QuicSentPacket(
            epoch=tls.Epoch.ONE_RTT,
            in_flight=True,
            is_ack_eliciting=True,
            is_crypto_packet=False,
            packet_number=0,
            packet_type=QuicPacketType.ONE_RTT,
            sent_bytes=1280,
            sent_time=0.0,
        )
        space = self.ONE_RTT_SPACE

        #  packet sent
        self.recovery.on_packet_sent(packet, space)
        assert self.recovery.bytes_in_flight == 1280
        assert space.ack_eliciting_in_flight == 1
        assert len(space.sent_packets) == 1

        # packet ack'd
        self.recovery.on_ack_received(
            space, ack_rangeset=RangeSet([range(0, 1)]), ack_delay=0.0, now=10.0
        )
        assert self.recovery.bytes_in_flight == 0
        assert space.ack_eliciting_in_flight == 0
        assert len(space.sent_packets) == 0

        # check RTT
        assert self.recovery._rtt_initialized
        assert self.recovery._rtt_latest == 10.0
        assert self.recovery._rtt_min == 10.0
        assert self.recovery._rtt_smoothed == 10.0

    def test_on_ack_received_non_ack_eliciting(self):
        packet = QuicSentPacket(
            epoch=tls.Epoch.ONE_RTT,
            in_flight=True,
            is_ack_eliciting=False,
            is_crypto_packet=False,
            packet_number=0,
            packet_type=QuicPacketType.ONE_RTT,
            sent_bytes=1280,
            sent_time=123.45,
        )
        space = self.ONE_RTT_SPACE

        #  packet sent
        self.recovery.on_packet_sent(packet, space)
        assert self.recovery.bytes_in_flight == 1280
        assert space.ack_eliciting_in_flight == 0
        assert len(space.sent_packets) == 1

        # packet ack'd
        self.recovery.on_ack_received(
            space, ack_rangeset=RangeSet([range(0, 1)]), ack_delay=0.0, now=10.0
        )
        assert self.recovery.bytes_in_flight == 0
        assert space.ack_eliciting_in_flight == 0
        assert len(space.sent_packets) == 0

        # check RTT
        assert not self.recovery._rtt_initialized
        assert self.recovery._rtt_latest == 0.0
        assert self.recovery._rtt_min == math.inf
        assert self.recovery._rtt_smoothed == 0.0

    def test_on_packet_lost_crypto(self):
        packet = QuicSentPacket(
            epoch=tls.Epoch.INITIAL,
            in_flight=True,
            is_ack_eliciting=True,
            is_crypto_packet=True,
            packet_number=0,
            packet_type=QuicPacketType.INITIAL,
            sent_bytes=1280,
            sent_time=0.0,
        )
        space = self.INITIAL_SPACE

        self.recovery.on_packet_sent(packet, space)
        assert self.recovery.bytes_in_flight == 1280
        assert space.ack_eliciting_in_flight == 1
        assert len(space.sent_packets) == 1

        self.recovery._detect_loss(space, now=1.0)
        assert self.recovery.bytes_in_flight == 0
        assert space.ack_eliciting_in_flight == 0
        assert len(space.sent_packets) == 0


class TestQuicRttMonitor:
    def test_monitor(self):
        monitor = QuicRttMonitor()

        assert not monitor.is_rtt_increasing(rtt=10, now=1000)
        assert monitor._samples == [10, 0.0, 0.0, 0.0, 0.0]
        assert not monitor._ready

        # not taken into account
        assert not monitor.is_rtt_increasing(rtt=11, now=1000)
        assert monitor._samples == [10, 0.0, 0.0, 0.0, 0.0]
        assert not monitor._ready

        assert not monitor.is_rtt_increasing(rtt=11, now=1001)
        assert monitor._samples == [10, 11, 0.0, 0.0, 0.0]
        assert not monitor._ready

        assert not monitor.is_rtt_increasing(rtt=12, now=1002)
        assert monitor._samples == [10, 11, 12, 0.0, 0.0]
        assert not monitor._ready

        assert not monitor.is_rtt_increasing(rtt=13, now=1003)
        assert monitor._samples == [10, 11, 12, 13, 0.0]
        assert not monitor._ready

        # we now have enough samples
        assert not monitor.is_rtt_increasing(rtt=14, now=1004)
        assert monitor._samples == [10, 11, 12, 13, 14]
        assert monitor._ready

        assert not monitor.is_rtt_increasing(rtt=20, now=1005)
        assert monitor._increases == 0

        assert not monitor.is_rtt_increasing(rtt=30, now=1006)
        assert monitor._increases == 0

        assert not monitor.is_rtt_increasing(rtt=40, now=1007)
        assert monitor._increases == 0

        assert not monitor.is_rtt_increasing(rtt=50, now=1008)
        assert monitor._increases == 0

        assert not monitor.is_rtt_increasing(rtt=60, now=1009)
        assert monitor._increases == 1

        assert not monitor.is_rtt_increasing(rtt=70, now=1010)
        assert monitor._increases == 2

        assert not monitor.is_rtt_increasing(rtt=80, now=1011)
        assert monitor._increases == 3

        assert not monitor.is_rtt_increasing(rtt=90, now=1012)
        assert monitor._increases == 4

        assert monitor.is_rtt_increasing(rtt=100, now=1013)
        assert monitor._increases == 5
