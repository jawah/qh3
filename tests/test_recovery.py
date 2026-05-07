from __future__ import annotations

import pytest
import math

from qh3 import tls
from qh3.quic.packet import QuicPacketType
from qh3.quic.packet_builder import QuicSentPacket
from qh3._hazmat import RangeSet, QuicPacketPacer, QuicRttMonitor
from qh3.quic.packet_builder import QuicDeliveryState
from qh3.quic.recovery import (
    K_MINIMUM_WINDOW,
    QuicCongestionControl,
    QuicPacketRecovery,
    QuicPacketSpace,
)


def send_probe():
    pass


class TestQuicPacketPacer:
    def setup_method(self):
        self.pacer = QuicPacketPacer(max_datagram_size=1280)

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
            max_datagram_size=1280,
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
        rs = RangeSet()
        rs.add(0, 1)
        self.recovery.on_ack_received(
            space, ack_rangeset=rs, ack_delay=0.0, now=10.0
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
        rs = RangeSet()
        rs.add(0, 1)
        self.recovery.on_ack_received(
            space, ack_rangeset=rs, ack_delay=0.0, now=10.0
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

    def test_reschedule_data_app_uses_rescheduled_path(self):
        # Application-data packet in flight; PTO triggers reschedule
        # (RFC 9002 6.2.4). Bytes must be reclaimed and the LOST handler
        # fired, but cwnd MUST NOT shrink and _pto_count MUST NOT reset.
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
        observed = []

        def _handler(state):
            observed.append(state)

        packet.delivery_handlers = [(_handler, ())]
        self.recovery.on_packet_sent(packet, self.ONE_RTT_SPACE)

        cwnd_before = self.recovery._cc.congestion_window
        self.recovery._pto_count = 2

        self.recovery.reschedule_data(now=5.0)

        assert observed == [QuicDeliveryState.LOST]
        assert self.recovery.bytes_in_flight == 0
        assert self.recovery._cc.congestion_window == cwnd_before
        assert self.recovery._pto_count == 2
        assert len(self.ONE_RTT_SPACE.sent_packets) == 0

    def test_on_ack_received_initial_does_not_reset_pto_count(self):
        # RFC 9002 6.2.1: a client MUST NOT reset its PTO backoff on
        # ACKs that only acknowledge Initial packets.
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
        self.recovery.on_packet_sent(packet, self.INITIAL_SPACE)
        self.recovery._pto_count = 3

        rs = RangeSet()
        rs.add(0, 1)
        self.recovery.on_ack_received(
            self.INITIAL_SPACE,
            ack_rangeset=rs,
            ack_delay=0.0,
            now=10.0,
            reset_pto_count=False,
        )
        assert self.recovery._pto_count == 3

        # control: default behaviour does reset
        packet2 = QuicSentPacket(
            epoch=tls.Epoch.ONE_RTT,
            in_flight=True,
            is_ack_eliciting=True,
            is_crypto_packet=False,
            packet_number=0,
            packet_type=QuicPacketType.ONE_RTT,
            sent_bytes=1280,
            sent_time=10.0,
        )
        self.recovery.on_packet_sent(packet2, self.ONE_RTT_SPACE)
        rs2 = RangeSet()
        rs2.add(0, 1)
        self.recovery.on_ack_received(
            self.ONE_RTT_SPACE, ack_rangeset=rs2, ack_delay=0.0, now=11.0
        )
        assert self.recovery._pto_count == 0

    def test_persistent_congestion_detected(self):
        # RFC 9002 7.6: if at least two ack-eliciting packets are
        # declared lost over a span longer than the persistent
        # congestion threshold, cwnd collapses to MIN.
        # Prime an RTT estimate so _rtt_initialized is True.
        prime = QuicSentPacket(
            epoch=tls.Epoch.ONE_RTT,
            in_flight=True,
            is_ack_eliciting=True,
            is_crypto_packet=False,
            packet_number=0,
            packet_type=QuicPacketType.ONE_RTT,
            sent_bytes=1280,
            sent_time=0.0,
        )
        self.recovery.on_packet_sent(prime, self.ONE_RTT_SPACE)
        rs = RangeSet()
        rs.add(0, 1)
        self.recovery.on_ack_received(
            self.ONE_RTT_SPACE, ack_rangeset=rs, ack_delay=0.0, now=0.05
        )
        assert self.recovery._rtt_initialized

        # send three ack-eliciting packets spread far apart in time
        for i, t in enumerate([1.0, 6.0, 11.0], start=1):
            self.recovery.on_packet_sent(
                QuicSentPacket(
                    epoch=tls.Epoch.ONE_RTT,
                    in_flight=True,
                    is_ack_eliciting=True,
                    is_crypto_packet=False,
                    packet_number=i,
                    packet_type=QuicPacketType.ONE_RTT,
                    sent_bytes=1280,
                    sent_time=t,
                ),
                self.ONE_RTT_SPACE,
            )

        cwnd_before = self.recovery._cc.congestion_window
        assert cwnd_before > 1280 * K_MINIMUM_WINDOW

        # ACK only the newest, forcing the older two into the lost set
        # via packet-threshold detection.
        ack = RangeSet()
        ack.add(3, 4)
        self.recovery.on_ack_received(
            self.ONE_RTT_SPACE, ack_rangeset=ack, ack_delay=0.0, now=11.05
        )

        # Persistent congestion collapsed cwnd to MIN.
        assert self.recovery._cc.congestion_window == 1280 * K_MINIMUM_WINDOW
        assert self.recovery._cc.ssthresh is None


    def test_reset_for_new_path_clears_rtt_state(self):
        """RFC 9000 9.4 / RFC 9002 5.1: path migration MUST clear RTT
        samples from the prior path; in particular min_rtt would
        otherwise pin loss_delay too low on a higher-latency path."""
        # Seed loss recovery with samples from "old path".
        self.recovery._rtt_initialized = True
        self.recovery._rtt_latest = 0.050
        self.recovery._rtt_latest_raw = 0.050
        self.recovery._rtt_min = 0.040
        self.recovery._rtt_smoothed = 0.045
        self.recovery._rtt_variance = 0.005

        self.recovery.reset_for_new_path()

        assert self.recovery._rtt_initialized is False
        assert self.recovery._rtt_latest == 0.0
        assert self.recovery._rtt_latest_raw == 0.0
        assert self.recovery._rtt_min == math.inf
        assert self.recovery._rtt_smoothed == 0.0
        assert self.recovery._rtt_variance == 0.0

    def test_on_persistent_congestion_collapses_state(self):
        cc = QuicCongestionControl(max_datagram_size=1280)

        # set non-trivial state
        cc.congestion_window = 100_000
        cc.ssthresh = 80_000
        cc._first_slow_start = False
        cc._starting_congestion_avoidance = True
        cc._K = 2.5
        cc._W_max = 120_000
        cc._W_est = 99_000
        cc._cwnd_epoch = 42
        cc._t_epoch = 10.0
        cc._congestion_recovery_start_time = 1.0

        cc.on_persistent_congestion(now=123.0)

        assert cc._congestion_recovery_start_time == 123.0
        assert cc.congestion_window == 1280 * K_MINIMUM_WINDOW
        assert cc.ssthresh is None
        assert cc._first_slow_start is True
        assert cc._starting_congestion_avoidance is False
        assert cc._K == 0.0
        assert cc._W_max == cc.congestion_window
        assert cc._W_est == 0
        assert cc._cwnd_epoch == 0
        assert cc._t_epoch == 0.0

    def test_post_collapse_loss_does_not_pin_ssthresh(self):
        # Regression guard: previously _congestion_recovery_start_time
        # was reset to 0.0, so the very next loss after collapse passed
        # the recovery-period guard in on_packets_lost and pinned
        # ssthresh = MINIMUM_WINDOW, terminating slow-start permanently.
        cc = QuicCongestionControl(max_datagram_size=1280)
        cc.on_persistent_congestion(now=100.0)
        assert cc.ssthresh is None

        # A packet sent BEFORE the collapse and declared lost AFTER
        # must not start a fresh congestion event.
        old = QuicSentPacket(
            epoch=tls.Epoch.ONE_RTT,
            in_flight=True,
            is_ack_eliciting=True,
            is_crypto_packet=False,
            packet_number=0,
            packet_type=QuicPacketType.ONE_RTT,
            sent_bytes=1280,
            sent_time=50.0,
        )
        cc.on_packet_sent(old)
        cc.on_packets_lost([old], now=101.0)
        assert cc.ssthresh is None  # slow-start still alive


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
