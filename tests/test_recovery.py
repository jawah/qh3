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
    K_HYSTART_CSS_ROUNDS,
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


class TestPmtuProbeLossDetection:
    """RFC 9000 14.4: PMTU probe loss MUST NOT trigger CC reaction."""

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

    def _probe_packet(self, pn: int, sent_time: float, size: int = 1452):
        pkt = QuicSentPacket(
            epoch=tls.Epoch.ONE_RTT,
            in_flight=True,
            is_ack_eliciting=True,
            is_crypto_packet=False,
            packet_number=pn,
            packet_type=QuicPacketType.ONE_RTT,
            sent_bytes=size,
            sent_time=sent_time,
            is_pmtu_probe=True,
        )
        return pkt

    def test_pmtu_probe_loss_does_not_reduce_cwnd(self):
        cc = self.recovery._cc
        baseline_cwnd = cc.congestion_window
        assert cc.ssthresh is None  # slow-start

        probe = self._probe_packet(pn=0, sent_time=0.0)
        self.recovery.on_packet_sent(probe, self.ONE_RTT_SPACE)
        assert cc.bytes_in_flight == 1452

        # Probe declared lost, must NOT trigger congestion reaction.
        self.recovery._on_packets_lost(
            [probe], space=self.ONE_RTT_SPACE, now=1.0
        )
        assert cc.bytes_in_flight == 0  # bytes reclaimed
        assert cc.congestion_window == baseline_cwnd  # cwnd unchanged
        assert cc.ssthresh is None  # slow-start preserved
        assert self.ONE_RTT_SPACE.ack_eliciting_in_flight == 0
        assert 0 not in self.ONE_RTT_SPACE.sent_packets

    def test_pmtu_probe_loss_fires_delivery_handler(self):
        captured: list[QuicDeliveryState] = []

        def handler(state: QuicDeliveryState, *args) -> None:
            captured.append(state)

        probe = self._probe_packet(pn=0, sent_time=0.0)
        probe.delivery_handlers = [(handler, ())]
        self.recovery.on_packet_sent(probe, self.ONE_RTT_SPACE)

        self.recovery._on_packets_lost(
            [probe], space=self.ONE_RTT_SPACE, now=1.0
        )
        assert captured == [QuicDeliveryState.LOST]

    def test_pmtu_probe_excluded_from_persistent_congestion(self):
        # Two PMTU probes lost over a long span MUST NOT trigger
        # persistent-congestion collapse.
        cc = self.recovery._cc
        # Establish RTT sample so persistent-congestion eligibility is met.
        normal = QuicSentPacket(
            epoch=tls.Epoch.ONE_RTT,
            in_flight=True,
            is_ack_eliciting=True,
            is_crypto_packet=False,
            packet_number=100,
            packet_type=QuicPacketType.ONE_RTT,
            sent_bytes=1280,
            sent_time=0.0,
        )
        self.recovery.on_packet_sent(normal, self.ONE_RTT_SPACE)
        rs = RangeSet()
        rs.add(100, 101)
        self.recovery.on_ack_received(
            self.ONE_RTT_SPACE, ack_rangeset=rs, ack_delay=0.0, now=0.05
        )
        baseline_cwnd = cc.congestion_window
        assert self.recovery._rtt_initialized

        p1 = self._probe_packet(pn=200, sent_time=10.0)
        p2 = self._probe_packet(pn=201, sent_time=20.0)
        self.recovery.on_packet_sent(p1, self.ONE_RTT_SPACE)
        self.recovery.on_packet_sent(p2, self.ONE_RTT_SPACE)

        self.recovery._on_packets_lost(
            [p1, p2], space=self.ONE_RTT_SPACE, now=21.0
        )
        # No collapse, no halving, slow-start preserved, cwnd unchanged.
        assert cc.ssthresh is None
        assert cc.congestion_window == baseline_cwnd
        assert cc.bytes_in_flight == 0

    def test_non_probe_loss_still_reduces_cwnd(self):
        # Sanity: regular ack-eliciting in-flight loss DOES reduce cwnd.
        cc = self.recovery._cc
        baseline_cwnd = cc.congestion_window

        regular = QuicSentPacket(
            epoch=tls.Epoch.ONE_RTT,
            in_flight=True,
            is_ack_eliciting=True,
            is_crypto_packet=False,
            packet_number=0,
            packet_type=QuicPacketType.ONE_RTT,
            sent_bytes=1280,
            sent_time=10.0,
        )
        self.recovery.on_packet_sent(regular, self.ONE_RTT_SPACE)
        self.recovery._on_packets_lost(
            [regular], space=self.ONE_RTT_SPACE, now=11.0
        )
        assert cc.congestion_window < baseline_cwnd
        assert cc.ssthresh is not None

    def test_pmtu_probe_does_not_arm_pto(self):
        # RFC 9000 14.4: a PMTU probe MUST NOT anchor
        # the standard loss-detection / PTO timer.
        probe = self._probe_packet(pn=0, sent_time=0.0)
        self.recovery.on_packet_sent(probe, self.ONE_RTT_SPACE)

        # Only a PMTU probe is in flight: ack_eliciting_in_flight stays 0,
        # so get_loss_detection_time returns None (no PTO armed).
        assert self.ONE_RTT_SPACE.ack_eliciting_in_flight == 0
        assert self.recovery.get_loss_detection_time() is None
        # Bytes are still in flight (probe consumes cwnd).
        assert self.recovery.bytes_in_flight == 1452

    def test_regular_packet_alongside_probe_drives_pto(self):
        # If a regular ack-eliciting packet is in flight alongside the
        # probe, PTO is anchored on the regular packet only.
        regular = QuicSentPacket(
            epoch=tls.Epoch.ONE_RTT,
            in_flight=True,
            is_ack_eliciting=True,
            is_crypto_packet=False,
            packet_number=10,
            packet_type=QuicPacketType.ONE_RTT,
            sent_bytes=1280,
            sent_time=5.0,
        )
        probe = self._probe_packet(pn=11, sent_time=99.0)
        self.recovery.on_packet_sent(regular, self.ONE_RTT_SPACE)
        self.recovery.on_packet_sent(probe, self.ONE_RTT_SPACE)

        assert self.ONE_RTT_SPACE.ack_eliciting_in_flight == 1
        # PTO time anchored on regular (sent_time=5.0), not probe (99.0).
        pto = self.recovery.get_loss_detection_time()
        assert pto is not None
        assert pto < 99.0

    def test_pmtu_probe_ack_does_not_underflow_counter(self):
        # Symmetric accounting: ACKing the probe must not decrement
        # ack_eliciting_in_flight below zero.
        probe = self._probe_packet(pn=0, sent_time=0.0)
        self.recovery.on_packet_sent(probe, self.ONE_RTT_SPACE)
        assert self.ONE_RTT_SPACE.ack_eliciting_in_flight == 0

        rs = RangeSet()
        rs.add(0, 1)
        self.recovery.on_ack_received(
            self.ONE_RTT_SPACE, ack_rangeset=rs, ack_delay=0.0, now=0.05
        )
        assert self.ONE_RTT_SPACE.ack_eliciting_in_flight == 0
        assert self.recovery.bytes_in_flight == 0


def _hystart_packet(pn: int, sent_time: float, size: int = 1280) -> QuicSentPacket:
    return QuicSentPacket(
        epoch=tls.Epoch.ONE_RTT,
        in_flight=True,
        is_ack_eliciting=True,
        is_crypto_packet=False,
        packet_number=pn,
        packet_type=QuicPacketType.ONE_RTT,
        sent_bytes=size,
        sent_time=sent_time,
    )


class TestHyStartPlusPlus:
    """RFC 9406 HyStart++ behavioural tests on QuicCongestionControl."""

    def _drive_round(
        self,
        cc: QuicCongestionControl,
        first_pn: int,
        rtt: float,
        n_acks: int = 8,
        send_time: float = 0.0,
    ) -> int:
        """Send N packets and ACK each one, supplying rtt per ACK.

        Mirrors qh3's real ``QuicPacketRecovery.on_ack_received`` ordering:
        on_packet_acked is invoked per acked packet first, and
        on_rtt_measurement is invoked once after the loop. We feed an
        RTT sample per ACK here (HyStart++ is sample-driven). This keeps
        the RFC 9406 ordering, round-end detection happens before a new
        sample is added to the next round.

        Returns the next PN to use for the following round.
        """
        for i in range(n_acks):
            cc.on_packet_sent(_hystart_packet(first_pn + i, send_time + i * 0.0001))
        now = send_time + 0.001
        for i in range(n_acks):
            cc.on_packet_acked(_hystart_packet(first_pn + i, send_time + i * 0.0001))
            cc.on_rtt_measurement(rtt, now)
        return first_pn + n_acks

    def test_default_enabled(self):
        cc = QuicCongestionControl(max_datagram_size=1280)
        # Per RFC 9406 recommendation HyStart++ is on by default.
        assert cc.hystart_enabled is True
        assert cc._hystart_in_css is False
        assert cc.ssthresh is None

    def test_steady_rtt_keeps_slow_start_active(self):
        """A flat RTT profile must NOT trip HyStart into CSS."""
        cc = QuicCongestionControl(max_datagram_size=1280)
        next_pn = 0
        # 5 bursts (each closes the previous round), RTT pinned at 50 ms.
        for r in range(5):
            next_pn = self._drive_round(
                cc, next_pn, rtt=0.050, send_time=r * 0.1
            )
        assert cc._hystart_in_css is False
        assert cc.ssthresh is None  # still in slow start

    def test_rtt_inflation_enters_css(self):
        """An RTT jump above the threshold must enter CSS.

        Each burst closes the round of the prior burst, so three bursts
        are required: burst-1 (baseline) populates round-1, burst-2's
        first ACK propagates last_round_min_rtt to baseline, burst-3
        at the inflated RTT trips the SS-exit check.
        """
        cc = QuicCongestionControl(max_datagram_size=1280)
        # Burst 1: baseline 20 ms; populates round-1 samples.
        next_pn = self._drive_round(cc, 0, rtt=0.020, send_time=0.0)
        # Burst 2: still 20 ms; closes round-1 (last_min = 0.020), fills round-2.
        next_pn = self._drive_round(cc, next_pn, rtt=0.020, send_time=0.1)
        assert cc._hystart_last_round_min_rtt == pytest.approx(0.020)
        assert cc._hystart_in_css is False
        # Burst 3: inflated to 50 ms (well above the 4 ms threshold).
        next_pn = self._drive_round(cc, next_pn, rtt=0.050, send_time=0.2)
        assert cc._hystart_in_css is True
        assert cc.ssthresh is None  # CSS keeps cwnd in slow-start regime

    def test_css_growth_uses_divisor(self):
        """In CSS, cwnd grows by sent_bytes/4 instead of sent_bytes."""
        cc = QuicCongestionControl(max_datagram_size=1280)
        # Force CSS without going through full RTT-sample dance.
        cc._hystart_in_css = True
        cc._hystart_window_end = 1_000_000  # well above any acked PN below
        cwnd0 = cc.congestion_window
        pkt = _hystart_packet(pn=0, sent_time=0.0, size=1280)
        cc.on_packet_sent(pkt)
        cc.on_packet_acked(pkt)
        # 1280 // 4 == 320
        assert cc.congestion_window == cwnd0 + 320

    def test_css_completes_after_five_rounds_then_exits_to_ca(self):
        cc = QuicCongestionControl(max_datagram_size=1280)
        # Bursts 1+2: baseline 20 ms (sets last_round_min_rtt = 0.020).
        next_pn = self._drive_round(cc, 0, rtt=0.020, send_time=0.0)
        next_pn = self._drive_round(cc, next_pn, rtt=0.020, send_time=0.1)
        # Burst 3: inflated -> CSS.
        next_pn = self._drive_round(cc, next_pn, rtt=0.050, send_time=0.2)
        assert cc._hystart_in_css is True
        # Now drive CSS_ROUNDS+1 additional bursts at the inflated RTT
        # (each new burst closes the prior round; one extra is needed to
        # close the final CSS round).
        send_t = 0.3
        for _ in range(K_HYSTART_CSS_ROUNDS + 1):
            next_pn = self._drive_round(cc, next_pn, rtt=0.050, send_time=send_t)
            send_t += 0.1
        # CSS budget exhausted -> ssthresh pinned, in_css cleared.
        # cwnd may grow slightly past ssthresh between the SS exit and
        # the CA path taking over on subsequent ACKs.
        assert cc._hystart_in_css is False
        assert cc.ssthresh is not None
        assert cc.ssthresh <= cc.congestion_window

    def test_css_false_trigger_returns_to_slow_start(self):
        """CSS must abandon and revert to SS when current round RTT
        falls back below the CSS baseline (false trigger detection,
        RFC 9406 4.3)."""
        cc = QuicCongestionControl(max_datagram_size=1280)
        # Bursts 1+2: baseline 20 ms.
        next_pn = self._drive_round(cc, 0, rtt=0.020, send_time=0.0)
        next_pn = self._drive_round(cc, next_pn, rtt=0.020, send_time=0.1)
        # Burst 3: inflated -> CSS.
        next_pn = self._drive_round(cc, next_pn, rtt=0.050, send_time=0.2)
        assert cc._hystart_in_css is True
        baseline = cc._hystart_css_baseline_min_rtt
        # Burst 4 at improved RTT (well below CSS baseline) closes round
        # 3 (which was inflated); burst 5 fills a CSS round with the
        # improved RTT and triggers the false-trigger path.
        next_pn = self._drive_round(
            cc, next_pn, rtt=baseline - 0.010, send_time=0.3
        )
        self._drive_round(
            cc, next_pn, rtt=baseline - 0.010, send_time=0.4
        )
        assert cc._hystart_in_css is False
        assert cc.ssthresh is None  # back to standard slow start

    def test_disable_falls_back_to_legacy_monitor(self):
        cc = QuicCongestionControl(max_datagram_size=1280)
        cc.hystart_enabled = False
        # Even with rtt inflation HyStart++ state stays untouched...
        cc.on_rtt_measurement(0.050, now=1.0)
        assert cc._hystart_rtt_sample_count == 0
        assert cc._hystart_in_css is False

    def test_persistent_congestion_resets_hystart(self):
        cc = QuicCongestionControl(max_datagram_size=1280)
        # Drive into CSS first (3 bursts: baseline, baseline, inflated).
        next_pn = self._drive_round(cc, 0, rtt=0.020, send_time=0.0)
        next_pn = self._drive_round(cc, next_pn, rtt=0.020, send_time=0.1)
        self._drive_round(cc, next_pn, rtt=0.050, send_time=0.2)
        assert cc._hystart_in_css is True
        cc.on_persistent_congestion(now=200.0)
        assert cc._hystart_in_css is False
        assert cc._hystart_window_end is None
        assert cc._hystart_rtt_sample_count == 0
        assert math.isinf(cc._hystart_last_round_min_rtt)


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
