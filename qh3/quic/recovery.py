from __future__ import annotations

import logging
import math
from typing import Any, Callable, Iterable

from .._hazmat import QuicPacketPacer, QuicRttMonitor, RangeSet
from .logger import QuicLoggerTrace
from .packet_builder import QuicDeliveryState, QuicSentPacket

# loss detection
K_PACKET_THRESHOLD = 3
K_GRANULARITY = 0.001  # seconds
K_TIME_THRESHOLD = 9 / 8
K_MICRO_SECOND = 0.000001
K_SECOND = 1.0

# congestion control
K_INITIAL_WINDOW = 10
K_MINIMUM_WINDOW = 2

# Cubic constants (RFC 9438)
K_CUBIC_C = 0.4
K_CUBIC_LOSS_REDUCTION_FACTOR = 0.7
K_CUBIC_MAX_IDLE_TIME = 2.0  # seconds

# HyStart++ constants (RFC 9406 4.2)
K_HYSTART_MIN_RTT_THRESH = 0.004  # 4 ms
K_HYSTART_MAX_RTT_THRESH = 0.016  # 16 ms
K_HYSTART_MIN_RTT_DIVISOR = 8
K_HYSTART_N_RTT_SAMPLE = 8
K_HYSTART_CSS_GROWTH_DIVISOR = 4
K_HYSTART_CSS_ROUNDS = 5


def _cubic_root(x: float) -> float:
    if x < 0:
        return -((-x) ** (1.0 / 3.0))
    return x ** (1.0 / 3.0)


class QuicPacketSpace:
    def __init__(self) -> None:
        self.ack_at: float | None = None
        self.ack_queue = RangeSet()
        self.discarded = False
        self.expected_packet_number = 0
        self.largest_received_packet = -1
        self.largest_received_time: float | None = None
        self.packet_number = 0  # next send PN for this space (RFC 9000 §12.3)

        # sent packets and loss
        self.ack_eliciting_in_flight = 0
        self.largest_acked_packet = 0
        self.loss_time: float | None = None
        self.sent_packets: dict[int, QuicSentPacket] = {}
        # RFC 9002 6.2.1: per-PN-space time of last sent ack-eliciting packet,
        # used as the reference for PTO computation.
        self.time_of_last_ack_eliciting_packet: float = 0.0


class QuicCongestionControl:
    """
    Cubic congestion control (RFC 9438).
    """

    def __init__(self, max_datagram_size: int) -> None:
        self._max_datagram_size = max_datagram_size
        self._rtt_monitor = QuicRttMonitor()
        self._congestion_recovery_start_time = 0.0
        self._rtt = 0.02  # initial RTT estimate (20 ms)
        self._last_ack = 0.0

        self.bytes_in_flight = 0
        self.congestion_window = max_datagram_size * K_INITIAL_WINDOW
        self.ssthresh: int | None = None

        # Cubic state
        self._first_slow_start = True
        self._starting_congestion_avoidance = False
        self._K: float = 0.0
        self._W_max: int = self.congestion_window
        self._W_est: int = 0
        self._cwnd_epoch: int = 0
        self._t_epoch: float = 0.0

        # HyStart++ state (RFC 9406). Enabled by default per spec
        # recommendation for slow-start exit detection.
        self.hystart_enabled: bool = True
        self._hystart_in_css: bool = False
        self._hystart_css_round: int = 0
        self._hystart_css_baseline_min_rtt: float = math.inf
        self._hystart_last_round_min_rtt: float = math.inf
        self._hystart_current_round_min_rtt: float = math.inf
        self._hystart_rtt_sample_count: int = 0
        self._hystart_window_end: int | None = None
        self._hystart_largest_sent_pn: int = -1

    def _W_cubic(self, t: float) -> int:
        W_max_segments = self._W_max / self._max_datagram_size
        target_segments = K_CUBIC_C * (t - self._K) ** 3 + W_max_segments
        return int(target_segments * self._max_datagram_size)

    def _reset(self) -> None:
        self.congestion_window = self._max_datagram_size * K_INITIAL_WINDOW
        self.ssthresh = None
        self._first_slow_start = True
        self._starting_congestion_avoidance = False
        self._K = 0.0
        self._W_max = self.congestion_window
        self._W_est = 0
        self._cwnd_epoch = 0
        self._t_epoch = 0.0
        self._hystart_reset()

    def _hystart_reset(self) -> None:
        """
        Reset HyStart++ slow-start exit detector. Called when entering a
        fresh slow-start phase: at construction, after idle restart, and
        after persistent congestion collapse.
        """
        self._hystart_in_css = False
        self._hystart_css_round = 0
        self._hystart_css_baseline_min_rtt = math.inf
        self._hystart_last_round_min_rtt = math.inf
        self._hystart_current_round_min_rtt = math.inf
        self._hystart_rtt_sample_count = 0
        self._hystart_window_end = None

    def _start_epoch(self, now: float) -> None:
        self._t_epoch = now
        self._cwnd_epoch = self.congestion_window
        self._W_est = self._cwnd_epoch
        W_max_seg = self._W_max / self._max_datagram_size
        cwnd_seg = self._cwnd_epoch / self._max_datagram_size
        self._K = _cubic_root((W_max_seg - cwnd_seg) / K_CUBIC_C)

    def on_packet_acked(self, packet: QuicSentPacket) -> None:
        self.bytes_in_flight -= packet.sent_bytes
        self._last_ack = packet.sent_time

        # HyStart++ round tracking (RFC 9406 4.3): a round ends when an
        # ACK is received for a packet whose number is at or above the
        # window-end PN recorded at the start of the round.
        if (
            self.hystart_enabled
            and self.ssthresh is None
            and self._hystart_window_end is not None
            and packet.packet_number >= self._hystart_window_end
        ):
            self._hystart_last_round_min_rtt = self._hystart_current_round_min_rtt
            self._hystart_current_round_min_rtt = math.inf
            self._hystart_rtt_sample_count = 0
            self._hystart_window_end = self._hystart_largest_sent_pn + 1
            if self._hystart_in_css:
                self._hystart_css_round += 1
                if self._hystart_css_round >= K_HYSTART_CSS_ROUNDS:
                    # Conservative slow start exhausted -> exit to CA.
                    self.ssthresh = self.congestion_window
                    self._hystart_in_css = False

        if self.ssthresh is None or self.congestion_window < self.ssthresh:
            # slow start
            if self._hystart_in_css:
                # Conservative Slow Start: dampened growth (RFC 9406 4.3).
                self.congestion_window += (
                    packet.sent_bytes // K_HYSTART_CSS_GROWTH_DIVISOR
                )
            else:
                self.congestion_window += packet.sent_bytes
        else:
            # congestion avoidance
            if self._first_slow_start and not self._starting_congestion_avoidance:
                # exiting slow start without a loss (HyStart triggered)
                self._first_slow_start = False
                self._W_max = self.congestion_window
                self._start_epoch(packet.sent_time)

            if self._starting_congestion_avoidance:
                # entering congestion avoidance after a loss
                self._starting_congestion_avoidance = False
                self._first_slow_start = False
                self._start_epoch(packet.sent_time)

            # TCP-friendly estimate (Reno-like linear growth)
            self._W_est = int(
                self._W_est
                + self._max_datagram_size * (packet.sent_bytes / self.congestion_window)
            )

            t = packet.sent_time - self._t_epoch
            W_cubic = self._W_cubic(t + self._rtt)

            # clamp target
            if W_cubic < self.congestion_window:
                target = self.congestion_window
            elif W_cubic > int(1.5 * self.congestion_window):
                target = int(1.5 * self.congestion_window)
            else:
                target = W_cubic

            if self._W_cubic(t) < self._W_est:
                # Reno-friendly region
                self.congestion_window = self._W_est
            else:
                # concave / convex region
                self.congestion_window = int(
                    self.congestion_window
                    + (target - self.congestion_window)
                    * (self._max_datagram_size / self.congestion_window)
                )

    def on_packet_sent(self, packet: QuicSentPacket) -> None:
        self.bytes_in_flight += packet.sent_bytes
        # Track largest sent PN and bootstrap the HyStart++ round window
        # on the first packet sent during slow start.
        if packet.packet_number > self._hystart_largest_sent_pn:
            self._hystart_largest_sent_pn = packet.packet_number
        if (
            self.hystart_enabled
            and self.ssthresh is None
            and self._hystart_window_end is None
        ):
            self._hystart_window_end = packet.packet_number
        # reset cwnd after prolonged idle
        if self._last_ack > 0.0:
            elapsed_idle = packet.sent_time - self._last_ack
            if elapsed_idle >= K_CUBIC_MAX_IDLE_TIME:
                self._reset()

    def on_packets_expired(self, packets: Iterable[QuicSentPacket]) -> None:
        for packet in packets:
            self.bytes_in_flight -= packet.sent_bytes

    def on_packets_rescheduled(self, packets: Iterable[QuicSentPacket]) -> None:
        """
        Mirror of on_packets_lost, but without congestion-control reduction.
        Used by PTO probes (RFC 9002 6.2.4): a PTO timer expiration MUST NOT
        cause prior unacknowledged packets to be marked as lost. We still
        reclaim bytes_in_flight so the application is allowed to retransmit
        the data on a fresh packet without being blocked by the congestion
        window.
        """
        for packet in packets:
            self.bytes_in_flight -= packet.sent_bytes

    def on_packets_lost(self, packets: Iterable[QuicSentPacket], now: float) -> None:
        lost_largest_time = 0.0
        for packet in packets:
            self.bytes_in_flight -= packet.sent_bytes
            lost_largest_time = packet.sent_time

        # start a new congestion event if packet was sent after the
        # start of the previous congestion recovery period.
        if lost_largest_time > self._congestion_recovery_start_time:
            self._congestion_recovery_start_time = now

            # fast convergence: if W_max is decreasing, reduce it further
            if self.congestion_window < self._W_max:
                self._W_max = int(
                    self.congestion_window * (1 + K_CUBIC_LOSS_REDUCTION_FACTOR) / 2
                )
            else:
                self._W_max = self.congestion_window

            self.congestion_window = max(
                int(self.congestion_window * K_CUBIC_LOSS_REDUCTION_FACTOR),
                self._max_datagram_size * K_MINIMUM_WINDOW,
            )
            self.ssthresh = self.congestion_window
            self._starting_congestion_avoidance = True
            # RFC 9406 4.2: loss/ECN during slow start or CSS sets
            # ssthresh = cwnd and exits to congestion avoidance. Clear the
            # HyStart++ CSS flag so a stale value can't influence growth
            # if the connection later re-enters slow start (e.g. after
            # idle resume)
            self._hystart_in_css = False

    def on_rtt_measurement(self, latest_rtt: float, now: float) -> None:
        self._rtt = latest_rtt
        if self.ssthresh is not None:
            return

        if self.hystart_enabled:
            # HyStart++ slow-start exit detection (RFC 9406 4.3).
            if latest_rtt < self._hystart_current_round_min_rtt:
                self._hystart_current_round_min_rtt = latest_rtt
            self._hystart_rtt_sample_count += 1

            if (
                self._hystart_rtt_sample_count >= K_HYSTART_N_RTT_SAMPLE
                and math.isfinite(self._hystart_last_round_min_rtt)
                and math.isfinite(self._hystart_current_round_min_rtt)
            ):
                rtt_thresh = max(
                    K_HYSTART_MIN_RTT_THRESH,
                    min(
                        K_HYSTART_MAX_RTT_THRESH,
                        self._hystart_last_round_min_rtt / K_HYSTART_MIN_RTT_DIVISOR,
                    ),
                )
                if self._hystart_in_css:
                    # In CSS: a sustained RTT improvement (current round
                    # min rtt drops below the CSS baseline) indicates the
                    # earlier RTT inflation was a false trigger; revert
                    # to standard slow start (RFC 9406 4.3).
                    if (
                        self._hystart_current_round_min_rtt
                        < self._hystart_css_baseline_min_rtt
                    ):
                        self._hystart_in_css = False
                        self._hystart_css_round = 0
                        self._hystart_css_baseline_min_rtt = math.inf
                else:
                    if (
                        self._hystart_current_round_min_rtt
                        >= self._hystart_last_round_min_rtt + rtt_thresh
                    ):
                        # Enter Conservative Slow Start.
                        self._hystart_in_css = True
                        self._hystart_css_baseline_min_rtt = (
                            self._hystart_current_round_min_rtt
                        )
                        self._hystart_css_round = 0
        else:
            # Fallback: legacy RTT-monotonic-rise heuristic.
            if self._rtt_monitor.is_rtt_increasing(latest_rtt, now):
                self.ssthresh = self.congestion_window

    def on_persistent_congestion(self, now: float) -> None:
        """
        RFC 9002 7.6: on persistent congestion the sender's cwnd is
        collapsed to the minimum window and slow-start state is reset
        so the controller re-probes capacity.

        Set ``_congestion_recovery_start_time`` to ``now`` (the time of
        the collapse), not 0.0. Otherwise, the very next packet declared
        lost (e.g. a probe sent just after collapse) passes the
        ``lost_largest_time > _congestion_recovery_start_time`` guard in
        ``on_packets_lost`` and pins ``ssthresh = MINIMUM_WINDOW``,
        terminating the new slow-start phase that this collapse was
        meant to start.
        """
        self._congestion_recovery_start_time = now
        self.congestion_window = self._max_datagram_size * K_MINIMUM_WINDOW
        self.ssthresh = None
        self._first_slow_start = True
        self._starting_congestion_avoidance = False
        self._K = 0.0
        self._W_max = self.congestion_window
        self._W_est = 0
        self._cwnd_epoch = 0
        self._t_epoch = 0.0
        self._hystart_reset()


class QuicPacketRecovery:
    """
    Packet loss and congestion controller.
    """

    def __init__(
        self,
        initial_rtt: float,
        peer_completed_address_validation: bool,
        send_probe: Callable[[], None],
        max_datagram_size: int = 1280,
        logger: logging.LoggerAdapter | None = None,
        quic_logger: QuicLoggerTrace | None = None,
    ) -> None:
        self.max_ack_delay = 0.025
        self.peer_completed_address_validation = peer_completed_address_validation
        self.spaces: list[QuicPacketSpace] = []

        # callbacks
        self._logger = logger
        self._quic_logger = quic_logger
        self._send_probe = send_probe

        # loss detection
        self._pto_count = 0
        self._pto_total = 0  # cumulative PTO fires (for diagnostics)
        self._loss_total = 0  # cumulative packets declared lost
        self._rtt_initial = initial_rtt
        self._rtt_initialized = False
        self._rtt_latest = 0.0
        # RFC 9002 6.1.2: loss_delay uses the raw latest_rtt sample,
        # i.e. the last RTT measurement not adjusted for ack delay.
        # We retain it separately because `rtt_latest above is reduced
        # by ack_delay for SRTT computation.
        self._rtt_latest_raw = 0.0
        self._rtt_min = math.inf
        self._rtt_smoothed = 0.0
        self._rtt_variance = 0.0
        self._time_of_last_sent_ack_eliciting_packet = 0.0

        # congestion control
        self._cc = QuicCongestionControl(max_datagram_size)
        self._pacer = QuicPacketPacer(max_datagram_size)

    @property
    def bytes_in_flight(self) -> int:
        return self._cc.bytes_in_flight

    @property
    def congestion_window(self) -> int:
        return self._cc.congestion_window

    def discard_space(self, space: QuicPacketSpace) -> None:
        assert space in self.spaces

        self._cc.on_packets_expired(
            filter(lambda x: x.in_flight, space.sent_packets.values())
        )
        space.sent_packets.clear()

        space.ack_at = None
        space.ack_eliciting_in_flight = 0
        space.loss_time = None

        # reset PTO count
        self._pto_count = 0

        if self._quic_logger is not None:
            self._log_metrics_updated()

    def get_loss_detection_time(self) -> float:
        # loss timer
        loss_space = self._get_loss_space()
        if loss_space is not None:
            return loss_space.loss_time

        # PTO timer (RFC 9002 6.2.1): if address validation is incomplete,
        # arm using the time of the last ack-eliciting packet sent across
        # any space; otherwise pick the earliest per-space last-sent time
        # among spaces that have ack-eliciting packets in flight.
        if not self.peer_completed_address_validation:
            timeout = self.get_probe_timeout() * (2**self._pto_count)
            return self._time_of_last_sent_ack_eliciting_packet + timeout

        earliest: float | None = None
        for space in self.spaces:
            if space.ack_eliciting_in_flight > 0:
                t = space.time_of_last_ack_eliciting_packet
                if earliest is None or t < earliest:
                    earliest = t
        if earliest is None:
            return None
        timeout = self.get_probe_timeout() * (2**self._pto_count)
        return earliest + timeout

    def get_probe_timeout(self) -> float:
        if not self._rtt_initialized:
            return 2 * self._rtt_initial
        return (
            self._rtt_smoothed
            + max(4 * self._rtt_variance, K_GRANULARITY)
            + self.max_ack_delay
        )

    def reset_for_new_path(self) -> None:
        """
        RFC 9000 9.4 / RFC 9002 5.1: when a path is changed, RTT samples
        from the prior path are no longer representative. ``min_rtt`` in
        particular MUST be reset because the new path may have higher
        latency, and a stale ``min_rtt`` would cause spurious loss
        declarations (since loss_delay scales with max(latest_rtt,
        smoothed_rtt) but min_rtt feeds the ack-delay floor in
        ``on_ack_received``). We additionally reset the smoothed RTT so a
        fresh sample is taken on the new path.
        """
        self._rtt_initialized = False
        self._rtt_latest = 0.0
        self._rtt_latest_raw = 0.0
        self._rtt_min = math.inf
        self._rtt_smoothed = 0.0
        self._rtt_variance = 0.0

    def on_ack_received(
        self,
        space: QuicPacketSpace,
        ack_rangeset: RangeSet,
        ack_delay: float,
        now: float,
        reset_pto_count: bool = True,
    ) -> None:
        """
        Update metrics as the result of an ACK being received.

        ``reset_pto_count`` MUST be False when the caller is a client
        processing an ACK in the Initial packet space and the server has
        not yet been confirmed to have validated the client's address
        (RFC 9002 6.2.1). Resetting in that case would prematurely
        clear the PTO backoff and let a stuck handshake under-probe.
        """
        is_ack_eliciting = False
        largest_acked = ack_rangeset.bounds()[1] - 1
        largest_newly_acked = None
        largest_sent_time = None

        if largest_acked > space.largest_acked_packet:
            space.largest_acked_packet = largest_acked

        for packet_number in sorted(space.sent_packets.keys()):
            if packet_number > largest_acked:
                break
            if packet_number in ack_rangeset:
                # remove packet and update counters
                packet = space.sent_packets.pop(packet_number)
                if packet.is_ack_eliciting:
                    is_ack_eliciting = True
                    if not packet.is_pmtu_probe:
                        space.ack_eliciting_in_flight -= 1
                if packet.in_flight:
                    self._cc.on_packet_acked(packet)
                largest_newly_acked = packet_number
                largest_sent_time = packet.sent_time

                # trigger callbacks
                dh = packet.delivery_handlers
                if dh is not None:
                    for handler, args in dh:
                        handler(QuicDeliveryState.ACKED, *args)

        # nothing to do if there are no newly acked packets
        if largest_newly_acked is None:
            return

        if largest_acked == largest_newly_acked and is_ack_eliciting:
            latest_rtt = now - largest_sent_time
            log_rtt = True

            # limit ACK delay to max_ack_delay
            ack_delay = min(ack_delay, self.max_ack_delay)

            # update RTT estimate, which cannot be < 1 ms
            self._rtt_latest = max(latest_rtt, 0.001)
            # RFC 9002 6.1.2 keeps the *raw* sample (pre ack-delay
            # subtraction) so the loss-detection time threshold is not
            # artificially shortened for slow peers.
            self._rtt_latest_raw = self._rtt_latest
            if self._rtt_latest < self._rtt_min:
                self._rtt_min = self._rtt_latest
            if self._rtt_latest >= self._rtt_min + ack_delay:
                self._rtt_latest -= ack_delay

            if not self._rtt_initialized:
                self._rtt_initialized = True
                self._rtt_variance = latest_rtt / 2
                self._rtt_smoothed = latest_rtt
            else:
                self._rtt_variance = 3 / 4 * self._rtt_variance + 1 / 4 * abs(
                    self._rtt_smoothed - self._rtt_latest
                )
                self._rtt_smoothed = (
                    7 / 8 * self._rtt_smoothed + 1 / 8 * self._rtt_latest
                )

            # inform congestion controller
            self._cc.on_rtt_measurement(latest_rtt, now=now)
            self._pacer.update_rate(
                congestion_window=self._cc.congestion_window,
                smoothed_rtt=self._rtt_smoothed,
            )

        else:
            log_rtt = False

        self._detect_loss(space, now=now)

        # reset PTO count
        if reset_pto_count:
            self._pto_count = 0

        if self._quic_logger is not None:
            self._log_metrics_updated(log_rtt=log_rtt)

    def on_loss_detection_timeout(self, now: float) -> None:
        loss_space = self._get_loss_space()
        if loss_space is not None:
            self._detect_loss(loss_space, now=now)
        else:
            self._pto_count += 1
            self._pto_total += 1
            self.reschedule_data(now=now)

    def on_packet_sent(self, packet: QuicSentPacket, space: QuicPacketSpace) -> None:
        space.sent_packets[packet.packet_number] = packet

        # RFC 9000 14.4: PMTU probes have their own probe
        # timer and MUST NOT anchor the standard PTO / loss-detection timer.
        # We exclude them from ack_eliciting_in_flight bookkeeping so they
        # neither arm PTO nor inflate _pto_count on probe loss.
        if packet.is_ack_eliciting and not packet.is_pmtu_probe:
            space.ack_eliciting_in_flight += 1
        if packet.in_flight:
            if packet.is_ack_eliciting and not packet.is_pmtu_probe:
                self._time_of_last_sent_ack_eliciting_packet = packet.sent_time
                space.time_of_last_ack_eliciting_packet = packet.sent_time

            # add packet to bytes in flight
            self._cc.on_packet_sent(packet)

            if self._quic_logger is not None:
                self._log_metrics_updated()

    def reschedule_data(self, now: float) -> None:
        """
        Schedule some data for retransmission upon PTO expiry.

        Per RFC 9002 6.2.4, on PTO the sender MUST send one or two
        ack-eliciting packets. A PTO event MUST NOT mark prior packets as
        lost or trigger a congestion-control reduction. Here we requeue
        outstanding CRYPTO (or up to two oldest application data packets)
        so their content is included with the probe; the bytes are
        reclaimed via on_packets_rescheduled rather than on_packets_lost
        to avoid an unwarranted cwnd reduction. If nothing was rescheduled
        the caller emits a PING frame as the ack-eliciting probe.
        """
        # if there is any outstanding CRYPTO, retransmit it
        crypto_scheduled = False
        for space in self.spaces:
            packets = tuple(
                filter(lambda i: i.is_crypto_packet, space.sent_packets.values())
            )
            if packets:
                self._on_packets_rescheduled(packets, space=space, now=now)
                crypto_scheduled = True
        if crypto_scheduled and self._logger is not None:
            self._logger.debug("Scheduled CRYPTO data for retransmission")

        # Reschedule oldest in-flight application data (up to 2 packets)
        # so it is sent in the same write cycle as the PTO probe.
        app_rescheduled = False
        if not crypto_scheduled:
            for space in self.spaces:
                if not space.sent_packets:
                    continue
                to_reschedule = []
                for pn in sorted(space.sent_packets.keys()):
                    pkt = space.sent_packets[pn]
                    if pkt.is_ack_eliciting and pkt.in_flight:
                        to_reschedule.append(pkt)
                        if len(to_reschedule) >= 2:
                            break
                if to_reschedule:
                    self._on_packets_rescheduled(to_reschedule, space=space, now=now)
                    app_rescheduled = True

        # If no data was rescheduled, send a PING as the ack-eliciting probe
        if not crypto_scheduled and not app_rescheduled:
            self._send_probe()

    def _detect_loss(self, space: QuicPacketSpace, now: float) -> None:
        """
        Check whether any packets should be declared lost.
        """
        # RFC 9002 6.1.2: loss_delay = kTimeThreshold * max(latest_rtt,
        # smoothed_rtt). latest_rtt here is the most recent raw
        # RTT sample (without the ack-delay subtraction applied to the
        # SRTT-input _rtt_latest).
        loss_delay = max(
            K_TIME_THRESHOLD
            * (
                max(self._rtt_latest_raw, self._rtt_smoothed)
                if self._rtt_initialized
                else self._rtt_initial
            ),
            K_GRANULARITY,
        )
        packet_threshold = space.largest_acked_packet - K_PACKET_THRESHOLD
        time_threshold = now - loss_delay

        lost_packets = []
        space.loss_time = None
        for packet_number, packet in space.sent_packets.items():
            if packet_number > space.largest_acked_packet:
                break

            if packet_number <= packet_threshold or packet.sent_time <= time_threshold:
                lost_packets.append(packet)
            else:
                packet_loss_time = packet.sent_time + loss_delay
                if space.loss_time is None or space.loss_time > packet_loss_time:
                    space.loss_time = packet_loss_time

        self._on_packets_lost(lost_packets, space=space, now=now)

    def _get_loss_space(self) -> QuicPacketSpace | None:
        loss_space = None
        for space in self.spaces:
            if space.loss_time is not None and (
                loss_space is None or space.loss_time < loss_space.loss_time
            ):
                loss_space = space
        return loss_space

    def _log_metrics_updated(self, log_rtt=False) -> None:
        data: dict[str, Any] = {
            "bytes_in_flight": self._cc.bytes_in_flight,
            "cwnd": self._cc.congestion_window,
        }
        if self._cc.ssthresh is not None:
            data["ssthresh"] = self._cc.ssthresh

        if log_rtt:
            data.update(
                {
                    "latest_rtt": self._quic_logger.encode_time(self._rtt_latest),
                    "min_rtt": self._quic_logger.encode_time(self._rtt_min),
                    "smoothed_rtt": self._quic_logger.encode_time(self._rtt_smoothed),
                    "rtt_variance": self._quic_logger.encode_time(self._rtt_variance),
                }
            )

        self._quic_logger.log_event(
            category="recovery", event="metrics_updated", data=data
        )

    def _on_packets_lost(
        self, packets: Iterable[QuicSentPacket], space: QuicPacketSpace, now: float
    ) -> None:
        lost_packets_cc = []
        for packet in packets:
            self._loss_total += 1
            del space.sent_packets[packet.packet_number]

            if packet.in_flight:
                if packet.is_pmtu_probe:
                    # RFC 9000 14.4: loss of a PMTU probe MUST NOT trigger
                    # a congestion control reaction. Reclaim bytes_in_flight
                    # directly so the connection is not wedged, but skip the
                    # congestion controller and persistent-congestion logic.
                    self._cc.bytes_in_flight -= packet.sent_bytes
                else:
                    lost_packets_cc.append(packet)

            if packet.is_ack_eliciting and not packet.is_pmtu_probe:
                space.ack_eliciting_in_flight -= 1

            if self._quic_logger is not None:
                self._quic_logger.log_event(
                    category="recovery",
                    event="packet_lost",
                    data={
                        "type": self._quic_logger.packet_type(packet.packet_type),
                        "packet_number": packet.packet_number,
                    },
                )
                self._log_metrics_updated()

            # trigger callbacks
            dh = packet.delivery_handlers
            if dh is not None:
                for handler, args in dh:
                    handler(QuicDeliveryState.LOST, *args)

        # inform congestion controller
        if lost_packets_cc:
            self._cc.on_packets_lost(lost_packets_cc, now=now)
            self._pacer.update_rate(
                congestion_window=self._cc.congestion_window,
                smoothed_rtt=self._rtt_smoothed,
            )

            # RFC 9002 7.6: detect persistent congestion. If at least two
            # ack-eliciting packets sent over a duration longer than
            # persistent_congestion_duration are lost, and an RTT sample
            # has been obtained on this connection (so peer liveness is
            # established), collapse the congestion window.
            if self._rtt_initialized:
                eliciting = [p for p in lost_packets_cc if p.is_ack_eliciting]
                if len(eliciting) >= 2:
                    pc_duration = (
                        self._rtt_smoothed
                        + max(4 * self._rtt_variance, K_GRANULARITY)
                        + self.max_ack_delay
                    ) * 3  # kPersistentCongestionThreshold
                    span = max(p.sent_time for p in eliciting) - min(
                        p.sent_time for p in eliciting
                    )
                    if span > pc_duration:
                        if self._logger is not None:
                            self._logger.debug(
                                "Persistent congestion detected (span=%.3fs > %.3fs); "
                                "collapsing cwnd",
                                span,
                                pc_duration,
                            )
                        self._cc.on_persistent_congestion(now)
                        self._pacer.update_rate(
                            congestion_window=self._cc.congestion_window,
                            smoothed_rtt=self._rtt_smoothed,
                        )
            if self._quic_logger is not None:
                self._log_metrics_updated()

    def _on_packets_rescheduled(
        self, packets: Iterable[QuicSentPacket], space: QuicPacketSpace, now: float
    ) -> None:
        """
        Requeue the contents of in-flight packets without declaring loss.
        Used by PTO probes (RFC 9002 6.2.4): the packet is removed from
        sent_packets and its delivery_handlers fire LOST so the stream
        sender re-enqueues the data, but congestion control is NOT informed
        and bytes_in_flight is reclaimed without applying a reduction.
        """
        rescheduled_cc: list[QuicSentPacket] = []
        for packet in packets:
            del space.sent_packets[packet.packet_number]

            if packet.in_flight:
                rescheduled_cc.append(packet)

            if packet.is_ack_eliciting and not packet.is_pmtu_probe:
                space.ack_eliciting_in_flight -= 1

            # trigger callbacks (so stream senders re-enqueue stream data)
            dh = packet.delivery_handlers
            if dh is not None:
                for handler, args in dh:
                    handler(QuicDeliveryState.LOST, *args)

        if rescheduled_cc:
            self._cc.on_packets_rescheduled(rescheduled_cc)
            if self._quic_logger is not None:
                self._log_metrics_updated()
