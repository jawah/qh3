//! QUIC loss recovery and congestion control.
//!
//! This module deliberately contains no transport or callback code.  It owns
//! recovery state and returns typed actions for the caller to apply.

use std::array;
use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use super::range::RangeSet;
use super::types::{DeliveryId, DeliveryOutcome, PacketNumberSpace, VARINT_MAX};

const PACKET_THRESHOLD: u64 = 3;
const TIME_THRESHOLD_NUMERATOR: u32 = 9;
const TIME_THRESHOLD_DENOMINATOR: u32 = 8;
const GRANULARITY: Duration = Duration::from_millis(1);
const INITIAL_WINDOW_PACKETS: u64 = 10;
const MINIMUM_WINDOW_PACKETS: u64 = 2;
const INITIAL_WINDOW_MINIMUM: u64 = 14_720;
const MAX_RECEIVED_RANGES: usize = 256;
const CUBIC_C: f64 = 0.4;
const CUBIC_BETA: f64 = 0.7;
const CUBIC_MAX_IDLE: Duration = Duration::from_secs(2);
const HYSTART_MIN_THRESHOLD: Duration = Duration::from_millis(4);
const HYSTART_MAX_THRESHOLD: Duration = Duration::from_millis(16);
const HYSTART_SAMPLES: usize = 8;
const HYSTART_CSS_ROUNDS: u8 = 5;
const HYSTART_CSS_DIVISOR: u64 = 4;
const PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;
const DEFAULT_ACK_FREQUENCY: u8 = 2;
const MAX_PACKET_NUMBER: u64 = VARINT_MAX;

/// Opaque path identity supplied by the connection layer.
pub type PathId = u64;

const PACKET_SPACES: [PacketNumberSpace; 3] = [
    PacketNumberSpace::Initial,
    PacketNumberSpace::Handshake,
    PacketNumberSpace::ApplicationData,
];

trait PacketSpaceIndex {
    fn index(self) -> usize;
}

impl PacketSpaceIndex for PacketNumberSpace {
    fn index(self) -> usize {
        match self {
            Self::Initial => 0,
            Self::Handshake => 1,
            Self::ApplicationData => 2,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryAction {
    pub id: DeliveryId,
    pub outcome: DeliveryOutcome,
    pub space: PacketNumberSpace,
    pub packet_number: u64,
}

/// Recovery metadata retained for every outstanding sent packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SentPacket {
    pub packet_number: u64,
    pub path_id: PathId,
    pub sent_time: Duration,
    pub sent_bytes: u64,
    pub ack_eliciting: bool,
    pub in_flight: bool,
    pub is_crypto: bool,
    pub is_pmtu_probe: bool,
    pub packet_type: super::types::PacketType,
    pub delivery_actions: Vec<DeliveryId>,
}

/// Events not represented by a delivery action ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryEvent {
    Delivery(DeliveryAction),
    SendProbe {
        space: PacketNumberSpace,
    },
    PmtuProbeAcked {
        space: PacketNumberSpace,
        packet_number: u64,
        path_id: PathId,
        sent_bytes: u64,
    },
    PmtuProbeLost {
        space: PacketNumberSpace,
        packet_number: u64,
        path_id: PathId,
        sent_bytes: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AckRange {
    /// Inclusive packet number.
    pub start: u64,
    /// Exclusive packet number.
    pub end: u64,
}

impl AckRange {
    pub const fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AckToSend {
    pub largest: u64,
    pub ack_delay: Duration,
    pub ranges: Vec<AckRange>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryError {
    InvalidConfiguration(&'static str),
    InvalidTime,
    PacketNumberOutOfRange(u64),
    DuplicatePacketNumber {
        space: PacketNumberSpace,
        packet_number: u64,
    },
    PacketNumberRegression {
        space: PacketNumberSpace,
        packet_number: u64,
    },
    EmptyAck,
    MalformedAckRanges,
    AckOfUnsentPacket {
        space: PacketNumberSpace,
        packet_number: u64,
    },
    DiscardedSpace(PacketNumberSpace),
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for RecoveryError {}

#[derive(Clone, Debug)]
pub struct RecoveryConfig {
    pub initial_rtt: Duration,
    pub ack_delay: Duration,
    pub max_ack_delay: Duration,
    pub max_datagram_size: u64,
    pub peer_completed_address_validation: bool,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            initial_rtt: Duration::from_millis(333),
            ack_delay: Duration::from_millis(1),
            max_ack_delay: Duration::from_millis(25),
            max_datagram_size: 1200,
            peer_completed_address_validation: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RttEstimator {
    initial: Duration,
    latest: Option<Duration>,
    latest_raw: Option<Duration>,
    minimum: Option<Duration>,
    smoothed: Option<Duration>,
    variance: Duration,
}

impl RttEstimator {
    fn new(initial: Duration) -> Self {
        Self {
            initial,
            latest: None,
            latest_raw: None,
            minimum: None,
            smoothed: None,
            variance: Duration::ZERO,
        }
    }

    pub fn latest(&self) -> Option<Duration> {
        self.latest
    }

    pub fn smoothed(&self) -> Option<Duration> {
        self.smoothed
    }

    pub fn initialized(&self) -> bool {
        self.smoothed.is_some()
    }

    fn update(&mut self, raw: Duration, ack_delay: Duration, max_ack_delay: Duration) {
        let raw = raw.max(GRANULARITY);
        self.latest_raw = Some(raw);
        self.minimum = Some(self.minimum.map_or(raw, |old| old.min(raw)));
        let delay = ack_delay.min(max_ack_delay);
        let minimum = self.minimum.unwrap_or(raw);
        let adjusted = if raw >= saturating_add(minimum, delay) {
            raw.saturating_sub(delay)
        } else {
            raw
        };
        self.latest = Some(adjusted);

        if let Some(smoothed) = self.smoothed {
            let deviation = duration_abs_diff(smoothed, adjusted);
            self.variance = weighted_duration(self.variance, 3, deviation, 1, 4);
            self.smoothed = Some(weighted_duration(smoothed, 7, adjusted, 1, 8));
        } else {
            self.smoothed = Some(raw);
            self.variance = div_duration(raw, 2);
        }
    }

    fn loss_delay(&self) -> Duration {
        let base = match (self.latest_raw, self.smoothed) {
            (Some(latest), Some(smoothed)) => latest.max(smoothed),
            _ => self.initial,
        };
        mul_ratio(base, TIME_THRESHOLD_NUMERATOR, TIME_THRESHOLD_DENOMINATOR).max(GRANULARITY)
    }

    fn pto(&self, max_ack_delay: Duration) -> Duration {
        let Some(smoothed) = self.smoothed else {
            return saturating_mul(self.initial, 2);
        };
        saturating_add(
            saturating_add(smoothed, saturating_mul(self.variance, 4).max(GRANULARITY)),
            max_ack_delay,
        )
    }

    fn reset(&mut self) {
        *self = Self::new(self.initial);
    }
}

#[derive(Clone, Debug, Default)]
struct PacketSpace {
    discarded: bool,
    outstanding: BTreeMap<u64, SentPacket>,
    sent: RangeSet,
    largest_sent: Option<u64>,
    largest_acked: Option<u64>,
    loss_time: Option<Duration>,
    ack_eliciting_in_flight: u64,
    last_ack_eliciting_sent: Option<Duration>,
    received: RangeSet,
    received_floor: u64,
    largest_received: Option<(u64, Duration)>,
    ack_deadline: Option<Duration>,
    ack_eliciting_since_ack: u8,
    ack_generation: u64,
    pending_ack_generation: Option<u64>,
    pc_start: Option<Duration>,
    pc_end: Option<Duration>,
}

#[derive(Clone, Debug)]
pub struct CongestionController {
    max_datagram_size: u64,
    bytes_in_flight: u64,
    congestion_window: u64,
    ssthresh: Option<u64>,
    recovery_start: Option<Duration>,
    last_ack: Option<Duration>,
    rtt: Duration,
    w_max: u64,
    w_est: f64,
    cubic_k: f64,
    epoch_start: Option<Duration>,
    first_slow_start: bool,
    start_congestion_avoidance: bool,
    hystart_enabled: bool,
    hystart_in_css: bool,
    hystart_css_round: u8,
    hystart_baseline: Option<Duration>,
    hystart_previous_round_min: Option<Duration>,
    hystart_current_round_min: Option<Duration>,
    hystart_samples: usize,
    hystart_window_end: Option<u64>,
    hystart_largest_sent: Option<u64>,
}

impl CongestionController {
    fn new(max_datagram_size: u64) -> Self {
        let congestion_window = initial_congestion_window(max_datagram_size);
        Self {
            max_datagram_size,
            bytes_in_flight: 0,
            congestion_window,
            ssthresh: None,
            recovery_start: None,
            last_ack: None,
            rtt: Duration::from_millis(20),
            w_max: congestion_window,
            w_est: 0.0,
            cubic_k: 0.0,
            epoch_start: None,
            first_slow_start: true,
            start_congestion_avoidance: false,
            hystart_enabled: true,
            hystart_in_css: false,
            hystart_css_round: 0,
            hystart_baseline: None,
            hystart_previous_round_min: None,
            hystart_current_round_min: None,
            hystart_samples: 0,
            hystart_window_end: None,
            hystart_largest_sent: None,
        }
    }

    pub fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    pub fn congestion_window(&self) -> u64 {
        self.congestion_window
    }

    #[cfg(test)]
    pub fn ssthresh(&self) -> Option<u64> {
        self.ssthresh
    }

    fn reset_hystart(&mut self) {
        self.hystart_in_css = false;
        self.hystart_css_round = 0;
        self.hystart_baseline = None;
        self.hystart_previous_round_min = None;
        self.hystart_current_round_min = None;
        self.hystart_samples = 0;
        self.hystart_window_end = None;
    }

    fn restart_after_idle(&mut self) {
        self.congestion_window = initial_congestion_window(self.max_datagram_size);
        self.ssthresh = None;
        self.w_max = self.congestion_window;
        self.w_est = 0.0;
        self.epoch_start = None;
        self.first_slow_start = true;
        self.start_congestion_avoidance = false;
        self.reset_hystart();
    }

    fn packet_sent(&mut self, packet: &SentPacket) {
        if !packet.is_pmtu_probe
            && self
                .last_ack
                .is_some_and(|last| packet.sent_time.saturating_sub(last) >= CUBIC_MAX_IDLE)
        {
            self.restart_after_idle();
        }
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(packet.sent_bytes);
        self.hystart_largest_sent = Some(
            self.hystart_largest_sent
                .map_or(packet.packet_number, |pn| pn.max(packet.packet_number)),
        );
        if self.hystart_enabled && self.ssthresh.is_none() && self.hystart_window_end.is_none() {
            self.hystart_window_end = Some(packet.packet_number);
        }
    }

    fn packet_acked(&mut self, packet: &SentPacket, now: Duration) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(packet.sent_bytes);
        self.last_ack = Some(now);
        if self
            .recovery_start
            .is_some_and(|recovery_start| packet.sent_time <= recovery_start)
        {
            return;
        }

        if self.hystart_enabled
            && self.ssthresh.is_none()
            && self
                .hystart_window_end
                .is_some_and(|end| packet.packet_number >= end)
        {
            self.hystart_previous_round_min = self.hystart_current_round_min.take();
            self.hystart_samples = 0;
            self.hystart_window_end = self.hystart_largest_sent.and_then(|pn| pn.checked_add(1));
            if self.hystart_in_css {
                self.hystart_css_round = self.hystart_css_round.saturating_add(1);
                if self.hystart_css_round >= HYSTART_CSS_ROUNDS {
                    self.ssthresh = Some(self.congestion_window);
                    self.hystart_in_css = false;
                }
            }
        }

        if self
            .ssthresh
            .map_or(true, |limit| self.congestion_window < limit)
        {
            let increase = if self.hystart_in_css {
                packet.sent_bytes / HYSTART_CSS_DIVISOR
            } else {
                packet.sent_bytes
            };
            self.congestion_window = self.congestion_window.saturating_add(increase);
            return;
        }

        if self.first_slow_start || self.start_congestion_avoidance {
            if self.first_slow_start && !self.start_congestion_avoidance {
                self.w_max = self.congestion_window;
            }
            self.first_slow_start = false;
            self.start_congestion_avoidance = false;
            self.start_epoch(now);
        }
        let cwnd = self.congestion_window.max(1) as f64;
        self.w_est += self.max_datagram_size as f64 * packet.sent_bytes as f64 / cwnd;
        let elapsed = now.saturating_sub(self.epoch_start.unwrap_or(now));
        let t = elapsed.as_secs_f64();
        let cubic_now = self.cubic_window(t);
        if cubic_now < self.w_est {
            self.congestion_window = float_to_u64(self.w_est).max(self.congestion_window);
        } else {
            let target = self
                .cubic_window(t + self.rtt.as_secs_f64())
                .clamp(cwnd, cwnd * 1.5);
            let increase = (target - cwnd).max(0.0) * self.max_datagram_size as f64 / cwnd;
            self.congestion_window = self
                .congestion_window
                .saturating_add(float_to_u64(increase));
        }
    }

    fn start_epoch(&mut self, now: Duration) {
        self.epoch_start = Some(now);
        self.w_est = self.congestion_window as f64;
        let w_max = self.w_max as f64 / self.max_datagram_size as f64;
        let cwnd = self.congestion_window as f64 / self.max_datagram_size as f64;
        self.cubic_k = ((w_max - cwnd) / CUBIC_C).cbrt();
    }

    fn cubic_window(&self, seconds: f64) -> f64 {
        let maximum = self.w_max as f64 / self.max_datagram_size as f64;
        (CUBIC_C * (seconds - self.cubic_k).powi(3) + maximum).max(0.0)
            * self.max_datagram_size as f64
    }

    fn packets_removed<'a>(&mut self, packets: impl IntoIterator<Item = &'a SentPacket>) {
        for packet in packets {
            if packet.in_flight {
                self.bytes_in_flight = self.bytes_in_flight.saturating_sub(packet.sent_bytes);
            }
        }
    }

    fn packets_lost(&mut self, packets: &[SentPacket], now: Duration) {
        let mut newest_sent = None;
        for packet in packets {
            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(packet.sent_bytes);
            newest_sent = Some(
                newest_sent.map_or(packet.sent_time, |old: Duration| old.max(packet.sent_time)),
            );
        }
        let starts_event =
            newest_sent.is_some_and(|sent| self.recovery_start.map_or(true, |start| sent > start));
        if starts_event {
            self.recovery_start = Some(now);
            self.w_max = if self.congestion_window < self.w_max {
                float_to_u64(self.congestion_window as f64 * (1.0 + CUBIC_BETA) / 2.0)
            } else {
                self.congestion_window
            };
            self.congestion_window = float_to_u64(self.congestion_window as f64 * CUBIC_BETA).max(
                self.max_datagram_size
                    .saturating_mul(MINIMUM_WINDOW_PACKETS),
            );
            self.ssthresh = Some(self.congestion_window);
            self.start_congestion_avoidance = true;
            self.hystart_in_css = false;
        }
    }

    fn rtt_sample(&mut self, sample: Duration) {
        self.rtt = sample;
        if !self.hystart_enabled || self.ssthresh.is_some() {
            return;
        }
        self.hystart_current_round_min = Some(
            self.hystart_current_round_min
                .map_or(sample, |minimum| minimum.min(sample)),
        );
        self.hystart_samples += 1;
        if self.hystart_samples < HYSTART_SAMPLES {
            return;
        }
        let (Some(previous), Some(current)) = (
            self.hystart_previous_round_min,
            self.hystart_current_round_min,
        ) else {
            return;
        };
        let threshold =
            div_duration(previous, 8).clamp(HYSTART_MIN_THRESHOLD, HYSTART_MAX_THRESHOLD);
        if self.hystart_in_css {
            if self
                .hystart_baseline
                .is_some_and(|baseline| current < baseline)
            {
                self.hystart_in_css = false;
                self.hystart_css_round = 0;
                self.hystart_baseline = None;
            }
        } else if current >= saturating_add(previous, threshold) {
            self.hystart_in_css = true;
            self.hystart_css_round = 0;
            self.hystart_baseline = Some(current);
        }
    }

    fn persistent_congestion(&mut self, now: Duration) {
        self.recovery_start = Some(now);
        self.congestion_window = self
            .max_datagram_size
            .saturating_mul(MINIMUM_WINDOW_PACKETS);
        self.ssthresh = None;
        self.w_max = self.congestion_window;
        self.w_est = 0.0;
        self.epoch_start = None;
        self.first_slow_start = true;
        self.start_congestion_avoidance = false;
        self.reset_hystart();
    }
}

/// Token-bucket pacer. A capacity of one congestion window permits an initial
/// burst while the steady-state rate is `cwnd / smoothed_rtt`.
#[derive(Clone, Debug)]
pub struct Pacer {
    max_datagram_size: u64,
    capacity: u64,
    tokens: f64,
    bytes_per_second: f64,
    last_update: Option<Duration>,
}

impl Pacer {
    fn new(max_datagram_size: u64) -> Self {
        Self {
            max_datagram_size,
            capacity: 0,
            tokens: 0.0,
            bytes_per_second: 0.0,
            last_update: None,
        }
    }

    pub fn start(&mut self, now: Duration, congestion_window: u64, rtt: Duration) {
        self.capacity = congestion_window.max(self.max_datagram_size);
        self.tokens = self.capacity as f64;
        self.last_update = Some(now);
        self.update_rate(congestion_window, rtt);
    }

    pub fn update_rate(&mut self, congestion_window: u64, rtt: Duration) {
        self.capacity = congestion_window.max(self.max_datagram_size);
        self.tokens = self.tokens.min(self.capacity as f64);
        self.bytes_per_second = if rtt.is_zero() {
            f64::INFINITY
        } else {
            congestion_window as f64 / rtt.as_secs_f64()
        };
    }

    fn refill(&mut self, now: Duration) {
        if let Some(last) = self.last_update {
            let elapsed = now.saturating_sub(last).as_secs_f64();
            self.tokens = (self.tokens + elapsed * self.bytes_per_second).min(self.capacity as f64);
        }
        self.last_update = Some(now.max(self.last_update.unwrap_or(now)));
    }

    pub fn poll(&mut self, now: Duration, bytes: u64) -> Option<Duration> {
        if bytes == 0 {
            return None;
        }
        self.refill(now);
        if self.tokens >= bytes as f64 {
            self.tokens -= bytes as f64;
            return None;
        }
        if !self.bytes_per_second.is_finite() || self.bytes_per_second <= 0.0 {
            return Some(Duration::MAX);
        }
        let wait =
            duration_from_secs_saturating((bytes as f64 - self.tokens) / self.bytes_per_second);
        Some(saturating_add(now, wait.max(Duration::from_micros(1))))
    }
}

#[derive(Clone, Debug)]
pub struct Recovery {
    spaces: [PacketSpace; 3],
    rtt: RttEstimator,
    congestion: CongestionController,
    pacer: Pacer,
    ack_delay: Duration,
    max_ack_delay: Duration,
    peer_completed_address_validation: bool,
    last_ack_eliciting_sent: Option<Duration>,
    pto_count: u32,
    pto_total: u64,
    loss_total: u64,
}

impl Recovery {
    pub fn new(config: RecoveryConfig) -> Result<Self, RecoveryError> {
        if config.initial_rtt.is_zero() {
            return Err(RecoveryError::InvalidConfiguration(
                "initial_rtt must be positive",
            ));
        }
        if config.max_datagram_size == 0 {
            return Err(RecoveryError::InvalidConfiguration(
                "max_datagram_size must be positive",
            ));
        }
        Ok(Self {
            spaces: array::from_fn(|_| PacketSpace::default()),
            rtt: RttEstimator::new(config.initial_rtt),
            congestion: CongestionController::new(config.max_datagram_size),
            pacer: Pacer::new(config.max_datagram_size),
            ack_delay: config.ack_delay,
            max_ack_delay: config.max_ack_delay,
            peer_completed_address_validation: config.peer_completed_address_validation,
            last_ack_eliciting_sent: None,
            pto_count: 0,
            pto_total: 0,
            loss_total: 0,
        })
    }

    pub fn rtt(&self) -> &RttEstimator {
        &self.rtt
    }

    pub fn congestion(&self) -> &CongestionController {
        &self.congestion
    }

    pub fn pacer_mut(&mut self) -> &mut Pacer {
        &mut self.pacer
    }

    pub fn pto_count(&self) -> u32 {
        self.pto_count
    }

    pub fn pto_total(&self) -> u64 {
        self.pto_total
    }

    pub fn loss_total(&self) -> u64 {
        self.loss_total
    }

    pub fn should_wait_for_ack(&self, now: Duration) -> bool {
        let outstanding = self
            .spaces
            .iter()
            .map(|space| space.ack_eliciting_in_flight)
            .sum::<u64>();
        outstanding >= 2
            || (outstanding == 1
                && self
                    .last_ack_eliciting_sent
                    .is_some_and(|sent| saturating_add(sent, self.max_ack_delay) <= now))
    }

    pub fn outstanding_packets(
        &self,
        space: PacketNumberSpace,
    ) -> impl Iterator<Item = &SentPacket> {
        self.spaces[space.index()].outstanding.values()
    }

    pub fn expected_packet_number(&self, space: PacketNumberSpace) -> u64 {
        self.largest_received(space).map_or(0, |pn| pn + 1)
    }

    pub fn restore_sent_packet_numbers(
        &mut self,
        space: PacketNumberSpace,
        next_packet_number: u64,
    ) -> Result<(), RecoveryError> {
        if next_packet_number > MAX_PACKET_NUMBER + 1 {
            return Err(RecoveryError::PacketNumberOutOfRange(next_packet_number));
        }
        let state = &mut self.spaces[space.index()];
        state.sent = RangeSet::new();
        if next_packet_number != 0 {
            state
                .sent
                .add(0, next_packet_number)
                .map_err(|_| RecoveryError::PacketNumberOutOfRange(next_packet_number))?;
        }
        state.largest_sent = next_packet_number.checked_sub(1);
        Ok(())
    }

    pub fn largest_received(&self, space: PacketNumberSpace) -> Option<u64> {
        let space = &self.spaces[space.index()];
        if space.discarded {
            return None;
        }
        space.largest_received.map(|(pn, _)| pn)
    }

    pub fn is_packet_received(&self, space: PacketNumberSpace, packet_number: u64) -> bool {
        let space = &self.spaces[space.index()];
        !space.discarded
            && (packet_number < space.received_floor || space.received.contains(packet_number))
    }

    pub fn set_peer_completed_address_validation(&mut self, completed: bool) {
        self.peer_completed_address_validation = completed;
    }

    pub fn set_max_ack_delay(&mut self, delay: Duration) {
        self.max_ack_delay = delay;
    }

    pub fn set_max_datagram_size(&mut self, size: u64) {
        self.congestion.max_datagram_size = size;
        self.pacer.max_datagram_size = size;
    }

    pub fn reset_for_new_path(
        &mut self,
        previous_path_id: u64,
        path_id: u64,
        retain_congestion: bool,
    ) {
        if retain_congestion {
            for space in &mut self.spaces {
                for packet in space.outstanding.values_mut() {
                    if packet.path_id == previous_path_id {
                        packet.path_id = path_id;
                    }
                }
            }
            return;
        }

        self.rtt.reset();
        for space in &mut self.spaces {
            for packet in space.outstanding.values_mut() {
                if packet.path_id != path_id {
                    packet.in_flight = false;
                }
            }
        }
        let max_datagram_size = self.congestion.max_datagram_size;
        let bytes_in_flight = self
            .spaces
            .iter()
            .flat_map(|space| space.outstanding.values())
            .filter(|packet| packet.path_id == path_id && packet.in_flight)
            .map(|packet| packet.sent_bytes)
            .sum();
        self.congestion = CongestionController::new(max_datagram_size);
        self.congestion.bytes_in_flight = bytes_in_flight;
        self.pacer = Pacer::new(max_datagram_size);
        for space in &mut self.spaces {
            space.ack_eliciting_in_flight = space
                .outstanding
                .values()
                .filter(|packet| {
                    packet.path_id == path_id
                        && packet.ack_eliciting
                        && packet.in_flight
                        && !packet.is_pmtu_probe
                })
                .count() as u64;
            space.last_ack_eliciting_sent = space
                .outstanding
                .values()
                .filter(|packet| {
                    packet.path_id == path_id
                        && packet.ack_eliciting
                        && packet.in_flight
                        && !packet.is_pmtu_probe
                })
                .map(|packet| packet.sent_time)
                .max();
            space.loss_time = None;
            space.pc_start = None;
            space.pc_end = None;
        }
        self.last_ack_eliciting_sent = self
            .spaces
            .iter()
            .filter_map(|space| space.last_ack_eliciting_sent)
            .max();
        self.pto_count = 0;
    }

    pub fn start_pacing(&mut self, now: Duration) {
        let rtt = self
            .rtt
            .smoothed()
            .unwrap_or(mul_ratio(self.rtt.initial, 4, 5));
        self.pacer
            .start(now, self.congestion.congestion_window, rtt);
    }

    pub fn on_packet_sent(
        &mut self,
        space_id: PacketNumberSpace,
        packet: SentPacket,
    ) -> Result<(), RecoveryError> {
        if packet.packet_number > MAX_PACKET_NUMBER {
            return Err(RecoveryError::PacketNumberOutOfRange(packet.packet_number));
        }
        let space = &self.spaces[space_id.index()];
        if space.discarded {
            return Err(RecoveryError::DiscardedSpace(space_id));
        }
        if space.sent.contains(packet.packet_number) {
            return Err(RecoveryError::DuplicatePacketNumber {
                space: space_id,
                packet_number: packet.packet_number,
            });
        }
        if space
            .largest_sent
            .is_some_and(|largest| packet.packet_number <= largest)
        {
            return Err(RecoveryError::PacketNumberRegression {
                space: space_id,
                packet_number: packet.packet_number,
            });
        }

        let tracks_pto = packet.ack_eliciting && packet.in_flight && !packet.is_pmtu_probe;
        if packet.in_flight {
            self.congestion.packet_sent(&packet);
        }
        if tracks_pto {
            self.last_ack_eliciting_sent = Some(packet.sent_time);
        }
        let space = &mut self.spaces[space_id.index()];
        if tracks_pto {
            space.ack_eliciting_in_flight = space.ack_eliciting_in_flight.saturating_add(1);
            space.last_ack_eliciting_sent = Some(packet.sent_time);
        }
        space.largest_sent = Some(packet.packet_number);
        space
            .sent
            .add(packet.packet_number, packet.packet_number + 1)
            .map_err(|_| RecoveryError::PacketNumberOutOfRange(packet.packet_number))?;
        if packet.in_flight
            || packet.ack_eliciting
            || packet.is_pmtu_probe
            || !packet.delivery_actions.is_empty()
        {
            space.outstanding.insert(packet.packet_number, packet);
        }
        Ok(())
    }

    /// Records a received packet and updates delayed-ACK state. Returns true
    /// only when this packet number was new.
    pub fn on_packet_received(
        &mut self,
        space_id: PacketNumberSpace,
        packet_number: u64,
        ack_eliciting: bool,
        now: Duration,
    ) -> Result<bool, RecoveryError> {
        if packet_number > MAX_PACKET_NUMBER {
            return Err(RecoveryError::PacketNumberOutOfRange(packet_number));
        }
        let space = &mut self.spaces[space_id.index()];
        if space.discarded {
            return Err(RecoveryError::DiscardedSpace(space_id));
        }
        if packet_number < space.received_floor || space.received.contains(packet_number) {
            return Ok(false);
        }
        space
            .received
            .add(packet_number, packet_number + 1)
            .map_err(|_| RecoveryError::PacketNumberOutOfRange(packet_number))?;
        if let Some(floor) = space.received.retain_last(MAX_RECEIVED_RANGES) {
            space.received_floor = space.received_floor.max(floor);
        }
        if space
            .largest_received
            .map_or(true, |(largest, _)| packet_number > largest)
        {
            space.largest_received = Some((packet_number, now));
        }
        if ack_eliciting {
            space.ack_eliciting_since_ack = space.ack_eliciting_since_ack.saturating_add(1);
            space.ack_generation = space.ack_generation.wrapping_add(1);
            let deadline = if space_id != PacketNumberSpace::ApplicationData
                || space.ack_eliciting_since_ack >= DEFAULT_ACK_FREQUENCY
            {
                now
            } else {
                saturating_add(now, self.ack_delay)
            };
            space.ack_deadline = Some(space.ack_deadline.map_or(deadline, |old| old.min(deadline)));
        }
        Ok(true)
    }

    pub fn ack_deadline(&self, space: PacketNumberSpace) -> Option<Duration> {
        self.spaces[space.index()].ack_deadline
    }

    pub fn expedite_ack(&mut self, space: PacketNumberSpace, now: Duration) {
        let state = &mut self.spaces[space.index()];
        if !state.discarded && !state.received.is_empty() {
            state.ack_deadline = Some(state.ack_deadline.map_or(now, |old| old.min(now)));
        }
    }

    /// Returns a due ACK without consuming it. Call [`Self::commit_ack`] only
    /// after the ACK has been successfully added to an outgoing packet.
    pub fn peek_ack(&mut self, space_id: PacketNumberSpace, now: Duration) -> Option<AckToSend> {
        let space = &mut self.spaces[space_id.index()];
        if space.discarded {
            return None;
        }
        let deadline = space.ack_deadline?;
        if deadline > now {
            return None;
        }
        let (largest, received_time) = space.largest_received?;
        space.pending_ack_generation = Some(space.ack_generation);
        Some(AckToSend {
            largest,
            ack_delay: now.saturating_sub(received_time),
            ranges: packet_ranges(&space.received),
        })
    }

    /// Commits the most recently peeked ACK. Returns false if new
    /// ACK-eliciting input arrived after it was peeked or no ACK was peeked.
    pub fn commit_ack(&mut self, space_id: PacketNumberSpace) -> bool {
        let space = &mut self.spaces[space_id.index()];
        let Some(generation) = space.pending_ack_generation.take() else {
            return false;
        };
        if space.discarded || generation != space.ack_generation {
            return false;
        }
        space.ack_deadline = None;
        space.ack_eliciting_since_ack = 0;
        true
    }

    pub fn acknowledge_ack(
        &mut self,
        space_id: PacketNumberSpace,
        highest_acked: u64,
    ) -> Result<(), RecoveryError> {
        let end = highest_acked
            .checked_add(1)
            .ok_or(RecoveryError::PacketNumberOutOfRange(highest_acked))?;
        let space = &mut self.spaces[space_id.index()];
        if space.discarded {
            return Err(RecoveryError::DiscardedSpace(space_id));
        }
        space.received_floor = space.received_floor.max(end);
        space
            .received
            .subtract(0, end)
            .map_err(|_| RecoveryError::MalformedAckRanges)
    }

    /// Compatibility helper that immediately commits a due ACK.
    #[cfg(test)]
    pub fn take_ack(&mut self, space_id: PacketNumberSpace, now: Duration) -> Option<AckToSend> {
        let ack = self.peek_ack(space_id, now)?;
        debug_assert!(self.commit_ack(space_id));
        Some(ack)
    }

    pub fn on_ack_received(
        &mut self,
        space_id: PacketNumberSpace,
        ranges: &[AckRange],
        ack_delay: Duration,
        now: Duration,
        reset_pto_count: bool,
    ) -> Result<Vec<RecoveryEvent>, RecoveryError> {
        self.validate_ack(space_id, ranges)?;
        let largest_acked = ranges.last().ok_or(RecoveryError::EmptyAck)?.end - 1;
        let packet_numbers: Vec<u64> = self.spaces[space_id.index()]
            .outstanding
            .range(..=largest_acked)
            .filter_map(|(&pn, _)| ranges_contain(ranges, pn).then_some(pn))
            .collect();
        self.spaces[space_id.index()].largest_acked = Some(
            self.spaces[space_id.index()]
                .largest_acked
                .map_or(largest_acked, |old| old.max(largest_acked)),
        );

        let mut events = Vec::new();
        let mut largest_newly_acked = None;
        let mut rtt_packet = None;
        for packet_number in packet_numbers {
            let Some(packet) = self.spaces[space_id.index()]
                .outstanding
                .remove(&packet_number)
            else {
                continue;
            };
            if packet.ack_eliciting && !packet.is_pmtu_probe && packet.in_flight {
                let space = &mut self.spaces[space_id.index()];
                space.ack_eliciting_in_flight = space.ack_eliciting_in_flight.saturating_sub(1);
                space.pc_start = None;
                space.pc_end = None;
            }
            if packet.in_flight {
                self.congestion.packet_acked(&packet, now);
            }
            if packet.in_flight && packet.ack_eliciting && packet.packet_number == largest_acked {
                rtt_packet = Some(packet.sent_time);
            }
            largest_newly_acked = Some(packet.packet_number);
            append_delivery_events(&mut events, space_id, &packet, DeliveryOutcome::Acked);
            if packet.is_pmtu_probe {
                events.push(RecoveryEvent::PmtuProbeAcked {
                    space: space_id,
                    packet_number,
                    path_id: packet.path_id,
                    sent_bytes: packet.sent_bytes,
                });
            }
        }
        if largest_newly_acked.is_none() {
            return Ok(events);
        }

        if let Some(sent_time) = rtt_packet {
            let sample = now
                .checked_sub(sent_time)
                .ok_or(RecoveryError::InvalidTime)?;
            self.rtt.update(sample, ack_delay, self.max_ack_delay);
            self.congestion.rtt_sample(sample);
            self.pacer.update_rate(
                self.congestion.congestion_window,
                self.rtt.smoothed().unwrap_or(self.rtt.initial),
            );
        }
        events.extend(self.detect_loss(space_id, now)?);
        if reset_pto_count {
            self.pto_count = 0;
        }
        Ok(events)
    }

    fn validate_ack(
        &self,
        space_id: PacketNumberSpace,
        ranges: &[AckRange],
    ) -> Result<(), RecoveryError> {
        let space = &self.spaces[space_id.index()];
        if space.discarded {
            return Err(RecoveryError::DiscardedSpace(space_id));
        }
        if ranges.is_empty() {
            return Err(RecoveryError::EmptyAck);
        }
        let mut previous_end = None;
        for range in ranges {
            if range.start >= range.end
                || range.end > MAX_PACKET_NUMBER + 1
                || previous_end.is_some_and(|end| range.start < end)
            {
                return Err(RecoveryError::MalformedAckRanges);
            }
            previous_end = Some(range.end);
        }
        for range in ranges {
            let covering = space
                .sent
                .iter()
                .find(|sent| sent.start <= range.start && range.start < sent.end);
            if !covering.is_some_and(|sent| range.end <= sent.end) {
                let missing = covering.map_or(range.start, |sent| sent.end.min(range.end));
                return Err(RecoveryError::AckOfUnsentPacket {
                    space: space_id,
                    packet_number: missing,
                });
            }
        }
        Ok(())
    }

    pub fn detect_loss(
        &mut self,
        space_id: PacketNumberSpace,
        now: Duration,
    ) -> Result<Vec<RecoveryEvent>, RecoveryError> {
        let Some(largest_acked) = self.spaces[space_id.index()].largest_acked else {
            return Ok(Vec::new());
        };
        let loss_delay = self.rtt.loss_delay();
        let threshold_time = now.saturating_sub(loss_delay);
        let mut loss_time = None;
        let mut lost_numbers = Vec::new();
        for (&pn, packet) in self.spaces[space_id.index()]
            .outstanding
            .range(..=largest_acked)
        {
            let packet_threshold = pn
                .checked_add(PACKET_THRESHOLD)
                .is_some_and(|threshold| threshold <= largest_acked);
            if packet_threshold || packet.sent_time <= threshold_time {
                lost_numbers.push(pn);
            } else {
                let candidate = saturating_add(packet.sent_time, loss_delay);
                loss_time = Some(loss_time.map_or(candidate, |old: Duration| old.min(candidate)));
            }
        }
        self.spaces[space_id.index()].loss_time = loss_time;
        self.remove_lost(space_id, &lost_numbers, now)
    }

    fn remove_lost(
        &mut self,
        space_id: PacketNumberSpace,
        packet_numbers: &[u64],
        now: Duration,
    ) -> Result<Vec<RecoveryEvent>, RecoveryError> {
        let mut events = Vec::new();
        let mut congestion_packets = Vec::new();
        for &packet_number in packet_numbers {
            let Some(packet) = self.spaces[space_id.index()]
                .outstanding
                .remove(&packet_number)
            else {
                continue;
            };
            self.loss_total = self.loss_total.saturating_add(1);
            if packet.ack_eliciting && !packet.is_pmtu_probe && packet.in_flight {
                let space = &mut self.spaces[space_id.index()];
                space.ack_eliciting_in_flight = space.ack_eliciting_in_flight.saturating_sub(1);
                space.pc_start = Some(
                    space
                        .pc_start
                        .map_or(packet.sent_time, |old| old.min(packet.sent_time)),
                );
                space.pc_end = Some(
                    space
                        .pc_end
                        .map_or(packet.sent_time, |old| old.max(packet.sent_time)),
                );
            }
            if packet.in_flight {
                if packet.is_pmtu_probe {
                    self.congestion.bytes_in_flight = self
                        .congestion
                        .bytes_in_flight
                        .saturating_sub(packet.sent_bytes);
                } else {
                    congestion_packets.push(packet.clone());
                }
            }
            append_delivery_events(&mut events, space_id, &packet, DeliveryOutcome::Lost);
            if packet.is_pmtu_probe {
                events.push(RecoveryEvent::PmtuProbeLost {
                    space: space_id,
                    packet_number,
                    path_id: packet.path_id,
                    sent_bytes: packet.sent_bytes,
                });
            }
        }
        if !congestion_packets.is_empty() {
            self.congestion.packets_lost(&congestion_packets, now);
            let space = &self.spaces[space_id.index()];
            if self.rtt.initialized()
                && space
                    .pc_start
                    .zip(space.pc_end)
                    .is_some_and(|(start, end)| {
                        end.saturating_sub(start)
                            > saturating_mul(
                                self.probe_timeout_for(space_id),
                                PERSISTENT_CONGESTION_THRESHOLD,
                            )
                    })
            {
                self.congestion.persistent_congestion(now);
                let space = &mut self.spaces[space_id.index()];
                space.pc_start = None;
                space.pc_end = None;
            }
            self.pacer.update_rate(
                self.congestion.congestion_window,
                self.rtt.smoothed().unwrap_or(self.rtt.initial),
            );
        }
        Ok(events)
    }

    pub fn expire_pmtu_probe(
        &mut self,
        space: PacketNumberSpace,
        packet_number: u64,
        now: Duration,
    ) -> Result<Vec<RecoveryEvent>, RecoveryError> {
        if !self.spaces[space.index()]
            .outstanding
            .get(&packet_number)
            .is_some_and(|packet| packet.is_pmtu_probe)
        {
            return Ok(Vec::new());
        }
        self.remove_lost(space, &[packet_number], now)
    }

    pub fn probe_timeout(&self) -> Duration {
        self.rtt.pto(self.max_ack_delay)
    }

    pub fn probe_timeout_for(&self, space: PacketNumberSpace) -> Duration {
        self.rtt
            .pto(if space == PacketNumberSpace::ApplicationData {
                self.max_ack_delay
            } else {
                Duration::ZERO
            })
    }

    pub fn loss_detection_time(&self) -> Option<Duration> {
        if let Some(loss_time) = self.spaces.iter().filter_map(|space| space.loss_time).min() {
            return Some(loss_time);
        }
        self.spaces
            .iter()
            .enumerate()
            .filter(|(_, space)| {
                !space.discarded
                    && (!self.peer_completed_address_validation
                        || space.ack_eliciting_in_flight > 0)
            })
            .filter_map(|(index, space)| {
                let id = PACKET_SPACES[index];
                space.last_ack_eliciting_sent.map(|sent| {
                    saturating_add(
                        sent,
                        saturating_mul_pow2(self.probe_timeout_for(id), self.pto_count),
                    )
                })
            })
            .min()
    }

    pub fn on_loss_detection_timeout(
        &mut self,
        now: Duration,
    ) -> Result<Vec<RecoveryEvent>, RecoveryError> {
        if let Some((space_id, _)) = PACKET_SPACES
            .iter()
            .filter_map(|&id| self.spaces[id.index()].loss_time.map(|time| (id, time)))
            .min_by_key(|(_, time)| *time)
        {
            return self.detect_loss(space_id, now);
        }
        self.pto_count = self.pto_count.saturating_add(1);
        self.pto_total = self.pto_total.saturating_add(1);
        let probe_space = PACKET_SPACES
            .iter()
            .copied()
            .filter(|&id| self.spaces[id.index()].ack_eliciting_in_flight > 0)
            .filter_map(|id| {
                self.spaces[id.index()]
                    .last_ack_eliciting_sent
                    .map(|sent| (id, sent))
            })
            .min_by_key(|(_, sent)| *sent)
            .map(|(id, _)| id)
            .or_else(|| {
                PACKET_SPACES
                    .iter()
                    .rev()
                    .copied()
                    .find(|&id| !self.spaces[id.index()].discarded)
            })
            .unwrap_or(PacketNumberSpace::ApplicationData);
        let mut events = self.probe_copies(probe_space, 2);
        events.push(RecoveryEvent::SendProbe { space: probe_space });
        events.push(RecoveryEvent::SendProbe { space: probe_space });
        Ok(events)
    }

    fn probe_copies(&self, space_id: PacketNumberSpace, limit: usize) -> Vec<RecoveryEvent> {
        let mut selected = Vec::new();
        let byte_limit = self
            .congestion
            .max_datagram_size
            .saturating_mul(limit as u64);
        let mut selected_bytes = 0_u64;
        for packet in self.spaces[space_id.index()]
            .outstanding
            .values()
            .filter(|packet| packet.is_crypto)
        {
            if selected_bytes != 0 && selected_bytes.saturating_add(packet.sent_bytes) > byte_limit
            {
                break;
            }
            append_delivery_events(&mut selected, space_id, packet, DeliveryOutcome::ProbeCopy);
            selected_bytes = selected_bytes.saturating_add(packet.sent_bytes);
            if selected_bytes >= byte_limit {
                return selected;
            }
        }
        if !selected.is_empty() {
            return selected;
        }
        for packet in self.spaces[space_id.index()]
            .outstanding
            .values()
            .filter(|packet| packet.in_flight && packet.ack_eliciting)
        {
            if selected_bytes != 0 && selected_bytes.saturating_add(packet.sent_bytes) > byte_limit
            {
                break;
            }
            append_delivery_events(&mut selected, space_id, packet, DeliveryOutcome::ProbeCopy);
            selected_bytes = selected_bytes.saturating_add(packet.sent_bytes);
            if selected_bytes >= byte_limit {
                break;
            }
        }
        selected
    }

    pub fn retire_and_retransmit(
        &mut self,
        space_id: PacketNumberSpace,
        packet_numbers: &[u64],
    ) -> Result<Vec<RecoveryEvent>, RecoveryError> {
        let mut packets = Vec::new();
        for &pn in packet_numbers {
            if let Some(packet) = self.spaces[space_id.index()].outstanding.remove(&pn) {
                if packet.ack_eliciting && !packet.is_pmtu_probe && packet.in_flight {
                    self.spaces[space_id.index()].ack_eliciting_in_flight = self.spaces
                        [space_id.index()]
                    .ack_eliciting_in_flight
                    .saturating_sub(1);
                }
                packets.push(packet);
            }
        }
        self.congestion.packets_removed(&packets);
        let mut events = Vec::new();
        for packet in packets {
            append_delivery_events(
                &mut events,
                space_id,
                &packet,
                DeliveryOutcome::RetireAndRetransmit,
            );
        }
        Ok(events)
    }

    pub fn reject_zero_rtt(&mut self) -> Vec<RecoveryEvent> {
        let packet_numbers: Vec<_> = self.spaces[PacketNumberSpace::ApplicationData.index()]
            .outstanding
            .values()
            .filter(|packet| packet.packet_type == super::types::PacketType::ZeroRtt)
            .map(|packet| packet.packet_number)
            .collect();
        self.retire_and_retransmit(PacketNumberSpace::ApplicationData, &packet_numbers)
            .unwrap_or_default()
    }

    pub fn discard_space(&mut self, space_id: PacketNumberSpace) -> Vec<RecoveryEvent> {
        let outstanding = std::mem::take(&mut self.spaces[space_id.index()].outstanding);
        self.congestion.packets_removed(outstanding.values());
        let mut events = Vec::new();
        for packet in outstanding.values() {
            append_delivery_events(&mut events, space_id, packet, DeliveryOutcome::Discarded);
        }
        self.spaces[space_id.index()] = PacketSpace {
            discarded: true,
            ..PacketSpace::default()
        };
        self.last_ack_eliciting_sent = self
            .spaces
            .iter()
            .filter(|space| !space.discarded)
            .filter_map(|space| space.last_ack_eliciting_sent)
            .max();
        self.pto_count = 0;
        events
    }
}

fn append_delivery_events(
    events: &mut Vec<RecoveryEvent>,
    space: PacketNumberSpace,
    packet: &SentPacket,
    outcome: DeliveryOutcome,
) {
    events.extend(packet.delivery_actions.iter().map(|&id| {
        RecoveryEvent::Delivery(DeliveryAction {
            id,
            outcome,
            space,
            packet_number: packet.packet_number,
        })
    }));
}

fn ranges_contain(ranges: &[AckRange], packet_number: u64) -> bool {
    ranges
        .iter()
        .any(|range| range.start <= packet_number && packet_number < range.end)
}

fn packet_ranges(packet_numbers: &RangeSet) -> Vec<AckRange> {
    packet_numbers
        .iter()
        .map(|range| AckRange::new(range.start, range.end))
        .collect()
}

fn initial_congestion_window(max_datagram_size: u64) -> u64 {
    max_datagram_size
        .saturating_mul(INITIAL_WINDOW_PACKETS)
        .min(
            max_datagram_size
                .saturating_mul(MINIMUM_WINDOW_PACKETS)
                .max(INITIAL_WINDOW_MINIMUM),
        )
}

fn duration_abs_diff(a: Duration, b: Duration) -> Duration {
    if a >= b {
        a - b
    } else {
        b - a
    }
}

fn saturating_add(a: Duration, b: Duration) -> Duration {
    a.checked_add(b).unwrap_or(Duration::MAX)
}

fn saturating_mul(duration: Duration, factor: u32) -> Duration {
    duration.checked_mul(factor).unwrap_or(Duration::MAX)
}

fn saturating_mul_pow2(duration: Duration, exponent: u32) -> Duration {
    if exponent >= 32 {
        Duration::MAX
    } else {
        saturating_mul(duration, 1_u32 << exponent)
    }
}

fn div_duration(duration: Duration, divisor: u32) -> Duration {
    Duration::from_nanos((duration.as_nanos() / divisor as u128).min(u64::MAX as u128) as u64)
}

fn mul_ratio(duration: Duration, numerator: u32, denominator: u32) -> Duration {
    let nanos = duration.as_nanos().saturating_mul(numerator as u128) / denominator as u128;
    Duration::from_nanos(nanos.min(u64::MAX as u128) as u64)
}

fn weighted_duration(a: Duration, aw: u32, b: Duration, bw: u32, divisor: u32) -> Duration {
    let nanos = a
        .as_nanos()
        .saturating_mul(aw as u128)
        .saturating_add(b.as_nanos().saturating_mul(bw as u128))
        / divisor as u128;
    Duration::from_nanos(nanos.min(u64::MAX as u128) as u64)
}

fn duration_from_secs_saturating(seconds: f64) -> Duration {
    if !seconds.is_finite() || seconds >= Duration::MAX.as_secs_f64() {
        Duration::MAX
    } else if seconds <= 0.0 {
        Duration::ZERO
    } else {
        Duration::from_secs_f64(seconds)
    }
}

fn float_to_u64(value: f64) -> u64 {
    if !value.is_finite() || value >= u64::MAX as f64 {
        u64::MAX
    } else if value <= 0.0 {
        0
    } else {
        value as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recovery() -> Recovery {
        Recovery::new(RecoveryConfig {
            initial_rtt: Duration::from_millis(100),
            ack_delay: Duration::from_millis(1),
            max_ack_delay: Duration::from_millis(25),
            max_datagram_size: 1200,
            peer_completed_address_validation: true,
        })
        .unwrap()
    }

    fn packet(number: u64, millis: u64) -> SentPacket {
        SentPacket {
            packet_number: number,
            path_id: 0,
            sent_time: Duration::from_millis(millis),
            sent_bytes: 1200,
            ack_eliciting: true,
            in_flight: true,
            is_crypto: false,
            is_pmtu_probe: false,
            packet_type: crate::quic::types::PacketType::OneRtt,
            delivery_actions: vec![DeliveryId(number + 100)],
        }
    }

    fn outcomes(events: &[RecoveryEvent], outcome: DeliveryOutcome) -> usize {
        events
            .iter()
            .filter(|event| matches!(event, RecoveryEvent::Delivery(action) if action.outcome == outcome))
            .count()
    }

    #[test]
    fn ack_updates_rtt_cwnd_and_typed_action() {
        let mut r = recovery();
        r.on_packet_sent(PacketNumberSpace::ApplicationData, packet(0, 1000))
            .unwrap();
        let events = r
            .on_ack_received(
                PacketNumberSpace::ApplicationData,
                &[AckRange::new(0, 1)],
                Duration::from_millis(10),
                Duration::from_millis(1100),
                true,
            )
            .unwrap();
        assert_eq!(outcomes(&events, DeliveryOutcome::Acked), 1);
        assert_eq!(r.rtt.smoothed(), Some(Duration::from_millis(100)));
        assert_eq!(r.congestion.congestion_window(), 13_200);
        assert_eq!(r.congestion.bytes_in_flight(), 0);
    }

    #[test]
    fn ack_wait_heuristic_uses_packet_count_and_peer_delay() {
        let mut r = recovery();
        assert!(!r.should_wait_for_ack(Duration::from_millis(1000)));

        r.on_packet_sent(PacketNumberSpace::ApplicationData, packet(0, 1000))
            .unwrap();
        assert!(!r.should_wait_for_ack(Duration::from_millis(1024)));
        assert!(r.should_wait_for_ack(Duration::from_millis(1025)));

        r.on_packet_sent(PacketNumberSpace::Handshake, packet(1, 1010))
            .unwrap();
        assert!(r.should_wait_for_ack(Duration::from_millis(1010)));
    }

    #[test]
    fn packet_threshold_loss() {
        let mut r = recovery();
        for pn in 0..=3 {
            r.on_packet_sent(PacketNumberSpace::ApplicationData, packet(pn, 1000))
                .unwrap();
        }
        let events = r
            .on_ack_received(
                PacketNumberSpace::ApplicationData,
                &[AckRange::new(3, 4)],
                Duration::ZERO,
                Duration::from_millis(1001),
                true,
            )
            .unwrap();
        assert_eq!(outcomes(&events, DeliveryOutcome::Lost), 1);
        assert_eq!(r.loss_total(), 1);
        assert_eq!(r.congestion.congestion_window(), 9240);
    }

    #[test]
    fn time_threshold_sets_timer_then_loses() {
        let mut r = recovery();
        r.rtt
            .update(Duration::from_millis(100), Duration::ZERO, Duration::ZERO);
        r.on_packet_sent(PacketNumberSpace::ApplicationData, packet(0, 1000))
            .unwrap();
        r.on_packet_sent(PacketNumberSpace::ApplicationData, packet(1, 1010))
            .unwrap();
        r.on_ack_received(
            PacketNumberSpace::ApplicationData,
            &[AckRange::new(1, 2)],
            Duration::ZERO,
            Duration::from_millis(1020),
            true,
        )
        .unwrap();
        let deadline = r.loss_detection_time().unwrap();
        assert!(deadline > Duration::from_millis(1020));
        let events = r.on_loss_detection_timeout(deadline).unwrap();
        assert_eq!(outcomes(&events, DeliveryOutcome::Lost), 1);
    }

    #[test]
    fn malformed_and_unsent_ack_are_atomic() {
        let mut r = recovery();
        r.on_packet_sent(PacketNumberSpace::Initial, packet(0, 1))
            .unwrap();
        r.on_packet_sent(PacketNumberSpace::Initial, packet(2, 2))
            .unwrap();
        assert_eq!(
            r.on_ack_received(
                PacketNumberSpace::Initial,
                &[AckRange::new(1, 2), AckRange::new(0, 1)],
                Duration::ZERO,
                Duration::from_millis(10),
                true
            ),
            Err(RecoveryError::MalformedAckRanges)
        );
        assert_eq!(
            r.on_ack_received(
                PacketNumberSpace::Initial,
                &[AckRange::new(0, 3)],
                Duration::ZERO,
                Duration::from_millis(10),
                true
            ),
            Err(RecoveryError::AckOfUnsentPacket {
                space: PacketNumberSpace::Initial,
                packet_number: 1
            })
        );
        assert_eq!(r.outstanding_packets(PacketNumberSpace::Initial).count(), 2);
    }

    #[test]
    fn restored_packet_number_history_is_range_bounded() {
        let mut r = recovery();
        r.restore_sent_packet_numbers(PacketNumberSpace::Initial, 1_000_000)
            .unwrap();

        assert_eq!(r.spaces[PacketNumberSpace::Initial.index()].sent.len(), 1);
        assert!(r
            .on_ack_received(
                PacketNumberSpace::Initial,
                &[AckRange::new(999_999, 1_000_000)],
                Duration::ZERO,
                Duration::from_millis(1),
                true,
            )
            .is_ok());
        assert_eq!(
            r.on_ack_received(
                PacketNumberSpace::Initial,
                &[AckRange::new(1_000_000, 1_000_001)],
                Duration::ZERO,
                Duration::from_millis(1),
                true,
            ),
            Err(RecoveryError::AckOfUnsentPacket {
                space: PacketNumberSpace::Initial,
                packet_number: 1_000_000,
            })
        );
    }

    #[test]
    fn receive_ack_scheduling_handles_delay_and_reordering() {
        let mut r = recovery();
        assert!(r
            .on_packet_received(
                PacketNumberSpace::ApplicationData,
                0,
                true,
                Duration::from_millis(10)
            )
            .unwrap());
        assert_eq!(
            r.ack_deadline(PacketNumberSpace::ApplicationData),
            Some(Duration::from_millis(11))
        );
        assert!(r
            .take_ack(
                PacketNumberSpace::ApplicationData,
                Duration::from_millis(10)
            )
            .is_none());
        r.on_packet_received(
            PacketNumberSpace::ApplicationData,
            2,
            true,
            Duration::from_millis(20),
        )
        .unwrap();
        assert_eq!(
            r.ack_deadline(PacketNumberSpace::ApplicationData),
            Some(Duration::from_millis(11))
        );
        let ack = r
            .take_ack(
                PacketNumberSpace::ApplicationData,
                Duration::from_millis(20),
            )
            .unwrap();
        assert_eq!(ack.largest, 2);
        assert_eq!(ack.ack_delay, Duration::ZERO);
        assert_eq!(ack.ranges, vec![AckRange::new(0, 1), AckRange::new(2, 3)]);
    }

    #[test]
    fn second_application_packet_makes_ack_immediate() {
        let mut r = recovery();
        for packet_number in 0..2 {
            r.on_packet_received(
                PacketNumberSpace::ApplicationData,
                packet_number,
                true,
                Duration::from_millis(10),
            )
            .unwrap();
        }

        assert_eq!(
            r.ack_deadline(PacketNumberSpace::ApplicationData),
            Some(Duration::from_millis(10))
        );
    }

    #[test]
    fn receive_queries_track_packet_number_state() {
        let mut r = recovery();
        assert_eq!(r.expected_packet_number(PacketNumberSpace::Handshake), 0);
        assert_eq!(r.largest_received(PacketNumberSpace::Handshake), None);
        assert!(!r.is_packet_received(PacketNumberSpace::Handshake, 4));

        r.on_packet_received(
            PacketNumberSpace::Handshake,
            4,
            false,
            Duration::from_millis(10),
        )
        .unwrap();
        r.on_packet_received(
            PacketNumberSpace::Handshake,
            2,
            false,
            Duration::from_millis(11),
        )
        .unwrap();

        assert_eq!(r.expected_packet_number(PacketNumberSpace::Handshake), 5);
        assert_eq!(r.largest_received(PacketNumberSpace::Handshake), Some(4));
        assert!(r.is_packet_received(PacketNumberSpace::Handshake, 2));
        assert!(!r.is_packet_received(PacketNumberSpace::Handshake, 3));
    }

    #[test]
    fn ack_is_not_consumed_until_committed() {
        let mut r = recovery();
        r.on_packet_received(
            PacketNumberSpace::Initial,
            0,
            true,
            Duration::from_millis(10),
        )
        .unwrap();

        let first = r
            .peek_ack(PacketNumberSpace::Initial, Duration::from_millis(10))
            .unwrap();
        let retry = r
            .peek_ack(PacketNumberSpace::Initial, Duration::from_millis(12))
            .unwrap();
        assert_eq!(first.ranges, retry.ranges);
        assert_eq!(retry.ack_delay, Duration::from_millis(2));
        assert!(r.commit_ack(PacketNumberSpace::Initial));
        assert_eq!(r.ack_deadline(PacketNumberSpace::Initial), None);
        assert!(r
            .peek_ack(PacketNumberSpace::Initial, Duration::from_millis(12))
            .is_none());
        assert!(!r.commit_ack(PacketNumberSpace::Initial));
    }

    #[test]
    fn stale_ack_commit_preserves_new_ack_obligation() {
        let mut r = recovery();
        r.on_packet_received(
            PacketNumberSpace::Initial,
            0,
            true,
            Duration::from_millis(10),
        )
        .unwrap();
        r.peek_ack(PacketNumberSpace::Initial, Duration::from_millis(10))
            .unwrap();
        r.on_packet_received(
            PacketNumberSpace::Initial,
            1,
            true,
            Duration::from_millis(11),
        )
        .unwrap();

        assert!(!r.commit_ack(PacketNumberSpace::Initial));
        let ack = r
            .peek_ack(PacketNumberSpace::Initial, Duration::from_millis(11))
            .unwrap();
        assert_eq!(ack.largest, 1);
        assert_eq!(ack.ranges, vec![AckRange::new(0, 2)]);
    }

    #[test]
    fn packet_replay_after_ack_of_ack_remains_duplicate() {
        let mut r = recovery();
        r.on_packet_received(
            PacketNumberSpace::ApplicationData,
            7,
            true,
            Duration::from_millis(10),
        )
        .unwrap();
        r.take_ack(
            PacketNumberSpace::ApplicationData,
            Duration::from_millis(11),
        )
        .unwrap();
        r.acknowledge_ack(PacketNumberSpace::ApplicationData, 7)
            .unwrap();

        assert!(r.is_packet_received(PacketNumberSpace::ApplicationData, 7));
        assert!(!r
            .on_packet_received(
                PacketNumberSpace::ApplicationData,
                7,
                true,
                Duration::from_millis(20),
            )
            .unwrap());
        assert_eq!(r.ack_deadline(PacketNumberSpace::ApplicationData), None);
    }

    #[test]
    fn sparse_receive_ranges_are_bounded_by_a_duplicate_floor() {
        let mut r = recovery();
        for packet_number in (0..=(MAX_RECEIVED_RANGES as u64 * 2)).step_by(2) {
            assert!(r
                .on_packet_received(
                    PacketNumberSpace::Initial,
                    packet_number,
                    true,
                    Duration::from_millis(packet_number),
                )
                .unwrap());
        }

        let space = &r.spaces[PacketNumberSpace::Initial.index()];
        assert_eq!(space.received.len(), MAX_RECEIVED_RANGES);
        assert_eq!(space.received_floor, 2);
        assert!(r.is_packet_received(PacketNumberSpace::Initial, 0));
        assert!(r.is_packet_received(PacketNumberSpace::Initial, 1));
        assert!(!r
            .on_packet_received(PacketNumberSpace::Initial, 1, true, Duration::from_secs(1),)
            .unwrap());
    }

    #[test]
    fn discarding_space_clears_receive_and_ack_state() {
        let mut r = recovery();
        let mut sent = packet(0, 0);
        sent.packet_type = crate::quic::types::PacketType::Initial;
        sent.is_crypto = true;
        r.on_packet_sent(PacketNumberSpace::Initial, sent).unwrap();
        r.on_packet_received(
            PacketNumberSpace::Initial,
            7,
            true,
            Duration::from_millis(10),
        )
        .unwrap();
        r.peek_ack(PacketNumberSpace::Initial, Duration::from_millis(10))
            .unwrap();
        let events = r.discard_space(PacketNumberSpace::Initial);

        assert_eq!(r.expected_packet_number(PacketNumberSpace::Initial), 0);
        assert_eq!(r.largest_received(PacketNumberSpace::Initial), None);
        assert!(!r.is_packet_received(PacketNumberSpace::Initial, 7));
        assert_eq!(r.ack_deadline(PacketNumberSpace::Initial), None);
        assert!(!r.commit_ack(PacketNumberSpace::Initial));
        assert_eq!(outcomes(&events, DeliveryOutcome::Discarded), 1);
        assert_eq!(outcomes(&events, DeliveryOutcome::RetireAndRetransmit), 0);
        assert_eq!(
            r.on_ack_received(
                PacketNumberSpace::Initial,
                &[],
                Duration::ZERO,
                Duration::from_millis(10),
                true,
            ),
            Err(RecoveryError::DiscardedSpace(PacketNumberSpace::Initial))
        );
    }

    #[test]
    fn pto_copies_without_retiring_or_reducing_cwnd() {
        let mut r = recovery();
        r.on_packet_sent(PacketNumberSpace::Handshake, packet(0, 1000))
            .unwrap();
        let cwnd = r.congestion.congestion_window();
        let events = r
            .on_loss_detection_timeout(Duration::from_millis(1200))
            .unwrap();
        assert_eq!(r.pto_count(), 1);
        assert_eq!(r.pto_total(), 1);
        assert_eq!(outcomes(&events, DeliveryOutcome::ProbeCopy), 1);
        assert!(events
            .iter()
            .filter_map(|event| match event {
                RecoveryEvent::SendProbe { space } => Some(*space),
                _ => None,
            })
            .all(|space| space == PacketNumberSpace::Handshake));
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, RecoveryEvent::SendProbe { .. }))
                .count(),
            2
        );
        assert_eq!(
            r.outstanding_packets(PacketNumberSpace::Handshake).count(),
            1
        );
        assert_eq!(r.congestion.congestion_window(), cwnd);
        assert_eq!(r.congestion.bytes_in_flight(), 1200);
    }

    #[test]
    fn explicit_retransmission_retires_without_declaring_loss() {
        let mut r = recovery();
        r.on_packet_sent(PacketNumberSpace::ApplicationData, packet(0, 1000))
            .unwrap();
        let cwnd = r.congestion.congestion_window();
        let events = r
            .retire_and_retransmit(PacketNumberSpace::ApplicationData, &[0])
            .unwrap();
        assert_eq!(outcomes(&events, DeliveryOutcome::RetireAndRetransmit), 1);
        assert_eq!(r.loss_total(), 0);
        assert_eq!(
            r.outstanding_packets(PacketNumberSpace::ApplicationData)
                .count(),
            0
        );
        assert_eq!(r.congestion.bytes_in_flight(), 0);
        assert_eq!(r.congestion.congestion_window(), cwnd);
    }

    #[test]
    fn persistent_congestion_collapses_window() {
        let mut r = recovery();
        r.rtt
            .update(Duration::from_millis(10), Duration::ZERO, Duration::ZERO);
        r.max_ack_delay = Duration::ZERO;
        r.on_packet_sent(PacketNumberSpace::ApplicationData, packet(0, 1000))
            .unwrap();
        r.on_packet_sent(PacketNumberSpace::ApplicationData, packet(1, 1400))
            .unwrap();
        r.on_packet_sent(PacketNumberSpace::ApplicationData, packet(2, 1410))
            .unwrap();
        r.on_packet_sent(PacketNumberSpace::ApplicationData, packet(3, 1420))
            .unwrap();
        r.on_packet_sent(PacketNumberSpace::ApplicationData, packet(4, 1500))
            .unwrap();
        r.on_ack_received(
            PacketNumberSpace::ApplicationData,
            &[AckRange::new(4, 5)],
            Duration::ZERO,
            Duration::from_millis(1600),
            true,
        )
        .unwrap();
        assert_eq!(r.congestion.congestion_window(), 2400);
        assert_eq!(r.congestion.ssthresh(), None);
    }

    #[test]
    fn pmtu_loss_has_metadata_but_no_congestion_reaction_or_pto() {
        let mut r = recovery();
        let mut probe = packet(0, 1000);
        probe.is_pmtu_probe = true;
        probe.path_id = 42;
        r.on_packet_sent(PacketNumberSpace::ApplicationData, probe)
            .unwrap();
        assert_eq!(r.loss_detection_time(), None);
        r.spaces[PacketNumberSpace::ApplicationData.index()].largest_acked = Some(3);
        let cwnd = r.congestion.congestion_window();
        let events = r
            .detect_loss(
                PacketNumberSpace::ApplicationData,
                Duration::from_millis(1001),
            )
            .unwrap();
        assert!(events
            .iter()
            .any(|e| matches!(e, RecoveryEvent::PmtuProbeLost { path_id: 42, .. })));
        assert_eq!(r.congestion.congestion_window(), cwnd);
        assert_eq!(r.congestion.bytes_in_flight(), 0);
    }

    #[test]
    fn pmtu_ack_preserves_path_identity() {
        let mut r = recovery();
        let mut probe = packet(0, 1000);
        probe.is_pmtu_probe = true;
        probe.path_id = 73;
        r.on_packet_sent(PacketNumberSpace::ApplicationData, probe)
            .unwrap();

        let events = r
            .on_ack_received(
                PacketNumberSpace::ApplicationData,
                &[AckRange::new(0, 1)],
                Duration::ZERO,
                Duration::from_millis(1010),
                true,
            )
            .unwrap();

        assert!(events
            .iter()
            .any(|event| matches!(event, RecoveryEvent::PmtuProbeAcked { path_id: 73, .. })));
    }

    #[test]
    fn pacer_refills_at_congestion_rate() {
        let mut pacer = Pacer::new(1200);
        pacer.start(Duration::ZERO, 12_000, Duration::from_millis(100));
        assert_eq!(pacer.poll(Duration::ZERO, 12_000), None);
        assert_eq!(
            pacer.poll(Duration::ZERO, 1200),
            Some(Duration::from_millis(10))
        );
        assert_eq!(pacer.poll(Duration::from_millis(10), 1200), None);
    }

    #[test]
    fn hystart_enters_css_and_dampens_growth() {
        let mut cc = CongestionController::new(1200);
        cc.hystart_previous_round_min = Some(Duration::from_millis(10));
        for _ in 0..HYSTART_SAMPLES {
            cc.rtt_sample(Duration::from_millis(20));
        }
        assert!(cc.hystart_in_css);
        let p = packet(0, 1);
        cc.packet_sent(&p);
        let before = cc.congestion_window();
        cc.packet_acked(&p, Duration::from_millis(21));
        assert_eq!(cc.congestion_window(), before + 300);
    }

    #[test]
    fn large_datagram_size_uses_rfc_initial_congestion_window() {
        let r = Recovery::new(RecoveryConfig {
            max_datagram_size: 2000,
            ..RecoveryConfig::default()
        })
        .unwrap();

        assert_eq!(r.congestion().congestion_window(), 14_720);
    }

    #[test]
    fn migration_resets_congestion_and_excludes_old_path_packets() {
        let mut r = recovery();
        let old = packet(0, 1200);
        let mut new = packet(1, 1200);
        new.path_id = 1;
        r.on_packet_sent(PacketNumberSpace::ApplicationData, old)
            .unwrap();
        r.on_packet_sent(PacketNumberSpace::ApplicationData, new)
            .unwrap();
        assert_eq!(r.congestion().bytes_in_flight(), 2400);

        r.reset_for_new_path(0, 1, false);
        assert_eq!(r.congestion().bytes_in_flight(), 1200);
        assert_eq!(
            r.congestion().congestion_window(),
            initial_congestion_window(1200)
        );

        r.on_ack_received(
            PacketNumberSpace::ApplicationData,
            &[AckRange::new(0, 1)],
            Duration::ZERO,
            Duration::from_millis(1100),
            true,
        )
        .unwrap();
        assert_eq!(r.congestion().bytes_in_flight(), 1200);
        assert_eq!(r.rtt().latest(), None);
    }

    #[test]
    fn port_only_rebinding_retains_congestion_state() {
        let mut r = recovery();
        r.on_packet_sent(PacketNumberSpace::ApplicationData, packet(0, 1200))
            .unwrap();
        let congestion_window = r.congestion().congestion_window();

        r.reset_for_new_path(0, 1, true);

        assert_eq!(r.congestion().bytes_in_flight(), 1200);
        assert_eq!(r.congestion().congestion_window(), congestion_window);
        assert_eq!(
            r.spaces[PacketNumberSpace::ApplicationData.index()]
                .outstanding
                .get(&0)
                .unwrap()
                .path_id,
            1
        );
    }

    #[test]
    fn arithmetic_saturates_at_edges() {
        assert_eq!(
            saturating_add(Duration::MAX, Duration::from_secs(1)),
            Duration::MAX
        );
        assert_eq!(
            saturating_mul_pow2(Duration::from_secs(1), 63),
            Duration::MAX
        );
        assert_eq!(
            mul_ratio(Duration::from_nanos(8), 9, 8),
            Duration::from_nanos(9)
        );
        let mut r = recovery();
        r.pto_count = u32::MAX;
        r.spaces[PacketNumberSpace::ApplicationData.index()].last_ack_eliciting_sent =
            Some(Duration::MAX);
        r.peer_completed_address_validation = false;
        assert_eq!(r.loss_detection_time(), Some(Duration::MAX));

        let mut r = recovery();
        assert_eq!(
            r.on_packet_received(
                PacketNumberSpace::ApplicationData,
                MAX_PACKET_NUMBER + 1,
                true,
                Duration::ZERO,
            ),
            Err(RecoveryError::PacketNumberOutOfRange(MAX_PACKET_NUMBER + 1))
        );
    }
}
