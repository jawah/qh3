use pyo3::prelude::*;

const K_GRANULARITY: f64 = 0.001; // seconds
const K_MICRO_SECOND: f64 = 0.000001;
const K_SECOND: f64 = 1.0;
const K_MAX_DATAGRAM_SIZE: usize = 1280;

/// A native Rust version of the packet pacer.
///
/// This type manages a “bucket” that replenishes over time and helps compute
/// the next packet send time.
#[pyclass]
pub struct QuicPacketPacer {
    bucket_max: f64,
    bucket_time: f64,
    evaluation_time: f64,
    packet_time: Option<f64>,
}

#[pymethods]
impl QuicPacketPacer {
    #[new]
    fn new() -> Self {
        QuicPacketPacer {
            bucket_max: 0.0,
            bucket_time: 0.0,
            evaluation_time: 0.0,
            packet_time: None,
        }
    }

    #[getter]
    fn bucket_max(&self) -> f64 {
        self.bucket_max
    }

    #[getter]
    fn bucket_time(&self) -> f64 {
        self.bucket_time
    }

    #[getter]
    fn packet_time(&self) -> Option<f64> {
        self.packet_time
    }

    /// Computes the next send time given the current time.
    ///
    /// If a packet time is defined and the bucket has been depleted (≤ 0),
    /// returns `now + packet_time`; otherwise, returns `None`.
    #[inline(always)]
    fn next_send_time(&mut self, now: f64) -> Option<f64> {
        if let Some(packet_time) = self.packet_time {
            self.update_bucket(now);
            if self.bucket_time <= 0.0 {
                return Some(now + packet_time);
            }
        }
        None
    }

    /// Updates the bucket after a packet is sent.
    ///
    /// If the bucket has less available time than the packet time, it is
    /// drained (set to 0). Otherwise, the packet time is subtracted.
    #[inline(always)]
    fn update_after_send(&mut self, now: f64) {
        if let Some(packet_time) = self.packet_time {
            self.update_bucket(now);
            if self.bucket_time < packet_time {
                self.bucket_time = 0.0;
            } else {
                self.bucket_time -= packet_time;
            }
        }
    }

    /// Replenishes the bucket based on the elapsed time since the last update.
    #[inline(always)]
    fn update_bucket(&mut self, now: f64) {
        if now > self.evaluation_time {
            // Increase the bucket by the time delta but do not exceed bucket_max.
            let delta = now - self.evaluation_time;
            self.bucket_time = (self.bucket_time + delta).min(self.bucket_max);
            self.evaluation_time = now;
        }
    }

    /// Updates the pacing rate based on the congestion window and smoothed RTT.
    ///
    /// The pacing rate is derived as:
    /// `pacing_rate = congestion_window / max(smoothed_rtt, K_MICRO_SECOND)`.
    ///
    /// The new packet time is limited between K_MICRO_SECOND and K_SECOND.
    ///
    /// The bucket maximum is computed as:
    /// ```text
    /// bucket_max = max(2*K_MAX_DATAGRAM_SIZE, min(congestion_window/4, 16*K_MAX_DATAGRAM_SIZE))
    ///              / pacing_rate
    /// ```
    #[inline(always)]
    fn update_rate(&mut self, congestion_window: usize, smoothed_rtt: f64) {
        let pacing_rate = (congestion_window as f64) / smoothed_rtt.max(K_MICRO_SECOND);
        let pt = (K_MAX_DATAGRAM_SIZE as f64) / pacing_rate;
        let new_packet_time = K_MICRO_SECOND.max(pt.min(K_SECOND));
        self.packet_time = Some(new_packet_time);

        let cw_div4 = (congestion_window as f64) / 4.0;
        let candidate = cw_div4.min(16.0 * (K_MAX_DATAGRAM_SIZE as f64));
        self.bucket_max = f64::max(2.0 * (K_MAX_DATAGRAM_SIZE as f64), candidate) / pacing_rate;
        if self.bucket_time > self.bucket_max {
            self.bucket_time = self.bucket_max;
        }
    }
}

/// Roundtrip time monitor for HyStart (adapted from Python).
#[pyclass]
pub struct QuicRttMonitor {
    _increases: usize,
    // _last_time is not used in the Python version, so we omit it.
    _ready: bool,
    _size: usize,               // fixed sample buffer size (5)
    _filtered_min: Option<f64>, // filtered minimum RTT so far
    _sample_idx: usize,
    _sample_max: Option<f64>,
    _sample_min: Option<f64>,
    _sample_time: f64,  // last time the sample buffer was updated
    _samples: Vec<f64>, // fixed-size buffer storing the RTT samples
}

#[pymethods]
impl QuicRttMonitor {
    #[new]
    fn new() -> Self {
        let size = 5;
        QuicRttMonitor {
            _increases: 0,
            _ready: false,
            _size: size,
            _filtered_min: None,
            _sample_idx: 0,
            _sample_max: None,
            _sample_min: None,
            _sample_time: 0.0,
            // Pre-allocate samples with zero values.
            _samples: vec![0.0; size],
        }
    }

    #[getter]
    fn _samples(&self) -> Vec<f64> {
        self._samples.clone()
    }

    #[getter]
    fn _ready(&self) -> bool {
        self._ready
    }

    #[getter]
    fn _increases(&self) -> usize {
        self._increases
    }

    /// Adds a new RTT sample.
    ///
    /// This updates the sample buffer with the new `rtt` value.
    /// When the buffer becomes full, it marks the monitor as ready and computes
    /// the minimum and maximum RTT from the samples.
    #[inline(always)]
    fn add_rtt(&mut self, rtt: f64) {
        // Insert the new RTT sample at the current index.
        self._samples[self._sample_idx] = rtt;
        self._sample_idx += 1;

        // If we've filled the buffer once, wrap around and mark as ready.
        if self._sample_idx >= self._size {
            self._sample_idx = 0;
            self._ready = true;
        }

        // If the buffer is ready, recompute the min and max from the samples.
        if self._ready {
            // Initialize sample_min and sample_max from the first sample.
            let mut sample_min = self._samples[0];
            let mut sample_max = self._samples[0];
            // Iterate over remaining samples.
            for &sample in self._samples.iter().skip(1) {
                if sample < sample_min {
                    sample_min = sample;
                } else if sample > sample_max {
                    sample_max = sample;
                }
            }
            self._sample_min = Some(sample_min);
            self._sample_max = Some(sample_max);
        }
    }

    /// Returns `True` if the RTT is considered to be increasing.
    ///
    /// The monitor updates its sample buffer if the current time `now`
    /// exceeds the last sample time by at least K_GRANULARITY, adds the new
    /// RTT sample, and then computes if the difference between the current
    /// minimum and the filtered minimum has increased significantly.
    ///
    /// If the RTT increase is sustained for at least `_size` increments,
    /// the method returns `True`.
    #[inline(always)]
    fn is_rtt_increasing(&mut self, rtt: f64, now: f64) -> bool {
        // Update the sample if enough time has elapsed.
        if now > self._sample_time + K_GRANULARITY {
            self.add_rtt(rtt);
            self._sample_time = now;

            if self._ready {
                // Update _filtered_min if it is not set, or if the current sample max is lower.
                if self._filtered_min.is_none()
                    || self._filtered_min.unwrap() > self._sample_max.unwrap()
                {
                    self._filtered_min = self._sample_max;
                }
                // Compute the delta between the current sample minimum and the filtered minimum.
                let filtered_min = self._filtered_min.unwrap();
                let sample_min = self._sample_min.unwrap();
                let delta = sample_min - filtered_min;

                // If the relative difference is large enough, count the increase.
                if delta * 4.0 >= filtered_min {
                    self._increases += 1;
                    if self._increases >= self._size {
                        return true;
                    }
                } else if delta > 0.0 {
                    // Otherwise, reset the counter.
                    self._increases = 0;
                }
            }
        }
        false
    }
}
