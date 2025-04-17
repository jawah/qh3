use pyo3::prelude::*;

#[pyfunction]
pub fn decode_packet_number(truncated: u64, num_bits: u8, expected: u64) -> u64 {
    let window = 1 << num_bits;
    let half_window = window / 2;
    let mask = window - 1;
    let candidate = (expected & !mask) | truncated;

    // Only subtract half_window from expected if expected >= half_window:
    if expected >= half_window
        && candidate <= expected - half_window
        && candidate < ((1 << 62) - window)
    {
        candidate + window
    } else if candidate > expected + half_window && candidate >= window {
        candidate - window
    } else {
        candidate
    }
}
