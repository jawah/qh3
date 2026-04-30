use pyo3::prelude::*;

/// Read a QUIC variable-length integer from data at the given offset.
/// Returns (value, bytes_consumed).
#[inline]
pub fn read_uint_var(data: &[u8], offset: usize) -> Result<(u64, usize), &'static str> {
    if offset >= data.len() {
        return Err("Read out of bounds");
    }

    let first = data[offset];
    let var_type = first >> 6;

    match var_type {
        0 => Ok(((first & 0x3F) as u64, 1)),
        1 => {
            if offset + 2 > data.len() {
                return Err("Read out of bounds");
            }
            let val = u16::from_be_bytes([data[offset], data[offset + 1]]);
            Ok(((val & 0x3FFF) as u64, 2))
        }
        2 => {
            if offset + 4 > data.len() {
                return Err("Read out of bounds");
            }
            let val = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            Ok(((val & 0x3FFFFFFF) as u64, 4))
        }
        _ => {
            if offset + 8 > data.len() {
                return Err("Read out of bounds");
            }
            let val = u64::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            Ok((val & 0x3FFFFFFFFFFFFFFF, 8))
        }
    }
}

/// Write a QUIC variable-length integer into a buffer. Returns bytes written.
#[inline]
pub fn write_uint_var(buf: &mut [u8], value: u64) -> usize {
    if value <= 0x3F {
        buf[0] = value as u8;
        1
    } else if value <= 0x3FFF {
        let v = (value as u16) | 0x4000;
        buf[0..2].copy_from_slice(&v.to_be_bytes());
        2
    } else if value <= 0x3FFFFFFF {
        let v = (value as u32) | 0x8000_0000;
        buf[0..4].copy_from_slice(&v.to_be_bytes());
        4
    } else {
        let v = value | 0xC000_0000_0000_0000;
        buf[0..8].copy_from_slice(&v.to_be_bytes());
        8
    }
}

#[inline(always)]
pub fn decode_packet_number_internal(truncated: u64, num_bits: u8, expected: u64) -> u64 {
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

#[pyfunction]
#[inline(always)]
pub fn decode_packet_number(truncated: u64, num_bits: u8, expected: u64) -> u64 {
    decode_packet_number_internal(truncated, num_bits, expected)
}
