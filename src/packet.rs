use pyo3::exceptions::PyValueError;
use pyo3::types::{PyBytes, PyList, PyListMethods};
use pyo3::{pyfunction, Bound, Py, PyResult, Python};

use crate::buffer::Buffer;
use crate::rangeset::RangeSet;
use crate::utils::{read_uint_var, write_uint_var};
use crate::BufferReadError;

/// Return type for `pull_quic_header`:
///   (version, packet_type, packet_length,
///    destination_cid, source_cid, token, integrity_tag,
///    supported_versions, encrypted_offset, end_offset)
type QuicHeaderTuple<'a> = (
    Option<u32>,
    u8,
    usize,
    Bound<'a, PyBytes>,
    Bound<'a, PyBytes>,
    Bound<'a, PyBytes>,
    Bound<'a, PyBytes>,
    Bound<'a, PyList>,
    usize,
    usize,
);

// Constants matching Python's packet.py
const PACKET_LONG_HEADER: u8 = 0x80;
const PACKET_FIXED_BIT: u8 = 0x40;
const CONNECTION_ID_MAX_SIZE: usize = 20;
const RETRY_INTEGRITY_TAG_SIZE: usize = 16;

// QUIC Protocol Versions
const QUIC_VERSION_NEGOTIATION: u32 = 0;
const QUIC_VERSION_2: u32 = 0x6B3343CF;

// Packet types (matching QuicPacketType enum values)
const PACKET_TYPE_INITIAL: u8 = 0;
const PACKET_TYPE_ZERO_RTT: u8 = 1;
const PACKET_TYPE_HANDSHAKE: u8 = 2;
const PACKET_TYPE_RETRY: u8 = 3;
const PACKET_TYPE_VERSION_NEGOTIATION: u8 = 4;
const PACKET_TYPE_ONE_RTT: u8 = 5;

/// Maximum value for a QUIC variable-length integer (2^62 - 1).
const UINT_VAR_MAX: u64 = (1 << 62) - 1;

#[inline]
fn decode_long_packet_type_v1(first_byte: u8) -> u8 {
    match (first_byte & 0x30) >> 4 {
        0 => PACKET_TYPE_INITIAL,
        1 => PACKET_TYPE_ZERO_RTT,
        2 => PACKET_TYPE_HANDSHAKE,
        3 => PACKET_TYPE_RETRY,
        _ => unreachable!(),
    }
}

#[inline]
fn decode_long_packet_type_v2(first_byte: u8) -> u8 {
    match (first_byte & 0x30) >> 4 {
        1 => PACKET_TYPE_INITIAL,
        2 => PACKET_TYPE_ZERO_RTT,
        3 => PACKET_TYPE_HANDSHAKE,
        0 => PACKET_TYPE_RETRY,
        _ => unreachable!(),
    }
}

/// Parse a QUIC packet header directly from raw bytes.
///
/// Arguments:
///   data: raw datagram bytes
///   offset: starting offset in data for this packet
///   host_cid_length: expected length of destination CID for short headers
///   datagram_length: total length of the datagram (data.len())
///
/// Returns a tuple:
///   (version, packet_type, packet_length,
///    destination_cid, source_cid, token, integrity_tag,
///    supported_versions, encrypted_offset, end_offset)
///
/// - encrypted_offset: offset from packet start where encrypted data begins
///   (i.e., where the PN bytes are, relative to the packet start)
/// - end_offset: absolute offset in `data` where this packet ends
#[pyfunction]
#[pyo3(signature = (data, offset, host_cid_length=None))]
pub fn pull_quic_header<'a>(
    py: Python<'a>,
    data: &[u8],
    offset: usize,
    host_cid_length: Option<usize>,
) -> PyResult<QuicHeaderTuple<'a>> {
    let datagram_length = data.len();
    let packet_start = offset;
    let mut pos = offset;

    if pos >= datagram_length {
        return Err(BufferReadError::new_err("Read out of bounds"));
    }

    let first_byte = data[pos];
    pos += 1;

    if first_byte & PACKET_LONG_HEADER != 0 {
        // Long Header Packet
        if pos + 4 > datagram_length {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }
        let version = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;

        // Destination CID
        if pos >= datagram_length {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }
        let dcid_len = data[pos] as usize;
        pos += 1;
        if dcid_len > CONNECTION_ID_MAX_SIZE {
            return Err(PyValueError::new_err(format!(
                "Destination CID is too long ({} bytes)",
                dcid_len
            )));
        }
        if pos + dcid_len > datagram_length {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }
        let destination_cid = PyBytes::new(py, &data[pos..pos + dcid_len]);
        pos += dcid_len;

        // Source CID
        if pos >= datagram_length {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }
        let scid_len = data[pos] as usize;
        pos += 1;
        if scid_len > CONNECTION_ID_MAX_SIZE {
            return Err(PyValueError::new_err(format!(
                "Source CID is too long ({} bytes)",
                scid_len
            )));
        }
        if pos + scid_len > datagram_length {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }
        let source_cid = PyBytes::new(py, &data[pos..pos + scid_len]);
        pos += scid_len;

        if version == QUIC_VERSION_NEGOTIATION {
            // Version Negotiation
            let supported_versions = PyList::empty(py);
            while pos + 4 <= datagram_length {
                let v =
                    u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
                pos += 4;
                supported_versions.append(v)?;
            }
            let packet_end = pos;
            let encrypted_offset = pos - packet_start;

            return Ok((
                Some(version),
                PACKET_TYPE_VERSION_NEGOTIATION,
                packet_end - packet_start,
                destination_cid,
                source_cid,
                PyBytes::new(py, &[]),
                PyBytes::new(py, &[]),
                supported_versions,
                encrypted_offset,
                packet_end,
            ));
        }

        // Non-negotiation long header
        if first_byte & PACKET_FIXED_BIT == 0 {
            return Err(PyValueError::new_err("Packet fixed bit is zero"));
        }

        let packet_type = if version == QUIC_VERSION_2 {
            decode_long_packet_type_v2(first_byte)
        } else {
            decode_long_packet_type_v1(first_byte)
        };

        let mut token_bytes: &[u8] = &[];
        let mut integrity_tag_bytes: &[u8] = &[];
        let rest_length: u64;

        if packet_type == PACKET_TYPE_INITIAL {
            // Token
            let (token_len, consumed) =
                read_uint_var(data, pos).map_err(BufferReadError::new_err)?;
            pos += consumed;
            let token_len = token_len as usize;
            if pos + token_len > datagram_length {
                return Err(BufferReadError::new_err("Read out of bounds"));
            }
            token_bytes = &data[pos..pos + token_len];
            pos += token_len;
            // Rest length
            let (rl, consumed) = read_uint_var(data, pos).map_err(BufferReadError::new_err)?;
            pos += consumed;
            rest_length = rl;
        } else if packet_type == PACKET_TYPE_ZERO_RTT || packet_type == PACKET_TYPE_HANDSHAKE {
            let (rl, consumed) = read_uint_var(data, pos).map_err(BufferReadError::new_err)?;
            pos += consumed;
            rest_length = rl;
        } else {
            // Retry packet
            if datagram_length < pos + RETRY_INTEGRITY_TAG_SIZE {
                return Err(BufferReadError::new_err("Read out of bounds"));
            }
            let token_len = datagram_length - pos - RETRY_INTEGRITY_TAG_SIZE;
            token_bytes = &data[pos..pos + token_len];
            pos += token_len;
            integrity_tag_bytes = &data[pos..pos + RETRY_INTEGRITY_TAG_SIZE];
            pos += RETRY_INTEGRITY_TAG_SIZE;
            rest_length = 0;
        }

        let encrypted_offset = pos - packet_start;
        let packet_end = pos + rest_length as usize;

        if packet_end > datagram_length {
            return Err(PyValueError::new_err("Packet payload is truncated"));
        }

        Ok((
            Some(version),
            packet_type,
            packet_end - packet_start,
            destination_cid,
            source_cid,
            PyBytes::new(py, token_bytes),
            PyBytes::new(py, integrity_tag_bytes),
            PyList::empty(py),
            encrypted_offset,
            packet_end,
        ))
    } else {
        // Short Header (1-RTT)
        if first_byte & PACKET_FIXED_BIT == 0 {
            return Err(PyValueError::new_err("Packet fixed bit is zero"));
        }

        let cid_len = host_cid_length.unwrap_or(0);
        if pos + cid_len > datagram_length {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }
        let destination_cid = PyBytes::new(py, &data[pos..pos + cid_len]);
        pos += cid_len;

        let encrypted_offset = pos - packet_start;
        let packet_end = datagram_length;

        Ok((
            None,
            PACKET_TYPE_ONE_RTT,
            packet_end - packet_start,
            destination_cid,
            PyBytes::new(py, &[]),
            PyBytes::new(py, &[]),
            PyBytes::new(py, &[]),
            PyList::empty(py),
            encrypted_offset,
            packet_end,
        ))
    }
}

/// Parse a QUIC ACK frame from the Buffer, building a RangeSet in Rust.
/// Returns (RangeSet, ack_delay).
///
/// This eliminates multiple pull_uint_var crossings per ACK frame.
#[pyfunction]
pub fn pull_ack_frame(py: Python<'_>, buffer: Py<Buffer>) -> PyResult<(RangeSet, u64)> {
    let mut buf = buffer.borrow_mut(py);
    let data = buf.data_ref();
    let capacity = buf.get_capacity();
    let mut pos = buf.get_pos();

    // Helper closure to read a varint
    let read_var = |pos: &mut usize| -> PyResult<u64> {
        if *pos >= capacity {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }
        let (val, consumed) = read_uint_var(data, *pos).map_err(BufferReadError::new_err)?;
        *pos += consumed;
        Ok(val)
    };

    let end_val = read_var(&mut pos)? as i64; // largest acknowledged
    let delay = read_var(&mut pos)?; // ack delay
    let ack_range_count = read_var(&mut pos)?; // range count
    let first_ack_range = read_var(&mut pos)? as i64; // first ack range

    let mut rangeset = RangeSet::new();
    let mut end = end_val;
    rangeset.add(end - first_ack_range, Some(end + 1));
    end -= first_ack_range;

    for _ in 0..ack_range_count {
        let gap = read_var(&mut pos)? as i64;
        end -= gap + 2;
        let ack_count = read_var(&mut pos)? as i64;
        rangeset.add(end - ack_count, Some(end + 1));
        end -= ack_count;
    }

    // Update buffer position
    buf.set_pos(pos);

    Ok((rangeset, delay))
}

// ============================================================================
// push_ack_frame — serialize ACK frame body into Buffer
// ============================================================================

/// Serialize an ACK frame body (after the frame-type varint) into the Buffer.
///
/// Mirrors Python `push_ack_frame` in packet.py.  Writes:
///   largest_ack, delay, range_count, first_range, (gap, range)...
///
/// Returns the number of ranges (== len(rangeset)).
#[pyfunction]
pub fn push_ack_frame(
    py: Python<'_>,
    buffer: Py<Buffer>,
    rangeset: Py<RangeSet>,
    delay: u64,
) -> PyResult<usize> {
    let rs = rangeset.borrow(py);
    let ranges = rs.len();
    if ranges == 0 {
        return Err(BufferReadError::new_err("Empty RangeSet"));
    }

    let mut buf = buffer.borrow_mut(py);
    let pos = buf.get_pos();
    let data = buf.data_mut()?;
    let mut pos = pos;

    // helper: write a varint, advance pos
    let write_var = |data: &mut [u8], pos: &mut usize, value: u64| {
        let n = write_uint_var(&mut data[*pos..], value);
        *pos += n;
    };

    let mut index = ranges - 1;
    let r = rs.get_item(index);
    // largest acknowledged = r.1 - 1
    write_var(data, &mut pos, (r.1 - 1) as u64);
    // ack delay
    write_var(data, &mut pos, delay);
    // ack range count
    write_var(data, &mut pos, index as u64);
    // first ack range
    write_var(data, &mut pos, (r.1 - 1 - r.0) as u64);

    let mut start = r.0;
    while index > 0 {
        index -= 1;
        let r = rs.get_item(index);
        // gap
        write_var(data, &mut pos, (start - r.1 - 1) as u64);
        // ack range
        write_var(data, &mut pos, (r.1 - r.0 - 1) as u64);
        start = r.0;
    }

    buf.set_pos(pos);
    Ok(ranges)
}

// ============================================================================
// Frame parsers for receive path
// ============================================================================

/// Skip padding bytes (0x00) in the Buffer.  Advances position past all
/// contiguous zero bytes starting at the current position.
#[pyfunction]
pub fn skip_padding(py: Python<'_>, buffer: Py<Buffer>) -> PyResult<()> {
    let mut buf = buffer.borrow_mut(py);
    let data = buf.data_ref();
    let capacity = buf.get_capacity();
    let mut pos = buf.get_pos();

    while pos < capacity && data[pos] == 0 {
        pos += 1;
    }

    buf.set_pos(pos);
    Ok(())
}

/// Parse a STREAM frame body (after the frame-type varint has already been
/// consumed).  `frame_type` carries the flag bits (OFF | LEN | FIN).
///
/// Returns (stream_id, offset, data_bytes, fin).
#[pyfunction]
pub fn pull_stream_frame<'a>(
    py: Python<'a>,
    buffer: Py<Buffer>,
    frame_type: u8,
) -> PyResult<(u64, u64, Bound<'a, PyBytes>, bool)> {
    let mut buf = buffer.borrow_mut(py);
    let data = buf.data_ref();
    let capacity = buf.get_capacity();
    let mut pos = buf.get_pos();

    // helper
    let read_var = |data: &[u8], pos: &mut usize| -> PyResult<u64> {
        if *pos >= capacity {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }
        let (val, consumed) = read_uint_var(data, *pos).map_err(BufferReadError::new_err)?;
        *pos += consumed;
        Ok(val)
    };

    let stream_id = read_var(data, &mut pos)?;

    let offset = if frame_type & 4 != 0 {
        read_var(data, &mut pos)?
    } else {
        0
    };

    let length = if frame_type & 2 != 0 {
        read_var(data, &mut pos)? as usize
    } else {
        capacity - pos
    };

    // Check for overflow before reading data
    if offset + length as u64 > UINT_VAR_MAX {
        return Err(PyValueError::new_err(
            "offset + length cannot exceed 2^62 - 1",
        ));
    }

    if pos + length > capacity {
        return Err(BufferReadError::new_err("Read out of bounds"));
    }
    let frame_data = PyBytes::new(py, &data[pos..pos + length]);
    pos += length;

    let fin = frame_type & 1 != 0;

    buf.set_pos(pos);
    Ok((stream_id, offset, frame_data, fin))
}

/// Parse a CRYPTO frame body (after the frame-type varint).
///
/// Returns (offset, data_bytes).
#[pyfunction]
pub fn pull_crypto_frame<'a>(
    py: Python<'a>,
    buffer: Py<Buffer>,
) -> PyResult<(u64, Bound<'a, PyBytes>)> {
    let mut buf = buffer.borrow_mut(py);
    let data = buf.data_ref();
    let capacity = buf.get_capacity();
    let mut pos = buf.get_pos();

    let read_var = |data: &[u8], pos: &mut usize| -> PyResult<u64> {
        if *pos >= capacity {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }
        let (val, consumed) = read_uint_var(data, *pos).map_err(BufferReadError::new_err)?;
        *pos += consumed;
        Ok(val)
    };

    let offset = read_var(data, &mut pos)?;
    let length = read_var(data, &mut pos)? as usize;

    // Check for overflow before reading data
    if offset + length as u64 > UINT_VAR_MAX {
        return Err(PyValueError::new_err(
            "offset + length cannot exceed 2^62 - 1",
        ));
    }

    if pos + length > capacity {
        return Err(BufferReadError::new_err("Read out of bounds"));
    }
    let frame_data = PyBytes::new(py, &data[pos..pos + length]);
    pos += length;

    buf.set_pos(pos);
    Ok((offset, frame_data))
}

// ============================================================================
// Frame serializers for send path
// ============================================================================

/// Write the body of a STREAM frame into the Buffer.
///
/// Writes: stream_id (varint), offset (varint, if non-zero),
///         length (2-byte varint with 0x4000 prefix), data.
///
/// The frame-type varint must already have been written by `start_frame`.
#[pyfunction]
pub fn push_stream_frame_body(
    py: Python<'_>,
    buffer: Py<Buffer>,
    stream_id: u64,
    offset: u64,
    data: &[u8],
) -> PyResult<()> {
    let mut buf = buffer.borrow_mut(py);
    let pos = buf.get_pos();
    let buf_data = buf.data_mut()?;
    let mut pos = pos;

    // stream_id
    pos += write_uint_var(&mut buf_data[pos..], stream_id);
    // offset (only if non-zero)
    if offset > 0 {
        pos += write_uint_var(&mut buf_data[pos..], offset);
    }
    // length as 2-byte varint (0x4000 | len)
    let len_val = (data.len() as u16) | 0x4000;
    buf_data[pos..pos + 2].copy_from_slice(&len_val.to_be_bytes());
    pos += 2;
    // data
    buf_data[pos..pos + data.len()].copy_from_slice(data);
    pos += data.len();

    buf.set_pos(pos);
    Ok(())
}

/// Write the body of a CRYPTO frame into the Buffer.
///
/// Writes: offset (varint), length (2-byte varint with 0x4000 prefix), data.
///
/// The frame-type varint must already have been written by `start_frame`.
#[pyfunction]
pub fn push_crypto_frame_body(
    py: Python<'_>,
    buffer: Py<Buffer>,
    offset: u64,
    data: &[u8],
) -> PyResult<()> {
    let mut buf = buffer.borrow_mut(py);
    let pos = buf.get_pos();
    let buf_data = buf.data_mut()?;
    let mut pos = pos;

    // offset
    pos += write_uint_var(&mut buf_data[pos..], offset);
    // length as 2-byte varint (0x4000 | len)
    let len_val = (data.len() as u16) | 0x4000;
    buf_data[pos..pos + 2].copy_from_slice(&len_val.to_be_bytes());
    pos += 2;
    // data
    buf_data[pos..pos + data.len()].copy_from_slice(data);
    pos += data.len();

    buf.set_pos(pos);
    Ok(())
}
