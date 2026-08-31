use pyo3::exceptions::PyValueError;
use pyo3::types::{PyBytes, PyList, PyListMethods};
use pyo3::{pyfunction, Bound, PyResult, Python};

use crate::utils::read_uint_var;
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
        let rest_length = if packet_type == PACKET_TYPE_INITIAL {
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
            rl
        } else if packet_type == PACKET_TYPE_ZERO_RTT || packet_type == PACKET_TYPE_HANDSHAKE {
            let (rl, consumed) = read_uint_var(data, pos).map_err(BufferReadError::new_err)?;
            pos += consumed;
            rl
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
            0
        };

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
