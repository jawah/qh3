use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::rangeset::RangeSet;

const DELIVERY_ACKED: u8 = 0;

/// Internal helper: compute size_uint_var without PyResult overhead.
#[inline(always)]
fn size_uint_var_fast(value: u64) -> usize {
    if value <= 0x3F {
        1
    } else if value <= 0x3FFF {
        2
    } else if value <= 0x3FFF_FFFF {
        4
    } else {
        8
    }
}

/// The send part of a QUIC stream, implemented in Rust for performance.
///
/// It finishes:
/// - immediately for a receive-only stream
/// - upon acknowledgement of a STREAM_RESET frame
/// - upon acknowledgement of a data frame with the FIN bit set
#[pyclass(module = "qh3._hazmat")]
pub struct QuicStreamSender {
    #[pyo3(get)]
    pub buffer_is_empty: bool,
    #[pyo3(get)]
    pub highest_offset: i64,
    #[pyo3(get)]
    pub is_finished: bool,
    #[pyo3(get)]
    pub reset_pending: bool,
    /// Count of times on_data_delivery was called with LOST (for diagnostics).
    #[pyo3(get)]
    pub loss_count: u32,
    /// Count of times on_data_delivery was called with ACKED (for diagnostics).
    #[pyo3(get)]
    pub ack_count: u32,

    acked: RangeSet,
    buffer: Vec<u8>,
    /// Logical start offset within `buffer`. Bytes before this index have been
    /// consumed (ACK'd). We advance this offset and compact periodically when
    /// wasted space exceeds the live data size.
    buf_offset: usize,
    buffer_fin: Option<i64>,
    buffer_start: i64,
    buffer_stop: i64,
    pending: RangeSet,
    pending_eof: bool,
    reset_error_code: Option<i64>,
    stream_id: Option<i64>,
    stream_id_size: usize,
}

/// Internal (non-pymethod) helpers.
impl QuicStreamSender {
    #[inline(always)]
    fn next_offset_internal(&self) -> i64 {
        if !self.pending.is_empty() {
            self.pending.get_item(0).0
        } else {
            self.buffer_stop
        }
    }

    /// Core get_frame logic. Returns (data_slice_start, data_slice_end, fin, offset) or None.
    /// Slice indices are relative to the physical buffer (include buf_offset).
    /// Mutates internal state (pending, highest_offset, pending_eof).
    #[inline(always)]
    fn get_frame_internal(
        &mut self,
        max_size: i64,
        max_offset: Option<i64>,
    ) -> Option<(usize, usize, bool, i64)> {
        if self.pending.is_empty() {
            if self.pending_eof {
                self.pending_eof = false;
                // FIN only — data range is empty (0, 0)
                return Some((0, 0, true, self.buffer_fin.unwrap()));
            }
            self.buffer_is_empty = true;
            return None;
        }

        let r = self.pending.get_item(0);
        let start = r.0;
        let mut stop = std::cmp::min(r.1, start + max_size);
        if let Some(mo) = max_offset {
            if stop > mo {
                stop = mo;
            }
        }
        if stop <= start {
            return None;
        }

        // buffer slice indices (adjusted for buf_offset)
        let s = self.buf_offset + (start - self.buffer_start) as usize;
        let e = self.buf_offset + (stop - self.buffer_start) as usize;

        self.pending.subtract(start, stop);

        // track highest offset
        if stop > self.highest_offset {
            self.highest_offset = stop;
        }

        // FIN bit
        let fin = self.buffer_fin == Some(stop);
        if fin {
            self.pending_eof = false;
        }

        Some((s, e, fin, start))
    }
}

#[pymethods]
impl QuicStreamSender {
    #[new]
    #[pyo3(signature = (stream_id=None, writable=true))]
    pub fn new(stream_id: Option<i64>, writable: bool) -> Self {
        let stream_id_size = match stream_id {
            Some(id) => size_uint_var_fast(id as u64),
            None => 0,
        };
        QuicStreamSender {
            buffer_is_empty: true,
            highest_offset: 0,
            is_finished: !writable,
            reset_pending: false,
            loss_count: 0,
            ack_count: 0,
            acked: RangeSet::new(),
            buffer: Vec::new(),
            buf_offset: 0,
            buffer_fin: None,
            buffer_start: 0,
            buffer_stop: 0,
            pending: RangeSet::new(),
            pending_eof: false,
            reset_error_code: None,
            stream_id,
            stream_id_size,
        }
    }

    /// The offset for the next frame to send.
    #[getter]
    pub fn next_offset(&self) -> i64 {
        self.next_offset_internal()
    }

    /// Expose _stream_id_size for connection.py (used in crypto frame overhead).
    #[getter(_stream_id_size)]
    pub fn stream_id_size(&self) -> usize {
        self.stream_id_size
    }

    /// Expose _pending for test introspection. Returns list of (start, stop) tuples.
    #[getter(_pending)]
    pub fn get_pending(&self) -> Vec<(i64, i64)> {
        let mut result = Vec::with_capacity(self.pending.len());
        for i in 0..self.pending.len() {
            result.push(self.pending.get_item(i));
        }
        result
    }

    /// Get a frame of data to send.
    ///
    /// Returns (data, fin, offset) or None.
    #[pyo3(signature = (max_size, max_offset=None))]
    pub fn get_frame<'py>(
        &mut self,
        py: Python<'py>,
        max_size: i64,
        max_offset: Option<i64>,
    ) -> Option<(Bound<'py, PyBytes>, bool, i64)> {
        let (s, e, fin, offset) = self.get_frame_internal(max_size, max_offset)?;
        let data = if s == e {
            PyBytes::new(py, b"")
        } else {
            PyBytes::new(py, &self.buffer[s..e])
        };
        Some((data, fin, offset))
    }

    /// Prepare and get a frame for stream frames in a single call.
    ///
    /// Combines next_offset, frame_overhead computation,
    /// and get_frame into one method.
    ///
    /// Returns (data, frame_type, offset, stop_offset, previous_highest, frame_overhead) or None.
    /// frame_type includes STREAM_BASE | LEN, plus OFF and FIN bits as appropriate.
    pub fn prepare_stream_frame<'py>(
        &mut self,
        py: Python<'py>,
        flight_space: i64,
        max_offset: i64,
    ) -> Option<(Bound<'py, PyBytes>, u8, i64, i64, i64, usize)> {
        let next_off = self.next_offset_internal();
        let next_off_size = if next_off != 0 {
            size_uint_var_fast(next_off as u64)
        } else {
            0
        };
        let frame_overhead = 3 + self.stream_id_size + next_off_size;
        let max_size = flight_space - frame_overhead as i64;

        let previous_highest = self.highest_offset;
        let (s, e, fin, offset) = self.get_frame_internal(max_size, Some(max_offset))?;

        let data = if s == e {
            PyBytes::new(py, b"")
        } else {
            PyBytes::new(py, &self.buffer[s..e])
        };

        // Compute frame_type bits: STREAM_BASE(0x08) | LEN(0x02) | OFF | FIN
        let mut frame_type: u8 = 0x08 | 0x02; // STREAM_BASE | length
        if offset != 0 {
            frame_type |= 0x04; // OFF bit
        }
        if fin {
            frame_type |= 0x01; // FIN bit
        }

        let stop_offset = offset + (e - s) as i64;

        Some((
            data,
            frame_type,
            offset,
            stop_offset,
            previous_highest,
            frame_overhead,
        ))
    }

    /// Get the reset frame data. Returns (error_code, final_size, stream_id).
    pub fn get_reset_frame(&mut self) -> (i64, i64, i64) {
        self.reset_pending = false;
        (
            self.reset_error_code.unwrap_or(0),
            self.highest_offset,
            self.stream_id.unwrap_or(0),
        )
    }

    /// Callback when sent data is ACK'd or lost.
    pub fn on_data_delivery(&mut self, delivery: u8, start: i64, stop: i64) {
        self.buffer_is_empty = false;
        if delivery == DELIVERY_ACKED {
            self.ack_count += 1;
            if stop > start {
                self.acked.add(start, Some(stop));
                let first_range = self.acked.get_item(0);
                if first_range.0 == self.buffer_start {
                    let size = (first_range.1 - first_range.0) as usize;
                    self.acked.shift();
                    self.buffer_start += size as i64;
                    // Advance logical drain offset
                    self.buf_offset += size;
                    // Compact when wasted space exceeds live data
                    let live = self.buffer.len() - self.buf_offset;
                    if self.buf_offset > live {
                        self.buffer.drain(..self.buf_offset);
                        self.buf_offset = 0;
                    }
                }
            }

            if Some(self.buffer_start) == self.buffer_fin {
                // all data up to the FIN has been ACK'd, we're done sending
                self.is_finished = true;
            }
        } else {
            // LOST
            self.loss_count += 1;
            if stop > start {
                self.pending.add(start, Some(stop));
            }
            if Some(stop) == self.buffer_fin {
                self.buffer_is_empty = false;
                self.pending_eof = true;
            }
        }
    }

    /// Callback when a reset is ACK'd or lost.
    pub fn on_reset_delivery(&mut self, delivery: u8) {
        if delivery == DELIVERY_ACKED {
            self.is_finished = true;
        } else {
            self.reset_pending = true;
        }
    }

    /// Abruptly terminate the sending part of the QUIC stream.
    pub fn reset(&mut self, error_code: i64) {
        if self.reset_error_code.is_none() {
            self.reset_error_code = Some(error_code);
            self.reset_pending = true;
            // Prevent any more data from being sent or re-sent.
            self.buffer_is_empty = true;
        }
    }

    /// Write some data bytes to the QUIC stream.
    #[pyo3(signature = (data, end_stream=false))]
    pub fn write(&mut self, data: &[u8], end_stream: bool) -> PyResult<()> {
        if self.buffer_fin.is_some() {
            return Err(pyo3::exceptions::PyAssertionError::new_err(
                "cannot call write() after FIN",
            ));
        }
        if self.reset_error_code.is_some() {
            return Err(pyo3::exceptions::PyAssertionError::new_err(
                "cannot call write() after reset()",
            ));
        }
        let size = data.len();

        if size > 0 {
            self.buffer_is_empty = false;
            self.pending
                .add(self.buffer_stop, Some(self.buffer_stop + size as i64));
            self.buffer.extend_from_slice(data);
            self.buffer_stop += size as i64;
        }
        if end_stream {
            self.buffer_is_empty = false;
            self.buffer_fin = Some(self.buffer_stop);
            self.pending_eof = true;
        }
        Ok(())
    }
}
