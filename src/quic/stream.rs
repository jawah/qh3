//! Native QUIC stream state.
//!
//! Packet construction is deliberately transactional: `reserve_*` methods only
//! create a description of work.  Pending state changes in `commit_*`, after the
//! packet containing the frame has been committed.

use std::collections::BTreeMap;
use std::fmt;

use super::range::RangeSet;
use super::types::{DeliveryOutcome, Role, StreamDirection, StreamId, VARINT_MAX};

/// Largest integer which can be encoded as a QUIC variable-length integer.
pub const MAX_STREAM_OFFSET: u64 = VARINT_MAX;

/// Maximum stream count allowed by MAX_STREAMS (RFC 9000, section 19.11).
pub const MAX_STREAM_COUNT: u64 = 1_u64 << 60;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StreamError {
    OffsetOverflow,
    FinalSize {
        expected: Option<u64>,
        received: u64,
    },
    FlowControl {
        limit: u64,
        offset: u64,
    },
    ReassemblyLimit {
        limit: usize,
        attempted: usize,
    },
    StreamState(&'static str),
    InvalidStreamId(StreamId),
    StreamLimit {
        direction: StreamDirection,
        limit: u64,
    },
    UnknownReservation,
    ReservationInProgress,
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OffsetOverflow => write!(f, "stream offset exceeds the QUIC limit"),
            Self::FinalSize { expected, received } => match expected {
                Some(expected) => write!(
                    f,
                    "invalid final size {received}; established final size is {expected}"
                ),
                None => write!(f, "final size {received} is below received data"),
            },
            Self::FlowControl { limit, offset } => {
                write!(
                    f,
                    "stream offset {offset} exceeds flow-control limit {limit}"
                )
            }
            Self::ReassemblyLimit { limit, attempted } => write!(
                f,
                "sparse receive buffer would use {attempted} bytes (limit {limit})"
            ),
            Self::StreamState(message) => f.write_str(message),
            Self::InvalidStreamId(id) => {
                write!(
                    f,
                    "stream ID {} is invalid in this context",
                    id.into_inner()
                )
            }
            Self::StreamLimit { direction, limit } => {
                write!(f, "{direction:?} stream limit {limit} exceeded")
            }
            Self::UnknownReservation => f.write_str("unknown or stale stream reservation"),
            Self::ReservationInProgress => {
                f.write_str("another stream reservation is already active")
            }
        }
    }
}

impl std::error::Error for StreamError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveEvent {
    pub stream_id: StreamId,
    pub data: Vec<u8>,
    pub end_stream: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StreamAction {
    ResetStream {
        stream_id: StreamId,
        error_code: u64,
        final_size: u64,
    },
    StopSending {
        stream_id: StreamId,
        error_code: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResetEvent {
    pub stream_id: StreamId,
    pub error_code: u64,
    pub final_size: u64,
}

/// Authoritative receive-side state for one stream.
pub struct RecvStream {
    stream_id: StreamId,
    highest_offset: u64,
    final_size: Option<u64>,
    read_offset: u64,
    chunks: BTreeMap<u64, Vec<u8>>,
    buffered: usize,
    max_data: u64,
    max_buffered: usize,
    finished: bool,
    reset: bool,
    stop: ControlState,
}

impl RecvStream {
    pub fn new(stream_id: StreamId, readable: bool, max_data: u64, max_buffered: usize) -> Self {
        Self {
            stream_id,
            highest_offset: 0,
            final_size: None,
            read_offset: 0,
            chunks: BTreeMap::new(),
            buffered: 0,
            max_data: max_data.min(MAX_STREAM_OFFSET),
            max_buffered,
            finished: !readable,
            reset: false,
            stop: ControlState::default(),
        }
    }

    pub fn highest_offset(&self) -> u64 {
        self.highest_offset
    }

    #[cfg(test)]
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    pub fn final_size(&self) -> Option<u64> {
        self.final_size
    }

    #[cfg(test)]
    pub fn buffered_len(&self) -> usize {
        self.buffered
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }

    pub fn set_max_data(&mut self, limit: u64) {
        self.max_data = self.max_data.max(limit.min(MAX_STREAM_OFFSET));
    }

    pub fn receive(
        &mut self,
        offset: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<Option<ReceiveEvent>, StreamError> {
        if self.finished && !self.reset && self.final_size.is_none() {
            return Err(StreamError::StreamState("stream is not readable"));
        }
        let length = u64::try_from(data.len()).map_err(|_| StreamError::OffsetOverflow)?;
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= MAX_STREAM_OFFSET)
            .ok_or(StreamError::OffsetOverflow)?;
        self.validate_final_size(end, fin)?;
        if end > self.max_data {
            return Err(StreamError::FlowControl {
                limit: self.max_data,
                offset: end,
            });
        }

        // Determine all genuinely new slices before changing any state.
        let start = offset.max(self.read_offset);
        let mut missing = Vec::new();
        let mut cursor = start.min(end);
        let mut covered = Vec::new();
        if let Some((&chunk_start, chunk)) = self.chunks.range(..=start).next_back() {
            let chunk_end = chunk_start + chunk.len() as u64;
            if chunk_end > start {
                covered.push((chunk_start, chunk_end));
            }
        }
        if start < end {
            covered.extend(
                self.chunks
                    .range(start.saturating_add(1)..end)
                    .map(|(&chunk_start, chunk)| (chunk_start, chunk_start + chunk.len() as u64)),
            );
        }
        for (chunk_start, chunk_end) in covered {
            if chunk_end <= cursor {
                continue;
            }
            if chunk_start > cursor {
                missing.push((cursor, chunk_start.min(end)));
            }
            cursor = cursor.max(chunk_end).min(end);
            if cursor == end {
                break;
            }
        }
        if cursor < end {
            missing.push((cursor, end));
        }
        let added = missing.iter().try_fold(0_usize, |total, (start, end)| {
            usize::try_from(end - start)
                .ok()
                .and_then(|length| total.checked_add(length))
        });
        let attempted = added
            .and_then(|added| self.buffered.checked_add(added))
            .ok_or(StreamError::OffsetOverflow)?;
        if attempted > self.max_buffered {
            return Err(StreamError::ReassemblyLimit {
                limit: self.max_buffered,
                attempted,
            });
        }

        let was_finished = self.finished;
        if fin {
            self.final_size = Some(end);
        }
        self.highest_offset = self.highest_offset.max(end);
        if self.reset {
            return Ok(None);
        }
        for (missing_start, missing_end) in missing {
            let from =
                usize::try_from(missing_start - offset).map_err(|_| StreamError::OffsetOverflow)?;
            let to =
                usize::try_from(missing_end - offset).map_err(|_| StreamError::OffsetOverflow)?;
            let chunk = data.get(from..to).ok_or(StreamError::OffsetOverflow)?;
            self.chunks.insert(missing_start, chunk.to_vec());
        }
        self.buffered = attempted;

        let mut contiguous = Vec::new();
        while let Some(chunk) = self.chunks.remove(&self.read_offset) {
            self.read_offset += chunk.len() as u64;
            self.buffered -= chunk.len();
            contiguous.extend_from_slice(&chunk);
        }
        let end_stream = self.final_size == Some(self.read_offset);
        if end_stream {
            self.finished = true;
        }
        if contiguous.is_empty() && (!end_stream || was_finished) {
            Ok(None)
        } else {
            Ok(Some(ReceiveEvent {
                stream_id: self.stream_id,
                data: contiguous,
                end_stream,
            }))
        }
    }

    pub fn receive_reset(
        &mut self,
        final_size: u64,
        error_code: u64,
    ) -> Result<Option<ResetEvent>, StreamError> {
        if final_size > MAX_STREAM_OFFSET {
            return Err(StreamError::OffsetOverflow);
        }
        if final_size > self.max_data {
            return Err(StreamError::FlowControl {
                limit: self.max_data,
                offset: final_size,
            });
        }
        if let Some(expected) = self.final_size {
            if expected != final_size {
                return Err(StreamError::FinalSize {
                    expected: Some(expected),
                    received: final_size,
                });
            }
        }
        if final_size < self.highest_offset {
            return Err(StreamError::FinalSize {
                expected: None,
                received: final_size,
            });
        }
        if self.reset {
            return Ok(None);
        }
        self.final_size = Some(final_size);
        self.highest_offset = self.highest_offset.max(final_size);
        self.chunks.clear();
        self.buffered = 0;
        self.finished = true;
        self.reset = true;
        Ok(Some(ResetEvent {
            stream_id: self.stream_id,
            error_code,
            final_size,
        }))
    }

    fn validate_final_size(&self, end: u64, fin: bool) -> Result<(), StreamError> {
        if let Some(expected) = self.final_size {
            if end > expected || (fin && end != expected) {
                return Err(StreamError::FinalSize {
                    expected: Some(expected),
                    received: end,
                });
            }
        }
        if fin && end < self.highest_offset {
            return Err(StreamError::FinalSize {
                expected: None,
                received: end,
            });
        }
        Ok(())
    }

    pub fn request_stop(&mut self, error_code: u64) {
        self.stop.request(error_code);
    }

    pub fn has_pending_stop(&self) -> bool {
        self.stop.has_pending()
    }

    pub fn reserve_stop(&mut self) -> Result<Option<ActionReservation>, StreamError> {
        let stream_id = self.stream_id;
        self.stop.reserve(|error_code| StreamAction::StopSending {
            stream_id,
            error_code,
        })
    }

    pub fn commit_stop(&mut self, reservation: &ActionReservation) -> Result<(), StreamError> {
        self.stop.commit(reservation)
    }

    #[cfg(test)]
    pub fn cancel_stop(&mut self, reservation: &ActionReservation) -> Result<(), StreamError> {
        self.stop.cancel(reservation)
    }

    pub fn on_stop_delivery(&mut self, outcome: DeliveryOutcome) {
        self.stop.on_delivery(outcome);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendReservation {
    token: u64,
    pub stream_id: StreamId,
    pub offset: u64,
    pub length: usize,
    pub fin: bool,
}

impl SendReservation {
    pub fn end_offset(&self) -> u64 {
        self.offset + self.length as u64
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionReservation {
    token: u64,
    pub action: StreamAction,
}

#[derive(Default)]
struct ControlState {
    error_code: Option<u64>,
    pending: bool,
    in_flight: bool,
    active: Option<ActionReservation>,
    next_token: u64,
}

impl ControlState {
    fn has_pending(&self) -> bool {
        self.pending
    }

    fn request(&mut self, error_code: u64) {
        if !self.in_flight {
            self.error_code = Some(error_code);
            self.pending = true;
        }
    }

    fn reserve<F>(&mut self, action: F) -> Result<Option<ActionReservation>, StreamError>
    where
        F: FnOnce(u64) -> StreamAction,
    {
        if !self.pending {
            return Ok(None);
        }
        if self.active.is_some() {
            return Err(StreamError::ReservationInProgress);
        }
        self.next_token = self.next_token.wrapping_add(1);
        let token = self.next_token;
        let reservation = ActionReservation {
            token,
            action: action(self.error_code.unwrap_or(0)),
        };
        self.active = Some(reservation.clone());
        Ok(Some(reservation))
    }

    fn commit(&mut self, reservation: &ActionReservation) -> Result<(), StreamError> {
        if self.active.as_ref() != Some(reservation) {
            return Err(StreamError::UnknownReservation);
        }
        self.active = None;
        self.pending = false;
        self.in_flight = true;
        Ok(())
    }

    #[cfg(test)]
    fn cancel(&mut self, reservation: &ActionReservation) -> Result<(), StreamError> {
        if self.active.as_ref() != Some(reservation) {
            return Err(StreamError::UnknownReservation);
        }
        self.active = None;
        Ok(())
    }

    fn on_delivery(&mut self, outcome: DeliveryOutcome) {
        match outcome {
            DeliveryOutcome::Acked => self.in_flight = false,
            DeliveryOutcome::Discarded => {
                self.in_flight = false;
                self.pending = false;
            }
            DeliveryOutcome::Lost | DeliveryOutcome::RetireAndRetransmit => {
                self.in_flight = false;
                self.pending = true;
            }
            DeliveryOutcome::ProbeCopy => self.pending = true,
        }
    }
}

/// Authoritative send-side state for one stream.
pub struct SendStream {
    stream_id: StreamId,
    writable: bool,
    buffer: Vec<u8>,
    buffer_index: usize,
    buffer_start: u64,
    buffer_end: u64,
    final_size: Option<u64>,
    pending: RangeSet,
    in_flight: RangeSet,
    acked: RangeSet,
    fin_pending: bool,
    fin_in_flight: bool,
    fin_acked: bool,
    highest_sent: u64,
    active: Option<SendReservation>,
    next_token: u64,
    reset: ControlState,
    reset_requested: bool,
    finished: bool,
}

impl SendStream {
    pub fn new(stream_id: StreamId, writable: bool) -> Self {
        Self {
            stream_id,
            writable,
            buffer: Vec::new(),
            buffer_index: 0,
            buffer_start: 0,
            buffer_end: 0,
            final_size: None,
            pending: RangeSet::default(),
            in_flight: RangeSet::default(),
            acked: RangeSet::default(),
            fin_pending: false,
            fin_in_flight: false,
            fin_acked: false,
            highest_sent: 0,
            active: None,
            next_token: 0,
            reset: ControlState::default(),
            reset_requested: false,
            finished: !writable,
        }
    }

    pub fn write(&mut self, data: &[u8], fin: bool) -> Result<(), StreamError> {
        if !self.writable {
            return Err(StreamError::StreamState("stream is not writable"));
        }
        if self.final_size.is_some() {
            return Err(StreamError::StreamState("cannot write after FIN"));
        }
        if self.reset_requested {
            return Err(StreamError::StreamState("cannot write after RESET_STREAM"));
        }
        let length = u64::try_from(data.len()).map_err(|_| StreamError::OffsetOverflow)?;
        let end = self
            .buffer_end
            .checked_add(length)
            .filter(|end| *end <= MAX_STREAM_OFFSET)
            .ok_or(StreamError::OffsetOverflow)?;
        if !data.is_empty() {
            self.buffer.extend_from_slice(data);
            self.pending
                .add(self.buffer_end, end)
                .map_err(|_| StreamError::OffsetOverflow)?;
            self.buffer_end = end;
        }
        if fin {
            self.final_size = Some(end);
            self.fin_pending = true;
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn highest_sent(&self) -> u64 {
        self.highest_sent
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }

    pub fn has_pending(&self) -> bool {
        !self.reset_requested && (!self.pending.is_empty() || self.fin_pending)
    }

    /// Reserve the next STREAM frame without consuming pending data.
    pub fn reserve(
        &mut self,
        max_len: usize,
        flow_limit: u64,
    ) -> Result<Option<SendReservation>, StreamError> {
        if self.active.is_some() {
            return Err(StreamError::ReservationInProgress);
        }
        if self.reset_requested {
            return Ok(None);
        }
        let (offset, end) = if let Some(range) = self.pending.iter().next() {
            let start = range.start;
            let range_end = range.end;
            let max_len = u64::try_from(max_len).unwrap_or(u64::MAX);
            let end = range_end.min(start.saturating_add(max_len)).min(flow_limit);
            if end <= start {
                return Ok(None);
            }
            (start, end)
        } else if self.fin_pending && self.final_size.is_some_and(|size| size <= flow_limit) {
            let size = self.final_size.ok_or(StreamError::StreamState(
                "final size missing while FIN is pending",
            ))?;
            (size, size)
        } else {
            return Ok(None);
        };
        let fin = self.fin_pending && self.final_size == Some(end);
        self.next_token = self.next_token.wrapping_add(1);
        let token = self.next_token;
        let reservation = SendReservation {
            token,
            stream_id: self.stream_id,
            offset,
            length: usize::try_from(end - offset).map_err(|_| StreamError::OffsetOverflow)?,
            fin,
        };
        self.active = Some(reservation.clone());
        Ok(Some(reservation))
    }

    /// Borrow the payload covered by the active reservation.
    pub fn reserved_data(&self, reservation: &SendReservation) -> Result<&[u8], StreamError> {
        if self.active.as_ref() != Some(reservation) {
            return Err(StreamError::UnknownReservation);
        }
        let relative = reservation
            .offset
            .checked_sub(self.buffer_start)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(StreamError::UnknownReservation)?;
        let from = self
            .buffer_index
            .checked_add(relative)
            .ok_or(StreamError::UnknownReservation)?;
        let to = from
            .checked_add(reservation.length)
            .ok_or(StreamError::UnknownReservation)?;
        self.buffer
            .get(from..to)
            .ok_or(StreamError::UnknownReservation)
    }

    pub fn commit(&mut self, reservation: &SendReservation) -> Result<(), StreamError> {
        if self.active.as_ref() != Some(reservation) {
            return Err(StreamError::UnknownReservation);
        }
        self.active = None;
        let end = reservation.end_offset();
        if end > reservation.offset {
            self.pending
                .subtract(reservation.offset, end)
                .map_err(|_| StreamError::UnknownReservation)?;
            self.in_flight
                .add(reservation.offset, end)
                .map_err(|_| StreamError::OffsetOverflow)?;
            self.highest_sent = self.highest_sent.max(end);
        }
        if reservation.fin {
            self.fin_pending = false;
            self.fin_in_flight = true;
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn cancel(&mut self, reservation: &SendReservation) -> Result<(), StreamError> {
        if self.active.as_ref() != Some(reservation) {
            return Err(StreamError::UnknownReservation);
        }
        self.active = None;
        Ok(())
    }

    pub fn on_data_delivery(
        &mut self,
        offset: u64,
        length: u64,
        fin: bool,
        outcome: DeliveryOutcome,
    ) -> Result<(), StreamError> {
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= MAX_STREAM_OFFSET)
            .ok_or(StreamError::OffsetOverflow)?;
        if outcome != DeliveryOutcome::ProbeCopy && offset < end {
            self.in_flight
                .subtract(offset, end)
                .map_err(|_| StreamError::OffsetOverflow)?;
        }
        match outcome {
            DeliveryOutcome::Acked => {
                if offset < end {
                    self.pending
                        .subtract(offset, end)
                        .map_err(|_| StreamError::OffsetOverflow)?;
                }
                if end > self.buffer_start {
                    self.acked
                        .add(offset.max(self.buffer_start), end)
                        .map_err(|_| StreamError::OffsetOverflow)?;
                }
                self.release_acked_prefix()?;
                if fin {
                    self.fin_pending = false;
                    self.fin_in_flight = false;
                    self.fin_acked = true;
                }
            }
            DeliveryOutcome::Discarded => {
                if fin {
                    self.fin_in_flight = false;
                }
            }
            DeliveryOutcome::Lost
            | DeliveryOutcome::ProbeCopy
            | DeliveryOutcome::RetireAndRetransmit => {
                if end > self.buffer_start {
                    self.pending
                        .add(offset.max(self.buffer_start), end)
                        .map_err(|_| StreamError::OffsetOverflow)?;
                    let acked: Vec<_> = self.acked.iter().cloned().collect();
                    for range in acked {
                        self.pending
                            .subtract(range.start, range.end)
                            .map_err(|_| StreamError::OffsetOverflow)?;
                    }
                }
                if fin && !self.fin_acked {
                    if outcome != DeliveryOutcome::ProbeCopy {
                        self.fin_in_flight = false;
                    }
                    self.fin_pending = true;
                }
            }
        }
        self.finished = self.fin_acked && self.final_size == Some(self.buffer_start);
        Ok(())
    }

    fn release_acked_prefix(&mut self) -> Result<(), StreamError> {
        while let Some(range) = self.acked.pop_first() {
            let start = range.start;
            let end = range.end;
            if start != self.buffer_start {
                self.acked
                    .add(start, end)
                    .map_err(|_| StreamError::OffsetOverflow)?;
                break;
            }
            let count = usize::try_from(end - start).map_err(|_| StreamError::OffsetOverflow)?;
            self.buffer_start = end;
            self.buffer_index = self
                .buffer_index
                .checked_add(count)
                .ok_or(StreamError::OffsetOverflow)?;
        }
        let live = self
            .buffer
            .len()
            .checked_sub(self.buffer_index)
            .ok_or(StreamError::OffsetOverflow)?;
        if self.buffer_index > live {
            self.buffer.drain(..self.buffer_index);
            self.buffer_index = 0;
        }
        Ok(())
    }

    pub fn request_reset(&mut self, error_code: u64) {
        if !self.reset_requested {
            self.reset_requested = true;
            self.pending = RangeSet::default();
            self.fin_pending = false;
            self.active = None;
        }
        self.reset.request(error_code);
    }

    pub fn has_pending_reset(&self) -> bool {
        self.reset.has_pending()
    }

    pub fn reserve_reset(&mut self) -> Result<Option<ActionReservation>, StreamError> {
        let stream_id = self.stream_id;
        let final_size = self.highest_sent;
        self.reset.reserve(|error_code| StreamAction::ResetStream {
            stream_id,
            error_code,
            final_size,
        })
    }

    pub fn commit_reset(&mut self, reservation: &ActionReservation) -> Result<(), StreamError> {
        self.reset.commit(reservation)
    }

    #[cfg(test)]
    pub fn cancel_reset(&mut self, reservation: &ActionReservation) -> Result<(), StreamError> {
        self.reset.cancel(reservation)
    }

    pub fn on_reset_delivery(&mut self, outcome: DeliveryOutcome) {
        self.reset.on_delivery(outcome);
        if outcome == DeliveryOutcome::Acked {
            self.finished = true;
        }
    }
}

pub struct Stream {
    pub id: StreamId,
    pub recv: RecvStream,
    pub send: SendStream,
}

impl Stream {
    fn new(id: StreamId, readable: bool, writable: bool, config: &StreamConfig) -> Self {
        Self {
            id,
            recv: RecvStream::new(id, readable, config.receive_window, config.max_reassembly),
            send: SendStream::new(id, writable),
        }
    }

    pub fn is_finished(&self) -> bool {
        self.recv.is_finished() && self.send.is_finished()
    }

    /// Whether this stream has data or a control action for a packet scheduler.
    pub fn has_pending(&self) -> bool {
        self.send.has_pending() || self.send.has_pending_reset() || self.recv.has_pending_stop()
    }
}

#[derive(Clone, Debug)]
pub struct StreamConfig {
    pub receive_window: u64,
    pub max_reassembly: usize,
    pub local_max_bidi: u64,
    pub local_max_uni: u64,
    pub peer_max_bidi: u64,
    pub peer_max_uni: u64,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            receive_window: 0,
            max_reassembly: 256 * 1024,
            local_max_bidi: 0,
            local_max_uni: 0,
            peer_max_bidi: 0,
            peer_max_uni: 0,
        }
    }
}

/// Owns stream IDs and validates initiator, direction, and stream-count limits.
pub struct StreamManager {
    role: Role,
    config: StreamConfig,
    streams: BTreeMap<StreamId, Stream>,
    next_local_bidi: u64,
    next_local_uni: u64,
    opened_peer_bidi: u64,
    opened_peer_uni: u64,
}

impl StreamManager {
    pub fn new(role: Role, config: StreamConfig) -> Self {
        let initiator = u64::from(role == Role::Server);
        Self {
            role,
            config,
            streams: BTreeMap::new(),
            next_local_bidi: initiator,
            next_local_uni: initiator | 2,
            opened_peer_bidi: 0,
            opened_peer_uni: 0,
        }
    }

    pub fn open(&mut self, direction: StreamDirection) -> Result<StreamId, StreamError> {
        let (next, limit) = match direction {
            StreamDirection::Bidirectional => {
                (&mut self.next_local_bidi, self.config.peer_max_bidi)
            }
            StreamDirection::Unidirectional => (&mut self.next_local_uni, self.config.peer_max_uni),
        };
        let ordinal = *next / 4;
        if ordinal >= limit {
            return Err(StreamError::StreamLimit { direction, limit });
        }
        let id = StreamId::new(*next).ok_or(StreamError::OffsetOverflow)?;
        *next = next.checked_add(4).ok_or(StreamError::OffsetOverflow)?;
        let readable = direction == StreamDirection::Bidirectional;
        self.streams
            .insert(id, Stream::new(id, readable, true, &self.config));
        Ok(id)
    }

    /// Create a specific local stream, accounting for lower stream IDs opened implicitly.
    pub fn create_local(&mut self, id: StreamId) -> Result<&mut Stream, StreamError> {
        if id.initiator() != self.role {
            return Err(StreamError::InvalidStreamId(id));
        }
        if self.streams.contains_key(&id) {
            return self
                .streams
                .get_mut(&id)
                .ok_or(StreamError::StreamState("stream disappeared"));
        }

        let direction = stream_direction(id);
        let limit = self.peer_max_streams(direction);
        if id.index() >= limit {
            return Err(StreamError::StreamLimit { direction, limit });
        }
        let next = match direction {
            StreamDirection::Bidirectional => &mut self.next_local_bidi,
            StreamDirection::Unidirectional => &mut self.next_local_uni,
        };
        if id.into_inner() >= *next {
            *next = id
                .into_inner()
                .checked_add(4)
                .ok_or(StreamError::OffsetOverflow)?;
        }
        let readable = direction == StreamDirection::Bidirectional;
        self.streams
            .insert(id, Stream::new(id, readable, true, &self.config));
        self.streams
            .get_mut(&id)
            .ok_or(StreamError::StreamState("stream insertion failed"))
    }

    /// Return an existing stream or create a peer-initiated stream after validation.
    pub fn get_or_create_peer(&mut self, id: StreamId) -> Result<&mut Stream, StreamError> {
        if id.initiator() != self.role.peer() {
            return Err(StreamError::InvalidStreamId(id));
        }
        if self.streams.contains_key(&id) {
            return self
                .streams
                .get_mut(&id)
                .ok_or(StreamError::StreamState("stream disappeared"));
        }
        let direction = stream_direction(id);
        let limit = self.local_max_streams(direction);
        if id.index() >= limit {
            return Err(StreamError::StreamLimit { direction, limit });
        }
        let opened = match direction {
            StreamDirection::Bidirectional => &mut self.opened_peer_bidi,
            StreamDirection::Unidirectional => &mut self.opened_peer_uni,
        };
        *opened = (*opened).max(id.index() + 1);
        let writable = direction == StreamDirection::Bidirectional;
        self.streams
            .insert(id, Stream::new(id, true, writable, &self.config));
        self.streams
            .get_mut(&id)
            .ok_or(StreamError::StreamState("stream insertion failed"))
    }

    /// Access a stream's receive side, creating valid peer streams as needed.
    pub fn get_or_create_receive(&mut self, id: StreamId) -> Result<&mut RecvStream, StreamError> {
        if id.initiator() == self.role.peer() {
            return Ok(&mut self.get_or_create_peer(id)?.recv);
        }
        if id.is_unidirectional()
            || id.index() >= self.opened_local_streams(StreamDirection::Bidirectional)
        {
            return Err(StreamError::InvalidStreamId(id));
        }
        if !self.streams.contains_key(&id) {
            self.streams
                .insert(id, Stream::new(id, true, true, &self.config));
        }
        Ok(&mut self
            .streams
            .get_mut(&id)
            .ok_or(StreamError::StreamState("stream disappeared"))?
            .recv)
    }

    /// Access a stream's send side, creating valid peer bidirectional streams as needed.
    pub fn get_or_create_send(&mut self, id: StreamId) -> Result<&mut SendStream, StreamError> {
        if id.initiator() == self.role.peer() {
            if id.is_unidirectional() {
                return Err(StreamError::InvalidStreamId(id));
            }
            return Ok(&mut self.get_or_create_peer(id)?.send);
        }
        let direction = stream_direction(id);
        if id.index() >= self.opened_local_streams(direction) {
            return Err(StreamError::InvalidStreamId(id));
        }
        if !self.streams.contains_key(&id) {
            let readable = direction == StreamDirection::Bidirectional;
            self.streams
                .insert(id, Stream::new(id, readable, true, &self.config));
        }
        Ok(&mut self
            .streams
            .get_mut(&id)
            .ok_or(StreamError::StreamState("stream disappeared"))?
            .send)
    }

    pub fn local_max_streams(&self, direction: StreamDirection) -> u64 {
        match direction {
            StreamDirection::Bidirectional => self.config.local_max_bidi,
            StreamDirection::Unidirectional => self.config.local_max_uni,
        }
    }

    pub fn peer_max_streams(&self, direction: StreamDirection) -> u64 {
        match direction {
            StreamDirection::Bidirectional => self.config.peer_max_bidi,
            StreamDirection::Unidirectional => self.config.peer_max_uni,
        }
    }

    /// Raise the stream limit advertised by this endpoint. Limits never decrease.
    pub fn update_local_max_streams(
        &mut self,
        direction: StreamDirection,
        limit: u64,
    ) -> Result<bool, StreamError> {
        validate_stream_count(limit)?;
        let current = match direction {
            StreamDirection::Bidirectional => &mut self.config.local_max_bidi,
            StreamDirection::Unidirectional => &mut self.config.local_max_uni,
        };
        let changed = limit > *current;
        *current = (*current).max(limit);
        Ok(changed)
    }

    /// Apply a MAX_STREAMS limit received from the peer. Limits never decrease.
    pub fn update_peer_max_streams(
        &mut self,
        direction: StreamDirection,
        limit: u64,
    ) -> Result<bool, StreamError> {
        validate_stream_count(limit)?;
        let current = match direction {
            StreamDirection::Bidirectional => &mut self.config.peer_max_bidi,
            StreamDirection::Unidirectional => &mut self.config.peer_max_uni,
        };
        let changed = limit > *current;
        *current = (*current).max(limit);
        Ok(changed)
    }

    pub fn replace_peer_max_streams(
        &mut self,
        direction: StreamDirection,
        limit: u64,
    ) -> Result<(), StreamError> {
        validate_stream_count(limit)?;
        match direction {
            StreamDirection::Bidirectional => self.config.peer_max_bidi = limit,
            StreamDirection::Unidirectional => self.config.peer_max_uni = limit,
        }
        Ok(())
    }

    /// Number of local streams opened, including streams opened implicitly by an ID gap.
    pub fn opened_local_streams(&self, direction: StreamDirection) -> u64 {
        let next = match direction {
            StreamDirection::Bidirectional => self.next_local_bidi,
            StreamDirection::Unidirectional => self.next_local_uni,
        };
        next >> 2
    }

    /// Number of peer streams opened, including streams opened implicitly by an ID gap.
    #[cfg(test)]
    pub fn opened_peer_streams(&self, direction: StreamDirection) -> u64 {
        match direction {
            StreamDirection::Bidirectional => self.opened_peer_bidi,
            StreamDirection::Unidirectional => self.opened_peer_uni,
        }
    }

    /// Number of locally initiated streams which have not reached terminal
    /// state in both directions.
    pub fn active_local_streams(&self, direction: StreamDirection) -> u64 {
        self.streams
            .values()
            .filter(|stream| {
                stream.id.initiator() == self.role
                    && stream_direction(stream.id) == direction
                    && !stream.is_finished()
            })
            .count() as u64
    }

    pub fn get(&self, id: StreamId) -> Option<&Stream> {
        self.streams.get(&id)
    }

    pub fn get_mut(&mut self, id: StreamId) -> Option<&mut Stream> {
        self.streams.get_mut(&id)
    }

    pub fn can_send(&self, id: StreamId) -> bool {
        if let Some(stream) = self.streams.get(&id) {
            return stream.send.writable
                && stream.send.final_size.is_none()
                && !stream.send.reset_requested
                && !stream.send.finished;
        }
        id.initiator() == self.role && id.index() < self.peer_max_streams(stream_direction(id))
    }

    pub fn remove(&mut self, id: StreamId) -> Option<Stream> {
        self.streams.remove(&id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&StreamId, &Stream)> {
        self.streams.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&StreamId, &mut Stream)> {
        self.streams.iter_mut()
    }

    #[cfg(test)]
    pub fn pending_stream_ids(&self) -> impl Iterator<Item = StreamId> + '_ {
        self.streams
            .iter()
            .filter_map(|(&id, stream)| stream.has_pending().then_some(id))
    }
}

fn stream_direction(id: StreamId) -> StreamDirection {
    if id.is_unidirectional() {
        StreamDirection::Unidirectional
    } else {
        StreamDirection::Bidirectional
    }
}

fn validate_stream_count(limit: u64) -> Result<(), StreamError> {
    if limit > MAX_STREAM_COUNT {
        Err(StreamError::OffsetOverflow)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream_id(id: u64) -> StreamId {
        StreamId::new(id).unwrap()
    }

    fn receiver() -> RecvStream {
        RecvStream::new(stream_id(0), true, 1_000, 1_000)
    }

    #[test]
    fn receive_in_order_and_fin() {
        let mut recv = receiver();
        let event = recv.receive(0, b"hello", true).unwrap().unwrap();
        assert_eq!(event.data, b"hello");
        assert!(event.end_stream);
        assert!(recv.is_finished());
    }

    #[test]
    fn receive_reordered_emits_only_contiguous_data() {
        let mut recv = receiver();
        assert_eq!(recv.receive(5, b"world", true).unwrap(), None);
        let event = recv.receive(0, b"hello", false).unwrap().unwrap();
        assert_eq!(event.data, b"helloworld");
        assert!(event.end_stream);
        assert_eq!(recv.buffered_len(), 0);
    }

    #[test]
    fn receive_overlap_and_duplicate_are_not_buffered_twice() {
        let mut recv = receiver();
        recv.receive(3, b"def", false).unwrap();
        recv.receive(2, b"CDE", false).unwrap();
        assert_eq!(recv.buffered_len(), 4);
        let event = recv.receive(0, b"abc", false).unwrap().unwrap();
        assert_eq!(event.data, b"abCdef");
        assert_eq!(recv.receive(0, b"abcdef", false).unwrap(), None);
    }

    #[test]
    fn fin_below_highest_received_is_rejected_without_mutation() {
        let mut recv = receiver();
        recv.receive(10, b"x", false).unwrap();
        let error = recv.receive(0, b"abc", true).unwrap_err();
        assert!(matches!(error, StreamError::FinalSize { .. }));
        assert_eq!(recv.final_size(), None);
        assert_eq!(recv.highest_offset(), 11);
    }

    #[test]
    fn established_final_size_cannot_change_or_be_exceeded() {
        let mut recv = receiver();
        recv.receive(5, b"", true).unwrap();
        assert!(matches!(
            recv.receive(5, b"x", false),
            Err(StreamError::FinalSize { .. })
        ));
        assert!(matches!(
            recv.receive(4, b"", true),
            Err(StreamError::FinalSize { .. })
        ));
    }

    #[test]
    fn reset_validates_highest_offset_and_is_idempotent() {
        let mut recv = receiver();
        recv.receive(5, b"x", false).unwrap();
        assert!(matches!(
            recv.receive_reset(5, 42),
            Err(StreamError::FinalSize { .. })
        ));
        let event = recv.receive_reset(6, 42).unwrap().unwrap();
        assert_eq!(event.error_code, 42);
        assert_eq!(recv.receive_reset(6, 42).unwrap(), None);
    }

    #[test]
    fn receive_limits_are_transactional() {
        let mut recv = RecvStream::new(stream_id(0), true, 10, 3);
        assert!(matches!(
            recv.receive(5, b"four", false),
            Err(StreamError::ReassemblyLimit { .. })
        ));
        assert_eq!(recv.highest_offset(), 0);
        assert_eq!(recv.buffered_len(), 0);
        assert!(matches!(
            recv.receive(9, b"xx", false),
            Err(StreamError::FlowControl { .. })
        ));
        assert_eq!(recv.highest_offset(), 0);
    }

    #[test]
    fn send_reserve_cancel_and_commit_are_transactional() {
        let mut send = SendStream::new(stream_id(0), true);
        send.write(b"abcdef", true).unwrap();
        let first = send.reserve(3, 100).unwrap().unwrap();
        assert_eq!(send.reserved_data(&first).unwrap(), b"abc");
        assert_eq!(send.highest_sent(), 0);
        send.cancel(&first).unwrap();
        assert_eq!(
            send.reserved_data(&first),
            Err(StreamError::UnknownReservation)
        );
        let again = send.reserve(3, 100).unwrap().unwrap();
        assert_eq!(again.offset, 0);
        assert_eq!(send.reserved_data(&again).unwrap(), b"abc");
        send.commit(&again).unwrap();
        assert_eq!(send.highest_sent(), 3);
        let second = send.reserve(10, 100).unwrap().unwrap();
        assert_eq!(send.reserved_data(&second).unwrap(), b"def");
        assert!(second.fin);
    }

    #[test]
    fn send_loss_requeues_and_ack_does_not_retransmit() {
        let mut send = SendStream::new(stream_id(0), true);
        send.write(b"abcdef", true).unwrap();
        let frame = send.reserve(6, 100).unwrap().unwrap();
        send.commit(&frame).unwrap();
        send.on_data_delivery(0, 6, true, DeliveryOutcome::Lost)
            .unwrap();
        let retry = send.reserve(6, 100).unwrap().unwrap();
        assert_eq!(send.reserved_data(&retry).unwrap(), b"abcdef");
        assert!(retry.fin);
        send.commit(&retry).unwrap();
        send.on_data_delivery(0, 6, true, DeliveryOutcome::Acked)
            .unwrap();
        assert!(send.is_finished());
        send.on_data_delivery(0, 6, true, DeliveryOutcome::Lost)
            .unwrap();
        assert!(!send.has_pending());
    }

    #[test]
    fn out_of_order_ack_releases_only_the_contiguous_prefix() {
        let mut send = SendStream::new(stream_id(0), true);
        send.write(b"abcdef", true).unwrap();
        let first = send.reserve(3, 100).unwrap().unwrap();
        send.commit(&first).unwrap();
        let second = send.reserve(3, 100).unwrap().unwrap();
        send.commit(&second).unwrap();

        send.on_data_delivery(3, 3, true, DeliveryOutcome::Acked)
            .unwrap();
        assert!(!send.is_finished());
        send.on_data_delivery(0, 3, false, DeliveryOutcome::Acked)
            .unwrap();
        assert!(send.is_finished());
    }

    #[test]
    fn altered_or_stale_reservations_cannot_mutate_send_state() {
        let mut send = SendStream::new(stream_id(0), true);
        send.write(b"abc", false).unwrap();
        let reservation = send.reserve(3, 100).unwrap().unwrap();
        let mut altered = reservation.clone();
        altered.offset = 1;
        assert_eq!(
            send.reserved_data(&altered),
            Err(StreamError::UnknownReservation)
        );
        assert_eq!(send.commit(&altered), Err(StreamError::UnknownReservation));
        assert_eq!(send.highest_sent(), 0);
        send.cancel(&reservation).unwrap();
        assert_eq!(
            send.commit(&reservation),
            Err(StreamError::UnknownReservation)
        );
        assert_eq!(send.highest_sent(), 0);
    }

    #[test]
    fn send_flow_limit_blocks_new_data_and_fin() {
        let mut send = SendStream::new(stream_id(0), true);
        send.write(b"abc", true).unwrap();
        let frame = send.reserve(10, 2).unwrap().unwrap();
        assert_eq!(send.reserved_data(&frame).unwrap(), b"ab");
        assert!(!frame.fin);
        send.commit(&frame).unwrap();
        assert_eq!(send.reserve(10, 2).unwrap(), None);
    }

    #[test]
    fn empty_fin_is_retransmitted() {
        let mut send = SendStream::new(stream_id(0), true);
        send.write(b"", true).unwrap();
        let fin = send.reserve(0, 0).unwrap().unwrap();
        assert!(fin.fin && fin.length == 0);
        send.commit(&fin).unwrap();
        send.on_data_delivery(0, 0, true, DeliveryOutcome::Lost)
            .unwrap();
        assert!(send.reserve(0, 0).unwrap().unwrap().fin);
    }

    #[test]
    fn reset_and_stop_reservations_cancel_without_consuming() {
        let mut send = SendStream::new(stream_id(0), true);
        send.write(b"abc", false).unwrap();
        send.request_reset(7);
        let reset = send.reserve_reset().unwrap().unwrap();
        assert_eq!(
            reset.action,
            StreamAction::ResetStream {
                stream_id: stream_id(0),
                error_code: 7,
                final_size: 0,
            }
        );
        send.cancel_reset(&reset).unwrap();
        let reset = send.reserve_reset().unwrap().unwrap();
        send.commit_reset(&reset).unwrap();
        assert_eq!(send.reserve_reset().unwrap(), None);
        send.on_reset_delivery(DeliveryOutcome::Lost);
        assert!(send.reserve_reset().unwrap().is_some());

        let mut recv = receiver();
        recv.request_stop(9);
        let stop = recv.reserve_stop().unwrap().unwrap();
        recv.cancel_stop(&stop).unwrap();
        assert!(recv.reserve_stop().unwrap().is_some());
    }

    #[test]
    fn manager_validates_ids_directions_and_limits() {
        let config = StreamConfig {
            receive_window: 100,
            max_reassembly: 100,
            local_max_bidi: 1,
            local_max_uni: 1,
            peer_max_bidi: 1,
            peer_max_uni: 1,
        };
        let mut manager = StreamManager::new(Role::Client, config);
        assert_eq!(
            manager.open(StreamDirection::Bidirectional).unwrap(),
            stream_id(0)
        );
        assert!(matches!(
            manager.open(StreamDirection::Bidirectional),
            Err(StreamError::StreamLimit { .. })
        ));
        assert_eq!(
            manager.open(StreamDirection::Unidirectional).unwrap(),
            stream_id(2)
        );
        assert_eq!(
            manager.get_or_create_peer(stream_id(1)).unwrap().id,
            stream_id(1)
        );
        assert_eq!(
            manager.get_or_create_peer(stream_id(3)).unwrap().id,
            stream_id(3)
        );
        assert!(matches!(
            manager.get_or_create_peer(stream_id(5)),
            Err(StreamError::StreamLimit { .. })
        ));
        assert!(matches!(
            manager.get_or_create_peer(stream_id(4)),
            Err(StreamError::InvalidStreamId(id)) if id == stream_id(4)
        ));
    }

    #[test]
    fn manager_creates_explicit_local_ids_and_accounts_for_gaps() {
        let mut manager = StreamManager::new(
            Role::Client,
            StreamConfig {
                peer_max_bidi: 4,
                peer_max_uni: 2,
                ..StreamConfig::default()
            },
        );

        assert_eq!(manager.create_local(stream_id(8)).unwrap().id, stream_id(8));
        assert_eq!(
            manager.opened_local_streams(StreamDirection::Bidirectional),
            3
        );
        assert_eq!(manager.create_local(stream_id(0)).unwrap().id, stream_id(0));
        assert_eq!(
            manager.opened_local_streams(StreamDirection::Bidirectional),
            3
        );
        assert_eq!(
            manager.open(StreamDirection::Bidirectional).unwrap(),
            stream_id(12)
        );
        assert!(matches!(
            manager.create_local(stream_id(1)),
            Err(StreamError::InvalidStreamId(_))
        ));
        assert!(matches!(
            manager.create_local(stream_id(18)),
            Err(StreamError::StreamLimit {
                direction: StreamDirection::Unidirectional,
                limit: 2
            })
        ));
    }

    #[test]
    fn receive_creation_accounts_for_implicit_peer_streams() {
        let mut manager = StreamManager::new(
            Role::Client,
            StreamConfig {
                receive_window: 100,
                max_reassembly: 100,
                local_max_bidi: 4,
                local_max_uni: 4,
                peer_max_bidi: 1,
                peer_max_uni: 1,
            },
        );

        assert_eq!(
            manager
                .get_or_create_receive(stream_id(9))
                .unwrap()
                .stream_id(),
            stream_id(9)
        );
        assert_eq!(
            manager.opened_peer_streams(StreamDirection::Bidirectional),
            3
        );
        assert_eq!(
            manager
                .get_or_create_receive(stream_id(1))
                .unwrap()
                .stream_id(),
            stream_id(1)
        );
        assert_eq!(manager.iter().count(), 2);

        assert!(matches!(
            manager.get_or_create_receive(stream_id(0)),
            Err(StreamError::InvalidStreamId(_))
        ));
        manager.create_local(stream_id(0)).unwrap();
        assert_eq!(
            manager
                .get_or_create_receive(stream_id(0))
                .unwrap()
                .stream_id(),
            stream_id(0)
        );
        manager.create_local(stream_id(2)).unwrap();
        assert!(matches!(
            manager.get_or_create_receive(stream_id(2)),
            Err(StreamError::InvalidStreamId(_))
        ));
        assert!(matches!(
            manager.get_or_create_send(stream_id(3)),
            Err(StreamError::InvalidStreamId(_))
        ));
    }

    #[test]
    fn stream_limit_updates_are_monotonic_and_validated() {
        let mut manager = StreamManager::new(Role::Server, StreamConfig::default());
        assert!(manager
            .update_peer_max_streams(StreamDirection::Bidirectional, 2)
            .unwrap());
        assert!(!manager
            .update_peer_max_streams(StreamDirection::Bidirectional, 1)
            .unwrap());
        assert_eq!(manager.peer_max_streams(StreamDirection::Bidirectional), 2);
        assert_eq!(
            manager.open(StreamDirection::Bidirectional).unwrap(),
            stream_id(1)
        );

        assert!(manager
            .update_local_max_streams(StreamDirection::Unidirectional, 3)
            .unwrap());
        assert_eq!(
            manager
                .get_or_create_receive(stream_id(10))
                .unwrap()
                .stream_id(),
            stream_id(10)
        );
        assert_eq!(
            manager.opened_peer_streams(StreamDirection::Unidirectional),
            3
        );
        assert_eq!(
            manager.update_local_max_streams(StreamDirection::Bidirectional, MAX_STREAM_COUNT + 1),
            Err(StreamError::OffsetOverflow)
        );
    }

    #[test]
    fn active_local_count_excludes_closed_streams() {
        let mut manager = StreamManager::new(
            Role::Client,
            StreamConfig {
                peer_max_bidi: 1,
                ..StreamConfig::default()
            },
        );
        let id = manager.open(StreamDirection::Bidirectional).unwrap();
        assert_eq!(
            manager.active_local_streams(StreamDirection::Bidirectional),
            1
        );

        let stream = manager.get_mut(id).unwrap();
        stream.recv.receive(0, b"", true).unwrap();
        stream.send.write(b"", true).unwrap();
        let fin = stream.send.reserve(0, 0).unwrap().unwrap();
        stream.send.commit(&fin).unwrap();
        stream
            .send
            .on_data_delivery(0, 0, true, DeliveryOutcome::Acked)
            .unwrap();

        assert_eq!(
            manager.opened_local_streams(StreamDirection::Bidirectional),
            1
        );
        assert_eq!(
            manager.active_local_streams(StreamDirection::Bidirectional),
            0
        );
    }

    #[test]
    fn scheduler_can_iterate_pending_streams_and_commit_by_id() {
        let mut manager = StreamManager::new(
            Role::Client,
            StreamConfig {
                peer_max_bidi: 2,
                ..StreamConfig::default()
            },
        );
        let first = manager.open(StreamDirection::Bidirectional).unwrap();
        let second = manager.open(StreamDirection::Bidirectional).unwrap();
        manager
            .get_mut(first)
            .unwrap()
            .send
            .write(b"data", false)
            .unwrap();
        manager.get_mut(second).unwrap().recv.request_stop(7);

        assert_eq!(
            manager.pending_stream_ids().collect::<Vec<_>>(),
            vec![first, second]
        );
        let reservation = manager
            .get_mut(first)
            .unwrap()
            .send
            .reserve(4, 100)
            .unwrap()
            .unwrap();
        manager
            .get_mut(first)
            .unwrap()
            .send
            .commit(&reservation)
            .unwrap();
        assert_eq!(
            manager.pending_stream_ids().collect::<Vec<_>>(),
            vec![second]
        );

        for (_, stream) in manager.iter_mut() {
            if stream.recv.has_pending_stop() {
                let stop = stream.recv.reserve_stop().unwrap().unwrap();
                stream.recv.cancel_stop(&stop).unwrap();
            }
        }
    }
}
