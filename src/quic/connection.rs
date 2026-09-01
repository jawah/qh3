//! Authoritative, I/O-free QUIC connection state.
//!
//! This module joins the native wire, crypto, stream, path, recovery, and packet
//! builder components. It deliberately has no TLS or Python dependency. CRYPTO
//! input is delivered to the embedding TLS implementation as an event.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use rand::RngCore;

use super::crypto::{derive_initial_keys, CryptoError, CryptoState, PacketCrypto, PacketKey};
use super::packet_builder::{
    BuildError, BuilderConfig, BuiltDatagram, FrameAction, PacketBuilder, PacketRequest,
    QueuedFrame,
};
use super::path::{
    CidAction, CidError, ConnectionId, FlowAction, FlowController, FlowError, LocalCidStore,
    NetworkAddress, PathAction, PathId, PathManager, PeerCidStore, PmtuProbeStatus,
    StreamFlowState,
};
use super::recovery::{
    AckRange, Recovery, RecoveryConfig, RecoveryError, RecoveryEvent, SentPacket,
};
use super::stream::{StreamAction, StreamConfig, StreamError, StreamManager};
use super::types::{
    ConnectionError, ConnectionState, DeliveryId, DeliveryOutcome, Epoch, FrameType,
    PacketNumberSpace, PacketType, Role, StreamDirection, StreamId, TransportErrorCode, VarInt,
    VARINT_MAX,
};
use super::wire::{
    decode_frames, encode_varint, parse_packet_header, Frame, WireError, QUIC_VERSION_1,
    QUIC_VERSION_2,
};

const CLOSE_TIMEOUT_MULTIPLIER: u32 = 3;
const MAX_STREAM_EVENT_SIZE: usize = 64 * 1024;
const MAX_CRYPTO_REASSEMBLY: usize = 512 * 1024;
const MIN_INITIAL_DATAGRAM_SIZE: usize = 1200;
const MIN_STATELESS_RESET_SIZE: usize = 21;
const MAX_LOCAL_CONNECTION_IDS: u64 = 8;
const PMTU_PROBE_UPPER_BOUND_IPV4: usize = 1472;
const PMTU_PROBE_UPPER_BOUND_IPV6: usize = 1452;
const PMTU_PROBE_TIMEOUT_MULTIPLIER: u32 = 3;
const MAX_STREAM_TOMBSTONES: usize = 1024;

#[derive(Clone, Debug)]
pub struct ConnectionConfig {
    pub role: Role,
    pub version: u32,
    pub local_address: NetworkAddress,
    pub remote_address: NetworkAddress,
    pub source_cid: Vec<u8>,
    pub destination_cid: Vec<u8>,
    pub peer_address_validated: bool,
    pub active_connection_id_limit: u64,
    pub max_datagram_size: usize,
    pub probe_datagram_size: bool,
    pub idle_timeout: Option<Duration>,
    pub initial_time: Duration,
    pub ack_delay_exponent: u8,
    /// Maximum encoded DATAGRAM frame size accepted from the peer.
    pub max_datagram_frame_size: Option<usize>,
    /// Maximum encoded DATAGRAM frame size the peer accepts from us.
    pub peer_max_datagram_frame_size: Option<usize>,
    pub connection_receive_window: u64,
    pub connection_send_limit: u64,
    pub stream_receive_window: u64,
    pub stream_send_limit_bidi_local: u64,
    pub stream_send_limit_bidi_remote: u64,
    pub stream_send_limit_uni: u64,
    pub max_stream_reassembly: usize,
    pub local_max_streams_bidi: u64,
    pub local_max_streams_uni: u64,
    pub peer_max_streams_bidi: u64,
    pub peer_max_streams_uni: u64,
    pub recovery: RecoveryConfig,
    pub peer_disable_active_migration: bool,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        let unspecified = NetworkAddress::from(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
        Self {
            role: Role::Client,
            version: QUIC_VERSION_1,
            local_address: unspecified,
            remote_address: unspecified,
            source_cid: vec![0; 8],
            destination_cid: vec![0; 8],
            peer_address_validated: false,
            active_connection_id_limit: 2,
            max_datagram_size: 1200,
            probe_datagram_size: false,
            idle_timeout: Some(Duration::from_secs(30)),
            initial_time: Duration::ZERO,
            ack_delay_exponent: 3,
            max_datagram_frame_size: None,
            peer_max_datagram_frame_size: None,
            connection_receive_window: 1024 * 1024,
            connection_send_limit: 1024 * 1024,
            stream_receive_window: 256 * 1024,
            stream_send_limit_bidi_local: 256 * 1024,
            stream_send_limit_bidi_remote: 256 * 1024,
            stream_send_limit_uni: 256 * 1024,
            max_stream_reassembly: 256 * 1024,
            local_max_streams_bidi: 16,
            local_max_streams_uni: 16,
            peer_max_streams_bidi: 0,
            peer_max_streams_uni: 0,
            recovery: RecoveryConfig::default(),
            peer_disable_active_migration: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveMeta {
    pub now: Duration,
    pub local: NetworkAddress,
    pub remote: NetworkAddress,
    pub ecn: Option<u8>,
}

#[derive(Clone, Copy, Debug)]
pub struct ReceivedDatagram<'a> {
    pub bytes: &'a [u8],
    pub meta: ReceiveMeta,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReceiveReport {
    pub datagrams: usize,
    pub bytes: usize,
    pub packets: usize,
    pub duplicates: usize,
    pub dropped: usize,
    pub events_added: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionEvent {
    CryptoData {
        epoch: Epoch,
        offset: u64,
        data: Vec<u8>,
    },
    StreamData {
        stream_id: StreamId,
        data: Vec<u8>,
        fin: bool,
    },
    StreamReset {
        stream_id: StreamId,
        error_code: u64,
        final_size: u64,
    },
    StreamFinished(StreamId),
    StopSending {
        stream_id: StreamId,
        error_code: u64,
    },
    Datagram(Vec<u8>),
    PingAcknowledged(u64),
    NewToken(Vec<u8>),
    HandshakeDone,
    PeerMigration {
        path: PathId,
    },
    PathValidated(PathId),
    ConnectionIdIssued(Vec<u8>),
    ConnectionIdRetired(Vec<u8>),
    StreamsAvailable {
        direction: StreamDirection,
        maximum: u64,
    },
    ConnectionCredit(u64),
    StreamCredit {
        stream_id: StreamId,
        maximum: u64,
    },
    PeerBlocked {
        stream_id: Option<StreamId>,
        limit: u64,
    },
    PeerClosed {
        application: bool,
        error_code: u64,
        frame_type: Option<u64>,
        reason: Vec<u8>,
    },
    VersionNegotiation(Vec<u32>),
    Retry {
        token: Vec<u8>,
        source_cid: Vec<u8>,
    },
    ProtocolError(ConnectionError),
    ConnectionTerminated {
        error_code: u64,
        frame_type: Option<u64>,
        reason: Vec<u8>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transmit {
    pub destination: NetworkAddress,
    pub source: NetworkAddress,
    pub ecn: Option<u8>,
    pub segment_size: Option<usize>,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimerKind {
    Ack(PacketNumberSpace),
    LossDetection,
    Pacing,
    Idle,
    Close,
    Pmtu,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionTimer {
    pub kind: TimerKind,
    pub deadline: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionCommand {
    OpenStream(StreamDirection),
    ResetStream {
        stream_id: StreamId,
        error_code: u64,
    },
    StopSending {
        stream_id: StreamId,
        error_code: u64,
    },
    SendPing(u64),
    Close {
        frame_type: Option<FrameType>,
        error_code: u64,
        reason: Vec<u8>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandResult {
    None,
    StreamOpened(StreamId),
}

#[derive(Debug)]
pub enum ConnectionCoreError {
    InvalidConfig(&'static str),
    Crypto(CryptoError),
    Wire(WireError),
    Recovery(RecoveryError),
    Stream(StreamError),
    Flow(FlowError),
    Build(BuildError),
    Closed,
    DatagramTooLarge,
    InvalidGroSegmentSize,
}

impl fmt::Display for ConnectionCoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(f, "invalid connection configuration: {reason}"),
            Self::Crypto(error) => error.fmt(f),
            Self::Wire(error) => error.fmt(f),
            Self::Recovery(error) => error.fmt(f),
            Self::Stream(error) => error.fmt(f),
            Self::Flow(error) => write!(f, "flow-control error: {error:?}"),
            Self::Build(error) => error.fmt(f),
            Self::Closed => f.write_str("connection is closed"),
            Self::DatagramTooLarge => f.write_str("datagram is too large"),
            Self::InvalidGroSegmentSize => f.write_str("GRO segment size must be non-zero"),
        }
    }
}

impl Error for ConnectionCoreError {}

macro_rules! from_error {
    ($source:ty, $variant:ident) => {
        impl From<$source> for ConnectionCoreError {
            fn from(error: $source) -> Self {
                Self::$variant(error)
            }
        }
    };
}

from_error!(CryptoError, Crypto);
from_error!(WireError, Wire);
from_error!(RecoveryError, Recovery);
from_error!(StreamError, Stream);
from_error!(FlowError, Flow);
from_error!(BuildError, Build);

#[derive(Clone, Debug)]
enum DeliveryTarget {
    Ack {
        space: PacketNumberSpace,
        highest_acked: u64,
    },
    Stream {
        stream: StreamId,
        offset: u64,
        length: u64,
        fin: bool,
    },
    Reset(StreamId),
    Stop(StreamId),
    MaxStreams {
        direction: StreamDirection,
        maximum: u64,
    },
    HandshakeDone,
    MaxData(u64),
    MaxStreamData {
        stream: StreamId,
        maximum: u64,
    },
    PathResponse {
        path: PathId,
        data: [u8; 8],
    },
    Ping(u64),
    Crypto {
        epoch: Epoch,
        offset: u64,
        data: Vec<u8>,
    },
    NewConnectionId {
        sequence: u64,
    },
    RetireConnectionId {
        sequence: u64,
    },
    PathChallenge {
        path: PathId,
        data: [u8; 8],
    },
}

pub struct ConnectionCore {
    config: ConnectionConfig,
    state: ConnectionState,
    crypto: CryptoState,
    recovery: Recovery,
    streams: StreamManager,
    flow: FlowController,
    paths: PathManager,
    peer_cids: PeerCidStore,
    local_cids: LocalCidStore,
    builder: PacketBuilder,
    initial_destination_cid: Vec<u8>,
    initial_token: Vec<u8>,
    events: VecDeque<ConnectionEvent>,
    transmits: VecDeque<Transmit>,
    path_responses: VecDeque<(PathId, [u8; 8])>,
    path_challenges: VecDeque<(PathId, [u8; 8])>,
    delivery: BTreeMap<DeliveryId, DeliveryTarget>,
    pending_streams: Vec<PendingStream>,
    stream_send_queue: VecDeque<StreamId>,
    streams_queued: BTreeSet<StreamId>,
    finishing_streams: BTreeSet<StreamId>,
    stream_tombstones: BTreeMap<StreamId, StreamTombstone>,
    stream_tombstone_order: VecDeque<StreamId>,
    pending_probes: VecDeque<PacketNumberSpace>,
    next_delivery_id: u64,
    last_activity: Duration,
    ack_eliciting_sent_since_receive: bool,
    peer_idle_timeout: Option<Duration>,
    close_deadline: Option<Duration>,
    pacing_deadline: Option<Duration>,
    local_error: Option<ConnectionError>,
    peer_error: Option<(bool, u64, Vec<u8>)>,
    close_frame: Option<(Option<FrameType>, u64, Vec<u8>)>,
    close_packet_number: Option<(PacketNumberSpace, u64)>,
    close_pending: bool,
    close_packets_received: u64,
    close_send_threshold: u64,
    termination: Option<(u64, Option<u64>, Vec<u8>)>,
    termination_emitted: bool,
    peer_ack_delay_exponent: u8,
    pending_peer_max_ack_delay: Duration,
    handshake_confirmed: bool,
    crypto_receive_offsets: [u64; 4],
    crypto_receive_chunks: [BTreeMap<u64, u8>; 4],
    received_client_initial: bool,
    received_authenticated_packet: bool,
    initial_mtu_fallback: bool,
}

#[derive(Clone, Copy, Debug)]
struct StreamTombstone {
    final_size: Option<u64>,
    highest_offset: u64,
}

impl ConnectionCore {
    pub fn new(config: ConnectionConfig) -> Result<Self, ConnectionCoreError> {
        if config.max_datagram_size < 1200 || config.ack_delay_exponent > 20 {
            return Err(ConnectionCoreError::InvalidConfig(
                "invalid datagram size or ACK exponent",
            ));
        }
        let crypto =
            CryptoState::with_initial(config.version, &config.destination_cid, config.role)?;
        Self::with_crypto(config, crypto)
    }

    pub fn with_crypto(
        config: ConnectionConfig,
        crypto: CryptoState,
    ) -> Result<Self, ConnectionCoreError> {
        let stream_config = StreamConfig {
            receive_window: config.stream_receive_window,
            max_reassembly: config.max_stream_reassembly,
            local_max_bidi: config.local_max_streams_bidi,
            local_max_uni: config.local_max_streams_uni,
            peer_max_bidi: config.peer_max_streams_bidi,
            peer_max_uni: config.peer_max_streams_uni,
        };
        let mut recovery_config = config.recovery.clone();
        recovery_config.max_datagram_size = config.max_datagram_size as u64;
        recovery_config.peer_completed_address_validation = config.peer_address_validated;
        // The peer's max_ack_delay is unknown until transport parameters are
        // processed and does not enter PTO calculations until confirmation.
        recovery_config.max_ack_delay = Duration::ZERO;
        let pmtu_current = u16::try_from(config.max_datagram_size).unwrap_or(u16::MAX);
        let pmtu_upper_bound = if config.role == Role::Client && config.probe_datagram_size {
            let probe_upper_bound = if config.remote_address.ip().is_ipv4() {
                PMTU_PROBE_UPPER_BOUND_IPV4
            } else {
                PMTU_PROBE_UPPER_BOUND_IPV6
            };
            config.max_datagram_size.max(probe_upper_bound)
        } else {
            config.max_datagram_size
        };
        let paths = PathManager::new(
            config.role,
            config.local_address,
            config.remote_address,
            config.peer_address_validated,
            pmtu_current,
            u16::try_from(pmtu_upper_bound).unwrap_or(u16::MAX),
        )
        .map_err(|_| ConnectionCoreError::InvalidConfig("invalid path MTU"))?;
        let builder = PacketBuilder::new(BuilderConfig {
            version: config.version,
            source_cid: config.source_cid.clone(),
            destination_cid: config.destination_cid.clone(),
            initial_token: Vec::new(),
            is_client: config.role == Role::Client,
            spin_bit: false,
            max_datagram_size: config.max_datagram_size,
        })?;
        let active_path = paths.active_path_id();
        let mut peer_cids = PeerCidStore::new(config.active_connection_id_limit)
            .map_err(|_| ConnectionCoreError::InvalidConfig("invalid active CID limit"))?;
        if !config.destination_cid.is_empty() {
            peer_cids
                .insert(
                    0,
                    0,
                    ConnectionId::for_new_connection_id(config.destination_cid.clone())
                        .map_err(|_| ConnectionCoreError::InvalidConfig("invalid peer CID"))?,
                    [0; 16],
                )
                .map_err(|_| ConnectionCoreError::InvalidConfig("invalid peer CID"))?;
            peer_cids
                .assign_to_path(active_path)
                .map_err(|_| ConnectionCoreError::InvalidConfig("invalid peer CID"))?;
        }
        let mut local_cids = LocalCidStore::new(config.active_connection_id_limit)
            .map_err(|_| ConnectionCoreError::InvalidConfig("invalid active CID limit"))?;
        if !config.source_cid.is_empty() {
            local_cids
                .issue(
                    ConnectionId::for_new_connection_id(config.source_cid.clone())
                        .map_err(|_| ConnectionCoreError::InvalidConfig("invalid local CID"))?,
                    [0; 16],
                )
                .map_err(|_| ConnectionCoreError::InvalidConfig("invalid local CID"))?;
            local_cids
                .assign_to_path(active_path, 0)
                .map_err(|_| ConnectionCoreError::InvalidConfig("invalid local CID"))?;
        }
        let mut recovery = Recovery::new(recovery_config)?;
        recovery.start_pacing(Duration::ZERO);
        let last_activity = config.initial_time;
        Ok(Self {
            state: ConnectionState::FirstFlight,
            recovery,
            streams: StreamManager::new(config.role, stream_config),
            flow: FlowController::new(
                config.connection_send_limit,
                config.connection_receive_window,
                config.connection_receive_window,
            )?,
            paths,
            peer_cids,
            local_cids,
            builder,
            initial_destination_cid: config.destination_cid.clone(),
            initial_token: Vec::new(),
            config,
            crypto,
            events: VecDeque::new(),
            transmits: VecDeque::new(),
            path_responses: VecDeque::new(),
            path_challenges: VecDeque::new(),
            delivery: BTreeMap::new(),
            pending_streams: Vec::new(),
            stream_send_queue: VecDeque::new(),
            streams_queued: BTreeSet::new(),
            finishing_streams: BTreeSet::new(),
            stream_tombstones: BTreeMap::new(),
            stream_tombstone_order: VecDeque::new(),
            pending_probes: VecDeque::new(),
            next_delivery_id: 0,
            last_activity,
            ack_eliciting_sent_since_receive: false,
            peer_idle_timeout: None,
            close_deadline: None,
            pacing_deadline: None,
            local_error: None,
            peer_error: None,
            close_frame: None,
            close_packet_number: None,
            close_pending: false,
            close_packets_received: 0,
            close_send_threshold: 1,
            termination: None,
            termination_emitted: false,
            peer_ack_delay_exponent: 3,
            pending_peer_max_ack_delay: Duration::ZERO,
            handshake_confirmed: false,
            crypto_receive_offsets: [0; 4],
            crypto_receive_chunks: std::array::from_fn(|_| BTreeMap::new()),
            received_client_initial: false,
            received_authenticated_packet: false,
            initial_mtu_fallback: false,
        })
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }
    pub fn version(&self) -> u32 {
        self.config.version
    }
    pub fn crypto(&self) -> &CryptoState {
        &self.crypto
    }
    pub fn recovery(&self) -> &Recovery {
        &self.recovery
    }

    pub fn should_wait_for_ack(&self, now: Duration) -> bool {
        self.recovery.should_wait_for_ack(now)
    }

    pub fn outstanding_application_packets(&self) -> Vec<(u64, u64, usize)> {
        self.recovery
            .outstanding_packets(PacketNumberSpace::ApplicationData)
            .map(|packet| {
                (
                    packet.packet_number,
                    packet.sent_bytes,
                    packet.delivery_actions.len(),
                )
            })
            .collect()
    }

    pub fn streams(&self) -> &StreamManager {
        &self.streams
    }
    pub fn paths(&self) -> &PathManager {
        &self.paths
    }
    pub fn local_error(&self) -> Option<&ConnectionError> {
        self.local_error.as_ref()
    }

    pub fn received_authenticated_packet(&self) -> bool {
        self.received_authenticated_packet
    }

    pub fn active_local_streams(&self, direction: StreamDirection) -> u64 {
        self.streams.active_local_streams(direction)
    }

    pub fn can_send_stream(&self, stream_id: StreamId) -> bool {
        !matches!(
            self.state,
            ConnectionState::Closing | ConnectionState::Draining | ConnectionState::Terminated
        ) && !self.stream_tombstones.contains_key(&stream_id)
            && self.streams.can_send(stream_id)
    }

    pub fn install_send_key(&mut self, epoch: Epoch, key: PacketKey) {
        self.crypto.install_send(epoch, key);
    }

    pub fn install_receive_key(&mut self, epoch: Epoch, key: PacketKey) {
        self.crypto.install_receive(epoch, key);
    }

    pub fn set_version(&mut self, version: u32) -> Result<(), ConnectionCoreError> {
        if version == self.config.version {
            return Ok(());
        }
        if !is_compatible_version_pair(self.config.version, version) || self.handshake_confirmed {
            return Err(ConnectionCoreError::InvalidConfig(
                "connection version cannot be changed",
            ));
        }
        if [
            PacketNumberSpace::Initial,
            PacketNumberSpace::Handshake,
            PacketNumberSpace::ApplicationData,
        ]
        .into_iter()
        .any(|space| self.builder.queued_frames(space) != 0)
        {
            return Err(ConnectionCoreError::InvalidConfig(
                "connection version cannot change with queued frames",
            ));
        }

        let mut builder = PacketBuilder::new(BuilderConfig {
            version,
            source_cid: self.config.source_cid.clone(),
            destination_cid: self.config.destination_cid.clone(),
            initial_token: self.initial_token.clone(),
            is_client: self.config.role == Role::Client,
            spin_bit: false,
            max_datagram_size: self.config.max_datagram_size,
        })?;
        for space in [
            PacketNumberSpace::Initial,
            PacketNumberSpace::Handshake,
            PacketNumberSpace::ApplicationData,
        ] {
            builder.restore_packet_number(space, self.builder.next_packet_number(space))?;
        }
        let (client, server) = derive_initial_keys(version, &self.initial_destination_cid)?;
        self.crypto.discard(Epoch::Initial);
        match self.config.role {
            Role::Client => {
                self.crypto.install_send(Epoch::Initial, client);
                self.crypto.install_receive(Epoch::Initial, server);
            }
            Role::Server => {
                self.crypto.install_send(Epoch::Initial, server);
                self.crypto.install_receive(Epoch::Initial, client);
            }
        }
        self.builder = builder;
        self.config.version = version;
        Ok(())
    }

    pub fn discard_keys(&mut self, epoch: Epoch) {
        self.crypto.discard(epoch);
        let space = epoch.packet_number_space();
        if epoch != Epoch::ZeroRtt {
            self.builder.discard_space(space);
            self.pending_probes.retain(|pending| *pending != space);
            let events = self.recovery.discard_space(space);
            self.apply_recovery_events(events);
        }
    }

    pub fn reject_zero_rtt(&mut self) -> Result<(), ConnectionCoreError> {
        self.crypto.discard(Epoch::ZeroRtt);
        let events = self.recovery.reject_zero_rtt();
        self.apply_recovery_events(events);

        // Ticket limits are provisional. Fresh transport parameters must be
        // able to replace them, including with smaller values after rejection.
        self.flow.replace_connection_send_maximum(0)?;
        self.streams
            .replace_peer_max_streams(StreamDirection::Bidirectional, 0)?;
        self.streams
            .replace_peer_max_streams(StreamDirection::Unidirectional, 0)?;
        for (_, stream) in self.streams.iter_mut() {
            if let Some(flow) = self.flow.stream_mut(stream.id) {
                flow.replace_send_maximum(0)?;
            }
        }
        self.config.connection_send_limit = 0;
        self.config.stream_send_limit_bidi_local = 0;
        self.config.stream_send_limit_bidi_remote = 0;
        self.config.stream_send_limit_uni = 0;
        self.config.peer_max_streams_bidi = 0;
        self.config.peer_max_streams_uni = 0;
        Ok(())
    }

    pub fn request_key_update(&mut self) -> Result<(), ConnectionCoreError> {
        self.crypto.request_key_update(
            self.last_activity,
            mul_duration(self.recovery.probe_timeout(), 3),
        )?;
        Ok(())
    }

    pub fn restore_send_packet_number(
        &mut self,
        space: PacketNumberSpace,
        packet_number: u64,
    ) -> Result<(), ConnectionCoreError> {
        self.builder.restore_packet_number(space, packet_number)?;
        self.recovery
            .restore_sent_packet_numbers(space, packet_number)?;
        Ok(())
    }

    pub fn set_initial_token(&mut self, token: Vec<u8>) {
        self.initial_token = token.clone();
        self.builder.set_initial_token(token);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_peer_transport_parameters(
        &mut self,
        connection_send_limit: u64,
        stream_send_limit_bidi_local: u64,
        stream_send_limit_bidi_remote: u64,
        stream_send_limit_uni: u64,
        peer_max_streams_bidi: u64,
        peer_max_streams_uni: u64,
        ack_delay_exponent: u8,
        max_ack_delay: Duration,
        peer_idle_timeout: Option<Duration>,
        max_datagram_frame_size: Option<usize>,
        stateless_reset_token: Option<[u8; 16]>,
        active_connection_id_limit: u64,
        disable_active_migration: bool,
        max_udp_payload_size: Option<usize>,
    ) -> Result<(), ConnectionCoreError> {
        if ack_delay_exponent > 20 {
            return Err(ConnectionCoreError::InvalidConfig("invalid ACK exponent"));
        }
        self.local_cids
            .set_peer_active_limit(active_connection_id_limit)
            .map_err(|_| ConnectionCoreError::InvalidConfig("invalid active CID limit"))?;
        self.config.peer_disable_active_migration = disable_active_migration;
        if let Some(peer_maximum) = max_udp_payload_size {
            let peer_maximum = peer_maximum.max(MIN_INITIAL_DATAGRAM_SIZE);
            let capped = self.config.max_datagram_size.min(peer_maximum);
            self.config.max_datagram_size = capped;
            self.builder.set_max_datagram_size(capped)?;
            self.recovery.set_max_datagram_size(capped as u64);
            self.paths
                .cap_pmtu(u16::try_from(peer_maximum).unwrap_or(u16::MAX))
                .map_err(|_| ConnectionCoreError::InvalidConfig("invalid peer UDP payload size"))?;
        }
        self.flow
            .increase_connection_send_maximum(connection_send_limit)?;
        self.streams
            .update_peer_max_streams(StreamDirection::Bidirectional, peer_max_streams_bidi)?;
        self.streams
            .update_peer_max_streams(StreamDirection::Unidirectional, peer_max_streams_uni)?;
        let stream_ids: Vec<_> = self.streams.iter().map(|(&id, _)| id).collect();
        for id in stream_ids {
            let maximum = if id.is_unidirectional() {
                if id.initiator() == self.config.role {
                    stream_send_limit_uni
                } else {
                    0
                }
            } else if id.initiator() == self.config.role {
                stream_send_limit_bidi_remote
            } else {
                stream_send_limit_bidi_local
            };
            if let Some(flow) = self.flow.stream_mut(id) {
                flow.increase_send_maximum(maximum)?;
            }
        }
        self.config.connection_send_limit = connection_send_limit;
        self.config.stream_send_limit_bidi_local = stream_send_limit_bidi_local;
        self.config.stream_send_limit_bidi_remote = stream_send_limit_bidi_remote;
        self.config.stream_send_limit_uni = stream_send_limit_uni;
        self.config.peer_max_streams_bidi = peer_max_streams_bidi;
        self.config.peer_max_streams_uni = peer_max_streams_uni;
        self.peer_ack_delay_exponent = ack_delay_exponent;
        self.pending_peer_max_ack_delay = max_ack_delay;
        self.peer_idle_timeout = peer_idle_timeout.filter(|timeout| !timeout.is_zero());
        self.config.peer_max_datagram_frame_size = max_datagram_frame_size;
        if self.handshake_confirmed {
            self.recovery.set_max_ack_delay(max_ack_delay);
        }
        if let Some(token) = stateless_reset_token {
            self.peer_cids
                .install_initial_reset_token(token)
                .map_err(|_| ConnectionCoreError::InvalidConfig("invalid stateless reset token"))?;
        }
        self.issue_spare_connection_ids()?;
        Ok(())
    }

    pub fn change_connection_id(&mut self) -> Result<(), ConnectionCoreError> {
        let path = self.paths.active_path_id();
        let (retired, replacement) = self
            .peer_cids
            .rotate_path(path)
            .map_err(|_| ConnectionCoreError::InvalidConfig("no unused peer connection ID"))?;
        let destination = replacement.connection_id.as_bytes().to_vec();
        self.builder.set_destination_cid(destination.clone())?;
        self.config.destination_cid = destination;
        self.queue_retire_connection_id(retired);
        Ok(())
    }

    pub fn handshake_complete(&mut self) {
        if self.config.role == Role::Server {
            let delivery = self.new_delivery(DeliveryTarget::HandshakeDone);
            self.builder.enqueue(
                PacketNumberSpace::ApplicationData,
                QueuedFrame::new(
                    FrameType::HANDSHAKE_DONE,
                    Vec::new(),
                    FrameAction::Notify(delivery),
                ),
            );
            self.confirm_handshake();
            self.discard_keys(Epoch::ZeroRtt);
        }
    }

    pub fn confirm_handshake(&mut self) {
        if self.handshake_confirmed {
            return;
        }
        self.handshake_confirmed = true;
        self.recovery
            .set_max_ack_delay(self.pending_peer_max_ack_delay);
        self.discard_keys(Epoch::Handshake);
        if self.config.role == Role::Client {
            self.discard_keys(Epoch::ZeroRtt);
        }
    }

    pub fn poll_event(&mut self) -> Option<ConnectionEvent> {
        let event = self.events.pop_front()?;
        if let ConnectionEvent::StreamData {
            stream_id, data, ..
        } = &event
        {
            let amount = data.len() as u64;
            let _ = self.flow.consume_connection(amount);
            let _ = self.flow.consume_stream(*stream_id, amount);
            let connection_update = self.flow.take_connection_update();
            let stream_update = self.flow.take_stream_update(*stream_id);
            if let Some(action) = connection_update {
                self.queue_flow_update(action);
            }
            if let Some(action) = stream_update {
                self.queue_flow_update(action);
            }
        }
        if let ConnectionEvent::StreamReset { stream_id, .. } = &event {
            if let Ok(Some(action)) = self.flow.consume_reset(*stream_id) {
                self.queue_flow_update(action);
            }
        }
        if let ConnectionEvent::StreamFinished(stream_id) = &event {
            self.remove_finished_stream(*stream_id);
        }
        Some(event)
    }
    pub fn has_events(&self) -> bool {
        !self.events.is_empty()
    }
    #[cfg(test)]
    pub fn receive_datagram(
        &mut self,
        bytes: &[u8],
        meta: ReceiveMeta,
    ) -> Result<ReceiveReport, ConnectionCoreError> {
        self.receive_datagram_with_size(bytes, bytes.len(), meta)
    }

    pub fn receive_datagram_with_size(
        &mut self,
        bytes: &[u8],
        datagram_size: usize,
        meta: ReceiveMeta,
    ) -> Result<ReceiveReport, ConnectionCoreError> {
        let before = self.events.len();
        let mut report = ReceiveReport {
            datagrams: 1,
            bytes: datagram_size,
            ..ReceiveReport::default()
        };
        let result = self.receive_one(bytes, datagram_size, meta, &mut report);
        self.finalize_receive_batch(Some(meta.now), &mut report);
        report.events_added = self.events.len().saturating_sub(before);
        result.map(|()| report)
    }

    pub fn receive_many_datagrams(
        &mut self,
        datagrams: &[ReceivedDatagram<'_>],
    ) -> Result<ReceiveReport, ConnectionCoreError> {
        let before = self.events.len();
        let mut report = ReceiveReport::default();
        let mut result = Ok(());
        for datagram in datagrams {
            report.datagrams += 1;
            report.bytes = report.bytes.saturating_add(datagram.bytes.len());
            if let Err(error) = self.receive_one(
                datagram.bytes,
                datagram.bytes.len(),
                datagram.meta,
                &mut report,
            ) {
                result = Err(error);
                break;
            }
        }
        self.finalize_receive_batch(datagrams.last().map(|d| d.meta.now), &mut report);
        report.events_added = self.events.len().saturating_sub(before);
        result.map(|()| report)
    }

    pub fn receive_gro_buffer(
        &mut self,
        buffer: &[u8],
        segment_size: usize,
        meta: ReceiveMeta,
    ) -> Result<ReceiveReport, ConnectionCoreError> {
        if segment_size == 0 {
            return Err(ConnectionCoreError::InvalidGroSegmentSize);
        }
        let before = self.events.len();
        let mut report = ReceiveReport::default();
        let mut result = Ok(());
        for bytes in buffer.chunks(segment_size) {
            report.datagrams += 1;
            report.bytes = report.bytes.saturating_add(bytes.len());
            if let Err(error) = self.receive_one(bytes, bytes.len(), meta, &mut report) {
                result = Err(error);
                break;
            }
        }
        self.finalize_receive_batch(Some(meta.now), &mut report);
        report.events_added = self.events.len().saturating_sub(before);
        result.map(|()| report)
    }

    fn receive_one(
        &mut self,
        bytes: &[u8],
        datagram_size: usize,
        meta: ReceiveMeta,
        report: &mut ReceiveReport,
    ) -> Result<(), ConnectionCoreError> {
        if matches!(
            self.state,
            ConnectionState::Draining | ConnectionState::Terminated
        ) {
            report.dropped += 1;
            return Ok(());
        }
        if bytes.len() > 65_535 {
            report.dropped += 1;
            return Err(ConnectionCoreError::DatagramTooLarge);
        }
        let mut authenticated_path = None;
        let mut offset = 0;
        while offset < bytes.len() {
            let header = match parse_packet_header(bytes, offset, self.config.source_cid.len()) {
                Ok(header) => header,
                Err(_) => {
                    report.dropped += 1;
                    return Ok(());
                }
            };
            if self.config.role == Role::Server
                && header.packet_type == PacketType::Initial
                && datagram_size < MIN_INITIAL_DATAGRAM_SIZE
            {
                report.dropped += 1;
                return Ok(());
            }
            let packet_end = header.packet.end;
            if packet_end <= offset {
                self.protocol_error(
                    ConnectionError::new(
                        TransportErrorCode::FRAME_ENCODING_ERROR,
                        None,
                        "empty packet",
                    ),
                    meta.now,
                );
                return Ok(());
            }
            match header.packet_type {
                PacketType::VersionNegotiation => {
                    let destination_cid = header.destination_cid.get(bytes).unwrap_or_default();
                    let source_cid = header.source_cid.get(bytes).unwrap_or_default();
                    if self.config.role == Role::Client
                        && !self.received_authenticated_packet
                        && destination_cid == self.config.source_cid
                        && source_cid == self.initial_destination_cid
                    {
                        self.events.push_back(ConnectionEvent::VersionNegotiation(
                            header.versions(bytes).collect(),
                        ));
                    } else {
                        report.dropped += 1;
                    }
                }
                PacketType::Retry => {
                    if self.config.role == Role::Client && !self.received_authenticated_packet {
                        self.events.push_back(ConnectionEvent::Retry {
                            token: header.token.get(bytes).unwrap_or_default().to_vec(),
                            source_cid: header.source_cid.get(bytes).unwrap_or_default().to_vec(),
                        });
                    } else {
                        report.dropped += 1;
                    }
                }
                packet_type => {
                    let alternate_version = match header.version {
                        Some(version) if version != self.config.version => {
                            if self.config.role != Role::Client
                                || self.received_authenticated_packet
                                || !is_compatible_version_pair(self.config.version, version)
                            {
                                report.dropped += 1;
                                offset = packet_end;
                                continue;
                            }
                            Some(version)
                        }
                        _ => None,
                    };
                    let Some(epoch) = packet_epoch(packet_type) else {
                        report.dropped += 1;
                        offset = packet_end;
                        continue;
                    };
                    let space = epoch.packet_number_space();
                    let packet_destination_cid = header
                        .destination_cid
                        .get(bytes)
                        .unwrap_or_default()
                        .to_vec();
                    let initial_server_cid = self.config.role == Role::Server
                        && !self.handshake_confirmed
                        && matches!(packet_type, PacketType::Initial | PacketType::ZeroRtt)
                        && packet_destination_cid == self.initial_destination_cid;
                    if !initial_server_cid
                        && ((!self.config.source_cid.is_empty()
                            && self
                                .local_cids
                                .sequence_for_cid(&packet_destination_cid)
                                .is_none())
                            || (self.config.source_cid.is_empty()
                                && !packet_destination_cid.is_empty()))
                    {
                        if packet_type == PacketType::OneRtt
                            && bytes.len() >= MIN_STATELESS_RESET_SIZE
                            && self
                                .peer_cids
                                .matches_reset_token(&bytes[bytes.len() - 16..])
                        {
                            self.terminate_stateless_reset();
                            return Ok(());
                        }
                        report.dropped += 1;
                        offset = packet_end;
                        continue;
                    }
                    let previous_version = if let Some(version) = alternate_version {
                        let previous = self.config.version;
                        if self.set_version(version).is_err() {
                            report.dropped += 1;
                            offset = packet_end;
                            continue;
                        }
                        Some(previous)
                    } else {
                        None
                    };
                    let packet = &bytes[header.packet.as_range()];
                    let pn_offset = header.protected_payload.start - header.packet.start;
                    let expected = self.recovery.expected_packet_number(space);
                    let decrypted = match if epoch == Epoch::OneRtt {
                        self.crypto.decrypt_one_rtt(
                            packet,
                            pn_offset,
                            expected,
                            meta.now,
                            mul_duration(self.recovery.probe_timeout(), 3),
                        )
                    } else {
                        self.crypto.decrypt(epoch, packet, pn_offset, expected)
                    } {
                        Ok(packet) => packet,
                        Err(CryptoError::MissingKey(_))
                        | Err(CryptoError::Decrypt)
                        | Err(CryptoError::HeaderProtection)
                        | Err(CryptoError::InvalidKeyPhase)
                        | Err(CryptoError::PacketTooShort)
                        | Err(CryptoError::InvalidHeader) => {
                            if let Some(version) = previous_version {
                                let _ = self.set_version(version);
                            }
                            if packet_type == PacketType::OneRtt
                                && bytes.len() >= MIN_STATELESS_RESET_SIZE
                                && self
                                    .peer_cids
                                    .matches_reset_token(&bytes[bytes.len() - 16..])
                            {
                                self.terminate_stateless_reset();
                                return Ok(());
                            }
                            report.dropped += 1;
                            offset = packet_end;
                            continue;
                        }
                        Err(error) => {
                            if let Some(version) = previous_version {
                                let _ = self.set_version(version);
                            }
                            report.dropped += 1;
                            return Err(error.into());
                        }
                    };
                    self.received_authenticated_packet = true;
                    let reserved_mask = if header.version.is_some() { 0x0c } else { 0x18 };
                    if decrypted.header[0] & reserved_mask != 0 {
                        self.protocol_error(
                            ConnectionError::new(
                                TransportErrorCode::PROTOCOL_VIOLATION,
                                None,
                                "packet has non-zero reserved bits",
                            ),
                            meta.now,
                        );
                        return Ok(());
                    }
                    if self
                        .recovery
                        .is_packet_received(space, decrypted.packet_number)
                    {
                        report.duplicates += 1;
                        offset = packet_end;
                        continue;
                    }
                    self.last_activity = self.last_activity.max(meta.now);
                    self.ack_eliciting_sent_since_receive = false;
                    if self.state == ConnectionState::Closing {
                        self.close_packets_received = self.close_packets_received.saturating_add(1);
                        if self.close_packets_received >= self.close_send_threshold {
                            self.close_packets_received = 0;
                            self.close_send_threshold = self.close_send_threshold.saturating_mul(2);
                            self.requeue_close()?;
                        }
                        return Ok(());
                    }
                    let path_id = if let Some(path_id) = authenticated_path {
                        path_id
                    } else {
                        if self.config.peer_disable_active_migration
                            && meta.remote.ip() != self.paths.active_path().remote.ip()
                        {
                            report.dropped += 1;
                            return Ok(());
                        }
                        let (path_id, path_action) =
                            match self.paths.observe_remote(meta.local, meta.remote) {
                                Ok(observed) => observed,
                                Err(super::path::PathError::PathLimitExceeded) => {
                                    report.dropped += 1;
                                    return Ok(());
                                }
                                Err(_) => {
                                    return Err(ConnectionCoreError::InvalidConfig(
                                        "path allocation failed",
                                    ));
                                }
                            };
                        if let Some(path) = self.paths.path_mut(path_id) {
                            path.receive(bytes.len());
                        }
                        if let Some(PathAction::PeerMigrationDetected { candidate, .. }) =
                            path_action
                        {
                            self.events
                                .push_back(ConnectionEvent::PeerMigration { path: candidate });
                            if let Some(sequence) =
                                self.local_cids.sequence_for_cid(&packet_destination_cid)
                            {
                                let _ = self.local_cids.assign_to_path(candidate, sequence);
                            }
                            let _ = self.peer_cids.assign_to_path(candidate);
                            let mut challenge = [0; 8];
                            rand::thread_rng().fill_bytes(&mut challenge);
                            if self.paths.path_mut(candidate).is_some_and(|path| {
                                path.start_validation(challenge, meta.now).is_ok()
                            }) {
                                self.path_challenges.push_back((candidate, challenge));
                            }
                        }
                        authenticated_path = Some(path_id);
                        path_id
                    };
                    if self.state == ConnectionState::FirstFlight && header.version.is_some() {
                        let source_cid = header.source_cid.get(bytes).unwrap_or_default();
                        if !source_cid.is_empty() && source_cid != self.config.destination_cid {
                            let source_cid = source_cid.to_vec();
                            self.peer_cids
                                .replace_initial(
                                    ConnectionId::for_new_connection_id(source_cid.clone())
                                        .map_err(|_| {
                                            ConnectionCoreError::InvalidConfig("invalid peer CID")
                                        })?,
                                )
                                .map_err(|_| {
                                    ConnectionCoreError::InvalidConfig("invalid peer CID")
                                })?;
                            self.builder.set_destination_cid(source_cid.clone())?;
                            self.config.destination_cid = source_cid;
                        }
                    }
                    let crypto_frame_required = self.config.role == Role::Server
                        && packet_type == PacketType::Initial
                        && !self.received_client_initial;
                    let decoded =
                        match decode_frames(&decrypted.payload, epoch, crypto_frame_required) {
                            Ok(decoded) => decoded,
                            Err(error) => {
                                let connection_error = error.connection_error.clone();
                                self.protocol_error(connection_error, meta.now);
                                return Ok(());
                            }
                        };
                    if self.config.role == Role::Server && packet_type == PacketType::Initial {
                        self.received_client_initial = true;
                    }
                    if self.config.role == Role::Server && packet_type == PacketType::Handshake {
                        if let Some(path) = self.paths.path_mut(path_id) {
                            path.validate();
                        }
                        self.recovery.set_peer_completed_address_validation(true);
                        self.discard_keys(Epoch::Initial);
                    }
                    let stream_fin = decoded
                        .frames
                        .iter()
                        .any(|record| matches!(record.frame, Frame::Stream { fin: true, .. }));
                    if let Err(error) = self.apply_frames(
                        epoch,
                        path_id,
                        self.local_cids.sequence_for_cid(&packet_destination_cid),
                        &decrypted.payload,
                        decoded.frames,
                        meta.now,
                    ) {
                        self.protocol_error(error, meta.now);
                        return Ok(());
                    }
                    match self.recovery.on_packet_received(
                        space,
                        decrypted.packet_number,
                        decoded.flags.ack_eliciting,
                        meta.now,
                    ) {
                        Ok(true) => report.packets += 1,
                        Ok(false) => report.duplicates += 1,
                        Err(error) => return Err(error.into()),
                    }
                    if stream_fin {
                        self.recovery.expedite_ack(space, meta.now);
                    }
                    if self.state == ConnectionState::FirstFlight {
                        self.state = ConnectionState::Connected;
                    }
                }
            }
            offset = packet_end;
        }
        Ok(())
    }

    fn apply_frames(
        &mut self,
        epoch: Epoch,
        path_id: PathId,
        packet_destination_sequence: Option<u64>,
        payload: &[u8],
        frames: Vec<super::wire::FrameRecord>,
        now: Duration,
    ) -> Result<(), ConnectionError> {
        let space = epoch.packet_number_space();
        for record in frames {
            let frame_type = record.frame_type;
            match record.frame {
                Frame::Padding { .. } | Frame::Ping => {}
                Frame::Ack { delay, ranges, .. } => {
                    let exponent = if space == PacketNumberSpace::ApplicationData {
                        self.peer_ack_delay_exponent
                    } else {
                        0
                    };
                    let micros = delay
                        .into_inner()
                        .checked_shl(u32::from(exponent))
                        .unwrap_or(u64::MAX);
                    if space == PacketNumberSpace::ApplicationData {
                        if let Some(largest_acked) = ranges
                            .iter()
                            .filter_map(|range| range.end.checked_sub(1))
                            .max()
                        {
                            self.crypto.acknowledge_one_rtt(largest_acked);
                        }
                    }
                    let ranges: Vec<AckRange> = ranges
                        .into_iter()
                        .map(|range| AckRange::new(range.start, range.end))
                        .collect();
                    let events = self
                        .recovery
                        .on_ack_received(space, &ranges, Duration::from_micros(micros), now, true)
                        .map_err(|error| {
                            protocol(
                                frame_type,
                                TransportErrorCode::PROTOCOL_VIOLATION,
                                error.to_string(),
                            )
                        })?;
                    self.apply_recovery_events(events);
                }
                Frame::ResetStream {
                    stream_id,
                    error_code,
                    final_size,
                } => {
                    if let Some(tombstone) = self.stream_tombstones.get(&stream_id) {
                        if tombstone.final_size != Some(final_size.into_inner()) {
                            return Err(protocol(
                                frame_type,
                                TransportErrorCode::FINAL_SIZE_ERROR,
                                "RESET_STREAM changes the final size of a completed stream",
                            ));
                        }
                        continue;
                    }
                    self.ensure_receive_stream(stream_id)?;
                    self.flow
                        .receive_stream(stream_id, final_size.into_inner(), true)
                        .map_err(|error| flow_protocol(frame_type, error))?;
                    if let Some(event) = self
                        .streams
                        .get_or_create_receive(stream_id)
                        .map_err(|error| stream_protocol(frame_type, error))?
                        .receive_reset(final_size.into_inner(), error_code.into_inner())
                        .map_err(|error| stream_protocol(frame_type, error))?
                    {
                        self.events.push_back(ConnectionEvent::StreamReset {
                            stream_id: event.stream_id,
                            error_code: event.error_code,
                            final_size: event.final_size,
                        });
                    }
                    self.refresh_stream_completion(stream_id);
                }
                Frame::StopSending {
                    stream_id,
                    error_code,
                } => {
                    if self.stream_tombstones.contains_key(&stream_id) {
                        continue;
                    }
                    let send = self
                        .streams
                        .get_or_create_send(stream_id)
                        .map_err(|error| stream_protocol(frame_type, error))?;
                    send.request_reset(error_code.into_inner());
                    self.schedule_stream(stream_id);
                    self.events.push_back(ConnectionEvent::StopSending {
                        stream_id,
                        error_code: error_code.into_inner(),
                    });
                }
                Frame::Crypto { offset, data } => {
                    self.receive_crypto(
                        epoch,
                        offset.into_inner(),
                        data.get(payload).unwrap_or_default(),
                    )?;
                }
                Frame::NewToken { token } => {
                    if self.config.role != Role::Client {
                        return Err(protocol(
                            frame_type,
                            TransportErrorCode::PROTOCOL_VIOLATION,
                            "clients must not send NEW_TOKEN frames",
                        ));
                    }
                    self.events.push_back(ConnectionEvent::NewToken(
                        token.get(payload).unwrap_or_default().to_vec(),
                    ));
                }
                Frame::Stream {
                    stream_id,
                    offset,
                    fin,
                    data,
                } => {
                    let bytes = data.get(payload).unwrap_or_default();
                    let end = offset
                        .into_inner()
                        .checked_add(bytes.len() as u64)
                        .ok_or_else(|| {
                            protocol(
                                frame_type,
                                TransportErrorCode::FINAL_SIZE_ERROR,
                                "stream offset overflow",
                            )
                        })?;
                    if let Some(tombstone) = self.stream_tombstones.get(&stream_id) {
                        if end > tombstone.final_size.unwrap_or(tombstone.highest_offset)
                            || (fin && tombstone.final_size != Some(end))
                        {
                            return Err(protocol(
                                frame_type,
                                TransportErrorCode::FINAL_SIZE_ERROR,
                                "STREAM frame changes the final size of a completed stream",
                            ));
                        }
                        continue;
                    }
                    self.ensure_receive_stream(stream_id)?;
                    let reservation = self
                        .flow
                        .prepare_receive(stream_id, end, fin)
                        .map_err(|error| flow_protocol(frame_type, error))?;
                    let receive = self
                        .streams
                        .get_or_create_receive(stream_id)
                        .map_err(|error| stream_protocol(frame_type, error))?
                        .receive(offset.into_inner(), bytes, fin)
                        .map_err(|error| stream_protocol(frame_type, error));
                    match receive {
                        Ok(event) => {
                            self.flow
                                .commit_receive(reservation)
                                .map_err(|error| flow_protocol(frame_type, error))?;
                            if let Some(event) = event {
                                self.push_stream_data_event(
                                    event.stream_id,
                                    event.data,
                                    event.end_stream,
                                );
                            }
                        }
                        Err(error) => {
                            let _ = self.flow.cancel_receive(reservation);
                            return Err(error);
                        }
                    }
                    self.refresh_stream_completion(stream_id);
                }
                Frame::MaxData { maximum } => {
                    if self
                        .flow
                        .increase_connection_send_maximum(maximum.into_inner())
                        .map_err(|error| flow_protocol(frame_type, error))?
                    {
                        self.events
                            .push_back(ConnectionEvent::ConnectionCredit(maximum.into_inner()));
                    }
                }
                Frame::MaxStreamData { stream_id, maximum } => {
                    if self.stream_tombstones.contains_key(&stream_id) {
                        continue;
                    }
                    self.ensure_send_stream(stream_id)?;
                    if self
                        .flow
                        .stream_mut(stream_id)
                        .ok_or_else(|| {
                            protocol(
                                frame_type,
                                TransportErrorCode::INTERNAL_ERROR,
                                "flow-control stream is missing",
                            )
                        })?
                        .increase_send_maximum(maximum.into_inner())
                        .map_err(|error| flow_protocol(frame_type, error))?
                    {
                        self.events.push_back(ConnectionEvent::StreamCredit {
                            stream_id,
                            maximum: maximum.into_inner(),
                        });
                    }
                }
                Frame::MaxStreams {
                    maximum,
                    unidirectional,
                } => {
                    let direction = if unidirectional {
                        StreamDirection::Unidirectional
                    } else {
                        StreamDirection::Bidirectional
                    };
                    if self
                        .streams
                        .update_peer_max_streams(direction, maximum.into_inner())
                        .map_err(|error| stream_protocol(frame_type, error))?
                    {
                        self.events.push_back(ConnectionEvent::StreamsAvailable {
                            direction,
                            maximum: maximum.into_inner(),
                        });
                    }
                }
                Frame::DataBlocked { limit } | Frame::StreamsBlocked { limit, .. } => {
                    self.events.push_back(ConnectionEvent::PeerBlocked {
                        stream_id: None,
                        limit: limit.into_inner(),
                    });
                }
                Frame::StreamDataBlocked { stream_id, limit } => {
                    self.events.push_back(ConnectionEvent::PeerBlocked {
                        stream_id: Some(stream_id),
                        limit: limit.into_inner(),
                    });
                }
                Frame::NewConnectionId {
                    sequence_number,
                    retire_prior_to,
                    connection_id,
                    stateless_reset_token,
                } => {
                    let cid = ConnectionId::for_new_connection_id(
                        connection_id.get(payload).unwrap_or_default().to_vec(),
                    )
                    .map_err(|error| {
                        protocol(
                            frame_type,
                            TransportErrorCode::CONNECTION_ID_LIMIT_ERROR,
                            format!("{error:?}"),
                        )
                    })?;
                    let mut token = [0; 16];
                    token.copy_from_slice(stateless_reset_token.get(payload).unwrap_or_default());
                    let actions = self
                        .peer_cids
                        .insert(
                            sequence_number.into_inner(),
                            retire_prior_to.into_inner(),
                            cid,
                            token,
                        )
                        .map_err(|error| cid_protocol(frame_type, error))?;
                    for action in actions {
                        self.apply_cid_action(action);
                    }
                    // A newly advertised CID is only selected when this path lost
                    // its prior assignment through retire_prior_to.
                    if self.peer_cids.assigned_to_path(path_id).is_none() {
                        let peer_cid = self.peer_cids.assign_to_path(path_id).map_err(|error| {
                            protocol(
                                frame_type,
                                TransportErrorCode::CONNECTION_ID_LIMIT_ERROR,
                                format!("{error:?}"),
                            )
                        })?;
                        let destination_cid = peer_cid.connection_id.as_bytes().to_vec();
                        if path_id == self.paths.active_path_id() {
                            self.builder
                                .set_destination_cid(destination_cid.clone())
                                .map_err(|error| {
                                    protocol(
                                        frame_type,
                                        TransportErrorCode::INTERNAL_ERROR,
                                        error.to_string(),
                                    )
                                })?;
                            self.config.destination_cid = destination_cid;
                        }
                    }
                }
                Frame::RetireConnectionId { sequence_number } => {
                    let sequence = sequence_number.into_inner();
                    if packet_destination_sequence == Some(sequence) {
                        return Err(protocol(
                            frame_type,
                            TransportErrorCode::PROTOCOL_VIOLATION,
                            "peer retired the destination CID used by this packet",
                        ));
                    }
                    let action = match self.local_cids.retire_from_peer(sequence) {
                        Ok(action) => action,
                        Err(CidError::AlreadyRetired(_)) => continue,
                        Err(error) => {
                            return Err(protocol(
                                frame_type,
                                TransportErrorCode::PROTOCOL_VIOLATION,
                                format!("{error:?}"),
                            ));
                        }
                    };
                    self.apply_cid_action(action);
                    self.issue_spare_connection_ids().map_err(|error| {
                        protocol(
                            frame_type,
                            TransportErrorCode::INTERNAL_ERROR,
                            error.to_string(),
                        )
                    })?;
                }
                Frame::PathChallenge { data } => {
                    let mut challenge = [0; 8];
                    challenge.copy_from_slice(data.get(payload).unwrap_or_default());
                    self.path_responses.push_back((path_id, challenge));
                }
                Frame::PathResponse { data } => {
                    let mut response = [0; 8];
                    response.copy_from_slice(data.get(payload).unwrap_or_default());
                    if let Some(path) = self.paths.path_mut(path_id) {
                        if let Ok(PathAction::PathValidated(id)) = path.receive_response(response) {
                            self.events.push_back(ConnectionEvent::PathValidated(id));
                            let previous = self.paths.active_path_id();
                            if self.peer_cids.assigned_to_path(id).is_none() {
                                let _ = self.peer_cids.move_assignment(previous, id);
                            }
                            if self.paths.activate(id).ok().flatten().is_some() {
                                let retain_congestion = self
                                    .paths
                                    .path(previous)
                                    .zip(self.paths.path(id))
                                    .is_some_and(|(old, new)| old.remote.ip() == new.remote.ip());
                                if let Some(cid) = self.peer_cids.assigned_to_path(id) {
                                    let destination = cid.connection_id.as_bytes().to_vec();
                                    self.builder
                                        .set_destination_cid(destination.clone())
                                        .map_err(|error| {
                                            protocol(
                                                frame_type,
                                                TransportErrorCode::INTERNAL_ERROR,
                                                error.to_string(),
                                            )
                                        })?;
                                    self.config.destination_cid = destination;
                                }
                                let datagram_size =
                                    self.paths.active_path().pmtu.current() as usize;
                                self.config.max_datagram_size = datagram_size;
                                self.builder.set_max_datagram_size(datagram_size).map_err(
                                    |error| {
                                        protocol(
                                            frame_type,
                                            TransportErrorCode::INTERNAL_ERROR,
                                            error.to_string(),
                                        )
                                    },
                                )?;
                                self.recovery.set_max_datagram_size(datagram_size as u64);
                                self.recovery.reset_for_new_path(
                                    previous.get(),
                                    id.get(),
                                    retain_congestion,
                                );
                                self.recovery.start_pacing(now);
                            }
                        }
                    }
                }
                Frame::ConnectionClose {
                    error_code,
                    reason,
                    application,
                    trigger_frame_type,
                } => {
                    let reason = reason.get(payload).unwrap_or_default().to_vec();
                    self.peer_error = Some((application, error_code.into_inner(), reason.clone()));
                    self.termination = Some((
                        error_code.into_inner(),
                        trigger_frame_type.map(FrameType::value),
                        reason.clone(),
                    ));
                    self.transmits.clear();
                    self.state = ConnectionState::Draining;
                    self.close_deadline = Some(add_duration(
                        now,
                        mul_duration(self.recovery.probe_timeout(), CLOSE_TIMEOUT_MULTIPLIER),
                    ));
                    self.events.push_back(ConnectionEvent::PeerClosed {
                        application,
                        error_code: error_code.into_inner(),
                        frame_type: trigger_frame_type.map(FrameType::value),
                        reason,
                    });
                    return Ok(());
                }
                Frame::HandshakeDone => {
                    if self.config.role != Role::Client {
                        return Err(protocol(
                            frame_type,
                            TransportErrorCode::PROTOCOL_VIOLATION,
                            "server received HANDSHAKE_DONE",
                        ));
                    }
                    self.confirm_handshake();
                    self.events.push_back(ConnectionEvent::HandshakeDone);
                }
                Frame::Datagram { data } => {
                    let data = data.get(payload).unwrap_or_default();
                    let Some(maximum) = self.config.max_datagram_frame_size else {
                        return Err(protocol(
                            frame_type,
                            TransportErrorCode::PROTOCOL_VIOLATION,
                            "DATAGRAM extension was not enabled",
                        ));
                    };
                    if record.span.len() > maximum {
                        return Err(protocol(
                            frame_type,
                            TransportErrorCode::PROTOCOL_VIOLATION,
                            "DATAGRAM frame exceeds the advertised maximum",
                        ));
                    }
                    self.events
                        .push_back(ConnectionEvent::Datagram(data.to_vec()));
                }
            }
        }
        Ok(())
    }

    fn finalize_receive_batch(&mut self, now: Option<Duration>, _report: &mut ReceiveReport) {
        if let Some(now) = now {
            if self.state == ConnectionState::Closing && self.close_deadline.is_none() {
                self.close_deadline = Some(add_duration(
                    now,
                    mul_duration(self.recovery.probe_timeout(), CLOSE_TIMEOUT_MULTIPLIER),
                ));
            }
        }
    }

    pub fn command(
        &mut self,
        command: ConnectionCommand,
    ) -> Result<CommandResult, ConnectionCoreError> {
        let error_code = match &command {
            ConnectionCommand::ResetStream { error_code, .. }
            | ConnectionCommand::StopSending { error_code, .. }
            | ConnectionCommand::Close { error_code, .. } => Some(*error_code),
            _ => None,
        };
        if error_code.is_some_and(|value| value > VARINT_MAX) {
            return Err(ConnectionCoreError::InvalidConfig(
                "error code exceeds the QUIC varint limit",
            ));
        }
        if matches!(
            self.state,
            ConnectionState::Closing | ConnectionState::Draining | ConnectionState::Terminated
        ) {
            if matches!(command, ConnectionCommand::Close { .. }) {
                return Ok(CommandResult::None);
            }
            return Err(ConnectionCoreError::Closed);
        }
        match command {
            ConnectionCommand::OpenStream(direction) => {
                let id = self.streams.open(direction)?;
                self.insert_flow_stream(id)?;
                Ok(CommandResult::StreamOpened(id))
            }
            ConnectionCommand::ResetStream {
                stream_id,
                error_code,
            } => {
                self.ensure_send_stream_core(stream_id)?;
                self.streams
                    .get_or_create_send(stream_id)?
                    .request_reset(error_code);
                self.schedule_stream(stream_id);
                Ok(CommandResult::None)
            }
            ConnectionCommand::StopSending {
                stream_id,
                error_code,
            } => {
                if self.stream_tombstones.contains_key(&stream_id) {
                    return Err(StreamError::StreamState(
                        "cannot stop receiving on a completed stream",
                    )
                    .into());
                }
                if stream_id.initiator() == self.config.role && stream_id.is_unidirectional() {
                    return Err(StreamError::StreamState(
                        "cannot stop receiving on a local-initiated unidirectional stream",
                    )
                    .into());
                }
                let stream = self
                    .streams
                    .get_mut(stream_id)
                    .ok_or(StreamError::StreamState(
                        "cannot stop receiving on an unknown stream",
                    ))?;
                stream.recv.request_stop(error_code);
                self.schedule_stream(stream_id);
                Ok(CommandResult::None)
            }
            ConnectionCommand::SendPing(uid) => {
                let delivery = self.new_delivery(DeliveryTarget::Ping(uid));
                self.builder.enqueue(
                    PacketNumberSpace::ApplicationData,
                    QueuedFrame::new(FrameType::PING, Vec::new(), FrameAction::Notify(delivery)),
                );
                Ok(CommandResult::None)
            }
            ConnectionCommand::Close {
                frame_type,
                error_code,
                reason,
            } => {
                self.start_close(frame_type, error_code, reason, self.last_activity)?;
                self.state = ConnectionState::Closing;
                Ok(CommandResult::None)
            }
        }
    }

    pub fn send_stream(
        &mut self,
        stream_id: StreamId,
        data: &[u8],
        fin: bool,
    ) -> Result<CommandResult, ConnectionCoreError> {
        self.ensure_send_command_allowed()?;
        self.ensure_send_stream_core(stream_id)?;
        self.streams
            .get_or_create_send(stream_id)?
            .write(data, fin)?;
        self.schedule_stream(stream_id);
        Ok(CommandResult::None)
    }

    pub fn send_datagram(&mut self, data: &[u8]) -> Result<CommandResult, ConnectionCoreError> {
        self.ensure_send_command_allowed()?;
        let maximum =
            self.config
                .peer_max_datagram_frame_size
                .ok_or(ConnectionCoreError::InvalidConfig(
                    "DATAGRAM extension is disabled",
                ))?;
        let length_size = varint_size(data.len() as u64);
        let encoded_size = 1_usize
            .checked_add(length_size)
            .and_then(|size| size.checked_add(data.len()))
            .ok_or(ConnectionCoreError::DatagramTooLarge)?;
        if encoded_size > maximum {
            return Err(ConnectionCoreError::DatagramTooLarge);
        }
        let mut body = Vec::with_capacity(length_size + data.len());
        push_varint(&mut body, data.len() as u64)?;
        body.extend_from_slice(data);
        self.builder.enqueue(
            PacketNumberSpace::ApplicationData,
            QueuedFrame::new(FrameType::DATAGRAM_WITH_LENGTH, body, FrameAction::None),
        );
        Ok(CommandResult::None)
    }

    pub fn send_crypto(
        &mut self,
        epoch: Epoch,
        offset: u64,
        data: &[u8],
    ) -> Result<CommandResult, ConnectionCoreError> {
        self.ensure_send_command_allowed()?;
        if offset
            .checked_add(data.len() as u64)
            .map_or(true, |end| end > VARINT_MAX)
        {
            return Err(ConnectionCoreError::InvalidConfig(
                "CRYPTO end offset exceeds the QUIC varint limit",
            ));
        }
        // Queued frames are atomic to the packet builder, so split TLS
        // flights here rather than allowing a large certificate flight
        // to exceed one QUIC packet.
        // A Retry token consumes Initial header space. Keep retransmittable CRYPTO
        // frames small enough to fit after the pre-authentication 1200-byte fallback.
        let crypto_chunk_size = if epoch == Epoch::Initial && !self.initial_token.is_empty() {
            900.min(
                MIN_INITIAL_DATAGRAM_SIZE
                    .saturating_sub(self.initial_token.len())
                    .saturating_sub(128)
                    .max(1),
            )
        } else {
            900
        };
        for (chunk_offset, chunk) in data.chunks(crypto_chunk_size).enumerate() {
            let chunk_offset = offset
                .checked_add((chunk_offset * crypto_chunk_size) as u64)
                .ok_or(ConnectionCoreError::InvalidConfig("CRYPTO offset overflow"))?;
            let mut body = Vec::with_capacity(
                varint_size(chunk_offset) + varint_size(chunk.len() as u64) + chunk.len(),
            );
            push_varint(&mut body, chunk_offset)?;
            push_varint(&mut body, chunk.len() as u64)?;
            body.extend_from_slice(chunk);
            let delivery = self.new_delivery(DeliveryTarget::Crypto {
                epoch,
                offset: chunk_offset,
                data: chunk.to_vec(),
            });
            self.builder.enqueue(
                epoch.packet_number_space(),
                QueuedFrame::new(FrameType::CRYPTO, body, FrameAction::Notify(delivery)),
            );
        }
        Ok(CommandResult::None)
    }

    fn ensure_send_command_allowed(&self) -> Result<(), ConnectionCoreError> {
        if matches!(
            self.state,
            ConnectionState::Closing | ConnectionState::Draining | ConnectionState::Terminated
        ) {
            Err(ConnectionCoreError::Closed)
        } else {
            Ok(())
        }
    }

    pub fn poll_transmit(
        &mut self,
        now: Duration,
    ) -> Result<Option<Transmit>, ConnectionCoreError> {
        if let Some(transmit) = self.transmits.pop_front() {
            return Ok(Some(transmit));
        }
        if self.state == ConnectionState::Terminated {
            return Ok(None);
        }
        if self.state == ConnectionState::Draining {
            return Ok(None);
        }
        if self.state == ConnectionState::Closing {
            return self.poll_close_transmit(now);
        }
        let send_path = self
            .path_responses
            .front()
            .map(|(path, _)| *path)
            .or_else(|| self.path_challenges.front().map(|(path, _)| *path))
            .unwrap_or_else(|| self.paths.active_path_id());
        let path_allowance = self
            .paths
            .path(send_path)
            .map_or(0, |path| path.send_allowance());
        let minimum_packet_size = 1_u64
            .saturating_add(self.config.destination_cid.len() as u64)
            .saturating_add(2)
            .saturating_add(18);
        if path_allowance < minimum_packet_size {
            return Ok(None);
        }
        let builder_limit = self
            .config
            .max_datagram_size
            .min(usize::try_from(path_allowance).unwrap_or(usize::MAX));

        let queued_before_ack = [
            PacketNumberSpace::Initial,
            PacketNumberSpace::Handshake,
            PacketNumberSpace::ApplicationData,
        ]
        .into_iter()
        .map(|space| self.builder.queued_frames(space))
        .sum::<usize>();
        let queued_acks = self.queue_due_ack(now)?;
        // ACK-only packets are not in flight and are not congestion controlled
        // (RFC 9002 section 7). In particular, the ACK for a response FIN must
        // still leave when request packets have filled the local congestion window.
        let ack_only = queued_before_ack == 0
            && queued_acks != 0
            && self.pending_streams.is_empty()
            && self.pending_probes.is_empty();
        self.queue_path_control();
        let pmtu_probe_size = if self.config.role == Role::Client
            && self.config.probe_datagram_size
            && self.handshake_confirmed
            && self.pending_streams.is_empty()
            && self.stream_send_queue.is_empty()
            && self.pending_probes.is_empty()
            && self.path_responses.is_empty()
            && self.path_challenges.is_empty()
            // Discarded packet-number spaces can retain unsent TLS frames. They
            // cannot contend with a 1-RTT probe and must not disable PMTUD.
            && self
                .builder
                .queued_frames(PacketNumberSpace::ApplicationData)
                == 0
        {
            self.paths
                .active_path()
                .pmtu
                .next_probe_size()
                .filter(|size| u64::from(*size) <= path_allowance)
        } else {
            None
        };
        if pmtu_probe_size.is_some() {
            self.builder.enqueue(
                PacketNumberSpace::ApplicationData,
                QueuedFrame::new(FrameType::PING, Vec::new(), FrameAction::None),
            );
        }
        let destination_cid = self
            .peer_cids
            .assigned_to_path(send_path)
            .map(|entry| entry.connection_id.as_bytes().to_vec())
            .unwrap_or_else(|| self.config.destination_cid.clone());
        self.builder.set_destination_cid(destination_cid)?;
        let congestion_allowance = self
            .recovery
            .congestion()
            .congestion_window()
            .saturating_sub(self.recovery.congestion().bytes_in_flight());
        let queued_packet_type = self.next_packet_type();
        let probe_packet_type = self
            .pending_probes
            .front()
            .copied()
            .map(packet_type_for_space);
        let sending_probe = probe_packet_type
            .is_some_and(|probe| queued_packet_type.is_none() || queued_packet_type == Some(probe));
        let mut reservations = std::mem::take(&mut self.pending_streams);
        let pacing_ready = if sending_probe || pmtu_probe_size.is_some() || ack_only {
            true
        } else if congestion_allowance >= self.config.max_datagram_size as u64 {
            match self
                .recovery
                .pacer_mut()
                .poll(now, self.config.max_datagram_size as u64)
            {
                Some(deadline) => {
                    self.pacing_deadline = Some(deadline);
                    false
                }
                None => {
                    self.pacing_deadline = None;
                    true
                }
            }
        } else {
            false
        };
        if reservations.is_empty()
            && (sending_probe
                || pmtu_probe_size.is_some()
                || congestion_allowance >= self.config.max_datagram_size as u64)
            && pacing_ready
        {
            if sending_probe {
                reservations = self.queue_probe_stream_actions()?;
            } else if pmtu_probe_size.is_none() {
                while reservations.len() < 16 {
                    let Some(pending) = self.queue_one_stream_action()? else {
                        break;
                    };
                    reservations.push(pending);
                }
            }
        }
        if !sending_probe
            && pmtu_probe_size.is_none()
            && !ack_only
            && congestion_allowance < self.config.max_datagram_size as u64
            && !reservations.is_empty()
        {
            self.pending_streams = reservations;
            return Ok(None);
        }
        if sending_probe {
            self.builder.enqueue(
                self.pending_probes[0],
                QueuedFrame::new(FrameType::PING, Vec::new(), FrameAction::None),
            );
        }
        let packet_type = if sending_probe {
            probe_packet_type
        } else {
            self.next_packet_type()
        };
        let Some(packet_type) = packet_type else {
            self.pending_streams = reservations;
            return Ok(None);
        };
        let mut request = PacketRequest::new(packet_type);
        if packet_type == PacketType::OneRtt {
            request.key_phase = self.crypto.send_key_phase() == Some(1);
        }
        if let Some(size) = pmtu_probe_size {
            self.builder.set_max_datagram_size(size as usize)?;
            request.pad_to_capacity = true;
            request.is_pmtu_probe = true;
        } else {
            self.builder.set_max_datagram_size(builder_limit)?;
        }
        let result = self.builder.build(request, &mut self.crypto);
        if pmtu_probe_size.is_some() {
            self.builder.set_max_datagram_size(builder_limit)?;
        }
        let mut result = match result {
            Ok(result) => result,
            Err(error) => {
                self.pending_streams = reservations;
                self.builder
                    .set_max_datagram_size(self.config.max_datagram_size)?;
                return Err(error.into());
            }
        };
        if packet_type != PacketType::OneRtt {
            if let Some(datagram) = self.builder.flush() {
                result.datagrams.push(datagram);
            }
        }
        self.builder
            .set_max_datagram_size(self.config.max_datagram_size)?;
        let sent_delivery_ids: Vec<_> = result
            .datagrams
            .iter()
            .flat_map(|datagram| &datagram.packets)
            .chain(result.packet.iter())
            .flat_map(|packet| &packet.frames)
            .filter_map(|frame| frame.delivery_id)
            .collect();
        for reservation in reservations {
            if sent_delivery_ids.contains(&reservation.delivery_id()) {
                self.commit_stream_reservation(Some(reservation))?;
            } else {
                self.pending_streams.push(reservation);
            }
        }
        if sending_probe {
            self.pending_probes.pop_front();
        }
        for datagram in result.datagrams {
            self.complete_datagram(datagram, send_path, now)?;
        }
        Ok(self.transmits.pop_front())
    }

    pub fn next_timer(&self) -> Option<ConnectionTimer> {
        if matches!(
            self.state,
            ConnectionState::Closing | ConnectionState::Draining
        ) {
            return self.close_deadline.map(|deadline| ConnectionTimer {
                kind: TimerKind::Close,
                deadline,
            });
        }
        if self.state == ConnectionState::Terminated {
            return None;
        }
        let mut timers = Vec::new();
        for space in [
            PacketNumberSpace::Initial,
            PacketNumberSpace::Handshake,
            PacketNumberSpace::ApplicationData,
        ] {
            if let Some(deadline) = self.recovery.ack_deadline(space) {
                timers.push(ConnectionTimer {
                    kind: TimerKind::Ack(space),
                    deadline,
                });
            }
        }
        if let Some(deadline) = self.recovery.loss_detection_time() {
            timers.push(ConnectionTimer {
                kind: TimerKind::LossDetection,
                deadline,
            });
        }
        if let Some(timeout) = self.effective_idle_timeout() {
            timers.push(ConnectionTimer {
                kind: TimerKind::Idle,
                deadline: add_duration(self.last_activity, timeout),
            });
        }
        if let Some(deadline) = self.close_deadline {
            timers.push(ConnectionTimer {
                kind: TimerKind::Close,
                deadline,
            });
        }
        if let Some(deadline) = self.pacing_deadline {
            timers.push(ConnectionTimer {
                kind: TimerKind::Pacing,
                deadline,
            });
        }
        if let Some(deadline) = self.pmtu_probe_deadline() {
            timers.push(ConnectionTimer {
                kind: TimerKind::Pmtu,
                deadline,
            });
        }
        timers.into_iter().min_by_key(|timer| timer.deadline)
    }

    pub fn handle_timeout(&mut self, now: Duration) -> Result<(), ConnectionCoreError> {
        self.crypto.expire_previous_receive(now);
        if self.close_deadline.is_some_and(|deadline| deadline <= now) {
            self.close_deadline = None;
            self.terminate();
            return Ok(());
        }
        if self
            .effective_idle_timeout()
            .is_some_and(|timeout| add_duration(self.last_activity, timeout) <= now)
        {
            self.termination.get_or_insert((
                TransportErrorCode::INTERNAL_ERROR.value(),
                Some(FrameType::PADDING.value()),
                b"Idle timeout".to_vec(),
            ));
            self.terminate();
            return Ok(());
        }
        if self.pacing_deadline.is_some_and(|deadline| deadline <= now) {
            self.pacing_deadline = None;
        }
        if self
            .recovery
            .loss_detection_time()
            .is_some_and(|deadline| deadline <= now)
        {
            if self.config.role == Role::Client
                && !self.received_authenticated_packet
                && !self.initial_mtu_fallback
                && self.config.max_datagram_size > MIN_INITIAL_DATAGRAM_SIZE
            {
                self.initial_mtu_fallback = true;
                self.config.max_datagram_size = MIN_INITIAL_DATAGRAM_SIZE;
                self.builder
                    .set_max_datagram_size(MIN_INITIAL_DATAGRAM_SIZE)?;
                self.recovery
                    .set_max_datagram_size(MIN_INITIAL_DATAGRAM_SIZE as u64);
                self.paths
                    .fall_back_active_pmtu(MIN_INITIAL_DATAGRAM_SIZE as u16)
                    .map_err(|_| ConnectionCoreError::InvalidConfig("invalid fallback path MTU"))?;
            }
            let events = self.recovery.on_loss_detection_timeout(now)?;
            self.apply_recovery_events(events);
        }
        if self
            .pmtu_probe_deadline()
            .is_some_and(|deadline| deadline <= now)
        {
            if let PmtuProbeStatus::InFlight { packet_number, .. } =
                self.paths.active_path().pmtu.status()
            {
                let events = self.recovery.expire_pmtu_probe(
                    PacketNumberSpace::ApplicationData,
                    packet_number,
                    now,
                )?;
                self.apply_recovery_events(events);
            }
        }
        self.queue_due_ack(now)?;
        Ok(())
    }

    fn ensure_receive_stream(&mut self, id: StreamId) -> Result<(), ConnectionError> {
        self.streams
            .get_or_create_receive(id)
            .map_err(|error| stream_protocol(FrameType::STREAM_BASE, error))?;
        if self.flow.stream(id).is_none() {
            self.insert_flow_stream(id).map_err(|error| {
                protocol(
                    FrameType::STREAM_BASE,
                    TransportErrorCode::INTERNAL_ERROR,
                    error.to_string(),
                )
            })?;
        }
        Ok(())
    }

    fn ensure_send_stream(&mut self, id: StreamId) -> Result<(), ConnectionError> {
        self.streams
            .get_or_create_send(id)
            .map_err(|error| stream_protocol(FrameType::MAX_STREAM_DATA, error))?;
        if self.flow.stream(id).is_none() {
            self.insert_flow_stream(id).map_err(|error| {
                protocol(
                    FrameType::MAX_STREAM_DATA,
                    TransportErrorCode::INTERNAL_ERROR,
                    error.to_string(),
                )
            })?;
        }
        Ok(())
    }

    fn ensure_send_stream_core(&mut self, id: StreamId) -> Result<(), ConnectionCoreError> {
        if self.stream_tombstones.contains_key(&id) {
            return Err(StreamError::StreamState("cannot send on a completed stream").into());
        }
        if id.initiator() == self.config.role {
            self.streams.create_local(id)?;
        } else {
            if id.is_unidirectional() {
                return Err(StreamError::StreamState(
                    "cannot send data on a peer-initiated unidirectional stream",
                )
                .into());
            }
            if self.streams.get(id).is_none() {
                return Err(StreamError::StreamState(
                    "cannot send data on an unknown peer-initiated stream",
                )
                .into());
            }
        }
        if self.flow.stream(id).is_none() {
            self.insert_flow_stream(id)?;
        }
        Ok(())
    }

    fn receive_crypto(
        &mut self,
        epoch: Epoch,
        offset: u64,
        data: &[u8],
    ) -> Result<(), ConnectionError> {
        let index = match epoch {
            Epoch::Initial => 0,
            Epoch::ZeroRtt => 1,
            Epoch::Handshake => 2,
            Epoch::OneRtt => 3,
        };
        let end = offset
            .checked_add(data.len() as u64)
            .filter(|end| *end <= VARINT_MAX)
            .ok_or_else(|| {
                protocol(
                    FrameType::CRYPTO,
                    TransportErrorCode::FRAME_ENCODING_ERROR,
                    "CRYPTO end offset exceeds the QUIC varint limit",
                )
            })?;
        let read_offset = self.crypto_receive_offsets[index];
        let chunks = &mut self.crypto_receive_chunks[index];
        for position in offset.max(read_offset)..end {
            let source = usize::try_from(position - offset).map_err(|_| {
                protocol(
                    FrameType::CRYPTO,
                    TransportErrorCode::FRAME_ENCODING_ERROR,
                    "CRYPTO slice offset exceeds platform limits",
                )
            })?;
            let byte = *data.get(source).ok_or_else(|| {
                protocol(
                    FrameType::CRYPTO,
                    TransportErrorCode::FRAME_ENCODING_ERROR,
                    "CRYPTO slice offset exceeds frame data",
                )
            })?;
            chunks.entry(position).or_insert(byte);
        }
        if chunks.len() > MAX_CRYPTO_REASSEMBLY {
            return Err(protocol(
                FrameType::CRYPTO,
                TransportErrorCode::CRYPTO_BUFFER_EXCEEDED,
                "CRYPTO receive buffer exceeded",
            ));
        }

        let start = self.crypto_receive_offsets[index];
        let mut contiguous = Vec::new();
        while let Some(byte) = chunks.remove(&self.crypto_receive_offsets[index]) {
            contiguous.push(byte);
            self.crypto_receive_offsets[index] += 1;
        }
        if !contiguous.is_empty() {
            self.events.push_back(ConnectionEvent::CryptoData {
                epoch,
                offset: start,
                data: contiguous,
            });
        }
        Ok(())
    }

    fn insert_flow_stream(&mut self, id: StreamId) -> Result<(), ConnectionCoreError> {
        let send_maximum = if id.is_unidirectional() {
            if id.initiator() == self.config.role {
                self.config.stream_send_limit_uni
            } else {
                0
            }
        } else if id.initiator() == self.config.role {
            self.config.stream_send_limit_bidi_remote
        } else {
            self.config.stream_send_limit_bidi_local
        };
        self.flow.insert_stream(StreamFlowState::new(
            id,
            send_maximum,
            self.config.stream_receive_window,
            self.config.stream_receive_window,
        )?)?;
        Ok(())
    }

    fn protocol_error(&mut self, error: ConnectionError, now: Duration) {
        if matches!(
            self.state,
            ConnectionState::Closing | ConnectionState::Draining | ConnectionState::Terminated
        ) {
            return;
        }
        self.local_error = Some(error.clone());
        self.termination = Some((
            error.code.value(),
            error.frame_type.map(FrameType::value),
            error.reason.as_bytes().to_vec(),
        ));
        self.events
            .push_back(ConnectionEvent::ProtocolError(error.clone()));
        let _ = self.start_close(
            Some(error.frame_type.unwrap_or(FrameType::PADDING)),
            error.code.value(),
            error.reason.as_bytes().to_vec(),
            now,
        );
        self.state = ConnectionState::Closing;
    }

    fn terminate_stateless_reset(&mut self) {
        if self.state == ConnectionState::Terminated {
            return;
        }
        self.close_deadline = None;
        self.termination.get_or_insert((0, None, Vec::new()));
        self.terminate();
    }

    fn start_close(
        &mut self,
        frame_type: Option<FrameType>,
        error_code: u64,
        reason: Vec<u8>,
        now: Duration,
    ) -> Result<(), ConnectionCoreError> {
        if self.close_frame.is_some() {
            return Ok(());
        }
        self.close_frame = Some((frame_type, error_code, reason.clone()));
        self.termination = Some((error_code, frame_type.map(FrameType::value), reason));
        self.transmits.clear();
        self.close_deadline = Some(add_duration(
            now,
            mul_duration(self.recovery.probe_timeout(), CLOSE_TIMEOUT_MULTIPLIER),
        ));
        self.requeue_close()
    }

    fn requeue_close(&mut self) -> Result<(), ConnectionCoreError> {
        if self.close_frame.is_none() {
            return Ok(());
        }
        self.close_pending = true;
        Ok(())
    }

    fn poll_close_transmit(
        &mut self,
        now: Duration,
    ) -> Result<Option<Transmit>, ConnectionCoreError> {
        let Some((frame_type, error_code, reason)) =
            self.close_frame.clone().filter(|_| self.close_pending)
        else {
            return Ok(None);
        };
        if error_code > VARINT_MAX || reason.len() as u64 > VARINT_MAX {
            return Err(ConnectionCoreError::InvalidConfig(
                "close value exceeds varint",
            ));
        }
        let allowance = self.paths.active_path().send_allowance();
        let minimum_packet_size = 1_u64
            .saturating_add(self.config.destination_cid.len() as u64)
            .saturating_add(2)
            .saturating_add(18);
        if allowance < minimum_packet_size {
            return Ok(None);
        }
        let mut body = Vec::new();
        push_varint(&mut body, error_code)?;
        if let Some(frame_type) = frame_type {
            push_varint(&mut body, frame_type.value())?;
        }
        push_varint(&mut body, reason.len() as u64)?;
        body.extend_from_slice(&reason);
        let epoch = self.highest_send_epoch();
        let packet_space = epoch.packet_number_space();
        let packet_type = match epoch {
            Epoch::Initial => PacketType::Initial,
            Epoch::ZeroRtt => PacketType::ZeroRtt,
            Epoch::Handshake => PacketType::Handshake,
            Epoch::OneRtt => PacketType::OneRtt,
        };
        let wire_frame_type =
            if frame_type.is_some() || matches!(epoch, Epoch::Initial | Epoch::Handshake) {
                FrameType::TRANSPORT_CLOSE
            } else {
                FrameType::APPLICATION_CLOSE
            };
        if wire_frame_type == FrameType::TRANSPORT_CLOSE && frame_type.is_none() {
            body.clear();
            push_varint(&mut body, TransportErrorCode::APPLICATION_ERROR.value())?;
            push_varint(&mut body, 0)?;
            push_varint(&mut body, reason.len() as u64)?;
            body.extend_from_slice(&reason);
        }
        let next_packet_number = self
            .close_packet_number
            .filter(|(space, _)| *space == packet_space)
            .map_or_else(
                || self.builder.next_packet_number(packet_space),
                |(_, pn)| pn,
            );
        let mut builder = PacketBuilder::new(BuilderConfig {
            version: self.config.version,
            source_cid: self.config.source_cid.clone(),
            destination_cid: self.config.destination_cid.clone(),
            initial_token: self.initial_token.clone(),
            is_client: self.config.role == Role::Client,
            spin_bit: false,
            max_datagram_size: self
                .config
                .max_datagram_size
                .min(usize::try_from(allowance).unwrap_or(usize::MAX)),
        })?;
        builder.restore_packet_number(packet_space, next_packet_number)?;
        builder.enqueue(
            packet_space,
            QueuedFrame::new(wire_frame_type, body, FrameAction::None),
        );
        let mut request = PacketRequest::new(packet_type);
        if packet_type == PacketType::OneRtt {
            request.key_phase = self.crypto.send_key_phase() == Some(1);
        }
        let result = builder.build(request, &mut self.crypto)?;
        for datagram in result.datagrams {
            self.complete_datagram(datagram, self.paths.active_path_id(), now)?;
        }
        if let Some(datagram) = builder.flush() {
            self.complete_datagram(datagram, self.paths.active_path_id(), now)?;
        }
        self.close_packet_number = Some((packet_space, next_packet_number.saturating_add(1)));
        self.close_pending = false;
        Ok(self.transmits.pop_front())
    }

    fn highest_send_epoch(&self) -> Epoch {
        if self.crypto.has_send_key(Epoch::OneRtt) {
            Epoch::OneRtt
        } else if self.crypto.has_send_key(Epoch::Handshake) {
            Epoch::Handshake
        } else if self.crypto.has_send_key(Epoch::ZeroRtt) {
            Epoch::ZeroRtt
        } else {
            Epoch::Initial
        }
    }

    fn effective_idle_timeout(&self) -> Option<Duration> {
        let local = self
            .config
            .idle_timeout
            .filter(|timeout| !timeout.is_zero());
        let negotiated = match (local, self.peer_idle_timeout) {
            (Some(local), Some(peer)) => Some(local.min(peer)),
            (Some(local), None) => Some(local),
            (None, Some(peer)) => Some(peer),
            (None, None) => None,
        }?;
        Some(negotiated.max(mul_duration(
            self.recovery.probe_timeout(),
            CLOSE_TIMEOUT_MULTIPLIER,
        )))
    }

    fn terminate(&mut self) {
        self.state = ConnectionState::Terminated;
        self.transmits.clear();
        if self.termination_emitted {
            return;
        }
        self.termination_emitted = true;
        let (error_code, frame_type, reason) =
            self.termination.clone().unwrap_or((0, None, Vec::new()));
        self.events
            .push_back(ConnectionEvent::ConnectionTerminated {
                error_code,
                frame_type,
                reason,
            });
    }

    fn queue_due_ack(&mut self, now: Duration) -> Result<usize, ConnectionCoreError> {
        let mut queued = 0;
        for space in [
            PacketNumberSpace::Initial,
            PacketNumberSpace::Handshake,
            PacketNumberSpace::ApplicationData,
        ] {
            if let Some(ack) = self.recovery.peek_ack(space, now) {
                let exponent = if space == PacketNumberSpace::ApplicationData {
                    self.config.ack_delay_exponent
                } else {
                    0
                };
                // RFC 9000 section 13.2.4 permits dropping the oldest ACK
                // ranges when they no longer fit in one packet.
                let first = ack.ranges.len().saturating_sub(64);
                let body = encode_ack(&ack.ranges[first..], ack.ack_delay, exponent)?;
                let delivery = self.new_delivery(DeliveryTarget::Ack {
                    space,
                    highest_acked: ack.largest,
                });
                self.builder.enqueue(
                    space,
                    QueuedFrame::new(FrameType::ACK, body, FrameAction::Notify(delivery)),
                );
                queued += 1;
                if ack.ranges.len() > 1 && self.builder.next_packet_number(space) % 8 == 0 {
                    self.builder.enqueue(
                        space,
                        QueuedFrame::new(FrameType::PING, Vec::new(), FrameAction::None),
                    );
                }
                self.recovery.commit_ack(space);
            }
        }
        Ok(queued)
    }

    fn queue_path_control(&mut self) -> Option<PathId> {
        if let Some((path, response)) = self.path_responses.pop_front() {
            let delivery = self.new_delivery(DeliveryTarget::PathResponse {
                path,
                data: response,
            });
            self.builder.enqueue(
                PacketNumberSpace::ApplicationData,
                QueuedFrame::new(
                    FrameType::PATH_RESPONSE,
                    response.to_vec(),
                    FrameAction::Notify(delivery),
                ),
            );
            Some(path)
        } else if let Some((path, challenge)) = self.path_challenges.pop_front() {
            self.queue_path_challenge(path, challenge);
            Some(path)
        } else {
            None
        }
    }

    fn queue_path_challenge(&mut self, path: PathId, challenge: [u8; 8]) {
        let delivery = self.new_delivery(DeliveryTarget::PathChallenge {
            path,
            data: challenge,
        });
        self.builder.enqueue(
            PacketNumberSpace::ApplicationData,
            QueuedFrame::new(
                FrameType::PATH_CHALLENGE,
                challenge.to_vec(),
                FrameAction::Notify(delivery),
            ),
        );
    }

    fn queue_flow_update(&mut self, action: FlowAction) {
        let (frame_type, stream_id, maximum) = match action {
            FlowAction::SendMaxData(maximum) => (FrameType::MAX_DATA, None, maximum),
            FlowAction::SendMaxStreamData { stream, maximum } => {
                if let Some(state) = self.streams.get_mut(stream) {
                    state.recv.set_max_data(maximum);
                }
                (FrameType::MAX_STREAM_DATA, Some(stream), maximum)
            }
        };
        let mut body = Vec::new();
        if let Some(stream_id) = stream_id {
            if push_varint(&mut body, stream_id.into_inner()).is_err() {
                return;
            }
        }
        if push_varint(&mut body, maximum).is_ok() {
            let target = stream_id.map_or(DeliveryTarget::MaxData(maximum), |stream| {
                DeliveryTarget::MaxStreamData { stream, maximum }
            });
            let delivery = self.new_delivery(target);
            self.builder.enqueue(
                PacketNumberSpace::ApplicationData,
                QueuedFrame::new(frame_type, body, FrameAction::Notify(delivery)),
            );
        }
    }

    fn pmtu_probe_deadline(&self) -> Option<Duration> {
        match self.paths.active_path().pmtu.status() {
            PmtuProbeStatus::InFlight { sent_at, .. } => Some(add_duration(
                sent_at,
                mul_duration(self.recovery.probe_timeout(), PMTU_PROBE_TIMEOUT_MULTIPLIER),
            )),
            _ => None,
        }
    }

    fn push_stream_data_event(&mut self, stream_id: StreamId, data: Vec<u8>, fin: bool) {
        if let Some(ConnectionEvent::StreamData {
            stream_id: queued_stream,
            data: queued_data,
            fin: queued_fin,
        }) = self.events.back_mut()
        {
            if *queued_stream == stream_id
                && !*queued_fin
                && queued_data.len().saturating_add(data.len()) <= MAX_STREAM_EVENT_SIZE
            {
                queued_data.extend_from_slice(&data);
                *queued_fin = fin;
                return;
            }
        }
        self.events.push_back(ConnectionEvent::StreamData {
            stream_id,
            data,
            fin,
        });
    }

    fn next_packet_type(&self) -> Option<PacketType> {
        if self.builder.queued_frames(PacketNumberSpace::Initial) > 0
            && self.crypto.has_send_key(Epoch::Initial)
        {
            Some(PacketType::Initial)
        } else if self.builder.queued_frames(PacketNumberSpace::Handshake) > 0
            && self.crypto.has_send_key(Epoch::Handshake)
        {
            Some(PacketType::Handshake)
        } else if self
            .builder
            .queued_frames(PacketNumberSpace::ApplicationData)
            > 0
        {
            if self.crypto.has_send_key(Epoch::OneRtt) {
                Some(PacketType::OneRtt)
            } else if self.config.role == Role::Client && self.crypto.has_send_key(Epoch::ZeroRtt) {
                Some(PacketType::ZeroRtt)
            } else {
                None
            }
        } else {
            None
        }
    }

    fn complete_datagram(
        &mut self,
        datagram: BuiltDatagram,
        path_id: PathId,
        now: Duration,
    ) -> Result<(), ConnectionCoreError> {
        self.paths
            .path_mut(path_id)
            .ok_or(ConnectionCoreError::InvalidConfig("unknown transmit path"))?
            .record_sent(datagram.bytes.len())
            .map_err(|_| ConnectionCoreError::InvalidConfig("anti-amplification limit"))?;
        for packet in &datagram.packets {
            if packet.is_pmtu_probe {
                self.paths
                    .path_mut(path_id)
                    .ok_or(ConnectionCoreError::InvalidConfig("unknown transmit path"))?
                    .pmtu
                    .probe_sent(
                        packet.packet_number,
                        u16::try_from(packet.sent_bytes).map_err(|_| {
                            ConnectionCoreError::InvalidConfig("PMTU probe is too large")
                        })?,
                        now,
                    )
                    .map_err(|_| ConnectionCoreError::InvalidConfig("invalid PMTU probe"))?;
            }
            let delivery_actions = packet
                .frames
                .iter()
                .filter_map(|frame| frame.delivery_id)
                .collect();
            self.recovery.on_packet_sent(
                packet.packet_space,
                SentPacket {
                    packet_number: packet.packet_number,
                    path_id: path_id.get(),
                    sent_time: now,
                    sent_bytes: packet.sent_bytes as u64,
                    ack_eliciting: packet.is_ack_eliciting,
                    in_flight: packet.in_flight,
                    is_crypto: packet.is_crypto_packet,
                    is_pmtu_probe: packet.is_pmtu_probe,
                    packet_type: packet.packet_type,
                    delivery_actions,
                },
            )?;
        }
        let path = self
            .paths
            .path(path_id)
            .ok_or(ConnectionCoreError::InvalidConfig("unknown transmit path"))?;
        self.transmits.push_back(Transmit {
            destination: path.remote,
            source: path.local,
            ecn: None,
            segment_size: None,
            bytes: datagram.bytes,
        });
        if !self.ack_eliciting_sent_since_receive
            && datagram
                .packets
                .iter()
                .any(|packet| packet.is_ack_eliciting)
        {
            self.last_activity = self.last_activity.max(now);
            self.ack_eliciting_sent_since_receive = true;
        }
        if self.config.role == Role::Client
            && datagram
                .packets
                .iter()
                .any(|packet| packet.packet_space == PacketNumberSpace::Handshake)
        {
            self.discard_keys(Epoch::Initial);
        }
        Ok(())
    }

    fn queue_one_stream_action(&mut self) -> Result<Option<PendingStream>, ConnectionCoreError> {
        while let Some(id) = self.stream_send_queue.pop_front() {
            self.streams_queued.remove(&id);
            match self.queue_stream_action(id) {
                Ok(Some(pending)) => return Ok(Some(pending)),
                Ok(None) | Err(ConnectionCoreError::Stream(StreamError::ReservationInProgress)) => {
                }
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }

    fn queue_probe_stream_actions(&mut self) -> Result<Vec<PendingStream>, ConnectionCoreError> {
        let mut pending = Vec::new();
        while let Some(id) = self.stream_send_queue.pop_front() {
            self.streams_queued.remove(&id);
            if let Some(action) = self.queue_stream_action(id)? {
                pending.push(action);
            }
        }
        Ok(pending)
    }

    fn queue_stream_action(
        &mut self,
        id: StreamId,
    ) -> Result<Option<PendingStream>, ConnectionCoreError> {
        let Some(stream) = self.streams.get_mut(id) else {
            return Ok(None);
        };
        if stream.send.has_pending_reset() {
            if let Some(reservation) = stream.send.reserve_reset()? {
                let (frame_type, body) = encode_stream_action(&reservation.action)?;
                let delivery = self.new_delivery(DeliveryTarget::Reset(id));
                self.builder.enqueue(
                    PacketNumberSpace::ApplicationData,
                    QueuedFrame::new(frame_type, body, FrameAction::Notify(delivery)),
                );
                return Ok(Some(PendingStream::Reset(id, reservation, delivery)));
            }
        }
        if stream.recv.has_pending_stop() {
            if let Some(reservation) = stream.recv.reserve_stop()? {
                let (frame_type, body) = encode_stream_action(&reservation.action)?;
                let delivery = self.new_delivery(DeliveryTarget::Stop(id));
                self.builder.enqueue(
                    PacketNumberSpace::ApplicationData,
                    QueuedFrame::new(frame_type, body, FrameAction::Notify(delivery)),
                );
                return Ok(Some(PendingStream::Stop(id, reservation, delivery)));
            }
        }
        if stream.send.has_pending() {
            let flow_limit = self.flow.stream(id).map_or(0, |state| state.send_maximum());
            if let Some(reservation) = stream
                .send
                .reserve(self.config.max_datagram_size.saturating_sub(64), flow_limit)?
            {
                self.flow.check_send(id, reservation.end_offset())?;
                let body = encode_stream(&reservation, stream.send.reserved_data(&reservation)?)?;
                let delivery = self.new_delivery(DeliveryTarget::Stream {
                    stream: id,
                    offset: reservation.offset,
                    length: reservation.length as u64,
                    fin: reservation.fin,
                });
                self.builder.enqueue(
                    PacketNumberSpace::ApplicationData,
                    QueuedFrame::new(
                        stream_frame_type(&reservation),
                        body,
                        FrameAction::Notify(delivery),
                    ),
                );
                return Ok(Some(PendingStream::Data(id, reservation, delivery)));
            }
        }
        Ok(None)
    }

    fn new_delivery(&mut self, target: DeliveryTarget) -> DeliveryId {
        let id = DeliveryId(self.next_delivery_id);
        self.next_delivery_id = self.next_delivery_id.wrapping_add(1);
        self.delivery.insert(id, target);
        id
    }

    fn schedule_stream(&mut self, stream_id: StreamId) {
        if self.streams.get(stream_id).is_some() && self.streams_queued.insert(stream_id) {
            self.stream_send_queue.push_back(stream_id);
        }
    }

    fn refresh_stream_completion(&mut self, stream_id: StreamId) {
        if !self
            .streams
            .get(stream_id)
            .is_some_and(|stream| stream.is_finished())
        {
            return;
        }
        if !self.finishing_streams.insert(stream_id) {
            return;
        }
        let direction = if stream_id.is_unidirectional() {
            StreamDirection::Unidirectional
        } else {
            StreamDirection::Bidirectional
        };
        if stream_id.initiator() == self.config.role {
            self.events
                .push_back(ConnectionEvent::StreamFinished(stream_id));
            return;
        }

        let maximum = self
            .streams
            .local_max_streams(direction)
            .saturating_add(1)
            .min(super::stream::MAX_STREAM_COUNT);
        if self
            .streams
            .update_local_max_streams(direction, maximum)
            .unwrap_or(false)
        {
            self.queue_max_streams(direction, maximum);
        }
        self.events
            .push_back(ConnectionEvent::StreamFinished(stream_id));
    }

    fn remove_finished_stream(&mut self, stream_id: StreamId) {
        let Some(stream) = self.streams.remove(stream_id) else {
            return;
        };
        self.flow.remove_stream(stream_id);
        self.finishing_streams.remove(&stream_id);
        self.streams_queued.remove(&stream_id);
        self.stream_send_queue.retain(|id| *id != stream_id);
        self.stream_tombstones.insert(
            stream_id,
            StreamTombstone {
                final_size: stream.recv.final_size(),
                highest_offset: stream.recv.highest_offset(),
            },
        );
        self.stream_tombstone_order.push_back(stream_id);
        while self.stream_tombstone_order.len() > MAX_STREAM_TOMBSTONES {
            if let Some(expired) = self.stream_tombstone_order.pop_front() {
                self.stream_tombstones.remove(&expired);
            }
        }
    }

    fn queue_max_streams(&mut self, direction: StreamDirection, maximum: u64) {
        let mut body = Vec::new();
        if push_varint(&mut body, maximum).is_err() {
            return;
        }
        let delivery = self.new_delivery(DeliveryTarget::MaxStreams { direction, maximum });
        let frame_type = match direction {
            StreamDirection::Bidirectional => FrameType::MAX_STREAMS_BIDI,
            StreamDirection::Unidirectional => FrameType::MAX_STREAMS_UNI,
        };
        self.builder.enqueue(
            PacketNumberSpace::ApplicationData,
            QueuedFrame::new(frame_type, body, FrameAction::Notify(delivery)),
        );
    }

    fn commit_stream_reservation(
        &mut self,
        pending: Option<PendingStream>,
    ) -> Result<(), ConnectionCoreError> {
        match pending {
            Some(PendingStream::Data(id, reservation, _)) => {
                let flow = self.flow.prepare_send(id, reservation.end_offset())?;
                self.streams
                    .get_mut(id)
                    .ok_or(StreamError::StreamState("reserved stream is missing"))?
                    .send
                    .commit(&reservation)?;
                self.flow.commit_send(flow)?;
                if self
                    .streams
                    .get_mut(id)
                    .is_some_and(|stream| stream.has_pending())
                {
                    self.schedule_stream(id);
                }
            }
            Some(PendingStream::Reset(id, reservation, _)) => self
                .streams
                .get_mut(id)
                .ok_or(StreamError::StreamState("reserved stream is missing"))?
                .send
                .commit_reset(&reservation)?,
            Some(PendingStream::Stop(id, reservation, _)) => self
                .streams
                .get_mut(id)
                .ok_or(StreamError::StreamState("reserved stream is missing"))?
                .recv
                .commit_stop(&reservation)?,
            None => {}
        }
        Ok(())
    }

    fn apply_recovery_events(&mut self, events: Vec<RecoveryEvent>) {
        for event in events {
            match event {
                RecoveryEvent::Delivery(action) => {
                    let Some(target) = self.delivery.get(&action.id).cloned() else {
                        continue;
                    };
                    match target {
                        DeliveryTarget::Ack {
                            space,
                            highest_acked,
                        } => {
                            if action.outcome == DeliveryOutcome::Acked {
                                let _ = self.recovery.acknowledge_ack(space, highest_acked);
                            }
                        }
                        DeliveryTarget::Stream {
                            stream,
                            offset,
                            length,
                            fin,
                        } => {
                            if let Some(stream) = self.streams.get_mut(stream) {
                                let _ = stream.send.on_data_delivery(
                                    offset,
                                    length,
                                    fin,
                                    action.outcome,
                                );
                            }
                            self.schedule_stream(stream);
                            self.refresh_stream_completion(stream);
                        }
                        DeliveryTarget::Reset(id) => {
                            if let Some(stream) = self.streams.get_mut(id) {
                                stream.send.on_reset_delivery(action.outcome);
                            }
                            self.schedule_stream(id);
                            self.refresh_stream_completion(id);
                        }
                        DeliveryTarget::Stop(id) => {
                            if let Some(stream) = self.streams.get_mut(id) {
                                stream.recv.on_stop_delivery(action.outcome);
                            }
                            self.schedule_stream(id);
                            self.refresh_stream_completion(id);
                        }
                        DeliveryTarget::MaxStreams { direction, maximum } => {
                            if action.outcome != DeliveryOutcome::Acked {
                                self.queue_max_streams(direction, maximum);
                            }
                        }
                        DeliveryTarget::HandshakeDone => {
                            if action.outcome != DeliveryOutcome::Acked {
                                let delivery = self.new_delivery(DeliveryTarget::HandshakeDone);
                                self.builder.enqueue(
                                    PacketNumberSpace::ApplicationData,
                                    QueuedFrame::new(
                                        FrameType::HANDSHAKE_DONE,
                                        Vec::new(),
                                        FrameAction::Notify(delivery),
                                    ),
                                );
                            }
                        }
                        DeliveryTarget::MaxData(maximum) => {
                            if action.outcome != DeliveryOutcome::Acked {
                                self.queue_flow_update(FlowAction::SendMaxData(maximum));
                            }
                        }
                        DeliveryTarget::MaxStreamData { stream, maximum } => {
                            if action.outcome != DeliveryOutcome::Acked {
                                self.queue_flow_update(FlowAction::SendMaxStreamData {
                                    stream,
                                    maximum,
                                });
                            }
                        }
                        DeliveryTarget::PathResponse { path, data } => {
                            if action.outcome != DeliveryOutcome::Acked {
                                self.path_responses.push_back((path, data));
                            }
                        }
                        DeliveryTarget::Ping(uid) => {
                            if action.outcome == DeliveryOutcome::Acked {
                                self.events
                                    .push_back(ConnectionEvent::PingAcknowledged(uid));
                            }
                        }
                        DeliveryTarget::Crypto {
                            epoch,
                            offset,
                            data,
                        } => {
                            if matches!(
                                action.outcome,
                                DeliveryOutcome::Lost
                                    | DeliveryOutcome::ProbeCopy
                                    | DeliveryOutcome::RetireAndRetransmit
                            ) {
                                let mut body = Vec::with_capacity(
                                    varint_size(offset)
                                        + varint_size(data.len() as u64)
                                        + data.len(),
                                );
                                if push_varint(&mut body, offset).is_ok()
                                    && push_varint(&mut body, data.len() as u64).is_ok()
                                {
                                    body.extend_from_slice(&data);
                                    let delivery = self.new_delivery(DeliveryTarget::Crypto {
                                        epoch,
                                        offset,
                                        data,
                                    });
                                    self.builder.enqueue(
                                        epoch.packet_number_space(),
                                        QueuedFrame::new(
                                            FrameType::CRYPTO,
                                            body,
                                            FrameAction::Notify(delivery),
                                        ),
                                    );
                                }
                            }
                        }
                        DeliveryTarget::NewConnectionId { sequence } => {
                            if action.outcome != DeliveryOutcome::Acked {
                                self.queue_new_connection_id(sequence);
                            }
                        }
                        DeliveryTarget::RetireConnectionId { sequence } => {
                            if action.outcome != DeliveryOutcome::Acked {
                                self.queue_retire_connection_id(sequence);
                            }
                        }
                        DeliveryTarget::PathChallenge { path, data } => {
                            if action.outcome != DeliveryOutcome::Acked {
                                self.path_challenges.push_back((path, data));
                            }
                        }
                    }
                    if action.outcome != DeliveryOutcome::ProbeCopy {
                        self.delivery.remove(&action.id);
                    }
                }
                RecoveryEvent::SendProbe { space } => self.pending_probes.push_back(space),
                RecoveryEvent::PmtuProbeAcked {
                    packet_number,
                    path_id,
                    ..
                } => {
                    let path_id = PathId::new(path_id);
                    if let Some(path) = self.paths.path_mut(path_id) {
                        if let Ok(size) = path.pmtu.probe_acked(packet_number) {
                            if path_id == self.paths.active_path_id() {
                                self.config.max_datagram_size = size as usize;
                                let _ = self.builder.set_max_datagram_size(size as usize);
                                self.recovery.set_max_datagram_size(size as u64);
                            }
                        }
                    }
                }
                RecoveryEvent::PmtuProbeLost {
                    packet_number,
                    path_id,
                    ..
                } => {
                    if let Some(path) = self.paths.path_mut(PathId::new(path_id)) {
                        let _ = path.pmtu.probe_lost(packet_number);
                    }
                }
            }
        }
    }

    fn apply_cid_action(&mut self, action: CidAction) {
        match action {
            CidAction::RetirePeer(sequence) => self.queue_retire_connection_id(sequence),
            CidAction::AdvertiseLocal(entry) => {
                self.events.push_back(ConnectionEvent::ConnectionIdIssued(
                    entry.connection_id.as_bytes().to_vec(),
                ));
                self.queue_new_connection_id(entry.sequence);
            }
            CidAction::LocalRetired(sequence) => {
                if let Some(entry) = self.local_cids.get(sequence) {
                    self.events.push_back(ConnectionEvent::ConnectionIdRetired(
                        entry.connection_id.as_bytes().to_vec(),
                    ));
                }
            }
        }
    }

    fn issue_spare_connection_ids(&mut self) -> Result<(), ConnectionCoreError> {
        let cid_len = self.config.source_cid.len();
        if cid_len == 0 {
            return Ok(());
        }
        let target = self
            .local_cids
            .peer_active_limit()
            .min(MAX_LOCAL_CONNECTION_IDS);
        while self.local_cids.active_count() < target {
            let action = loop {
                let mut cid = vec![0; cid_len];
                let mut token = [0; 16];
                rand::thread_rng().fill_bytes(&mut cid);
                rand::thread_rng().fill_bytes(&mut token);
                match self.local_cids.issue(
                    ConnectionId::for_new_connection_id(cid)
                        .map_err(|_| ConnectionCoreError::InvalidConfig("invalid local CID"))?,
                    token,
                ) {
                    Ok(action) => break action,
                    Err(CidError::DuplicateConnectionId | CidError::DuplicateResetToken) => {
                        continue
                    }
                    Err(_) => {
                        return Err(ConnectionCoreError::InvalidConfig(
                            "failed to issue local connection ID",
                        ));
                    }
                }
            };
            self.apply_cid_action(action);
        }
        Ok(())
    }

    fn queue_new_connection_id(&mut self, sequence: u64) {
        let Some(entry) = self.local_cids.get(sequence) else {
            return;
        };
        let connection_id = entry.connection_id.as_bytes().to_vec();
        let reset_token = entry.reset_token;
        let mut body = Vec::new();
        if push_varint(&mut body, sequence).is_err()
            || push_varint(&mut body, 0).is_err()
            || u8::try_from(connection_id.len()).is_err()
        {
            return;
        }
        body.push(connection_id.len() as u8);
        body.extend_from_slice(&connection_id);
        body.extend_from_slice(&reset_token);
        let delivery = self.new_delivery(DeliveryTarget::NewConnectionId { sequence });
        self.builder.enqueue(
            PacketNumberSpace::ApplicationData,
            QueuedFrame::new(
                FrameType::NEW_CONNECTION_ID,
                body,
                FrameAction::Notify(delivery),
            ),
        );
    }

    fn queue_retire_connection_id(&mut self, sequence: u64) {
        let mut body = Vec::new();
        if push_varint(&mut body, sequence).is_ok() {
            let delivery = self.new_delivery(DeliveryTarget::RetireConnectionId { sequence });
            self.builder.enqueue(
                PacketNumberSpace::ApplicationData,
                QueuedFrame::new(
                    FrameType::RETIRE_CONNECTION_ID,
                    body,
                    FrameAction::Notify(delivery),
                ),
            );
        }
    }
}

enum PendingStream {
    Data(StreamId, super::stream::SendReservation, DeliveryId),
    Reset(StreamId, super::stream::ActionReservation, DeliveryId),
    Stop(StreamId, super::stream::ActionReservation, DeliveryId),
}

impl PendingStream {
    fn delivery_id(&self) -> DeliveryId {
        match self {
            Self::Data(_, _, id) | Self::Reset(_, _, id) | Self::Stop(_, _, id) => *id,
        }
    }
}

fn packet_epoch(packet_type: PacketType) -> Option<Epoch> {
    match packet_type {
        PacketType::Initial => Some(Epoch::Initial),
        PacketType::ZeroRtt => Some(Epoch::ZeroRtt),
        PacketType::Handshake => Some(Epoch::Handshake),
        PacketType::OneRtt => Some(Epoch::OneRtt),
        PacketType::Retry | PacketType::VersionNegotiation => None,
    }
}

fn is_compatible_version_pair(left: u32, right: u32) -> bool {
    matches!(
        (left, right),
        (QUIC_VERSION_1, QUIC_VERSION_2) | (QUIC_VERSION_2, QUIC_VERSION_1)
    )
}

fn packet_type_for_space(space: PacketNumberSpace) -> PacketType {
    match space {
        PacketNumberSpace::Initial => PacketType::Initial,
        PacketNumberSpace::Handshake => PacketType::Handshake,
        PacketNumberSpace::ApplicationData => PacketType::OneRtt,
    }
}

fn protocol(
    frame: FrameType,
    code: TransportErrorCode,
    reason: impl Into<String>,
) -> ConnectionError {
    ConnectionError::new(code, Some(frame), reason)
}

fn stream_protocol(frame: FrameType, error: StreamError) -> ConnectionError {
    let code = match error {
        StreamError::FlowControl { .. } => TransportErrorCode::FLOW_CONTROL_ERROR,
        StreamError::FinalSize { .. } => TransportErrorCode::FINAL_SIZE_ERROR,
        StreamError::StreamLimit { .. } => TransportErrorCode::STREAM_LIMIT_ERROR,
        _ => TransportErrorCode::STREAM_STATE_ERROR,
    };
    protocol(frame, code, error.to_string())
}

fn flow_protocol(frame: FrameType, error: FlowError) -> ConnectionError {
    let code = match error {
        FlowError::FinalSizeChanged { .. } | FlowError::FinalSizeSmallerThanReceived { .. } => {
            TransportErrorCode::FINAL_SIZE_ERROR
        }
        FlowError::StreamNotFound(_) => TransportErrorCode::STREAM_STATE_ERROR,
        _ => TransportErrorCode::FLOW_CONTROL_ERROR,
    };
    protocol(frame, code, format!("{error:?}"))
}

fn cid_protocol(frame: FrameType, error: CidError) -> ConnectionError {
    let code = if matches!(error, CidError::ActiveConnectionIdLimitExceeded { .. }) {
        TransportErrorCode::CONNECTION_ID_LIMIT_ERROR
    } else {
        TransportErrorCode::PROTOCOL_VIOLATION
    };
    protocol(frame, code, format!("{error:?}"))
}

fn push_varint(output: &mut Vec<u8>, value: u64) -> Result<(), ConnectionCoreError> {
    let value = VarInt::new(value).ok_or(ConnectionCoreError::InvalidConfig("varint overflow"))?;
    let mut bytes = [0; 8];
    let len = encode_varint(value, &mut bytes).map_err(ConnectionCoreError::Wire)?;
    output.extend_from_slice(&bytes[..len]);
    Ok(())
}

fn varint_size(value: u64) -> usize {
    if value < (1 << 6) {
        1
    } else if value < (1 << 14) {
        2
    } else if value < (1 << 30) {
        4
    } else {
        8
    }
}

fn encode_ack(
    ranges: &[AckRange],
    delay: Duration,
    exponent: u8,
) -> Result<Vec<u8>, ConnectionCoreError> {
    let largest_range = ranges
        .last()
        .ok_or(ConnectionCoreError::InvalidConfig("empty ACK"))?;
    let mut body = Vec::new();
    push_varint(&mut body, largest_range.end - 1)?;
    push_varint(
        &mut body,
        (delay.as_micros().min(u64::MAX as u128) as u64) >> exponent,
    )?;
    push_varint(&mut body, ranges.len().saturating_sub(1) as u64)?;
    push_varint(&mut body, largest_range.end - largest_range.start - 1)?;
    let mut previous_start = largest_range.start;
    for range in ranges[..ranges.len() - 1].iter().rev() {
        push_varint(&mut body, previous_start - range.end - 1)?;
        push_varint(&mut body, range.end - range.start - 1)?;
        previous_start = range.start;
    }
    Ok(body)
}

fn encode_stream(
    reservation: &super::stream::SendReservation,
    data: &[u8],
) -> Result<Vec<u8>, ConnectionCoreError> {
    let mut body = Vec::with_capacity(
        varint_size(reservation.stream_id.into_inner())
            + varint_size(reservation.offset)
            + varint_size(reservation.length as u64)
            + reservation.length,
    );
    push_varint(&mut body, reservation.stream_id.into_inner())?;
    push_varint(&mut body, reservation.offset)?;
    push_varint(&mut body, reservation.length as u64)?;
    body.extend_from_slice(data);
    Ok(body)
}

fn stream_frame_type(reservation: &super::stream::SendReservation) -> FrameType {
    if reservation.fin {
        FrameType::STREAM_WITH_OFFSET_LENGTH_FIN
    } else {
        FrameType::STREAM_WITH_OFFSET_LENGTH
    }
}

fn encode_stream_action(
    action: &StreamAction,
) -> Result<(FrameType, Vec<u8>), ConnectionCoreError> {
    let mut body = Vec::new();
    match *action {
        StreamAction::ResetStream {
            stream_id,
            error_code,
            final_size,
        } => {
            push_varint(&mut body, stream_id.into_inner())?;
            push_varint(&mut body, error_code)?;
            push_varint(&mut body, final_size)?;
            Ok((FrameType::RESET_STREAM, body))
        }
        StreamAction::StopSending {
            stream_id,
            error_code,
        } => {
            push_varint(&mut body, stream_id.into_inner())?;
            push_varint(&mut body, error_code)?;
            Ok((FrameType::STOP_SENDING, body))
        }
    }
}

fn add_duration(left: Duration, right: Duration) -> Duration {
    left.checked_add(right).unwrap_or(Duration::MAX)
}

fn mul_duration(value: Duration, factor: u32) -> Duration {
    value.checked_mul(factor).unwrap_or(Duration::MAX)
}

#[cfg(test)]
mod tests {
    use super::super::crypto::derive_initial_keys;
    use super::super::crypto::{AeadAlgorithm, HeaderProtectionAlgorithm};
    use super::*;

    fn addresses() -> (NetworkAddress, NetworkAddress) {
        (
            SocketAddr::from(([127, 0, 0, 1], 443)).into(),
            SocketAddr::from(([127, 0, 0, 1], 4444)).into(),
        )
    }

    fn pair() -> (ConnectionCore, ConnectionCore) {
        let (server_addr, client_addr) = addresses();
        let dcid = vec![7; 8];
        let client = ConnectionConfig {
            local_address: client_addr,
            remote_address: server_addr,
            destination_cid: dcid.clone(),
            source_cid: vec![8; 8],
            max_datagram_frame_size: Some(1200),
            peer_max_datagram_frame_size: Some(1200),
            peer_max_streams_bidi: 16,
            peer_max_streams_uni: 16,
            ..ConnectionConfig::default()
        };
        let mut server = client.clone();
        server.role = Role::Server;
        server.local_address = server_addr;
        server.remote_address = client_addr;
        server.source_cid = dcid.clone();
        server.destination_cid = client.source_cid.clone();
        server.peer_address_validated = true;
        let (client_key, _) = derive_initial_keys(QUIC_VERSION_1, &dcid).unwrap();
        let mut server_crypto = CryptoState::new();
        server_crypto.install_receive(Epoch::Initial, client_key);
        (
            ConnectionCore::new(client).unwrap(),
            ConnectionCore::with_crypto(server, server_crypto).unwrap(),
        )
    }

    fn transfer(
        sender: &mut ConnectionCore,
        receiver: &mut ConnectionCore,
        now: Duration,
    ) -> ReceiveReport {
        let tx = sender.poll_transmit(now).unwrap().unwrap();
        receiver
            .receive_datagram(
                &tx.bytes,
                ReceiveMeta {
                    now,
                    local: tx.destination,
                    remote: tx.source,
                    ecn: None,
                },
            )
            .unwrap()
    }

    fn install_application_pair(client: &mut ConnectionCore, server: &mut ConnectionCore) {
        let make_key = || {
            PacketKey::new(
                AeadAlgorithm::Aes128Gcm,
                HeaderProtectionAlgorithm::Aes128,
                &[1; 16],
                &[2; 12],
                &[3; 16],
                0,
            )
            .unwrap()
        };
        client.install_send_key(Epoch::OneRtt, make_key());
        client.install_receive_key(Epoch::OneRtt, make_key());
        server.install_send_key(Epoch::OneRtt, make_key());
        server.install_receive_key(Epoch::OneRtt, make_key());
    }

    #[test]
    fn outbound_streams_start_blocked_without_peer_parameters() {
        let config = ConnectionConfig {
            destination_cid: vec![1; 8],
            ..ConnectionConfig::default()
        };
        let mut connection = ConnectionCore::new(config).unwrap();
        assert!(matches!(
            connection.command(ConnectionCommand::OpenStream(
                StreamDirection::Bidirectional
            )),
            Err(ConnectionCoreError::Stream(StreamError::StreamLimit {
                limit: 0,
                ..
            }))
        ));
    }

    #[test]
    fn peer_stream_data_limits_follow_initiator_and_direction() {
        let (mut client, _) = pair();
        client
            .apply_peer_transport_parameters(
                100,
                11,
                22,
                33,
                2,
                2,
                3,
                Duration::from_millis(25),
                None,
                None,
                None,
                2,
                false,
                None,
            )
            .unwrap();

        client
            .send_stream(StreamId::new(0).unwrap(), &[], false)
            .unwrap();
        client
            .send_stream(StreamId::new(2).unwrap(), &[], false)
            .unwrap();
        client
            .ensure_receive_stream(StreamId::new(1).unwrap())
            .unwrap();

        assert_eq!(
            client
                .flow
                .stream(StreamId::new(0).unwrap())
                .unwrap()
                .send_maximum(),
            22
        );
        assert_eq!(
            client
                .flow
                .stream(StreamId::new(1).unwrap())
                .unwrap()
                .send_maximum(),
            11
        );
        assert_eq!(
            client
                .flow
                .stream(StreamId::new(2).unwrap())
                .unwrap()
                .send_maximum(),
            33
        );
    }

    #[test]
    fn initial_crypto_packet_and_event_round_trip() {
        let (mut client, mut server) = pair();
        client.send_crypto(Epoch::Initial, 0, b"hello").unwrap();
        let report = transfer(&mut client, &mut server, Duration::from_millis(1));
        assert_eq!(report.packets, 1);
        assert!(
            matches!(server.poll_event(), Some(ConnectionEvent::CryptoData { data, .. })
            if data == b"hello")
        );
    }

    #[test]
    fn anti_amplification_is_checked_before_send_state_is_committed() {
        let (server_addr, client_addr) = addresses();
        let mut server = ConnectionCore::new(ConnectionConfig {
            role: Role::Server,
            local_address: server_addr,
            remote_address: client_addr,
            source_cid: vec![7; 8],
            destination_cid: vec![8; 8],
            peer_address_validated: false,
            ..ConnectionConfig::default()
        })
        .unwrap();
        let key = || {
            PacketKey::new(
                AeadAlgorithm::Aes128Gcm,
                HeaderProtectionAlgorithm::Aes128,
                &[1; 16],
                &[2; 12],
                &[3; 16],
                0,
            )
            .unwrap()
        };
        server.install_send_key(Epoch::OneRtt, key());
        server.install_receive_key(Epoch::OneRtt, key());
        server.command(ConnectionCommand::SendPing(1)).unwrap();
        server
            .pending_probes
            .push_back(PacketNumberSpace::ApplicationData);
        let path = server.paths.active_path_id();
        server.paths.path_mut(path).unwrap().receive(1);

        assert!(server
            .poll_transmit(Duration::from_millis(1))
            .unwrap()
            .is_none());
        assert_eq!(server.paths.active_path().bytes_sent(), 0);
        assert_eq!(server.pending_probes.len(), 1);
        assert_eq!(
            server
                .recovery
                .outstanding_packets(PacketNumberSpace::ApplicationData)
                .count(),
            0
        );

        server.paths.path_mut(path).unwrap().receive(9);
        let transmit = server
            .poll_transmit(Duration::from_millis(2))
            .unwrap()
            .unwrap();
        assert!(transmit.bytes.len() <= 30);
        assert!(server.pending_probes.is_empty());
    }

    #[test]
    fn outbound_varints_are_validated_before_mutation() {
        let (mut client, _) = pair();
        let stream_id = StreamId::new(0).unwrap();
        let queued = client.builder.queued_frames(PacketNumberSpace::Initial);

        assert!(matches!(
            client.command(ConnectionCommand::ResetStream {
                stream_id,
                error_code: VARINT_MAX + 1,
            }),
            Err(ConnectionCoreError::InvalidConfig(_))
        ));
        assert!(client.streams.get(stream_id).is_none());
        assert!(matches!(
            client.command(ConnectionCommand::StopSending {
                stream_id: StreamId::new(1).unwrap(),
                error_code: VARINT_MAX + 1,
            }),
            Err(ConnectionCoreError::InvalidConfig(_))
        ));
        assert!(matches!(
            client.command(ConnectionCommand::Close {
                frame_type: None,
                error_code: VARINT_MAX + 1,
                reason: Vec::new(),
            }),
            Err(ConnectionCoreError::InvalidConfig(_))
        ));
        assert_eq!(client.state(), ConnectionState::FirstFlight);
        assert!(matches!(
            client.send_crypto(Epoch::Initial, VARINT_MAX, &[1]),
            Err(ConnectionCoreError::InvalidConfig(_))
        ));
        assert_eq!(
            client.builder.queued_frames(PacketNumberSpace::Initial),
            queued
        );
    }

    #[test]
    fn unit_many_and_gro_have_equivalent_accounting() {
        let make_packet = || {
            let (mut client, _) = pair();
            client.send_crypto(Epoch::Initial, 0, &[1]).unwrap();
            client
                .poll_transmit(Duration::from_millis(1))
                .unwrap()
                .unwrap()
                .bytes
        };
        let bytes = make_packet();
        let (_, mut one) = pair();
        let (_, mut many) = pair();
        let (_, mut gro) = pair();
        let meta = ReceiveMeta {
            now: Duration::from_millis(1),
            local: addresses().0,
            remote: addresses().1,
            ecn: None,
        };
        let a = one.receive_datagram(&bytes, meta).unwrap();
        let b = many
            .receive_many_datagrams(&[ReceivedDatagram {
                bytes: &bytes,
                meta,
            }])
            .unwrap();
        let c = gro.receive_gro_buffer(&bytes, bytes.len(), meta).unwrap();
        assert_eq!(
            (a.datagrams, a.packets, a.events_added),
            (b.datagrams, b.packets, b.events_added)
        );
        assert_eq!(
            (a.datagrams, a.packets, a.events_added),
            (c.datagrams, c.packets, c.events_added)
        );
    }

    #[test]
    fn malformed_packet_closes_without_panicking() {
        let (_, mut server) = pair();
        let meta = ReceiveMeta {
            now: Duration::from_secs(1),
            local: addresses().0,
            remote: addresses().1,
            ecn: None,
        };
        let report = server.receive_datagram(&[0], meta).unwrap();
        assert_eq!(report.dropped, 1);
        assert_eq!(server.state(), ConnectionState::FirstFlight);
        assert!(server.poll_event().is_none());
    }

    #[test]
    fn protected_stream_data_is_delivered_and_duplicate_is_ignored() {
        let (mut client, mut server) = pair();
        install_application_pair(&mut client, &mut server);
        let id = match client
            .command(ConnectionCommand::OpenStream(
                StreamDirection::Bidirectional,
            ))
            .unwrap()
        {
            CommandResult::StreamOpened(id) => id,
            CommandResult::None => panic!("stream ID was not returned"),
        };
        client.send_stream(id, b"stream data", true).unwrap();
        let tx = client
            .poll_transmit(Duration::from_millis(1))
            .unwrap()
            .unwrap();
        let meta = ReceiveMeta {
            now: Duration::from_millis(2),
            local: tx.destination,
            remote: tx.source,
            ecn: None,
        };
        let first = server.receive_datagram(&tx.bytes, meta).unwrap();
        let duplicate = server.receive_datagram(&tx.bytes, meta).unwrap();
        assert_eq!(first.packets, 1);
        assert_eq!(duplicate.duplicates, 1);
        assert!(matches!(
            server.poll_event(),
            Some(ConnectionEvent::StreamData { stream_id, data, fin })
                if stream_id == id && data == b"stream data" && fin
        ));
        assert!(server.poll_event().is_none());
    }

    #[test]
    fn terminal_stream_state_is_pruned_and_late_frames_use_tombstones() {
        let (mut client, mut server) = pair();
        install_application_pair(&mut client, &mut server);
        let id = match client
            .command(ConnectionCommand::OpenStream(
                StreamDirection::Bidirectional,
            ))
            .unwrap()
        {
            CommandResult::StreamOpened(id) => id,
            CommandResult::None => panic!("stream ID was not returned"),
        };
        client.send_stream(id, b"request", true).unwrap();
        transfer(&mut client, &mut server, Duration::from_millis(1));
        assert!(matches!(
            server.poll_event(),
            Some(ConnectionEvent::StreamData { fin: true, .. })
        ));
        server.send_stream(id, b"response", true).unwrap();
        transfer(&mut server, &mut client, Duration::from_millis(2));
        assert!(matches!(
            client.poll_event(),
            Some(ConnectionEvent::StreamData { fin: true, .. })
        ));
        assert!(matches!(
            client.poll_event(),
            Some(ConnectionEvent::StreamFinished(stream)) if stream == id
        ));
        transfer(&mut client, &mut server, Duration::from_millis(3));
        assert!(matches!(
            server.poll_event(),
            Some(ConnectionEvent::StreamFinished(stream)) if stream == id
        ));

        assert!(client.streams.get(id).is_none());
        assert!(client.flow.stream(id).is_none());
        assert!(server.streams.get(id).is_none());
        assert!(server.flow.stream(id).is_none());
        assert!(server.stream_tombstones.contains_key(&id));

        let sender = PacketKey::new(
            AeadAlgorithm::Aes128Gcm,
            HeaderProtectionAlgorithm::Aes128,
            &[1; 16],
            &[2; 12],
            &[3; 16],
            0,
        )
        .unwrap();
        let mut header = vec![0x40];
        header.extend_from_slice(&[7; 8]);
        header.push(100);
        let mut payload = vec![0x0f, 0, 0, 7];
        payload.extend_from_slice(b"request");
        let header_len = header.len();
        header.extend_from_slice(&payload);
        let packet = sender.protect_packet(header, header_len, 100).unwrap();
        let report = server
            .receive_datagram(
                &packet,
                ReceiveMeta {
                    now: Duration::from_millis(4),
                    local: addresses().0,
                    remote: addresses().1,
                    ecn: None,
                },
            )
            .unwrap();
        assert_eq!(report.packets, 1);
        assert!(server.poll_event().is_none());
        assert!(server.streams.get(id).is_none());
    }

    #[test]
    fn stale_stream_scheduler_entries_are_ignored() {
        let (mut client, _) = pair();
        let stream_id = match client
            .command(ConnectionCommand::OpenStream(
                StreamDirection::Bidirectional,
            ))
            .unwrap()
        {
            CommandResult::StreamOpened(id) => id,
            CommandResult::None => unreachable!(),
        };
        client.stream_send_queue.push_back(stream_id);
        client.streams_queued.insert(stream_id);
        client.streams.remove(stream_id);

        assert!(client.queue_one_stream_action().unwrap().is_none());
        assert!(client.stream_send_queue.is_empty());
        client.schedule_stream(stream_id);
        assert!(client.stream_send_queue.is_empty());
    }

    #[test]
    fn first_server_initial_requires_crypto() {
        let (mut client, mut server) = pair();
        client.builder.enqueue(
            PacketNumberSpace::Initial,
            QueuedFrame::new(FrameType::PING, Vec::new(), FrameAction::None),
        );

        transfer(&mut client, &mut server, Duration::from_millis(1));

        assert_eq!(server.state(), ConnectionState::Closing);
        assert_eq!(
            server.local_error().map(|error| error.code),
            Some(TransportErrorCode::PROTOCOL_VIOLATION)
        );
    }

    #[test]
    fn authenticated_reserved_bits_are_a_protocol_violation() {
        let (mut client, mut server) = pair();
        install_application_pair(&mut client, &mut server);
        let sender = PacketKey::new(
            AeadAlgorithm::Aes128Gcm,
            HeaderProtectionAlgorithm::Aes128,
            &[1; 16],
            &[2; 12],
            &[3; 16],
            0,
        )
        .unwrap();
        let mut header = vec![0x48];
        header.extend_from_slice(&[7; 8]);
        header.push(0);
        let header_len = header.len();
        header.extend_from_slice(&[0x01, 0x00, 0x00]);
        let packet = sender.protect_packet(header, header_len, 0).unwrap();
        let meta = ReceiveMeta {
            now: Duration::from_millis(1),
            local: addresses().0,
            remote: addresses().1,
            ecn: None,
        };

        server.receive_datagram(&packet, meta).unwrap();

        assert_eq!(server.state(), ConnectionState::Closing);
        assert_eq!(
            server.local_error().map(|error| error.code),
            Some(TransportErrorCode::PROTOCOL_VIOLATION)
        );
    }

    #[test]
    fn unauthenticated_packets_do_not_create_paths_or_adopt_source_cids() {
        let (_, mut server) = pair();
        let alternate: NetworkAddress = SocketAddr::from(([127, 0, 0, 2], 5555)).into();
        let original_cid = server.config.destination_cid.clone();
        let meta = ReceiveMeta {
            now: Duration::from_millis(1),
            local: addresses().0,
            remote: alternate,
            ecn: None,
        };
        let mut invalid_initial = vec![0xc0];
        invalid_initial.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
        invalid_initial.extend_from_slice(&[8]);
        invalid_initial.extend_from_slice(&[7; 8]);
        invalid_initial.extend_from_slice(&[8]);
        invalid_initial.extend_from_slice(&[9; 8]);
        invalid_initial.extend_from_slice(&[0, 20]);
        invalid_initial.extend_from_slice(&[0; 20]);
        invalid_initial.resize(MIN_INITIAL_DATAGRAM_SIZE, 0);

        server.receive_datagram(&invalid_initial, meta).unwrap();

        assert!(server.paths.find(meta.local, alternate).is_none());
        assert_eq!(server.config.destination_cid, original_cid);
        assert_eq!(server.paths.active_path().bytes_received(), 0);
    }

    #[test]
    fn stateless_reset_token_terminates_only_once() {
        let (mut client, mut server) = pair();
        install_application_pair(&mut client, &mut server);
        let token = [0xa5; 16];
        client
            .apply_peer_transport_parameters(
                0,
                0,
                0,
                0,
                16,
                16,
                3,
                Duration::from_millis(25),
                None,
                None,
                Some(token),
                2,
                false,
                None,
            )
            .unwrap();
        while client.poll_event().is_some() {}
        let mut reset = vec![0x40; MIN_STATELESS_RESET_SIZE - token.len()];
        reset.extend_from_slice(&token);
        let meta = ReceiveMeta {
            now: Duration::from_millis(1),
            local: addresses().1,
            remote: addresses().0,
            ecn: None,
        };

        client.receive_datagram(&reset, meta).unwrap();
        client.receive_datagram(&reset, meta).unwrap();

        assert_eq!(client.state(), ConnectionState::Terminated);
        assert!(matches!(
            client.poll_event(),
            Some(ConnectionEvent::ConnectionTerminated { .. })
        ));
        assert!(client.poll_event().is_none());
    }

    #[test]
    fn protected_ack_removes_outstanding_packet() {
        let (mut client, mut server) = pair();
        install_application_pair(&mut client, &mut server);
        client.send_datagram(&[9]).unwrap();
        transfer(&mut client, &mut server, Duration::from_millis(1));
        assert_eq!(
            client
                .recovery()
                .outstanding_packets(PacketNumberSpace::ApplicationData)
                .count(),
            1
        );
        transfer(&mut server, &mut client, Duration::from_millis(30));
        assert_eq!(
            client
                .recovery()
                .outstanding_packets(PacketNumberSpace::ApplicationData)
                .count(),
            0
        );
    }

    #[test]
    fn datagram_limits_include_type_and_length_encoding() {
        let (mut client, mut server) = pair();
        install_application_pair(&mut client, &mut server);
        client.config.peer_max_datagram_frame_size = Some(3);
        server.config.max_datagram_frame_size = Some(3);

        client.send_datagram(&[1]).unwrap();
        transfer(&mut client, &mut server, Duration::from_millis(1));
        assert_eq!(
            server.poll_event(),
            Some(ConnectionEvent::Datagram(vec![1]))
        );

        assert!(matches!(
            client.send_datagram(&[1, 2]),
            Err(ConnectionCoreError::DatagramTooLarge)
        ));

        client.config.peer_max_datagram_frame_size = Some(1200);
        client.send_datagram(&[1, 2]).unwrap();
        transfer(&mut client, &mut server, Duration::from_millis(2));
        assert_eq!(server.state(), ConnectionState::Closing);
        assert_eq!(
            server.local_error().map(|error| error.frame_type),
            Some(Some(FrameType::DATAGRAM_WITH_LENGTH))
        );
    }

    #[test]
    fn server_rejects_new_token() {
        let (mut client, mut server) = pair();
        install_application_pair(&mut client, &mut server);
        client.builder.enqueue(
            PacketNumberSpace::ApplicationData,
            QueuedFrame::new(
                FrameType::NEW_TOKEN,
                vec![3, b'o', b'n', b'e'],
                FrameAction::None,
            ),
        );

        transfer(&mut client, &mut server, Duration::from_millis(1));

        assert_eq!(server.state(), ConnectionState::Closing);
        assert_eq!(
            server
                .local_error()
                .map(|error| (error.code, error.frame_type)),
            Some((
                TransportErrorCode::PROTOCOL_VIOLATION,
                Some(FrameType::NEW_TOKEN)
            ))
        );
    }

    #[test]
    fn packets_for_unknown_destination_cids_are_dropped() {
        let (mut client, mut server) = pair();
        install_application_pair(&mut client, &mut server);
        client
            .peer_cids
            .replace_initial(ConnectionId::for_new_connection_id(vec![0xaa; 8]).unwrap())
            .unwrap();
        client.command(ConnectionCommand::SendPing(1)).unwrap();

        let tx = client
            .poll_transmit(Duration::from_millis(1))
            .unwrap()
            .unwrap();
        let report = server
            .receive_datagram(
                &tx.bytes,
                ReceiveMeta {
                    now: Duration::from_millis(1),
                    local: tx.destination,
                    remote: tx.source,
                    ecn: None,
                },
            )
            .unwrap();

        assert_eq!(report.dropped, 1);
        assert_eq!(report.packets, 0);
        assert!(server.poll_event().is_none());
    }

    #[test]
    fn final_stream_ack_bypasses_full_congestion_window() {
        let (mut client, mut server) = pair();
        install_application_pair(&mut client, &mut server);
        let id = match client
            .command(ConnectionCommand::OpenStream(
                StreamDirection::Bidirectional,
            ))
            .unwrap()
        {
            CommandResult::StreamOpened(id) => id,
            CommandResult::None => unreachable!(),
        };
        client.send_stream(id, b"request", true).unwrap();
        transfer(&mut client, &mut server, Duration::from_millis(1));

        while client.recovery().congestion().congestion_window()
            - client.recovery().congestion().bytes_in_flight()
            >= client.config.max_datagram_size as u64
        {
            client.send_datagram(&vec![0; 1100]).unwrap();
            let tx = client
                .poll_transmit(Duration::from_millis(1))
                .unwrap()
                .unwrap();
            server
                .receive_datagram(
                    &tx.bytes,
                    ReceiveMeta {
                        now: Duration::from_millis(1),
                        local: tx.destination,
                        remote: tx.source,
                        ecn: None,
                    },
                )
                .unwrap();
        }
        assert!(
            client.recovery().congestion().congestion_window()
                - client.recovery().congestion().bytes_in_flight()
                < client.config.max_datagram_size as u64
        );

        server.send_stream(id, b"response", true).unwrap();
        transfer(&mut server, &mut client, Duration::from_millis(2));

        let ack = client
            .poll_transmit(Duration::from_millis(2))
            .unwrap()
            .expect("ACK-only packet must bypass congestion control");
        server
            .receive_datagram(
                &ack.bytes,
                ReceiveMeta {
                    now: Duration::from_millis(3),
                    local: ack.destination,
                    remote: ack.source,
                    ecn: None,
                },
            )
            .unwrap();
        assert_eq!(
            server
                .recovery()
                .outstanding_packets(PacketNumberSpace::ApplicationData)
                .count(),
            0
        );
    }

    #[test]
    fn authenticated_malformed_frame_and_peer_close_change_state() {
        let (mut client, mut server) = pair();
        install_application_pair(&mut client, &mut server);
        client.builder.enqueue(
            PacketNumberSpace::ApplicationData,
            QueuedFrame::new(
                FrameType(VarInt::new(0x20).unwrap()),
                Vec::new(),
                FrameAction::None,
            ),
        );
        transfer(&mut client, &mut server, Duration::from_millis(1));
        assert_eq!(server.state(), ConnectionState::Closing);
        assert!(server.local_error().is_some());

        let (mut client, mut server) = pair();
        install_application_pair(&mut client, &mut server);
        client
            .command(ConnectionCommand::Close {
                frame_type: None,
                error_code: 42,
                reason: b"finished".to_vec(),
            })
            .unwrap();
        transfer(&mut client, &mut server, Duration::from_millis(2));
        assert_eq!(server.state(), ConnectionState::Draining);
        assert!(matches!(
            server.poll_event(),
            Some(ConnectionEvent::PeerClosed {
                application: true,
                error_code: 42,
                reason,
                ..
            }) if reason == b"finished"
        ));
    }

    #[test]
    fn missing_key_does_not_consume_stream_reservation() {
        let (mut client, mut server) = pair();
        let id = match client
            .command(ConnectionCommand::OpenStream(
                StreamDirection::Bidirectional,
            ))
            .unwrap()
        {
            CommandResult::StreamOpened(id) => id,
            CommandResult::None => unreachable!(),
        };
        client.send_stream(id, b"later", false).unwrap();
        assert!(client
            .poll_transmit(Duration::from_millis(1))
            .unwrap()
            .is_none());
        assert_eq!(client.pending_streams.len(), 1);
        install_application_pair(&mut client, &mut server);
        let report = transfer(&mut client, &mut server, Duration::from_millis(2));
        assert_eq!(report.packets, 1);
        assert!(matches!(
            server.poll_event(),
            Some(ConnectionEvent::StreamData { data, .. }) if data == b"later"
        ));

        client.send_stream(id, b" again", false).unwrap();
        let report = transfer(&mut client, &mut server, Duration::from_millis(3));
        assert_eq!(report.packets, 1);
        assert!(matches!(
            server.poll_event(),
            Some(ConnectionEvent::StreamData { data, .. }) if data == b" again"
        ));
    }

    #[test]
    fn pto_retransmits_stream_data_when_congestion_window_is_full() {
        let (mut client, mut server) = pair();
        install_application_pair(&mut client, &mut server);
        for _ in 0..10 {
            let id = match client
                .command(ConnectionCommand::OpenStream(
                    StreamDirection::Bidirectional,
                ))
                .unwrap()
            {
                CommandResult::StreamOpened(id) => id,
                CommandResult::None => unreachable!(),
            };
            client.send_stream(id, &vec![1; 1100], true).unwrap();
        }
        for _ in 0..10 {
            assert!(client
                .poll_transmit(Duration::from_millis(1))
                .unwrap()
                .is_some());
        }
        assert!(
            client.recovery().congestion().congestion_window()
                - client.recovery().congestion().bytes_in_flight()
                < client.config.max_datagram_size as u64
        );
        assert!(client
            .poll_transmit(Duration::from_millis(1))
            .unwrap()
            .is_none());

        let timeout = client.recovery().loss_detection_time().unwrap();
        client.handle_timeout(timeout).unwrap();
        assert_eq!(client.recovery().pto_count(), 1);
        let before = client
            .recovery()
            .outstanding_packets(PacketNumberSpace::ApplicationData)
            .count();

        let first_probe = client.poll_transmit(timeout).unwrap().unwrap();
        assert!(!first_probe.bytes.is_empty());
        assert_eq!(
            client
                .recovery()
                .outstanding_packets(PacketNumberSpace::ApplicationData)
                .count(),
            before + 1
        );
        assert!(client
            .recovery()
            .outstanding_packets(PacketNumberSpace::ApplicationData)
            .last()
            .is_some_and(|packet| packet.ack_eliciting && packet.delivery_actions.len() == 1));

        let second_probe = client.poll_transmit(timeout).unwrap().unwrap();
        assert!(!second_probe.bytes.is_empty());
        assert!(client.pending_probes.is_empty());
        assert!(client.pending_streams.is_empty());
    }

    #[test]
    fn close_and_idle_timers_terminate() {
        let (mut client, _) = pair();
        client
            .command(ConnectionCommand::Close {
                frame_type: None,
                error_code: 4,
                reason: b"bye".to_vec(),
            })
            .unwrap();
        client.finalize_receive_batch(Some(Duration::from_secs(2)), &mut ReceiveReport::default());
        let timer = client.next_timer().unwrap();
        client.handle_timeout(timer.deadline).unwrap();
        assert_eq!(client.state(), ConnectionState::Terminated);
        assert!(matches!(
            client.poll_event(),
            Some(ConnectionEvent::ConnectionTerminated { .. })
        ));
    }

    #[test]
    fn idle_timeout_terminates_an_open_connection() {
        let (mut client, _) = pair();
        client.config.idle_timeout = Some(Duration::from_secs(3));
        client.peer_idle_timeout = Some(Duration::from_secs(10));
        client.last_activity = Duration::from_secs(1);

        let timer = client.next_timer().unwrap();
        assert_eq!(timer.kind, TimerKind::Idle);
        assert_eq!(timer.deadline, Duration::from_secs(4));
        client.handle_timeout(timer.deadline).unwrap();

        assert_eq!(client.state(), ConnectionState::Terminated);
        assert_eq!(
            client.poll_event(),
            Some(ConnectionEvent::ConnectionTerminated {
                error_code: TransportErrorCode::INTERNAL_ERROR.value(),
                frame_type: Some(FrameType::PADDING.value()),
                reason: b"Idle timeout".to_vec(),
            })
        );
    }

    #[test]
    fn retire_connection_id_rejects_current_and_unknown_sequences() {
        for (packet_sequence, retired_sequence) in [(Some(0), 0), (None, 8)] {
            let (mut client, _) = pair();
            let frame_type = FrameType::RETIRE_CONNECTION_ID;
            let error = client
                .apply_frames(
                    Epoch::OneRtt,
                    client.paths.active_path_id(),
                    packet_sequence,
                    &[],
                    vec![super::super::wire::FrameRecord {
                        frame_type,
                        span: super::super::wire::Span::new(0, 0),
                        frame: Frame::RetireConnectionId {
                            sequence_number: VarInt::new(retired_sequence).unwrap(),
                        },
                    }],
                    Duration::from_secs(1),
                )
                .unwrap_err();
            assert_eq!(error.code, TransportErrorCode::PROTOCOL_VIOLATION);
            assert_eq!(error.frame_type, Some(frame_type));
        }
    }

    #[test]
    fn stream_frames_enforce_direction_final_size_and_flow_limits() {
        let frame_type = FrameType(VarInt::new(0x0f).unwrap());
        let frame = |stream_id, offset, fin, span| super::super::wire::FrameRecord {
            frame_type,
            span,
            frame: Frame::Stream {
                stream_id: StreamId::new(stream_id).unwrap(),
                offset: VarInt::new(offset).unwrap(),
                fin,
                data: span,
            },
        };

        for stream_id in [0, 2] {
            let (mut client, _) = pair();
            let error = client
                .apply_frames(
                    Epoch::OneRtt,
                    client.paths.active_path_id(),
                    None,
                    &[],
                    vec![frame(
                        stream_id,
                        0,
                        false,
                        super::super::wire::Span::new(0, 0),
                    )],
                    Duration::from_secs(1),
                )
                .unwrap_err();
            assert_eq!(error.code, TransportErrorCode::STREAM_STATE_ERROR);
        }

        let (mut client, _) = pair();
        let error = client
            .apply_frames(
                Epoch::OneRtt,
                client.paths.active_path_id(),
                None,
                &[],
                vec![frame(65, 0, false, super::super::wire::Span::new(0, 0))],
                Duration::from_secs(1),
            )
            .unwrap_err();
        assert_eq!(error.code, TransportErrorCode::STREAM_LIMIT_ERROR);

        let (mut client, _) = pair();
        client
            .apply_frames(
                Epoch::OneRtt,
                client.paths.active_path_id(),
                None,
                &[],
                vec![frame(1, 8, true, super::super::wire::Span::new(0, 0))],
                Duration::from_secs(1),
            )
            .unwrap();
        let error = client
            .apply_frames(
                Epoch::OneRtt,
                client.paths.active_path_id(),
                None,
                &[],
                vec![frame(1, 5, true, super::super::wire::Span::new(0, 0))],
                Duration::from_secs(2),
            )
            .unwrap_err();
        assert_eq!(error.code, TransportErrorCode::FINAL_SIZE_ERROR);

        let (mut client, _) = pair();
        client.config.stream_receive_window = 1;
        client.flow = FlowController::new(0, 10, 10).unwrap();
        let error = client
            .apply_frames(
                Epoch::OneRtt,
                client.paths.active_path_id(),
                None,
                b"xx",
                vec![frame(1, 0, false, super::super::wire::Span::new(0, 2))],
                Duration::from_secs(1),
            )
            .unwrap_err();
        assert_eq!(error.code, TransportErrorCode::FLOW_CONTROL_ERROR);

        let (mut client, _) = pair();
        client.flow = FlowController::new(0, 1, 1).unwrap();
        let error = client
            .apply_frames(
                Epoch::OneRtt,
                client.paths.active_path_id(),
                None,
                b"xx",
                vec![frame(1, 0, false, super::super::wire::Span::new(0, 2))],
                Duration::from_secs(1),
            )
            .unwrap_err();
        assert_eq!(error.code, TransportErrorCode::FLOW_CONTROL_ERROR);
    }

    #[test]
    fn peer_transport_timing_is_separate_and_deferred() {
        let (mut client, _) = pair();
        client.config.idle_timeout = Some(Duration::from_secs(10));
        client
            .apply_peer_transport_parameters(
                0,
                0,
                0,
                0,
                16,
                16,
                9,
                Duration::from_millis(25),
                Some(Duration::from_secs(5)),
                None,
                None,
                2,
                false,
                None,
            )
            .unwrap();

        assert_eq!(client.config.ack_delay_exponent, 3);
        assert_eq!(client.peer_ack_delay_exponent, 9);
        assert_eq!(
            client.effective_idle_timeout(),
            Some(Duration::from_secs(5))
        );

        client
            .recovery
            .on_packet_sent(
                PacketNumberSpace::ApplicationData,
                SentPacket {
                    packet_number: 0,
                    path_id: 0,
                    sent_time: Duration::from_secs(1),
                    sent_bytes: 1200,
                    ack_eliciting: true,
                    in_flight: true,
                    is_crypto: false,
                    is_pmtu_probe: false,
                    packet_type: PacketType::OneRtt,
                    delivery_actions: Vec::new(),
                },
            )
            .unwrap();
        client
            .recovery
            .on_ack_received(
                PacketNumberSpace::ApplicationData,
                &[AckRange::new(0, 1)],
                Duration::ZERO,
                Duration::from_millis(1100),
                true,
            )
            .unwrap();
        let before_confirmation = client
            .recovery
            .probe_timeout_for(PacketNumberSpace::ApplicationData);
        client.confirm_handshake();
        assert_eq!(
            client
                .recovery
                .probe_timeout_for(PacketNumberSpace::ApplicationData),
            add_duration(before_confirmation, Duration::from_millis(25))
        );
        assert_eq!(
            client
                .recovery
                .probe_timeout_for(PacketNumberSpace::Handshake),
            before_confirmation
        );
    }

    #[test]
    fn server_confirmation_discards_handshake_and_zero_rtt_keys() {
        let (_, mut server) = pair();
        let make_key = || {
            PacketKey::new(
                AeadAlgorithm::Aes128Gcm,
                HeaderProtectionAlgorithm::Aes128,
                &[1; 16],
                &[2; 12],
                &[3; 16],
                0,
            )
            .unwrap()
        };
        server.install_send_key(Epoch::Handshake, make_key());
        server.install_send_key(Epoch::ZeroRtt, make_key());
        assert!(server.crypto.has_send_key(Epoch::Handshake));
        assert!(server.crypto.has_send_key(Epoch::ZeroRtt));

        server.handshake_complete();

        assert!(!server.crypto.has_send_key(Epoch::Handshake));
        assert!(!server.crypto.has_send_key(Epoch::ZeroRtt));
    }

    #[test]
    fn discarding_handshake_keys_purges_queued_frames_and_probes() {
        let (mut client, _) = pair();
        client.builder.enqueue(
            PacketNumberSpace::Handshake,
            QueuedFrame::new(FrameType::PING, Vec::new(), FrameAction::None),
        );
        client
            .pending_probes
            .push_back(PacketNumberSpace::Handshake);

        client.discard_keys(Epoch::Handshake);

        assert_eq!(
            client.builder.queued_frames(PacketNumberSpace::Handshake),
            0
        );
        assert!(!client
            .pending_probes
            .contains(&PacketNumberSpace::Handshake));
        assert!(client.poll_transmit(Duration::from_millis(1)).is_ok());
    }

    #[test]
    fn consecutive_stream_events_are_coalesced_without_reordering() {
        let (mut client, _) = pair();
        let stream = StreamId::new(0).unwrap();
        client.push_stream_data_event(stream, b"one".to_vec(), false);
        client.push_stream_data_event(stream, b"two".to_vec(), true);
        assert_eq!(
            client.poll_event(),
            Some(ConnectionEvent::StreamData {
                stream_id: stream,
                data: b"onetwo".to_vec(),
                fin: true,
            })
        );
        assert!(!client.has_events());

        client.push_stream_data_event(stream, vec![0; MAX_STREAM_EVENT_SIZE], false);
        client.push_stream_data_event(stream, vec![1], false);
        assert_eq!(client.events.len(), 2);
    }
}
