use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::time::Duration;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyBytesMethods, PyTuple};

use crate::quic::connection::{
    CommandResult, ConnectionCommand, ConnectionConfig, ConnectionCore, ConnectionCoreError,
    ConnectionEvent, ReceiveMeta, ReceiveReport, ReceivedDatagram, TimerKind, Transmit,
};
use crate::quic::crypto::{AeadAlgorithm, CryptoError, HeaderProtectionAlgorithm, PacketKey};
use crate::quic::path::NetworkAddress;
use crate::quic::recovery::RecoveryConfig;
use crate::quic::types::{
    ConnectionState, Epoch, FrameType, PacketNumberSpace, Role, StreamDirection, StreamId,
};

#[pyclass(name = "QuicConnectionCore", module = "qh3._hazmat")]
pub struct PyQuicConnectionCore {
    inner: ConnectionCore,
}

#[pymethods]
impl PyQuicConnectionCore {
    #[new]
    #[pyo3(signature = (
        is_client, version, local_addr, remote_addr, source_cid, destination_cid,
        peer_address_validated, active_connection_id_limit, max_datagram_size,
        probe_datagram_size, idle_timeout, ack_delay_exponent, max_datagram_frame_size,
        peer_max_datagram_frame_size,
        connection_receive_window, connection_send_limit, stream_receive_window,
        stream_send_limit_bidi_local, stream_send_limit_bidi_remote,
        stream_send_limit_uni, max_stream_reassembly, local_max_streams_bidi,
        local_max_streams_uni, peer_max_streams_bidi, peer_max_streams_uni,
        initial_rtt, max_ack_delay
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        is_client: bool,
        version: u32,
        local_addr: &Bound<'_, PyAny>,
        remote_addr: &Bound<'_, PyAny>,
        source_cid: &Bound<'_, PyBytes>,
        destination_cid: &Bound<'_, PyBytes>,
        peer_address_validated: bool,
        active_connection_id_limit: u64,
        max_datagram_size: usize,
        probe_datagram_size: bool,
        idle_timeout: Option<f64>,
        ack_delay_exponent: u8,
        max_datagram_frame_size: Option<usize>,
        peer_max_datagram_frame_size: Option<usize>,
        connection_receive_window: u64,
        connection_send_limit: u64,
        stream_receive_window: u64,
        stream_send_limit_bidi_local: u64,
        stream_send_limit_bidi_remote: u64,
        stream_send_limit_uni: u64,
        max_stream_reassembly: usize,
        local_max_streams_bidi: u64,
        local_max_streams_uni: u64,
        peer_max_streams_bidi: u64,
        peer_max_streams_uni: u64,
        initial_rtt: f64,
        max_ack_delay: f64,
    ) -> PyResult<Self> {
        let _ = max_ack_delay;
        let config = ConnectionConfig {
            role: if is_client {
                Role::Client
            } else {
                Role::Server
            },
            version,
            local_address: parse_address(local_addr)?.into(),
            remote_address: parse_address(remote_addr)?.into(),
            source_cid: source_cid.as_bytes().to_vec(),
            destination_cid: destination_cid.as_bytes().to_vec(),
            peer_address_validated,
            active_connection_id_limit,
            max_datagram_size,
            probe_datagram_size,
            idle_timeout: idle_timeout.map(duration_from_seconds).transpose()?,
            ack_delay_exponent,
            max_datagram_frame_size,
            peer_max_datagram_frame_size,
            connection_receive_window,
            connection_send_limit,
            stream_receive_window,
            stream_send_limit_bidi_local,
            stream_send_limit_bidi_remote,
            stream_send_limit_uni,
            max_stream_reassembly,
            local_max_streams_bidi,
            local_max_streams_uni,
            peer_max_streams_bidi,
            peer_max_streams_uni,
            recovery: RecoveryConfig {
                initial_rtt: duration_from_seconds(initial_rtt)?,
                ack_delay: Duration::from_millis(1),
                max_ack_delay: Duration::ZERO,
                max_datagram_size: max_datagram_size as u64,
                peer_completed_address_validation: peer_address_validated,
            },
            peer_disable_active_migration: false,
        };
        Ok(Self {
            inner: ConnectionCore::new(config).map_err(core_error)?,
        })
    }

    #[pyo3(signature = (data, addr, now, datagram_size=None))]
    fn receive_datagram(
        &mut self,
        data: &Bound<'_, PyBytes>,
        addr: &Bound<'_, PyAny>,
        now: f64,
        datagram_size: Option<usize>,
    ) -> PyResult<(usize, usize, usize, usize, usize, usize)> {
        let meta = self.receive_meta(addr, now)?;
        self.inner
            .receive_datagram_with_size(
                data.as_bytes(),
                datagram_size.unwrap_or(data.as_bytes().len()),
                meta,
            )
            .map(report_tuple)
            .map_err(core_error)
    }

    fn receive_many_datagrams(
        &mut self,
        datagrams: Vec<Bound<'_, PyBytes>>,
        addr: &Bound<'_, PyAny>,
        now: f64,
    ) -> PyResult<(usize, usize, usize, usize, usize, usize)> {
        let meta = self.receive_meta(addr, now)?;
        let datagrams: Vec<_> = datagrams
            .iter()
            .map(|data| ReceivedDatagram {
                bytes: data.as_bytes(),
                meta,
            })
            .collect();
        self.inner
            .receive_many_datagrams(&datagrams)
            .map(report_tuple)
            .map_err(core_error)
    }

    fn receive_gro_buffer(
        &mut self,
        buffer: &Bound<'_, PyBytes>,
        segment_size: usize,
        addr: &Bound<'_, PyAny>,
        now: f64,
    ) -> PyResult<(usize, usize, usize, usize, usize, usize)> {
        let meta = self.receive_meta(addr, now)?;
        self.inner
            .receive_gro_buffer(buffer.as_bytes(), segment_size, meta)
            .map(report_tuple)
            .map_err(core_error)
    }

    fn next_event(&mut self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        self.inner
            .poll_event()
            .map(|event| event_to_python(py, event))
            .transpose()
    }

    fn poll_transmit(&mut self, py: Python<'_>, now: f64) -> PyResult<Option<Py<PyAny>>> {
        self.inner
            .poll_transmit(duration_from_seconds(now)?)
            .map_err(core_error)?
            .map(|transmit| transmit_to_python(py, transmit))
            .transpose()
    }

    fn get_timer(&self) -> Option<(String, f64)> {
        self.inner.next_timer().map(|timer| {
            (
                timer_name(timer.kind).to_owned(),
                timer.deadline.as_secs_f64(),
            )
        })
    }

    fn handle_timer(&mut self, now: f64) -> PyResult<()> {
        self.inner
            .handle_timeout(duration_from_seconds(now)?)
            .map_err(core_error)
    }

    fn set_initial_token(&mut self, token: &Bound<'_, PyBytes>) {
        self.inner.set_initial_token(token.as_bytes().to_vec());
    }

    fn open_stream(&mut self, unidirectional: bool) -> PyResult<u64> {
        let direction = if unidirectional {
            StreamDirection::Unidirectional
        } else {
            StreamDirection::Bidirectional
        };
        match self
            .inner
            .command(ConnectionCommand::OpenStream(direction))
            .map_err(core_error)?
        {
            CommandResult::StreamOpened(id) => Ok(id.into_inner()),
            CommandResult::None => Err(PyRuntimeError::new_err(
                "native core returned no stream identifier",
            )),
        }
    }

    #[pyo3(signature = (stream_id, data, fin=false))]
    fn send_stream(
        &mut self,
        stream_id: u64,
        data: &Bound<'_, PyBytes>,
        fin: bool,
    ) -> PyResult<()> {
        self.inner
            .send_stream(parse_stream_id(stream_id)?, data.as_bytes(), fin)
            .map(|_| ())
            .map_err(core_error)
    }

    fn reset_stream(&mut self, stream_id: u64, error_code: u64) -> PyResult<()> {
        self.command(ConnectionCommand::ResetStream {
            stream_id: parse_stream_id(stream_id)?,
            error_code,
        })
    }

    fn stop_sending(&mut self, stream_id: u64, error_code: u64) -> PyResult<()> {
        self.command(ConnectionCommand::StopSending {
            stream_id: parse_stream_id(stream_id)?,
            error_code,
        })
    }

    fn send_datagram(&mut self, data: &Bound<'_, PyBytes>) -> PyResult<()> {
        self.inner
            .send_datagram(data.as_bytes())
            .map(|_| ())
            .map_err(core_error)
    }

    fn send_ping(&mut self, uid: u64) -> PyResult<()> {
        self.command(ConnectionCommand::SendPing(uid))
    }

    fn send_crypto(&mut self, epoch: u8, offset: u64, data: &Bound<'_, PyBytes>) -> PyResult<()> {
        self.inner
            .send_crypto(parse_epoch(epoch)?, offset, data.as_bytes())
            .map(|_| ())
            .map_err(core_error)
    }

    #[pyo3(signature = (error_code, frame_type=None, reason=None))]
    fn close(
        &mut self,
        error_code: u64,
        frame_type: Option<u64>,
        reason: Option<&Bound<'_, PyBytes>>,
    ) -> PyResult<()> {
        self.command(ConnectionCommand::Close {
            frame_type: frame_type
                .map(FrameType::try_from)
                .transpose()
                .map_err(|_| PyValueError::new_err("frame type exceeds the QUIC varint limit"))?,
            error_code,
            reason: reason.map_or_else(Vec::new, |value| value.as_bytes().to_vec()),
        })
    }

    #[pyo3(signature = (direction, epoch, algorithms, key, iv, hp, phase, traffic_secret=None, version=None))]
    #[allow(clippy::too_many_arguments)]
    fn install_packet_key(
        &mut self,
        direction: &str,
        epoch: u8,
        algorithms: (String, String),
        key: &Bound<'_, PyBytes>,
        iv: &Bound<'_, PyBytes>,
        hp: &Bound<'_, PyBytes>,
        phase: u8,
        traffic_secret: Option<&Bound<'_, PyBytes>>,
        version: Option<u32>,
    ) -> PyResult<()> {
        let epoch = parse_epoch(epoch)?;
        let aead = parse_aead(&algorithms.0)?;
        let hp_algorithm = parse_hp(&algorithms.1)?;
        let packet_key = if let Some(secret) = traffic_secret {
            PacketKey::with_traffic_secret(
                aead,
                hp_algorithm,
                key.as_bytes(),
                iv.as_bytes(),
                hp.as_bytes(),
                phase,
                secret.as_bytes(),
                version.ok_or_else(|| {
                    PyValueError::new_err("version is required with a traffic secret")
                })?,
            )
        } else {
            PacketKey::new(
                aead,
                hp_algorithm,
                key.as_bytes(),
                iv.as_bytes(),
                hp.as_bytes(),
                phase,
            )
        }
        .map_err(crypto_value_error)?;
        match direction {
            "send" => self.inner.install_send_key(epoch, packet_key),
            "receive" => self.inner.install_receive_key(epoch, packet_key),
            _ => {
                return Err(PyValueError::new_err(
                    "direction must be 'send' or 'receive'",
                ))
            }
        }
        Ok(())
    }

    fn request_key_update(&mut self) -> PyResult<()> {
        self.inner.request_key_update().map_err(core_error)
    }

    fn change_connection_id(&mut self) -> PyResult<()> {
        self.inner.change_connection_id().map_err(core_error)
    }

    fn discard_keys(&mut self, epoch: u8) -> PyResult<()> {
        self.inner.discard_keys(parse_epoch(epoch)?);
        Ok(())
    }

    fn set_version(&mut self, version: u32) -> PyResult<()> {
        self.inner.set_version(version).map_err(core_error)
    }

    fn reject_zero_rtt(&mut self) -> PyResult<()> {
        self.inner.reject_zero_rtt().map_err(core_error)
    }

    fn restore_send_packet_number(&mut self, space: u8, packet_number: u64) -> PyResult<()> {
        let space = match space {
            0 => PacketNumberSpace::Initial,
            1 => PacketNumberSpace::Handshake,
            2 => PacketNumberSpace::ApplicationData,
            _ => {
                return Err(PyValueError::new_err(
                    "packet space must be between 0 and 2",
                ))
            }
        };
        self.inner
            .restore_send_packet_number(space, packet_number)
            .map_err(core_error)
    }

    #[pyo3(signature = (
        connection_send_limit, stream_send_limit_bidi_local,
        stream_send_limit_bidi_remote, stream_send_limit_uni, peer_max_streams_bidi,
        peer_max_streams_uni, ack_delay_exponent, max_ack_delay,
        peer_idle_timeout, max_datagram_frame_size, stateless_reset_token=None,
        active_connection_id_limit=2, disable_active_migration=false,
        max_udp_payload_size=None
    ))]
    #[allow(clippy::too_many_arguments)]
    fn apply_peer_transport_parameters(
        &mut self,
        connection_send_limit: u64,
        stream_send_limit_bidi_local: u64,
        stream_send_limit_bidi_remote: u64,
        stream_send_limit_uni: u64,
        peer_max_streams_bidi: u64,
        peer_max_streams_uni: u64,
        ack_delay_exponent: u8,
        max_ack_delay: f64,
        peer_idle_timeout: Option<f64>,
        max_datagram_frame_size: Option<usize>,
        stateless_reset_token: Option<&Bound<'_, PyBytes>>,
        active_connection_id_limit: u64,
        disable_active_migration: bool,
        max_udp_payload_size: Option<usize>,
    ) -> PyResult<()> {
        let stateless_reset_token = stateless_reset_token
            .map(|token| {
                token.as_bytes().try_into().map_err(|_| {
                    PyValueError::new_err("stateless reset token must be exactly 16 bytes")
                })
            })
            .transpose()?;
        self.inner
            .apply_peer_transport_parameters(
                connection_send_limit,
                stream_send_limit_bidi_local,
                stream_send_limit_bidi_remote,
                stream_send_limit_uni,
                peer_max_streams_bidi,
                peer_max_streams_uni,
                ack_delay_exponent,
                duration_from_seconds(max_ack_delay)?,
                peer_idle_timeout.map(duration_from_seconds).transpose()?,
                max_datagram_frame_size,
                stateless_reset_token,
                active_connection_id_limit,
                disable_active_migration,
                max_udp_payload_size,
            )
            .map_err(core_error)
    }

    fn handshake_complete(&mut self) {
        self.inner.handshake_complete();
    }

    fn handshake_confirmed(&mut self) {
        self.inner.confirm_handshake();
    }

    #[getter]
    fn state(&self) -> &'static str {
        match self.inner.state() {
            ConnectionState::FirstFlight => "first_flight",
            ConnectionState::Connected => "connected",
            ConnectionState::Closing => "closing",
            ConnectionState::Draining => "draining",
            ConnectionState::Terminated => "terminated",
        }
    }

    #[getter]
    fn version(&self) -> u32 {
        self.inner.version()
    }

    #[getter]
    fn has_events(&self) -> bool {
        self.inner.has_events()
    }

    #[getter]
    fn received_authenticated_packet(&self) -> bool {
        self.inner.received_authenticated_packet()
    }

    #[getter]
    fn local_error(&self) -> Option<(u64, Option<u64>, String)> {
        self.inner.local_error().map(|error| {
            (
                error.code.value(),
                error.frame_type.map(|frame| frame.value()),
                error.reason.clone(),
            )
        })
    }

    #[getter]
    fn send_key_phase(&self) -> Option<u8> {
        self.inner.crypto().send_key_phase()
    }

    #[getter]
    fn receive_key_phase(&self) -> Option<u8> {
        self.inner.crypto().receive_key_phase()
    }

    #[getter]
    fn bytes_in_flight(&self) -> u64 {
        self.inner.recovery().congestion().bytes_in_flight()
    }

    #[getter]
    fn congestion_window(&self) -> u64 {
        self.inner.recovery().congestion().congestion_window()
    }

    #[getter]
    fn smoothed_rtt(&self) -> Option<f64> {
        self.inner
            .recovery()
            .rtt()
            .smoothed()
            .map(|value| value.as_secs_f64())
    }

    #[getter]
    fn latest_rtt(&self) -> Option<f64> {
        self.inner
            .recovery()
            .rtt()
            .latest()
            .map(|value| value.as_secs_f64())
    }

    #[getter]
    fn pto_count(&self) -> u32 {
        self.inner.recovery().pto_count()
    }

    #[getter]
    fn pto_total(&self) -> u64 {
        self.inner.recovery().pto_total()
    }

    #[getter]
    fn loss_total(&self) -> u64 {
        self.inner.recovery().loss_total()
    }

    fn should_wait_for_ack(&self, now: f64) -> PyResult<bool> {
        Ok(self.inner.should_wait_for_ack(duration_from_seconds(now)?))
    }

    #[getter]
    fn stream_limits(&self) -> (u64, u64, u64, u64) {
        let streams = self.inner.streams();
        (
            streams.peer_max_streams(StreamDirection::Bidirectional),
            streams.peer_max_streams(StreamDirection::Unidirectional),
            streams.opened_local_streams(StreamDirection::Bidirectional),
            streams.opened_local_streams(StreamDirection::Unidirectional),
        )
    }

    #[getter]
    fn active_local_streams(&self) -> (u64, u64) {
        (
            self.inner
                .active_local_streams(StreamDirection::Bidirectional),
            self.inner
                .active_local_streams(StreamDirection::Unidirectional),
        )
    }

    fn can_send_stream(&self, stream_id: u64) -> PyResult<bool> {
        Ok(self.inner.can_send_stream(parse_stream_id(stream_id)?))
    }

    #[getter]
    fn outstanding_application_packets(&self) -> Vec<(u64, u64, usize)> {
        self.inner.outstanding_application_packets()
    }

    #[getter]
    fn active_path(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let path = self.inner.paths().active_path();
        let local = address_to_python(py, path.local)?;
        let remote = address_to_python(py, path.remote)?;
        let value = (
            path.id.get(),
            local,
            remote,
            path.bytes_sent(),
            path.bytes_received(),
            path.pmtu.current(),
        );
        Ok(value.into_pyobject(py)?.unbind().into_any())
    }
}

impl PyQuicConnectionCore {
    fn receive_meta(&self, addr: &Bound<'_, PyAny>, now: f64) -> PyResult<ReceiveMeta> {
        Ok(ReceiveMeta {
            now: duration_from_seconds(now)?,
            local: self.inner.paths().active_path().local,
            remote: parse_address(addr)?.into(),
            ecn: None,
        })
    }

    fn command(&mut self, command: ConnectionCommand) -> PyResult<()> {
        self.inner.command(command).map(|_| ()).map_err(core_error)
    }
}

fn duration_from_seconds(seconds: f64) -> PyResult<Duration> {
    if !seconds.is_finite() || seconds < 0.0 {
        return Err(PyValueError::new_err(
            "time must be a finite, non-negative number",
        ));
    }
    Duration::try_from_secs_f64(seconds)
        .map_err(|_| PyValueError::new_err("time is outside the supported range"))
}

fn parse_address(value: &Bound<'_, PyAny>) -> PyResult<SocketAddr> {
    let tuple = value
        .cast::<PyTuple>()
        .map_err(|_| PyValueError::new_err("address must be a 2- or 4-item tuple"))?;
    if tuple.len() != 2 && tuple.len() != 4 {
        return Err(PyValueError::new_err(
            "address must be (host, port) or (host, port, flowinfo, scope_id)",
        ));
    }
    let host: String = tuple.get_item(0)?.extract()?;
    let port: u16 = tuple.get_item(1)?.extract()?;
    let ip: IpAddr = host
        .parse()
        .map_err(|_| PyValueError::new_err("address host must be a numeric IP address"))?;
    if tuple.len() == 2 {
        return Ok(SocketAddr::new(ip, port));
    }
    let IpAddr::V6(ip) = ip else {
        return Err(PyValueError::new_err(
            "the 4-item address form requires an IPv6 host",
        ));
    };
    let flowinfo: u32 = tuple.get_item(2)?.extract()?;
    let scope_id: u32 = tuple.get_item(3)?.extract()?;
    Ok(SocketAddr::V6(SocketAddrV6::new(
        ip, port, flowinfo, scope_id,
    )))
}

fn address_to_python(py: Python<'_>, address: NetworkAddress) -> PyResult<Py<PyAny>> {
    let address: SocketAddr = address.into();
    let object = match address {
        SocketAddr::V4(address) => (address.ip().to_string(), address.port())
            .into_pyobject(py)?
            .unbind()
            .into_any(),
        SocketAddr::V6(address) => (
            address.ip().to_string(),
            address.port(),
            address.flowinfo(),
            address.scope_id(),
        )
            .into_pyobject(py)?
            .unbind()
            .into_any(),
    };
    Ok(object)
}

fn parse_epoch(epoch: u8) -> PyResult<Epoch> {
    match epoch {
        0 => Ok(Epoch::Initial),
        1 => Ok(Epoch::ZeroRtt),
        2 => Ok(Epoch::Handshake),
        3 => Ok(Epoch::OneRtt),
        _ => Err(PyValueError::new_err("epoch must be between 0 and 3")),
    }
}

fn epoch_number(epoch: Epoch) -> u8 {
    match epoch {
        Epoch::Initial => 0,
        Epoch::ZeroRtt => 1,
        Epoch::Handshake => 2,
        Epoch::OneRtt => 3,
    }
}

fn parse_stream_id(stream_id: u64) -> PyResult<StreamId> {
    StreamId::new(stream_id).ok_or_else(|| PyValueError::new_err("invalid QUIC stream ID"))
}

fn parse_aead(name: &str) -> PyResult<AeadAlgorithm> {
    match name {
        "aes-128-gcm" => Ok(AeadAlgorithm::Aes128Gcm),
        "aes-256-gcm" => Ok(AeadAlgorithm::Aes256Gcm),
        "chacha20-poly1305" => Ok(AeadAlgorithm::ChaCha20Poly1305),
        _ => Err(PyValueError::new_err("unsupported AEAD algorithm")),
    }
}

fn parse_hp(name: &str) -> PyResult<HeaderProtectionAlgorithm> {
    match name {
        "aes-128" | "aes-128-ecb" => Ok(HeaderProtectionAlgorithm::Aes128),
        "aes-256" | "aes-256-ecb" => Ok(HeaderProtectionAlgorithm::Aes256),
        "chacha20" => Ok(HeaderProtectionAlgorithm::ChaCha20),
        _ => Err(PyValueError::new_err(
            "unsupported header-protection algorithm",
        )),
    }
}

fn report_tuple(report: ReceiveReport) -> (usize, usize, usize, usize, usize, usize) {
    (
        report.datagrams,
        report.bytes,
        report.packets,
        report.duplicates,
        report.dropped,
        report.events_added,
    )
}

fn timer_name(kind: TimerKind) -> &'static str {
    match kind {
        TimerKind::Ack(PacketNumberSpace::Initial) => "ack_initial",
        TimerKind::Ack(PacketNumberSpace::Handshake) => "ack_handshake",
        TimerKind::Ack(PacketNumberSpace::ApplicationData) => "ack_application",
        TimerKind::LossDetection => "loss_detection",
        TimerKind::Pacing => "pacing",
        TimerKind::Idle => "idle",
        TimerKind::Close => "close",
        TimerKind::Pmtu => "pmtu",
    }
}

fn event_to_python(py: Python<'_>, event: ConnectionEvent) -> PyResult<Py<PyAny>> {
    macro_rules! object {
        ($value:expr) => {
            Ok($value.into_pyobject(py)?.unbind().into_any())
        };
    }
    match event {
        ConnectionEvent::CryptoData {
            epoch,
            offset,
            data,
        } => object!((
            "crypto_data",
            epoch_number(epoch),
            offset,
            PyBytes::new(py, &data)
        )),
        ConnectionEvent::StreamData {
            stream_id,
            data,
            fin,
        } => object!((
            "stream_data",
            stream_id.into_inner(),
            PyBytes::new(py, &data),
            fin
        )),
        ConnectionEvent::StreamReset {
            stream_id,
            error_code,
            final_size,
        } => object!((
            "stream_reset",
            stream_id.into_inner(),
            error_code,
            final_size
        )),
        ConnectionEvent::StreamFinished(stream_id) => {
            object!(("stream_finished", stream_id.into_inner()))
        }
        ConnectionEvent::StopSending {
            stream_id,
            error_code,
        } => object!(("stop_sending", stream_id.into_inner(), error_code)),
        ConnectionEvent::Datagram(data) => object!(("datagram", PyBytes::new(py, &data))),
        ConnectionEvent::PingAcknowledged(uid) => object!(("ping_acknowledged", uid)),
        ConnectionEvent::NewToken(data) => object!(("new_token", PyBytes::new(py, &data))),
        ConnectionEvent::HandshakeDone => object!(("handshake_done",)),
        ConnectionEvent::PeerMigration { path } => object!(("peer_migration", path.get())),
        ConnectionEvent::PathValidated(path) => object!(("path_validated", path.get())),
        ConnectionEvent::ConnectionIdIssued(connection_id) => {
            object!(("connection_id_issued", PyBytes::new(py, &connection_id)))
        }
        ConnectionEvent::ConnectionIdRetired(connection_id) => {
            object!(("connection_id_retired", PyBytes::new(py, &connection_id)))
        }
        ConnectionEvent::StreamsAvailable { direction, maximum } => object!((
            "streams_available",
            direction == StreamDirection::Unidirectional,
            maximum
        )),
        ConnectionEvent::ConnectionCredit(maximum) => {
            object!(("connection_credit", maximum))
        }
        ConnectionEvent::StreamCredit { stream_id, maximum } => {
            object!(("stream_credit", stream_id.into_inner(), maximum))
        }
        ConnectionEvent::PeerBlocked { stream_id, limit } => {
            object!(("peer_blocked", stream_id.map(StreamId::into_inner), limit))
        }
        ConnectionEvent::PeerClosed {
            application,
            error_code,
            frame_type,
            reason,
        } => object!((
            "peer_closed",
            application,
            error_code,
            frame_type,
            PyBytes::new(py, &reason)
        )),
        ConnectionEvent::VersionNegotiation(versions) => {
            object!(("version_negotiation", versions))
        }
        ConnectionEvent::Retry { token, source_cid } => object!((
            "retry",
            PyBytes::new(py, &token),
            PyBytes::new(py, &source_cid)
        )),
        ConnectionEvent::ProtocolError(error) => object!((
            "protocol_error",
            error.code.value(),
            error.frame_type.map(|frame| frame.value()),
            error.reason
        )),
        ConnectionEvent::ConnectionTerminated {
            error_code,
            frame_type,
            reason,
        } => object!((
            "connection_terminated",
            error_code,
            frame_type,
            PyBytes::new(py, &reason)
        )),
    }
}

fn transmit_to_python(py: Python<'_>, transmit: Transmit) -> PyResult<Py<PyAny>> {
    let destination = address_to_python(py, transmit.destination)?;
    let source = address_to_python(py, transmit.source)?;
    Ok((
        PyBytes::new(py, &transmit.bytes),
        destination,
        source,
        transmit.ecn,
        transmit.segment_size,
    )
        .into_pyobject(py)?
        .unbind()
        .into_any())
}

fn crypto_value_error(error: CryptoError) -> PyErr {
    PyValueError::new_err(error.to_string())
}

fn core_error(error: ConnectionCoreError) -> PyErr {
    match error {
        ConnectionCoreError::InvalidConfig(_)
        | ConnectionCoreError::DatagramTooLarge
        | ConnectionCoreError::InvalidGroSegmentSize
        | ConnectionCoreError::Crypto(CryptoError::InvalidKey)
        | ConnectionCoreError::Crypto(CryptoError::InvalidHeaderProtectionKey)
        | ConnectionCoreError::Crypto(CryptoError::InvalidIv)
        | ConnectionCoreError::Crypto(CryptoError::InvalidKeyPhase) => {
            PyValueError::new_err(error.to_string())
        }
        ConnectionCoreError::Stream(_) => PyValueError::new_err(error.to_string()),
        _ => PyRuntimeError::new_err(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_conversion_rejects_invalid_values() {
        assert!(duration_from_seconds(-1.0).is_err());
        assert!(duration_from_seconds(f64::NAN).is_err());
        assert_eq!(
            duration_from_seconds(1.25).unwrap(),
            Duration::from_millis(1250)
        );
    }

    #[test]
    fn facade_epoch_values_match_python_tls_epoch() {
        for value in 0..=3 {
            assert_eq!(epoch_number(parse_epoch(value).unwrap()), value);
        }
        assert!(parse_epoch(4).is_err());
    }
}
