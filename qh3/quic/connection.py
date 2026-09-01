from __future__ import annotations

import logging
import os
import socket
from collections import deque
from enum import IntEnum
from hmac import compare_digest
from typing import Any, Callable, TypeVar

from .. import tls
from .._hazmat import Buffer, QuicConnectionCore
from .._hazmat import Certificate as X509Certificate
from .._hazmat import pull_quic_header as _pull_quic_header
from . import events
from .configuration import QuicConfiguration
from .crypto import CIPHER_SUITES
from .logger import hexdump
from .packet import (
    QuicErrorCode,
    QuicPacketType,
    QuicTransportParameters,
    get_retry_integrity_tag,
    pull_quic_transport_parameters,
    stream_is_client_initiated,
    stream_is_unidirectional,
)
from .tls_bridge import QuicTlsBridge, QuicTlsBridgeError

logger = logging.getLogger("quic")
NetworkAddress = Any
_T = TypeVar("_T")

__all__ = [
    "NetworkAddress",
    "QuicConnection",
    "QuicConnectionError",
    "QuicConnectionState",
    "stream_is_client_initiated",
    "stream_is_unidirectional",
]


class QuicConnectionError(Exception):
    def __init__(self, error_code: int, frame_type: int | None, reason_phrase: str):
        self.error_code = error_code
        self.frame_type = frame_type
        self.reason_phrase = reason_phrase

    def __str__(self) -> str:
        message = f"Error: {self.error_code}, reason: {self.reason_phrase}"
        if self.frame_type is not None:
            message += f", frame_type: {self.frame_type}"
        return message


class QuicConnectionState(IntEnum):
    FIRSTFLIGHT = 0
    CONNECTED = 1
    CLOSING = 2
    DRAINING = 3
    TERMINATED = 4


class QuicConnection:
    """QUIC connection facade backed exclusively by the native packet core.

    Preferred addresses are parsed and validated by TLS but are not activated
    until path creation and CID installation can be performed atomically.
    """

    def __init__(
        self,
        *,
        configuration: QuicConfiguration,
        original_destination_connection_id: bytes | None = None,
        retry_source_connection_id: bytes | None = None,
        session_ticket_fetcher: tls.SessionTicketFetcher | None = None,
        session_ticket_handler: tls.SessionTicketHandler | None = None,
    ) -> None:
        if configuration.is_client:
            assert original_destination_connection_id is None, (
                "Cannot set original_destination_connection_id for a client"
            )
            assert retry_source_connection_id is None, (
                "Cannot set retry_source_connection_id for a client"
            )
        else:
            assert configuration.certificate is not None, (
                "SSL certificate is required for a server"
            )
            assert configuration.private_key is not None, (
                "SSL private key is required for a server"
            )
            assert original_destination_connection_id is not None, (
                "original_destination_connection_id is required for a server"
            )

        self._configuration = configuration
        self._is_client = configuration.is_client
        self._original_destination_connection_id = original_destination_connection_id
        self._retry_source_connection_id = retry_source_connection_id
        self._session_ticket_fetcher = session_ticket_fetcher
        self._session_ticket_handler = session_ticket_handler
        self._core: QuicConnectionCore | None = None
        self._tls: QuicTlsBridge | None = None
        self._events: deque[events.QuicEvent] = deque()
        self._remote_addr: NetworkAddress | None = None
        self._connect_called = False
        self._state = QuicConnectionState.FIRSTFLIGHT
        self._handshake_complete = False
        self._handshake_confirmed = False
        self._transport_parameters_applied = False
        self._applied_transport_parameters: QuicTransportParameters | None = None
        self._early_data_attempted = False
        self._zero_rtt_resolved = False
        self._retry_count = 0
        self._version_negotiated = False
        self._pre_handshake_streams: list[tuple[int, bool]] = []
        self._pre_handshake_writes: list[tuple[int, bytes, bool]] = []
        self._pre_handshake_state_replayed = False
        self._version: int | None = None
        self._quic_logger = None
        self._remote_max_datagram_frame_size: int | None = None
        self._peer_token = b""
        self._remote_max_stream_data_bidi_remote = 0
        self._close_event: events.ConnectionTerminated | None = None
        self.host_cid = os.urandom(configuration.connection_id_length)
        self._next_stream_id_bidi = 0 if self._is_client else 1
        self._next_stream_id_uni = 2 if self._is_client else 3
        self._local_next_stream_id_bidi = self._next_stream_id_bidi
        self._local_next_stream_id_uni = self._next_stream_id_uni
        self._created_local_stream_ids: set[int] = set()
        if self._is_client:
            self._original_destination_connection_id = os.urandom(
                configuration.connection_id_length
            )
        if configuration.quic_logger is not None:
            self._quic_logger = configuration.quic_logger.start_trace(
                is_client=self._is_client,
                odcid=self._original_destination_connection_id,
            )

    @property
    def configuration(self) -> QuicConfiguration:
        return self._configuration

    @property
    def original_destination_connection_id(self) -> bytes:
        return self._original_destination_connection_id

    @property
    def open_outbound_streams(self) -> int:
        """Return locally initiated streams not yet terminal in both directions."""
        if self._core is None:
            return 0
        active = self._core.active_local_streams
        return active[0] + active[1]

    @property
    def max_concurrent_bidi_streams(self) -> int:
        return 0 if self._core is None else self._core.stream_limits[0]

    @property
    def max_concurrent_uni_streams(self) -> int:
        return 0 if self._core is None else self._core.stream_limits[1]

    @property
    def ech_retry_configs(self) -> bytes | None:
        return None if self._tls is None else self._tls.ech_retry_configs

    @property
    def ech_accepted(self) -> bool:
        return self._tls is not None and self._tls.ech_accepted

    def get_cipher(self) -> tls.CipherSuite | None:
        return None if self._tls is None else self._tls.cipher_suite

    def get_peercert(self) -> X509Certificate | None:
        return None if self._tls is None else self._tls.peer_certificate

    def get_issuercerts(self) -> list[X509Certificate]:
        return [] if self._tls is None else self._tls.peer_certificate_chain

    @property
    def tls(self) -> tls.Context | None:
        return None if self._tls is None else self._tls.tls

    def connect(self, addr: NetworkAddress, now: float) -> None:
        assert self._is_client and not self._connect_called, (
            "connect() can only be called for clients and a single time"
        )
        self._connect_called = True
        self._remote_addr = self._normalize_address(addr)
        self._version = int(
            self._configuration.original_version
            or self._configuration.supported_versions[0]
        )
        self._create_core(self._remote_addr, self._original_destination_connection_id)
        self._create_tls(remote_source_cid=None)
        self._tls.start()
        self._drain_tls()

    def receive_datagram(self, data: bytes, addr: NetworkAddress, now: float) -> None:
        address = self._normalize_address(addr)
        self._log_datagram("datagrams_received", data)
        if self._core is None:
            if self._is_client:
                return
            if len(data) < 1200:
                return
            try:
                header = _pull_quic_header(
                    data, 0, self._configuration.connection_id_length
                )
            except ValueError:
                return
            if header[1] != int(QuicPacketType.INITIAL):
                return
            version, destination_cid = header[0], header[3]
            if version not in self._configuration.supported_versions:
                return
            self._remote_addr = address
            self._version = version
            self._create_core(address, destination_cid)
            self._create_tls(remote_source_cid=None)
        else:
            if self._receive_version_negotiation(data, address):
                return
            if self._receive_retry(data, address, now):
                return
        # TLS must consume Initial CRYPTO and install keys before a coalesced
        # Handshake packet from the same UDP datagram is processed.
        offset = 0
        while offset < len(data):
            try:
                packet_end = _pull_quic_header(
                    data, offset, self._configuration.connection_id_length
                )[9]
            except ValueError:
                packet_end = len(data)
            if packet_end <= offset:
                packet_end = len(data)
            report = self._call_core(
                self._core.receive_datagram,
                data[offset:packet_end],
                address,
                now,
                len(data),
            )
            if report[2]:
                self._log_packet(
                    "packet_received", data[offset:packet_end], packet_end - offset
                )
            elif report[4]:
                self._log_packet_dropped(data[offset:packet_end])
            if report[2]:
                self._learn_remote_source_cid(data[offset:packet_end])
            self._drain_core()
            offset = packet_end

    def receive_many_datagrams(
        self, datagrams: list[bytes], addr: NetworkAddress, now: float
    ) -> None:
        if self._core is None:
            if not datagrams:
                return
            self.receive_datagram(datagrams[0], addr, now)
            datagrams = datagrams[1:]
        if not datagrams:
            return
        if not self._handshake_complete:
            for data in datagrams:
                self.receive_datagram(data, addr, now)
            return
        address = self._normalize_address(addr)
        for data in datagrams:
            self._log_datagram("datagrams_received", data)
        self._call_core(self._core.receive_many_datagrams, datagrams, address, now)
        self._drain_core()

    def receive_gro_buffer(
        self, buffer: bytes, segment_size: int, addr: NetworkAddress, now: float
    ) -> None:
        if segment_size <= 0:
            raise ValueError("segment_size must be positive")
        if self._core is None:
            self.receive_many_datagrams(
                [
                    buffer[i : i + segment_size]
                    for i in range(0, len(buffer), segment_size)
                ],
                addr,
                now,
            )
            return
        if not self._handshake_complete:
            self.receive_many_datagrams(
                [
                    buffer[i : i + segment_size]
                    for i in range(0, len(buffer), segment_size)
                ],
                addr,
                now,
            )
            return
        address = self._normalize_address(addr)
        for offset in range(0, len(buffer), segment_size):
            self._log_datagram(
                "datagrams_received", buffer[offset : offset + segment_size]
            )
        self._call_core(
            self._core.receive_gro_buffer, buffer, segment_size, address, now
        )
        self._drain_core()

    def datagrams_to_send(self, now: float) -> list[tuple[bytes, NetworkAddress]]:
        if self._core is None:
            return []
        datagrams = []
        while True:
            transmit = self._call_core(self._core.poll_transmit, now)
            if transmit is None:
                break
            self._log_datagram("datagrams_sent", transmit[0])
            self._log_packets("packet_sent", transmit[0])
            datagrams.append((transmit[0], transmit[1]))
        return datagrams

    def get_timer(self) -> float | None:
        if self._core is None:
            return None
        timer = self._core.get_timer()
        return None if timer is None else timer[1]

    def handle_timer(self, now: float) -> None:
        if self._core is not None:
            self._call_core(self._core.handle_timer, now)
            self._drain_core()

    def should_wait_for_ack(self, now: float) -> bool:
        """Return whether the peer is expected to send an ACK soon.

        This is a flow-control scheduling heuristic. It returns ``True`` when
        at least two ACK-eliciting packets are outstanding, or when one has
        remained outstanding for the peer's negotiated maximum ACK delay.
        ``now`` must use the same clock as the other connection methods.
        """
        return self._core is not None and self._call_core(
            self._core.should_wait_for_ack, now
        )

    def next_event(self) -> events.QuicEvent | None:
        return self._events.popleft() if self._events else None

    def get_next_available_stream_id(self, is_unidirectional: bool = False) -> int:
        """Peek at the ID which the next send will create."""
        return (
            self._next_stream_id_uni if is_unidirectional else self._next_stream_id_bidi
        )

    def _open_stream(self, is_unidirectional: bool = False) -> int:
        stream_id = self.get_next_available_stream_id(is_unidirectional)
        self._record_local_stream(stream_id)
        if self._handshake_complete:
            core = self._require_core()
            native_stream_id = self._call_core(core.open_stream, is_unidirectional)
            if native_stream_id != stream_id:
                raise QuicConnectionError(
                    QuicErrorCode.INTERNAL_ERROR,
                    None,
                    "native stream allocation is out of sync",
                )
        return stream_id

    def send_stream_data(
        self, stream_id: int, data: bytes, end_stream: bool = False
    ) -> None:
        self._record_local_stream(stream_id)
        if not self._handshake_complete:
            self._pre_handshake_writes.append((stream_id, bytes(data), end_stream))
            if self._core is None or (
                not self._transport_parameters_applied
                and self._remembered_transport_parameters() is None
            ):
                return
            if not self._pre_handshake_state_replayed:
                self._replay_pre_handshake_state("connection start")
                return
        core = self._require_core()
        self._call_core(core.send_stream, stream_id, data, end_stream)

    def _stream_can_send(self, stream_id: int) -> bool:
        if self._core is None:
            return self._close_event is None
        return self._core.can_send_stream(stream_id)

    def reset_stream(self, stream_id: int, error_code: int) -> None:
        core = self._require_core()
        self._call_core(core.reset_stream, stream_id, error_code)
        self._record_local_stream(stream_id)

    def stop_stream(self, stream_id: int, error_code: int) -> None:
        core = self._require_core()
        self._call_core(core.stop_sending, stream_id, error_code)

    def send_datagram_frame(self, data: bytes) -> None:
        core = self._require_core()
        self._call_core(core.send_datagram, data)

    def send_ping(self, uid: int) -> None:
        core = self._require_core()
        self._call_core(core.send_ping, uid)

    def request_key_update(self) -> None:
        assert self._handshake_confirmed, (
            "cannot change key before handshake is confirmed"
        )
        core = self._require_core()
        self._call_core(core.request_key_update)

    def change_connection_id(self) -> None:
        core = self._require_core()
        self._call_core(core.change_connection_id)

    def close(
        self,
        error_code: int = QuicErrorCode.NO_ERROR,
        frame_type: int | None = None,
        reason_phrase: str = "",
    ) -> None:
        if self._core is not None and self._close_event is None:
            self._call_core(
                self._core.close,
                error_code,
                frame_type,
                reason_phrase.encode("utf8"),
            )
            self._close_event = events.ConnectionTerminated(
                error_code, frame_type, reason_phrase
            )

    def _create_core(self, remote_addr: NetworkAddress, initial_dcid: bytes) -> None:
        configuration = self._configuration
        remembered = self._remembered_transport_parameters()
        self._core = QuicConnectionCore(
            self._is_client,
            self._version,
            ("0.0.0.0", 0),
            remote_addr,
            self.host_cid,
            initial_dcid,
            self._is_client or self._retry_source_connection_id is not None,
            configuration.active_connection_id_limit or (2 if self._is_client else 8),
            configuration.max_datagram_size,
            configuration.probe_datagram_size,
            configuration.idle_timeout,
            3,
            (
                configuration.max_datagram_frame_size
                if configuration.max_datagram_frame_size is not None
                else (65536 if self._is_client else None)
            ),
            (remembered.max_datagram_frame_size if remembered is not None else None),
            configuration.max_data,
            (remembered.initial_max_data or 0) if remembered is not None else 0,
            configuration.max_stream_data,
            (
                remembered.initial_max_stream_data_bidi_local or 0
                if remembered is not None
                else 0
            ),
            (
                remembered.initial_max_stream_data_bidi_remote or 0
                if remembered is not None
                else 0
            ),
            (
                remembered.initial_max_stream_data_uni or 0
                if remembered is not None
                else 0
            ),
            configuration.max_stream_data,
            100,
            103,
            (remembered.initial_max_streams_bidi or 0 if remembered is not None else 0),
            (remembered.initial_max_streams_uni or 0 if remembered is not None else 0),
            configuration.initial_rtt,
            0.025,
        )
        self._applied_transport_parameters = None
        self._pre_handshake_state_replayed = False

    def _create_tls(self, remote_source_cid: bytes | None) -> QuicTlsBridge:
        tls_bridge = QuicTlsBridge(
            self._configuration,
            version=self._version,
            local_initial_source_connection_id=self.host_cid,
            remote_initial_source_connection_id=remote_source_cid,
            original_destination_connection_id=self._original_destination_connection_id,
            retry_source_connection_id=self._retry_source_connection_id,
            session_ticket_fetcher=self._session_ticket_fetcher,
            session_ticket_handler=self._session_ticket_handler,
            quic_logger=self._quic_logger,
            version_change_handler=self._set_version,
        )
        self._tls = tls_bridge
        return tls_bridge

    def _set_version(self, version: int) -> None:
        core = self._require_core()
        self._call_core(core.set_version, version)
        self._version = version

    def _receive_retry(self, data: bytes, address: NetworkAddress, now: float) -> bool:
        if not self._is_client:
            return False
        try:
            header = _pull_quic_header(
                data, 0, self._configuration.connection_id_length
            )
        except ValueError:
            return False
        if header[1] != int(QuicPacketType.RETRY):
            return False
        if (
            self._state is not QuicConnectionState.FIRSTFLIGHT
            or self._core.state != "first_flight"
        ):
            return True
        version, destination_cid, source_cid = header[0], header[3], header[4]
        token, integrity_tag, packet_end = header[5], header[6], header[9]
        if (
            self._retry_count
            or version != self._version
            or destination_cid != self.host_cid
            or packet_end != len(data)
            or not compare_digest(
                integrity_tag,
                get_retry_integrity_tag(
                    data[: packet_end - len(integrity_tag)],
                    self._original_destination_connection_id,
                    version=version,
                ),
            )
        ):
            return True

        self._retry_count = 1
        self._retry_source_connection_id = source_cid
        self._transport_parameters_applied = False
        self._core = None
        self._tls = None
        self._create_core(address, source_cid)
        self._require_core().set_initial_token(token)
        self._create_tls(remote_source_cid=None).start()
        self._drain_tls()
        return True

    def _receive_version_negotiation(
        self, data: bytes, address: NetworkAddress
    ) -> bool:
        if (
            not self._is_client
            or self._state is not QuicConnectionState.FIRSTFLIGHT
            or self._version_negotiated
        ):
            return False
        try:
            header = _pull_quic_header(
                data, 0, self._configuration.connection_id_length
            )
        except ValueError:
            return False
        if header[1] != int(QuicPacketType.VERSION_NEGOTIATION):
            return False

        expected_source_cid = (
            self._retry_source_connection_id or self._original_destination_connection_id
        )
        if (
            self._core.received_authenticated_packet
            or header[3] != self.host_cid
            or header[4] != expected_source_cid
            or header[9] != len(data)
        ):
            return True

        versions = header[7]
        if self._version in versions:
            return True
        version = next(
            (
                candidate
                for candidate in self._configuration.supported_versions
                if candidate in versions
            ),
            None,
        )
        if version is None:
            self._close_event = events.ConnectionTerminated(
                QuicErrorCode.INTERNAL_ERROR,
                None,
                "Could not find a common protocol version",
            )
            self._events.append(self._close_event)
            self._state = QuicConnectionState.TERMINATED
            self._end_trace()
            return True

        self._version = int(version)
        self._version_negotiated = True
        self._transport_parameters_applied = False
        self._core = None
        self._tls = None
        self._create_core(address, self._original_destination_connection_id)
        self._create_tls(remote_source_cid=None).start()
        self._drain_tls()
        return True

    def _drain_core(self) -> None:
        while True:
            native = self._core.next_event()
            if native is None:
                break
            kind = native[0]
            if kind == "crypto_data":
                try:
                    self._tls.receive_crypto(
                        tls.Epoch(native[1]),
                        native[3],
                        native[2],
                        version=self._core.version,
                    )
                    self._drain_tls()
                except QuicTlsBridgeError as exc:
                    self._call_core(
                        self._core.close,
                        exc.error_code,
                        int(exc.frame_type),
                        exc.reason_phrase.encode(),
                    )
                    self._close_event = events.ConnectionTerminated(
                        exc.error_code, exc.frame_type, exc.reason_phrase
                    )
            elif kind == "stream_data":
                self._events.append(
                    events.StreamDataReceived(native[2], native[3], native[1])
                )
            elif kind == "stream_reset":
                self._events.append(events.StreamReset(native[2], native[1]))
            elif kind == "stream_finished":
                self._created_local_stream_ids.discard(native[1])
            elif kind == "stop_sending":
                self._events.append(events.StopSendingReceived(native[2], native[1]))
            elif kind == "datagram":
                self._events.append(events.DatagramFrameReceived(native[1]))
            elif kind == "new_token":
                # QuicConfiguration has no token callback; retain the newest token
                # in the peer-token slot used for future Initial packets.
                self._peer_token = native[1]
            elif kind == "ping_acknowledged":
                self._events.append(events.PingAcknowledged(native[1]))
            elif kind == "handshake_done":
                self._handshake_confirmed = True
                self._core.handshake_confirmed()
            elif kind == "connection_id_issued":
                self._events.append(events.ConnectionIdIssued(native[1]))
            elif kind == "connection_id_retired":
                self._events.append(events.ConnectionIdRetired(native[1]))
            elif kind == "peer_closed":
                logger.warning("Native peer close: %r", native)
                self._close_event = events.ConnectionTerminated(
                    native[2], native[3], native[4].decode("utf8", "replace")
                )
            elif kind == "protocol_error":
                logger.warning("Native protocol error: %r", native)
                self._close_event = events.ConnectionTerminated(
                    native[1], native[2], native[3]
                )
            elif kind == "connection_terminated":
                self._state = QuicConnectionState.TERMINATED
                self._close_event = events.ConnectionTerminated(
                    native[1], native[2], native[3].decode("utf8", "replace")
                )
                self._events.append(self._close_event)
                if self._quic_logger is not None:
                    self._quic_logger.log_event(
                        category="connectivity",
                        event="connection_closed",
                        data={
                            "error_code": native[1],
                            "frame_type": native[2],
                            "reason": native[3].decode("utf8", "replace"),
                        },
                    )
                self._end_trace()

    def _drain_tls(self) -> None:
        core = self._require_core()
        assert self._tls is not None
        if core.version != self._tls.version:
            self._call_core(core.set_version, self._tls.version)
        self._version = self._tls.version
        while True:
            secret = self._tls.next_traffic_secret()
            if secret is None:
                break
            hp_name, aead_name = CIPHER_SUITES[secret.cipher_suite]
            direction = (
                "send" if secret.direction == tls.Direction.ENCRYPT else "receive"
            )
            self._call_core(
                core.install_packet_key,
                direction,
                int(secret.epoch),
                (aead_name.decode(), hp_name.decode()),
                secret.key,
                secret.iv,
                secret.hp,
                0,
                secret.secret,
                secret.version,
            )
            if secret.epoch == tls.Epoch.ZERO_RTT:
                self._early_data_attempted = True
        while True:
            crypto = self._tls.next_crypto_data()
            if crypto is None:
                break
            self._call_core(
                core.send_crypto, int(crypto.epoch), crypto.offset, crypto.data
            )
        if (
            not self._pre_handshake_state_replayed
            and self._remembered_transport_parameters() is not None
        ):
            self._replay_pre_handshake_state("early data")
        if (
            self._tls.remote_transport_parameters is not None
            and self._applied_transport_parameters
            is not self._tls.remote_transport_parameters
        ):
            parameters = self._tls.remote_transport_parameters
            if (
                self._is_client
                and self._early_data_attempted
                and not self._zero_rtt_resolved
            ):
                if not self._tls.tls.early_data_accepted:
                    self._call_core(core.reject_zero_rtt)
                self._zero_rtt_resolved = True
            self._remote_max_datagram_frame_size = parameters.max_datagram_frame_size
            self._remote_max_stream_data_bidi_remote = (
                parameters.initial_max_stream_data_bidi_remote or 0
            )
            # preferred_address intentionally stays inactive: the native core
            # cannot yet install its CID/reset token and path atomically.
            self._call_core(
                core.apply_peer_transport_parameters,
                parameters.initial_max_data or 0,
                parameters.initial_max_stream_data_bidi_local or 0,
                parameters.initial_max_stream_data_bidi_remote or 0,
                parameters.initial_max_stream_data_uni or 0,
                parameters.initial_max_streams_bidi or 0,
                parameters.initial_max_streams_uni or 0,
                (
                    3
                    if parameters.ack_delay_exponent is None
                    else parameters.ack_delay_exponent
                ),
                (
                    0.025
                    if parameters.max_ack_delay is None
                    else parameters.max_ack_delay / 1000
                ),
                (
                    None
                    if not parameters.max_idle_timeout
                    else parameters.max_idle_timeout / 1000
                ),
                parameters.max_datagram_frame_size,
                parameters.stateless_reset_token,
                parameters.active_connection_id_limit or 2,
                bool(parameters.disable_active_migration),
                parameters.max_udp_payload_size,
            )
            self._transport_parameters_applied = True
            self._replay_pre_handshake_state("transport parameters")
            self._applied_transport_parameters = parameters
        while True:
            event = self._tls.next_event()
            if event is None:
                break
            self._events.append(event)
        if self._tls.handshake_complete and not self._handshake_complete:
            self._handshake_complete = True
            self._pre_handshake_streams.clear()
            self._pre_handshake_writes.clear()
            self._pre_handshake_state_replayed = True
            self._state = QuicConnectionState.CONNECTED
            core.handshake_complete()
            if not self._is_client:
                self._handshake_confirmed = True
            elif not self._tls.tls.early_data_accepted:
                # Rejection is normally resolved when EncryptedExtensions
                # supplies fresh transport parameters. Keep this defensive for
                # handshakes which complete without attempting early data.
                if self._early_data_attempted and not self._zero_rtt_resolved:
                    self._call_core(core.reject_zero_rtt)
                    self._zero_rtt_resolved = True
                else:
                    core.discard_keys(int(tls.Epoch.ZERO_RTT))

    def _learn_remote_source_cid(self, data: bytes) -> None:
        if self._handshake_complete or self._tls is None:
            return
        try:
            header = _pull_quic_header(
                data, 0, self._configuration.connection_id_length
            )
        except ValueError:
            return
        if header[4]:
            self._tls.remote_initial_source_connection_id = header[4]

    def _require_core(self) -> QuicConnectionCore:
        if self._core is None:
            raise AssertionError("connection has not been started")
        return self._core

    def _call_core(self, operation: Callable[..., _T], *args: Any) -> _T:
        try:
            return operation(*args)
        except RuntimeError as exc:
            raise QuicConnectionError(
                QuicErrorCode.INTERNAL_ERROR, None, str(exc)
            ) from exc

    def _record_local_stream(self, stream_id: int) -> None:
        local_initiator = stream_id & 1 == (0 if self._is_client else 1)
        if not local_initiator or stream_id in self._created_local_stream_ids:
            return
        self._created_local_stream_ids.add(stream_id)
        is_unidirectional = bool(stream_id & 2)
        if not self._handshake_complete:
            self._pre_handshake_streams.append((stream_id, is_unidirectional))
        if is_unidirectional:
            self._next_stream_id_uni = max(self._next_stream_id_uni, stream_id + 4)
            self._local_next_stream_id_uni = self._next_stream_id_uni
        else:
            self._next_stream_id_bidi = max(self._next_stream_id_bidi, stream_id + 4)
            self._local_next_stream_id_bidi = self._next_stream_id_bidi

    def _reopen_pre_handshake_streams(self, context: str) -> None:
        for expected_stream_id, is_unidirectional in self._pre_handshake_streams:
            while True:
                stream_id = self._call_core(self._core.open_stream, is_unidirectional)
                if stream_id == expected_stream_id:
                    break
                if stream_id > expected_stream_id:
                    raise QuicConnectionError(
                        QuicErrorCode.INTERNAL_ERROR,
                        None,
                        f"native stream allocation changed across {context}",
                    )

    def _replay_pre_handshake_state(self, context: str) -> None:
        if self._pre_handshake_state_replayed or self._core is None:
            return
        self._reopen_pre_handshake_streams(context)
        for stream_id, data, end_stream in self._pre_handshake_writes:
            self._call_core(self._core.send_stream, stream_id, data, end_stream)
        self._pre_handshake_state_replayed = True

    def _remembered_transport_parameters(self) -> QuicTransportParameters | None:
        configuration = self._configuration
        ticket = configuration.session_ticket
        if (
            not self._is_client
            or ticket is None
            or not ticket.is_valid
            or ticket.server_name != configuration.server_name
            or ticket.max_early_data_size != 0xFFFFFFFF
        ):
            return None
        for extension_type, extension_data in ticket.other_extensions:
            if extension_type == tls.ExtensionType.QUIC_TRANSPORT_PARAMETERS:
                try:
                    return pull_quic_transport_parameters(Buffer(data=extension_data))
                except ValueError:
                    return None
        return None

    def _normalize_address(self, addr: NetworkAddress) -> NetworkAddress:
        socket.inet_pton(socket.AF_INET6 if ":" in addr[0] else socket.AF_INET, addr[0])
        return addr

    def _end_trace(self) -> None:
        quic_logger = self._quic_logger
        if quic_logger is not None:
            self._quic_logger = None
            self._configuration.quic_logger.end_trace(quic_logger)

    def _log_datagram(self, event: str, data: bytes) -> None:
        if self._quic_logger is not None:
            self._quic_logger.log_event(
                category="transport",
                event=event,
                data={
                    "count": 1,
                    "raw": [{"length": len(data) + 8, "payload_length": len(data)}],
                },
            )

    def _log_packet(self, event: str, data: bytes, length: int | None = None) -> None:
        if self._quic_logger is None:
            return
        try:
            header = _pull_quic_header(
                data, 0, self._configuration.connection_id_length
            )
            packet_type = QuicPacketType(header[1])
        except (ValueError, KeyError):
            return
        self._quic_logger.log_event(
            category="transport",
            event=event,
            data={
                "frames": [],
                "header": {
                    "packet_type": self._quic_logger.packet_type(packet_type),
                    "dcid": hexdump(header[3]),
                    "scid": hexdump(header[4]),
                },
                "raw": {"length": len(data) if length is None else length},
            },
        )

    def _log_packets(self, event: str, data: bytes) -> None:
        offset = 0
        while offset < len(data):
            try:
                packet_end = _pull_quic_header(
                    data, offset, self._configuration.connection_id_length
                )[9]
            except ValueError:
                break
            if packet_end <= offset:
                break
            self._log_packet(event, data[offset:packet_end], packet_end - offset)
            offset = packet_end

    def _log_packet_dropped(self, data: bytes) -> None:
        if self._quic_logger is not None:
            self._quic_logger.log_event(
                category="transport",
                event="packet_dropped",
                data={"trigger": "payload_decrypt_error", "raw": {"length": len(data)}},
            )
