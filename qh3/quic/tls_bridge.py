from __future__ import annotations

import logging
import os
from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

from .. import tls
from .._compat import DATACLASS_KWARGS
from .._hazmat import Buffer
from .._hazmat import Certificate as X509Certificate
from . import events
from .configuration import QuicConfiguration
from .crypto import derive_key_iv_hp
from .packet import (
    SMALLEST_MAX_DATAGRAM_SIZE,
    QuicErrorCode,
    QuicFrameType,
    QuicProtocolVersion,
    QuicTransportParameters,
    QuicVersionInformation,
    pull_quic_transport_parameters,
    push_quic_transport_parameters,
)

if TYPE_CHECKING:
    from .logger import QuicLoggerTrace

CRYPTO_BUFFER_SIZE = 16384
MAX_EARLY_DATA = 0xFFFFFFFF

_SECRETS_LABELS = [
    [
        None,
        "CLIENT_EARLY_TRAFFIC_SECRET",
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0",
    ],
    [None, None, "SERVER_HANDSHAKE_TRAFFIC_SECRET", "SERVER_TRAFFIC_SECRET_0"],
]


@dataclass(frozen=True, **DATACLASS_KWARGS)
class QuicTlsCryptoData:
    epoch: tls.Epoch
    offset: int
    data: bytes


@dataclass(frozen=True, **DATACLASS_KWARGS)
class QuicTlsTrafficSecret:
    direction: tls.Direction
    epoch: tls.Epoch
    cipher_suite: tls.CipherSuite
    version: int
    key: bytes
    iv: bytes
    hp: bytes
    secret: bytes


class QuicTlsBridgeError(Exception):
    def __init__(self, error_code: int, reason_phrase: str) -> None:
        self.error_code = error_code
        self.frame_type = QuicFrameType.CRYPTO
        self.reason_phrase = reason_phrase
        super().__init__(reason_phrase)

    def __str__(self) -> str:
        return (
            f"Error: {self.error_code}, reason: {self.reason_phrase}, "
            f"frame_type: {self.frame_type}"
        )


class QuicTlsBridge:
    """TLS half of QUIC for a transport which owns packet processing.

    Input passed to :meth:`receive_crypto` must already be contiguous within an
    encryption epoch. Output offsets are maintained independently for each epoch.
    """

    def __init__(
        self,
        configuration: QuicConfiguration,
        *,
        version: int,
        local_initial_source_connection_id: bytes,
        remote_initial_source_connection_id: bytes | None = None,
        original_destination_connection_id: bytes | None = None,
        retry_source_connection_id: bytes | None = None,
        stateless_reset_token: bytes | None = None,
        session_ticket_fetcher: tls.SessionTicketFetcher | None = None,
        session_ticket_handler: tls.SessionTicketHandler | None = None,
        logger: logging.Logger | logging.LoggerAdapter | None = None,
        quic_logger: QuicLoggerTrace | None = None,
        grease_quic_version: int | None = None,
        grease_transport_parameter: int | None = None,
        version_change_handler: Callable[[int], None] | None = None,
    ) -> None:
        if not configuration.is_client:
            assert configuration.certificate is not None, (
                "SSL certificate is required for a server"
            )
            assert configuration.private_key is not None, (
                "SSL private key is required for a server"
            )

        self.configuration = configuration
        self.version = version
        self.local_initial_source_connection_id = local_initial_source_connection_id
        self.remote_initial_source_connection_id = remote_initial_source_connection_id
        self.original_destination_connection_id = original_destination_connection_id
        self.retry_source_connection_id = retry_source_connection_id
        self.stateless_reset_token = (
            stateless_reset_token
            if stateless_reset_token is not None
            else (os.urandom(16) if not configuration.is_client else None)
        )
        self.grease_quic_version = (
            grease_quic_version
            if grease_quic_version is not None
            else ((int.from_bytes(os.urandom(1), "big") << 24) | 0x0A0A0A0A)
            & 0xFFFFFFFF
        )
        self.grease_transport_parameter = (
            grease_transport_parameter
            if grease_transport_parameter is not None
            else 31 * int.from_bytes(os.urandom(4), "big") + 27
        )
        self.remote_transport_parameters: QuicTransportParameters | None = None
        self.remembered_transport_parameters: QuicTransportParameters | None = None
        self._session_ticket_handler = session_ticket_handler
        self._version_change_handler = version_change_handler
        self._quic_logger = quic_logger
        self._events: deque[events.QuicEvent] = deque()
        self._outbound: deque[QuicTlsCryptoData] = deque()
        self._traffic_secrets: deque[QuicTlsTrafficSecret] = deque()
        self._input_offsets = {epoch: 0 for epoch in self._crypto_epochs()}
        self._output_offsets = {epoch: 0 for epoch in self._crypto_epochs()}
        self._handshake_complete = False

        self.tls = tls.Context(
            alpn_protocols=configuration.alpn_protocols,
            cadata=configuration.cadata,
            cafile=configuration.cafile,
            capath=configuration.capath,
            cipher_suites=configuration.cipher_suites,
            is_client=configuration.is_client,
            logger=logger,
            max_early_data=None if configuration.is_client else MAX_EARLY_DATA,
            server_name=configuration.server_name,
            verify_mode=configuration.verify_mode,
            hostname_checks_common_name=configuration.hostname_checks_common_name,
            assert_fingerprint=configuration.assert_fingerprint,
            verify_hostname=configuration.verify_hostname,
            ech_config_list=configuration.ech_config_list,
            signature_algorithms=configuration.signature_algorithms,
            offer_ec_key_shares=configuration.offer_ec_key_shares,
            offer_certificate_status_request=(
                configuration.offer_certificate_status_request
            ),
        )
        self._validate_certificate(configuration)
        self.tls.certificate = configuration.certificate
        self.tls.certificate_chain = configuration.certificate_chain
        self.tls.certificate_private_key = configuration.private_key
        self.tls.handshake_extensions = [
            (
                tls.ExtensionType.QUIC_TRANSPORT_PARAMETERS,
                self.serialize_transport_parameters(),
            )
        ]

        ticket = configuration.session_ticket
        if (
            configuration.is_client
            and ticket is not None
            and ticket.is_valid
            and ticket.server_name == configuration.server_name
        ):
            self.tls.session_ticket = ticket
            if ticket.max_early_data_size == MAX_EARLY_DATA:
                for extension_type, extension_data in ticket.other_extensions:
                    if extension_type == tls.ExtensionType.QUIC_TRANSPORT_PARAMETERS:
                        self.parse_transport_parameters(
                            extension_data, from_session_ticket=True
                        )
                        break

        self.tls.alpn_cb = self._on_alpn
        self.tls.get_session_ticket_cb = session_ticket_fetcher
        if session_ticket_handler is not None:
            self.tls.new_session_ticket_cb = self._on_session_ticket
        self.tls.update_traffic_key_cb = self._on_traffic_secret

    @staticmethod
    def _crypto_epochs() -> tuple[tls.Epoch, tls.Epoch, tls.Epoch]:
        return (tls.Epoch.INITIAL, tls.Epoch.HANDSHAKE, tls.Epoch.ONE_RTT)

    @property
    def handshake_complete(self) -> bool:
        return self._handshake_complete

    @property
    def ech_accepted(self) -> bool:
        return self.tls.ech_accepted

    @property
    def ech_retry_configs(self) -> bytes | None:
        return self.tls.ech_retry_configs

    @property
    def peer_certificate(self) -> X509Certificate | None:
        return self.tls.peer_certificate

    @property
    def peer_certificate_chain(self) -> list[X509Certificate]:
        return self.tls.peer_certificate_chain

    @property
    def cipher_suite(self) -> tls.CipherSuite | None:
        if self.tls.key_schedule is None:
            return None
        return self.tls.key_schedule.cipher_suite

    def start(self) -> None:
        """Generate the client's first TLS flight."""
        if not self.configuration.is_client:
            raise RuntimeError("only a client can start a TLS handshake")
        self._handle_tls(b"", tls.Epoch.INITIAL)

    def receive_crypto(
        self,
        epoch: tls.Epoch,
        data: bytes,
        offset: int | None = None,
        *,
        version: int | None = None,
    ) -> None:
        """Pass contiguous CRYPTO stream data from the transport to TLS."""
        if epoch not in self._input_offsets:
            raise ValueError(f"TLS CRYPTO is not valid at epoch {epoch!r}")
        expected = self._input_offsets[epoch]
        if offset is not None and offset != expected:
            raise ValueError(
                f"non-contiguous CRYPTO data for {epoch.name}: "
                f"expected offset {expected}, got {offset}"
            )
        if version is not None:
            self.version = version
        self._input_offsets[epoch] = expected + len(data)
        self._handle_tls(data, epoch)

    handle_crypto_data = receive_crypto

    def next_crypto_data(self) -> QuicTlsCryptoData | None:
        return self._outbound.popleft() if self._outbound else None

    def next_event(self) -> events.QuicEvent | None:
        return self._events.popleft() if self._events else None

    def next_traffic_secret(self) -> QuicTlsTrafficSecret | None:
        return self._traffic_secrets.popleft() if self._traffic_secrets else None

    def serialize_transport_parameters(self) -> bytes:
        configuration = self.configuration
        parameters = QuicTransportParameters(
            ack_delay_exponent=3,
            active_connection_id_limit=(
                configuration.active_connection_id_limit
                if configuration.active_connection_id_limit is not None
                else 8
            ),
            max_idle_timeout=int(configuration.idle_timeout * 1000),
            initial_max_data=configuration.max_data,
            initial_max_stream_data_bidi_local=configuration.max_stream_data,
            initial_max_stream_data_bidi_remote=configuration.max_stream_data,
            initial_max_stream_data_uni=configuration.max_stream_data,
            initial_max_streams_bidi=100,
            initial_max_streams_uni=103,
            initial_source_connection_id=self.local_initial_source_connection_id,
            max_ack_delay=25,
            max_datagram_frame_size=configuration.max_datagram_frame_size,
            quantum_readiness=(
                b"Q" * SMALLEST_MAX_DATAGRAM_SIZE
                if configuration.quantum_readiness_test
                else None
            ),
            stateless_reset_token=self.stateless_reset_token,
            version_information=QuicVersionInformation(
                chosen_version=self.version,
                available_versions=configuration.supported_versions,
            ),
        )
        if configuration.is_client:
            parameters.ack_delay_exponent = None
            parameters.max_ack_delay = None
            parameters.active_connection_id_limit = (
                configuration.active_connection_id_limit
            )
            parameters.stateless_reset_token = None
            parameters.max_udp_payload_size = 1472
            if configuration.max_datagram_frame_size is None:
                parameters.max_datagram_frame_size = 65536
            parameters.google_connection_options = b"ORIG"
            parameters.initial_rtt = int(configuration.initial_rtt * 1000000)
            parameters.greased_transport_parameter = (
                self.grease_transport_parameter,
                b"",
            )
            parameters.version_information.available_versions = [
                *configuration.supported_versions,
                self.grease_quic_version,
            ]
        else:
            parameters.original_destination_connection_id = (
                self.original_destination_connection_id
            )
            parameters.retry_source_connection_id = self.retry_source_connection_id

        if self._quic_logger is not None:
            self._quic_logger.log_event(
                category="transport",
                event="parameters_set",
                data=self._quic_logger.encode_transport_parameters(
                    owner="local", parameters=parameters
                ),
            )

        buf = Buffer(capacity=3 * configuration.max_datagram_size)
        push_quic_transport_parameters(buf, parameters)
        return buf.data

    def parse_transport_parameters(
        self, data: bytes, *, from_session_ticket: bool = False
    ) -> QuicTransportParameters:
        try:
            parameters = pull_quic_transport_parameters(Buffer(data=data))
        except ValueError as exc:
            raise self._transport_parameter_error(
                "Could not parse QUIC transport parameters"
            ) from exc

        if self._quic_logger is not None and not from_session_ticket:
            self._quic_logger.log_event(
                category="transport",
                event="parameters_set",
                data=self._quic_logger.encode_transport_parameters(
                    owner="remote", parameters=parameters
                ),
            )

        if not self.configuration.is_client:
            for name in (
                "original_destination_connection_id",
                "preferred_address",
                "retry_source_connection_id",
                "stateless_reset_token",
            ):
                if getattr(parameters, name) is not None:
                    raise self._transport_parameter_error(
                        f"{name} is not allowed for clients"
                    )

        if not from_session_ticket:
            if (
                parameters.initial_source_connection_id
                != self.remote_initial_source_connection_id
            ):
                raise self._transport_parameter_error(
                    "initial_source_connection_id does not match"
                )
            if self.configuration.is_client and (
                parameters.original_destination_connection_id
                != self.original_destination_connection_id
            ):
                raise self._transport_parameter_error(
                    "original_destination_connection_id does not match"
                )
            if self.configuration.is_client and (
                parameters.retry_source_connection_id != self.retry_source_connection_id
            ):
                raise self._transport_parameter_error(
                    "retry_source_connection_id does not match"
                )
            if (
                parameters.active_connection_id_limit is not None
                and parameters.active_connection_id_limit < 2
            ):
                raise self._transport_parameter_error(
                    "active_connection_id_limit must be no less than 2"
                )
            if (
                parameters.ack_delay_exponent is not None
                and parameters.ack_delay_exponent > 20
            ):
                raise self._transport_parameter_error(
                    "ack_delay_exponent must be <= 20"
                )
            if (
                parameters.max_ack_delay is not None
                and parameters.max_ack_delay >= 2**14
            ):
                raise self._transport_parameter_error("max_ack_delay must be < 2^14")
            if (
                parameters.max_udp_payload_size is not None
                and parameters.max_udp_payload_size < SMALLEST_MAX_DATAGRAM_SIZE
            ):
                raise self._transport_parameter_error(
                    f"max_udp_payload_size must be >= {SMALLEST_MAX_DATAGRAM_SIZE}"
                )
            if (
                parameters.stateless_reset_token is not None
                and len(parameters.stateless_reset_token) != 16
            ):
                raise self._transport_parameter_error(
                    "stateless_reset_token must be exactly 16 bytes"
                )
            for name in ("initial_max_streams_bidi", "initial_max_streams_uni"):
                value = getattr(parameters, name)
                if value is not None and value > 2**60:
                    raise self._transport_parameter_error(
                        f"{name} must not exceed 2^60"
                    )
            information = parameters.version_information
            if information is not None:
                if (
                    not self.configuration.is_client
                    and information.chosen_version not in information.available_versions
                ):
                    raise self._transport_parameter_error(
                        "version_information's chosen_version is not included in "
                        "available_versions"
                    )
                if information.chosen_version != self.version:
                    raise QuicTlsBridgeError(
                        QuicErrorCode.VERSION_NEGOTIATION_ERROR,
                        "version_information's chosen_version does not match the "
                        "version in use",
                    )

        if from_session_ticket:
            self.remembered_transport_parameters = parameters
        else:
            if self.tls.early_data_accepted:
                self._validate_early_transport_parameters(parameters)
            self.remote_transport_parameters = parameters
        return parameters

    def _validate_early_transport_parameters(
        self, parameters: QuicTransportParameters
    ) -> None:
        remembered = self.remembered_transport_parameters
        if remembered is None:
            return
        for name, default in (
            ("initial_max_data", 0),
            ("initial_max_stream_data_bidi_local", 0),
            ("initial_max_stream_data_bidi_remote", 0),
            ("initial_max_stream_data_uni", 0),
            ("initial_max_streams_bidi", 0),
            ("initial_max_streams_uni", 0),
            ("active_connection_id_limit", 2),
        ):
            old = getattr(remembered, name)
            new = getattr(parameters, name)
            if (default if new is None else new) < (default if old is None else old):
                raise self._transport_parameter_error(
                    f"{name} cannot decrease when accepting 0-RTT"
                )
        old_datagram = remembered.max_datagram_frame_size
        new_datagram = parameters.max_datagram_frame_size
        if old_datagram is not None and (
            new_datagram is None or new_datagram < old_datagram
        ):
            raise self._transport_parameter_error(
                "max_datagram_frame_size cannot decrease when accepting 0-RTT"
            )

    def _handle_tls(self, data: bytes, epoch: tls.Epoch) -> None:
        buffers = {
            item: Buffer(capacity=CRYPTO_BUFFER_SIZE) for item in self._crypto_epochs()
        }
        try:
            self.tls.handle_message(data, buffers, epoch=epoch)
        except tls.AlertECHRequired as exc:
            raise QuicTlsBridgeError(
                QuicErrorCode.CRYPTO_ERROR + int(exc.description), str(exc)
            ) from exc
        except tls.Alert as exc:
            raise QuicTlsBridgeError(
                QuicErrorCode.CRYPTO_ERROR + int(exc.description), str(exc)
            ) from exc
        for output_epoch, buf in buffers.items():
            output = buf.data
            if output:
                offset = self._output_offsets[output_epoch]
                self._outbound.append(QuicTlsCryptoData(output_epoch, offset, output))
                self._output_offsets[output_epoch] = offset + len(output)

        if not self._handshake_complete and self.tls.state in (
            tls.State.CLIENT_POST_HANDSHAKE,
            tls.State.SERVER_POST_HANDSHAKE,
        ):
            self._handshake_complete = True
            self._events.append(
                events.HandshakeCompleted(
                    alpn_protocol=self.tls.alpn_negotiated,
                    early_data_accepted=self.tls.early_data_accepted,
                    session_resumed=self.tls.session_resumed,
                )
            )

    def _on_alpn(self, alpn_protocol: str | None) -> None:
        for extension_type, extension_data in self.tls.received_extensions:
            if extension_type == tls.ExtensionType.QUIC_TRANSPORT_PARAMETERS:
                self.parse_transport_parameters(extension_data)
                break
        else:
            raise QuicTlsBridgeError(
                QuicErrorCode.CRYPTO_ERROR + tls.AlertDescription.missing_extension,
                "No QUIC transport parameters received",
            )

        information = self.remote_transport_parameters.version_information
        if not self.configuration.is_client and information is not None:
            for candidate in information.available_versions:
                if candidate == self.version:
                    break
                if candidate in self.configuration.supported_versions and {
                    candidate,
                    self.version,
                } == {
                    QuicProtocolVersion.VERSION_1,
                    QuicProtocolVersion.VERSION_2,
                }:
                    self.version = candidate
                    if self._version_change_handler is not None:
                        self._version_change_handler(candidate)
                    self.tls.handshake_extensions = [
                        (
                            tls.ExtensionType.QUIC_TRANSPORT_PARAMETERS,
                            self.serialize_transport_parameters(),
                        )
                    ]
                    break
        self._events.append(events.ProtocolNegotiated(alpn_protocol=alpn_protocol))

    def _on_traffic_secret(
        self,
        direction: tls.Direction,
        epoch: tls.Epoch,
        cipher_suite: tls.CipherSuite,
        secret: bytes,
    ) -> None:
        key, iv, hp = derive_key_iv_hp(
            cipher_suite=cipher_suite, secret=secret, version=self.version
        )
        self._traffic_secrets.append(
            QuicTlsTrafficSecret(
                direction=direction,
                epoch=epoch,
                cipher_suite=cipher_suite,
                version=self.version,
                key=key,
                iv=iv,
                hp=hp,
                secret=secret,
            )
        )
        if self._quic_logger is not None:
            epoch_name = ["initial", "0rtt", "handshake", "1rtt"][epoch.value]
            local_secret = direction == tls.Direction.ENCRYPT
            owner = (
                "client" if local_secret == self.configuration.is_client else "server"
            )
            self._quic_logger.log_event(
                category="security",
                event="key_updated",
                data={
                    "key_type": f"{owner}_{epoch_name}_secret",
                    "trigger": "tls",
                },
            )
        secrets_log_file = self.configuration.secrets_log_file
        if secrets_log_file is not None:
            row = self.configuration.is_client == (direction == tls.Direction.DECRYPT)
            label = _SECRETS_LABELS[row][epoch.value]
            secrets_log_file.write(
                f"{label} {self.tls.client_random.hex()} {secret.hex()}\n"
            )
            secrets_log_file.flush()

    def _on_session_ticket(self, ticket: tls.SessionTicket) -> None:
        if (
            ticket.max_early_data_size is not None
            and ticket.max_early_data_size != MAX_EARLY_DATA
        ):
            raise QuicTlsBridgeError(
                QuicErrorCode.PROTOCOL_VIOLATION,
                f"Invalid max_early_data value {ticket.max_early_data_size}",
            )
        self._session_ticket_handler(ticket)

    @staticmethod
    def _validate_certificate(configuration: QuicConfiguration) -> None:
        if configuration.certificate is not None and not isinstance(
            configuration.certificate, X509Certificate
        ):
            raise RuntimeError(
                "qh3 v1.0+ no longer support passing cryptography certificate "
                "objects within a QuicConfiguration object. Use "
                "configuration.load_cert_chain(...) instead using PEM encoded values."
            )
        if configuration.certificate_chain and not isinstance(
            configuration.certificate_chain[0], X509Certificate
        ):
            raise RuntimeError(
                "qh3 v1.0+ no longer support passing cryptography certificate "
                "objects within a QuicConfiguration object. Use "
                "configuration.load_cert_chain(...) instead using PEM encoded values."
            )
        if configuration.private_key and "cryptography" in str(
            type(configuration.private_key)
        ):
            raise RuntimeError(
                "qh3 v1.0+ no longer support passing cryptography private key "
                "objects within a QuicConfiguration object. Use "
                "configuration.load_cert_chain(...) instead using PEM encoded values."
            )

    def _transport_parameter_error(self, reason: str) -> QuicTlsBridgeError:
        return QuicTlsBridgeError(QuicErrorCode.TRANSPORT_PARAMETER_ERROR, reason)
