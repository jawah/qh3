from __future__ import annotations

import io
from types import SimpleNamespace

import pytest

from qh3 import tls
from qh3._hazmat import Buffer
from qh3.quic import events
from qh3.quic.configuration import QuicConfiguration
from qh3.quic.crypto import derive_key_iv_hp
from qh3.quic.packet import (
    QuicErrorCode,
    QuicProtocolVersion,
    QuicTransportParameters,
    QuicVersionInformation,
    pull_quic_transport_parameters,
    push_quic_transport_parameters,
)
from qh3.quic.tls_bridge import QuicTlsBridge, QuicTlsBridgeError

from .utils import SERVER_CACERTFILE, SERVER_CERTFILE, SERVER_KEYFILE


def make_client_configuration() -> QuicConfiguration:
    configuration = QuicConfiguration(
        alpn_protocols=["h3"], is_client=True, server_name="localhost"
    )
    configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
    return configuration


def make_server_configuration() -> QuicConfiguration:
    configuration = QuicConfiguration(alpn_protocols=["h3"], is_client=False)
    configuration.load_cert_chain(SERVER_CERTFILE, SERVER_KEYFILE)
    return configuration


def drain_crypto(source: QuicTlsBridge, destination: QuicTlsBridge) -> int:
    count = 0
    while True:
        item = source.next_crypto_data()
        if item is None:
            return count
        destination.receive_crypto(item.epoch, item.data, item.offset)
        count += 1


def encode_transport_parameters(parameters: QuicTransportParameters) -> bytes:
    buf = Buffer(capacity=1024)
    push_quic_transport_parameters(buf, parameters)
    return buf.data


def make_validation_bridge(*, is_client: bool = True) -> QuicTlsBridge:
    configuration = (
        make_client_configuration() if is_client else make_server_configuration()
    )
    return QuicTlsBridge(
        configuration,
        version=QuicProtocolVersion.VERSION_1,
        local_initial_source_connection_id=b"local",
        remote_initial_source_connection_id=b"remote",
        original_destination_connection_id=b"odcid",
        retry_source_connection_id=b"retry" if is_client else None,
    )


def test_tls_bridge_constructor_getters_and_start_validation() -> None:
    configuration = make_client_configuration()
    bridge = QuicTlsBridge(
        configuration,
        version=QuicProtocolVersion.VERSION_1,
        local_initial_source_connection_id=b"client",
    )
    assert not bridge.handshake_complete
    assert bridge.cipher_suite is None
    assert bridge.peer_certificate is None
    assert bridge.peer_certificate_chain == []
    assert bridge.ech_accepted is False
    assert bridge.ech_retry_configs is None
    assert bridge.next_crypto_data() is None
    assert bridge.next_event() is None
    assert bridge.next_traffic_secret() is None
    assert "frame_type: 6" in str(QuicTlsBridgeError(1, "bad"))

    server_configuration = QuicConfiguration(is_client=False)
    with pytest.raises(AssertionError, match="SSL certificate"):
        QuicTlsBridge(
            server_configuration,
            version=QuicProtocolVersion.VERSION_1,
            local_initial_source_connection_id=b"server",
        )
    server_configuration.load_cert_chain(SERVER_CERTFILE, SERVER_KEYFILE)
    server = QuicTlsBridge(
        server_configuration,
        version=QuicProtocolVersion.VERSION_1,
        local_initial_source_connection_id=b"server",
    )
    assert len(server.stateless_reset_token) == 16
    with pytest.raises(RuntimeError, match="only a client"):
        server.start()


def test_tls_bridge_crypto_input_validation_and_version_update() -> None:
    bridge = make_validation_bridge()
    with pytest.raises(ValueError, match="not valid"):
        bridge.receive_crypto(tls.Epoch.ZERO_RTT, b"early")

    def accept_empty(data, buffers, *, epoch):
        assert data == b""
        assert epoch == tls.Epoch.INITIAL

    bridge.tls.handle_message = accept_empty
    bridge.receive_crypto(
        tls.Epoch.INITIAL,
        b"",
        version=QuicProtocolVersion.VERSION_2,
    )
    assert bridge.version == QuicProtocolVersion.VERSION_2


def test_tls_bridge_wraps_tls_alerts(monkeypatch) -> None:
    bridge = make_validation_bridge()

    def raise_alert(*args, **kwargs):
        raise tls.AlertDecodeError("malformed handshake")

    monkeypatch.setattr(bridge.tls, "handle_message", raise_alert)
    with pytest.raises(QuicTlsBridgeError) as caught:
        bridge.receive_crypto(tls.Epoch.INITIAL, b"bad")
    assert caught.value.error_code == (
        QuicErrorCode.CRYPTO_ERROR + tls.AlertDescription.decode_error
    )
    assert caught.value.reason_phrase == "malformed handshake"

    def raise_ech(*args, **kwargs):
        raise tls.AlertECHRequired("retry ECH")

    monkeypatch.setattr(bridge.tls, "handle_message", raise_ech)
    with pytest.raises(QuicTlsBridgeError) as caught:
        bridge.receive_crypto(tls.Epoch.HANDSHAKE, b"bad")
    assert caught.value.error_code == (
        QuicErrorCode.CRYPTO_ERROR + tls.AlertDescription.ech_required
    )


def test_tls_bridge_rejects_malformed_and_client_only_parameters() -> None:
    bridge = make_validation_bridge()
    with pytest.raises(
        QuicTlsBridgeError, match="Could not parse QUIC transport parameters"
    ):
        bridge.parse_transport_parameters(b"\xff")

    server = make_validation_bridge(is_client=False)
    parameters = QuicTransportParameters(
        initial_source_connection_id=b"remote",
        original_destination_connection_id=b"not-allowed",
    )
    with pytest.raises(QuicTlsBridgeError, match="not allowed for clients"):
        server.parse_transport_parameters(encode_transport_parameters(parameters))


@pytest.mark.parametrize(
    ("parameters", "message"),
    [
        (
            QuicTransportParameters(initial_source_connection_id=b"wrong"),
            "initial_source_connection_id does not match",
        ),
        (
            QuicTransportParameters(
                initial_source_connection_id=b"remote",
                original_destination_connection_id=b"wrong",
                retry_source_connection_id=b"retry",
            ),
            "original_destination_connection_id does not match",
        ),
        (
            QuicTransportParameters(
                initial_source_connection_id=b"remote",
                original_destination_connection_id=b"odcid",
                retry_source_connection_id=b"wrong",
            ),
            "retry_source_connection_id does not match",
        ),
        (
            QuicTransportParameters(
                initial_source_connection_id=b"remote",
                original_destination_connection_id=b"odcid",
                retry_source_connection_id=b"retry",
                ack_delay_exponent=21,
            ),
            "ack_delay_exponent must be <= 20",
        ),
        (
            QuicTransportParameters(
                initial_source_connection_id=b"remote",
                original_destination_connection_id=b"odcid",
                retry_source_connection_id=b"retry",
                max_ack_delay=2**14,
            ),
            "max_ack_delay must be < 2^14",
        ),
        (
            QuicTransportParameters(
                initial_source_connection_id=b"remote",
                original_destination_connection_id=b"odcid",
                retry_source_connection_id=b"retry",
                max_udp_payload_size=1199,
            ),
            "max_udp_payload_size must be >= 1200",
        ),
        (
            QuicTransportParameters(
                initial_source_connection_id=b"remote",
                original_destination_connection_id=b"odcid",
                retry_source_connection_id=b"retry",
                stateless_reset_token=b"short",
            ),
            "stateless_reset_token must be exactly 16 bytes",
        ),
        (
            QuicTransportParameters(
                initial_source_connection_id=b"remote",
                original_destination_connection_id=b"odcid",
                retry_source_connection_id=b"retry",
                initial_max_streams_bidi=2**60 + 1,
            ),
            "initial_max_streams_bidi must not exceed 2^60",
        ),
        (
            QuicTransportParameters(
                initial_source_connection_id=b"remote",
                original_destination_connection_id=b"odcid",
                retry_source_connection_id=b"retry",
                initial_max_streams_uni=2**60 + 1,
            ),
            "initial_max_streams_uni must not exceed 2^60",
        ),
    ],
)
def test_tls_bridge_transport_parameter_checks(parameters, message) -> None:
    bridge = make_validation_bridge()
    with pytest.raises(QuicTlsBridgeError) as caught:
        bridge.parse_transport_parameters(encode_transport_parameters(parameters))
    assert caught.value.reason_phrase == message


def test_tls_bridge_version_information_checks() -> None:
    server = make_validation_bridge(is_client=False)
    parameters = QuicTransportParameters(
        initial_source_connection_id=b"remote",
        version_information=SimpleNamespace(
            chosen_version=QuicProtocolVersion.VERSION_1,
            available_versions=[QuicProtocolVersion.VERSION_2],
        ),
    )
    with pytest.raises(QuicTlsBridgeError, match="not included"):
        server.parse_transport_parameters(encode_transport_parameters(parameters))

    parameters.version_information.chosen_version = QuicProtocolVersion.VERSION_2
    with pytest.raises(QuicTlsBridgeError) as caught:
        server.parse_transport_parameters(encode_transport_parameters(parameters))
    assert caught.value.error_code == QuicErrorCode.VERSION_NEGOTIATION_ERROR


def test_tls_bridge_accepts_parameters_without_version_information() -> None:
    bridge = make_validation_bridge()
    parameters = QuicTransportParameters(
        initial_source_connection_id=b"remote",
        original_destination_connection_id=b"odcid",
        retry_source_connection_id=b"retry",
    )
    assert bridge.parse_transport_parameters(
        encode_transport_parameters(parameters)
    ).version_information is None


def test_tls_bridge_server_selects_compatible_version() -> None:
    bridge = make_validation_bridge(is_client=False)
    bridge.configuration.supported_versions = [
        QuicProtocolVersion.VERSION_1,
        QuicProtocolVersion.VERSION_2,
    ]
    parameters = QuicTransportParameters(
        initial_source_connection_id=b"remote",
        version_information=SimpleNamespace(
            chosen_version=QuicProtocolVersion.VERSION_1,
            available_versions=[
                QuicProtocolVersion.VERSION_2,
                QuicProtocolVersion.VERSION_1,
            ],
        ),
    )
    bridge.tls.received_extensions = [
        (
            tls.ExtensionType.QUIC_TRANSPORT_PARAMETERS,
            encode_transport_parameters(parameters),
        )
    ]
    bridge._on_alpn("h3")
    assert bridge.version == QuicProtocolVersion.VERSION_2
    advertised = pull_quic_transport_parameters(
        Buffer(data=bridge.tls.handshake_extensions[0][1])
    )
    assert advertised.version_information.chosen_version == QuicProtocolVersion.VERSION_2
    bridge._on_traffic_secret(
        tls.Direction.ENCRYPT,
        tls.Epoch.HANDSHAKE,
        tls.CipherSuite.AES_128_GCM_SHA256,
        b"s" * 32,
    )
    assert bridge.next_traffic_secret().version == QuicProtocolVersion.VERSION_2
    assert bridge.next_event() == events.ProtocolNegotiated("h3")


@pytest.mark.parametrize(
    "name",
    [
        "initial_max_data",
        "initial_max_stream_data_bidi_local",
        "initial_max_stream_data_bidi_remote",
        "initial_max_stream_data_uni",
        "initial_max_streams_bidi",
        "initial_max_streams_uni",
        "active_connection_id_limit",
    ],
)
def test_tls_bridge_rejects_decreased_early_limits(name) -> None:
    bridge = make_validation_bridge()
    remembered = QuicTransportParameters()
    current = QuicTransportParameters()
    setattr(remembered, name, 3)
    setattr(current, name, 2)
    bridge.remembered_transport_parameters = remembered
    with pytest.raises(QuicTlsBridgeError, match=f"{name} cannot decrease"):
        bridge._validate_early_transport_parameters(current)


def test_tls_bridge_early_datagram_and_alpn_errors() -> None:
    bridge = make_validation_bridge()
    bridge.remembered_transport_parameters = QuicTransportParameters(
        max_datagram_frame_size=100
    )
    with pytest.raises(QuicTlsBridgeError, match="max_datagram_frame_size"):
        bridge._validate_early_transport_parameters(QuicTransportParameters())

    bridge.remembered_transport_parameters = None
    bridge._validate_early_transport_parameters(QuicTransportParameters())
    bridge.tls.received_extensions = []
    with pytest.raises(QuicTlsBridgeError, match="No QUIC transport parameters"):
        bridge._on_alpn("h3")


def test_tls_bridge_secret_log_and_invalid_session_ticket() -> None:
    output = io.StringIO()
    configuration = make_client_configuration()
    configuration.secrets_log_file = output
    tickets = []
    bridge = QuicTlsBridge(
        configuration,
        version=QuicProtocolVersion.VERSION_1,
        local_initial_source_connection_id=b"client",
        session_ticket_handler=tickets.append,
    )
    bridge.tls.client_random = b"r" * 32
    bridge._on_traffic_secret(
        tls.Direction.ENCRYPT,
        tls.Epoch.HANDSHAKE,
        tls.CipherSuite.AES_128_GCM_SHA256,
        b"s" * 32,
    )
    assert "CLIENT_HANDSHAKE_TRAFFIC_SECRET" in output.getvalue()

    invalid = SimpleNamespace(max_early_data_size=1)
    with pytest.raises(QuicTlsBridgeError, match="Invalid max_early_data"):
        bridge._on_session_ticket(invalid)
    valid = SimpleNamespace(max_early_data_size=None)
    bridge._on_session_ticket(valid)
    assert tickets == [valid]


@pytest.mark.parametrize("field", ["certificate", "certificate_chain", "private_key"])
def test_tls_bridge_rejects_legacy_cryptography_objects(field) -> None:
    configuration = make_client_configuration()
    if field == "certificate_chain":
        configuration.certificate_chain = [object()]
    elif field == "private_key":
        CryptographyKey = type("CryptographyKey", (), {})
        CryptographyKey.__module__ = "cryptography.hazmat"
        configuration.private_key = CryptographyKey()
    else:
        configuration.certificate = object()
    with pytest.raises(RuntimeError, match="no longer support"):
        QuicTlsBridge(
            configuration,
            version=QuicProtocolVersion.VERSION_1,
            local_initial_source_connection_id=b"client",
        )


def test_client_transport_parameters() -> None:
    configuration = make_client_configuration()
    bridge = QuicTlsBridge(
        configuration,
        version=QuicProtocolVersion.VERSION_1,
        local_initial_source_connection_id=b"client-cid",
        original_destination_connection_id=b"original-cid",
        grease_quic_version=0x1A2A3A4A,
        grease_transport_parameter=0x1F * 100 + 27,
    )

    parameters = pull_quic_transport_parameters(
        Buffer(data=bridge.serialize_transport_parameters())
    )
    assert parameters.initial_source_connection_id == b"client-cid"
    assert parameters.initial_max_data == configuration.max_data
    assert (
        parameters.initial_max_stream_data_bidi_local == configuration.max_stream_data
    )
    assert (
        parameters.initial_max_stream_data_bidi_remote == configuration.max_stream_data
    )
    assert parameters.initial_max_stream_data_uni == configuration.max_stream_data
    assert parameters.initial_max_streams_bidi == 100
    assert parameters.initial_max_streams_uni == 103
    assert parameters.max_udp_payload_size == 1472
    assert parameters.max_datagram_frame_size == 65536
    assert bridge.tls.certificate is configuration.certificate
    assert bridge.tls.certificate_chain is configuration.certificate_chain
    assert bridge.tls.certificate_private_key is configuration.private_key


def test_transport_parameter_validation_matches_connection() -> None:
    bridge = QuicTlsBridge(
        make_client_configuration(),
        version=QuicProtocolVersion.VERSION_1,
        local_initial_source_connection_id=b"client",
        remote_initial_source_connection_id=b"server",
        original_destination_connection_id=b"odcid",
    )
    buf = Buffer(capacity=256)
    push_quic_transport_parameters(
        buf,
        QuicTransportParameters(
            initial_source_connection_id=b"server",
            original_destination_connection_id=b"odcid",
            active_connection_id_limit=1,
        ),
    )

    with pytest.raises(QuicTlsBridgeError) as caught:
        bridge.parse_transport_parameters(buf.data)
    assert caught.value.error_code == QuicErrorCode.TRANSPORT_PARAMETER_ERROR
    assert caught.value.reason_phrase == (
        "active_connection_id_limit must be no less than 2"
    )


@pytest.mark.parametrize(
    ("parameter", "value", "reason"),
    [
        (
            "active_connection_id_limit",
            0,
            "active_connection_id_limit must be no less than 2",
        ),
        ("ack_delay_exponent", 21, "ack_delay_exponent must be <= 20"),
        ("max_ack_delay", 2**14, "max_ack_delay must be < 2^14"),
        ("max_udp_payload_size", 1199, "max_udp_payload_size must be >= 1200"),
        (
            "initial_source_connection_id",
            b"wrong-server",
            "initial_source_connection_id does not match",
        ),
    ],
)
def test_transport_parameter_validation_rejects_historical_invalid_values(
    parameter: str, value, reason: str
) -> None:
    bridge = QuicTlsBridge(
        make_client_configuration(),
        version=QuicProtocolVersion.VERSION_1,
        local_initial_source_connection_id=b"client",
        remote_initial_source_connection_id=b"server",
        original_destination_connection_id=b"odcid",
    )
    parameters = QuicTransportParameters(
        initial_source_connection_id=b"server",
        original_destination_connection_id=b"odcid",
    )
    setattr(parameters, parameter, value)
    buf = Buffer(capacity=256)
    push_quic_transport_parameters(buf, parameters)

    with pytest.raises(QuicTlsBridgeError) as caught:
        bridge.parse_transport_parameters(buf.data)
    assert caught.value.error_code == QuicErrorCode.TRANSPORT_PARAMETER_ERROR
    assert caught.value.reason_phrase == reason


def test_transport_parameter_validation_rejects_malformed_encoding() -> None:
    bridge = QuicTlsBridge(
        make_client_configuration(),
        version=QuicProtocolVersion.VERSION_1,
        local_initial_source_connection_id=b"client",
    )

    with pytest.raises(QuicTlsBridgeError) as caught:
        bridge.parse_transport_parameters(b"0")
    assert caught.value.error_code == QuicErrorCode.TRANSPORT_PARAMETER_ERROR
    assert caught.value.reason_phrase == "Could not parse QUIC transport parameters"


def test_server_rejects_inconsistent_version_information() -> None:
    bridge = QuicTlsBridge(
        make_server_configuration(),
        version=QuicProtocolVersion.VERSION_1,
        local_initial_source_connection_id=b"server",
        remote_initial_source_connection_id=b"client",
    )
    buf = Buffer(capacity=256)
    push_quic_transport_parameters(
        buf,
        QuicTransportParameters(
            initial_source_connection_id=b"client",
            version_information=QuicVersionInformation(
                chosen_version=QuicProtocolVersion.VERSION_1,
                available_versions=[QuicProtocolVersion.VERSION_2],
            ),
        ),
    )

    with pytest.raises(QuicTlsBridgeError) as caught:
        bridge.parse_transport_parameters(buf.data)
    assert caught.value.error_code == QuicErrorCode.TRANSPORT_PARAMETER_ERROR
    assert caught.value.reason_phrase == (
        "version_information's chosen_version is not included in available_versions"
    )


def test_tls_handshake_outputs_events_and_derived_secrets() -> None:
    client_cid = b"client01"
    server_cid = b"server01"
    original_destination_cid = b"original"
    client = QuicTlsBridge(
        make_client_configuration(),
        version=QuicProtocolVersion.VERSION_1,
        local_initial_source_connection_id=client_cid,
        remote_initial_source_connection_id=server_cid,
        original_destination_connection_id=original_destination_cid,
        grease_quic_version=0x1A2A3A4A,
        grease_transport_parameter=31 * 7 + 27,
    )
    server = QuicTlsBridge(
        make_server_configuration(),
        version=QuicProtocolVersion.VERSION_1,
        local_initial_source_connection_id=server_cid,
        remote_initial_source_connection_id=client_cid,
        original_destination_connection_id=original_destination_cid,
        stateless_reset_token=bytes(16),
    )

    client.start()
    assert drain_crypto(client, server) == 1
    assert drain_crypto(server, client) == 2
    assert drain_crypto(client, server) == 1
    drain_crypto(server, client)

    assert client.handshake_complete
    assert server.handshake_complete
    for bridge in (client, server):
        protocol_event = bridge.next_event()
        handshake_event = bridge.next_event()
        assert protocol_event == events.ProtocolNegotiated(alpn_protocol="h3")
        assert handshake_event == events.HandshakeCompleted(
            alpn_protocol="h3",
            early_data_accepted=False,
            session_resumed=False,
        )
        assert bridge.next_event() is None
        assert bridge.remote_transport_parameters is not None

        secrets = []
        while True:
            secret = bridge.next_traffic_secret()
            if secret is None:
                break
            secrets.append(secret)
        assert {secret.epoch for secret in secrets} >= {
            tls.Epoch.HANDSHAKE,
            tls.Epoch.ONE_RTT,
        }
        for secret in secrets:
            assert len(secret.iv) == 12
            assert secret.version == QuicProtocolVersion.VERSION_1


def test_traffic_secret_record_uses_existing_derivation() -> None:
    bridge = QuicTlsBridge(
        make_client_configuration(),
        version=QuicProtocolVersion.VERSION_2,
        local_initial_source_connection_id=b"client",
    )
    secret = bytes(range(32))
    bridge._on_traffic_secret(
        tls.Direction.ENCRYPT,
        tls.Epoch.HANDSHAKE,
        tls.CipherSuite.AES_128_GCM_SHA256,
        secret,
    )
    record = bridge.next_traffic_secret()
    key, iv, hp = derive_key_iv_hp(
        cipher_suite=tls.CipherSuite.AES_128_GCM_SHA256,
        secret=secret,
        version=QuicProtocolVersion.VERSION_2,
    )
    assert record is not None
    assert (record.key, record.iv, record.hp) == (key, iv, hp)
    assert record.secret == secret


def test_crypto_input_must_be_contiguous_and_output_has_offset() -> None:
    bridge = QuicTlsBridge(
        make_client_configuration(),
        version=QuicProtocolVersion.VERSION_1,
        local_initial_source_connection_id=b"client",
    )
    bridge.start()
    first = bridge.next_crypto_data()
    assert first is not None
    assert first.epoch == tls.Epoch.INITIAL
    assert first.offset == 0

    with pytest.raises(ValueError, match="expected offset 0, got 1"):
        bridge.receive_crypto(tls.Epoch.INITIAL, b"x", offset=1)


def test_session_ticket_callbacks_support_early_data_resumption() -> None:
    client_ticket = None
    tickets = {}

    def save_client_ticket(ticket) -> None:
        nonlocal client_ticket
        client_ticket = ticket

    def save_server_ticket(ticket) -> None:
        tickets[ticket.ticket] = ticket

    client = QuicTlsBridge(
        make_client_configuration(),
        version=QuicProtocolVersion.VERSION_1,
        local_initial_source_connection_id=b"client01",
        remote_initial_source_connection_id=b"server01",
        original_destination_connection_id=b"original",
        session_ticket_handler=save_client_ticket,
    )
    server = QuicTlsBridge(
        make_server_configuration(),
        version=QuicProtocolVersion.VERSION_1,
        local_initial_source_connection_id=b"server01",
        remote_initial_source_connection_id=b"client01",
        original_destination_connection_id=b"original",
        session_ticket_handler=save_server_ticket,
    )
    client.start()
    drain_crypto(client, server)
    drain_crypto(server, client)
    drain_crypto(client, server)
    drain_crypto(server, client)
    assert client_ticket is not None
    assert tickets

    client_configuration = make_client_configuration()
    client_configuration.session_ticket = client_ticket
    resumed_client = QuicTlsBridge(
        client_configuration,
        version=QuicProtocolVersion.VERSION_1,
        local_initial_source_connection_id=b"client02",
        remote_initial_source_connection_id=b"server02",
        original_destination_connection_id=b"original2",
    )
    resumed_server = QuicTlsBridge(
        make_server_configuration(),
        version=QuicProtocolVersion.VERSION_1,
        local_initial_source_connection_id=b"server02",
        remote_initial_source_connection_id=b"client02",
        original_destination_connection_id=b"original2",
        session_ticket_fetcher=lambda label: tickets.pop(label, None),
    )
    resumed_client.start()
    assert any(
        secret.epoch == tls.Epoch.ZERO_RTT
        for secret in iter(resumed_client.next_traffic_secret, None)
    )
    drain_crypto(resumed_client, resumed_server)
    assert any(
        secret.epoch == tls.Epoch.ZERO_RTT
        for secret in iter(resumed_server.next_traffic_secret, None)
    )
    drain_crypto(resumed_server, resumed_client)
    drain_crypto(resumed_client, resumed_server)
    assert resumed_client.tls.early_data_accepted
    assert resumed_server.tls.early_data_accepted
