from __future__ import annotations

import asyncio
import os
import socket

import pytest

from qh3 import tls
from qh3._hazmat import pull_quic_header
from qh3.asyncio import client as asyncio_client
from qh3.asyncio import server as asyncio_server
from qh3.h3.connection import H3Connection
from qh3.quic import events
from qh3.quic.configuration import QuicConfiguration
from qh3.quic.connection import (
    QuicConnection,
    QuicConnectionError,
    QuicConnectionState,
)
from qh3.quic.logger import QuicLogger
from qh3.quic.packet import (
    QuicErrorCode,
    QuicFrameType,
    QuicPreferredAddress,
    QuicProtocolVersion,
    encode_quic_retry,
    encode_quic_version_negotiation,
)

from .utils import SERVER_CACERTFILE, SERVER_CERTFILE, SERVER_KEYFILE

CLIENT_ADDR = ("127.0.0.1", 4433)
SERVER_ADDR = ("127.0.0.1", 4434)
REBOUND_CLIENT_ADDR = ("127.0.0.1", 54321)


class CountingQuicLogger(QuicLogger):
    def __init__(self) -> None:
        super().__init__()
        self.ended = []

    def end_trace(self, trace) -> None:
        self.ended.append(trace)
        super().end_trace(trace)


def make_pair() -> tuple[QuicConnection, QuicConnection]:
    client_configuration = QuicConfiguration(
        alpn_protocols=["h3"], is_client=True, server_name="localhost"
    )
    client_configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
    client = QuicConnection(configuration=client_configuration)

    server_configuration = QuicConfiguration(alpn_protocols=["h3"], is_client=False)
    server_configuration.load_cert_chain(SERVER_CERTFILE, SERVER_KEYFILE)
    server = QuicConnection(
        configuration=server_configuration,
        original_destination_connection_id=(client.original_destination_connection_id),
    )
    return client, server


def transfer(
    source: QuicConnection,
    destination: QuicConnection,
    source_addr,
    now: float,
) -> int:
    datagrams = source.datagrams_to_send(now)
    for data, _ in datagrams:
        destination.receive_datagram(data, source_addr, now)
    return len(datagrams)


def handshake(
    client: QuicConnection, server: QuicConnection
) -> tuple[list[events.QuicEvent], list[events.QuicEvent], float]:
    now = 1.0 if not client._connect_called else 2.01
    if not client._connect_called:
        client.connect(SERVER_ADDR, now)
    for _ in range(100):
        sent = transfer(client, server, CLIENT_ADDR, now)
        sent += transfer(server, client, SERVER_ADDR, now)
        now += 0.01
        for connection in (client, server):
            timer = connection.get_timer()
            if timer is not None and timer <= now:
                connection.handle_timer(now)
        if client._handshake_complete and server._handshake_complete and not sent:
            break

    client_events = []
    server_events = []
    event = client.next_event()
    while event is not None:
        client_events.append(event)
        event = client.next_event()
    event = server.next_event()
    while event is not None:
        server_events.append(event)
        event = server.next_event()
    return client_events, server_events, now


def drain_events(connection: QuicConnection) -> list[events.QuicEvent]:
    pending = []
    event = connection.next_event()
    while event is not None:
        pending.append(event)
        event = connection.next_event()
    return pending


class SessionTicketStore:
    def __init__(self) -> None:
        self.tickets = {}

    def add(self, ticket) -> None:
        self.tickets[ticket.ticket] = ticket

    def pop(self, label):
        return self.tickets.pop(label, None)


def issue_session_ticket():
    client_ticket = None
    store = SessionTicketStore()

    def save_ticket(ticket) -> None:
        nonlocal client_ticket
        client_ticket = ticket

    client_configuration = QuicConfiguration(
        alpn_protocols=["h3"], is_client=True, server_name="localhost"
    )
    client_configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
    client = QuicConnection(
        configuration=client_configuration, session_ticket_handler=save_ticket
    )
    server_configuration = QuicConfiguration(alpn_protocols=["h3"], is_client=False)
    server_configuration.load_cert_chain(SERVER_CERTFILE, SERVER_KEYFILE)
    server = QuicConnection(
        configuration=server_configuration,
        original_destination_connection_id=client.original_destination_connection_id,
        session_ticket_handler=store.add,
    )
    handshake(client, server)
    assert client_ticket is not None
    assert store.tickets
    return client_ticket, store


def make_client() -> QuicConnection:
    return QuicConnection(
        configuration=QuicConfiguration(is_client=True, server_name="localhost")
    )


def test_native_constructor_validation_and_unstarted_facade() -> None:
    client_configuration = QuicConfiguration(is_client=True)
    with pytest.raises(AssertionError, match="original_destination_connection_id"):
        QuicConnection(
            configuration=client_configuration,
            original_destination_connection_id=b"odcid",
        )
    with pytest.raises(AssertionError, match="retry_source_connection_id"):
        QuicConnection(
            configuration=client_configuration,
            retry_source_connection_id=b"retry",
        )

    server_configuration = QuicConfiguration(is_client=False)
    with pytest.raises(AssertionError, match="SSL certificate"):
        QuicConnection(configuration=server_configuration)
    server_configuration.load_cert_chain(SERVER_CERTFILE, SERVER_KEYFILE)
    with pytest.raises(AssertionError, match="original_destination_connection_id"):
        QuicConnection(configuration=server_configuration)

    client = make_client()
    assert client.open_outbound_streams == 0
    assert client.max_concurrent_bidi_streams == 0
    assert client.max_concurrent_uni_streams == 0
    assert client.ech_retry_configs is None
    assert not client.ech_accepted
    assert client.get_cipher() is None
    assert client.get_peercert() is None
    assert client.get_issuercerts() == []
    assert client.tls is None
    assert client.datagrams_to_send(0) == []
    assert client.get_timer() is None
    assert not client.should_wait_for_ack(0)
    client.handle_timer(0)
    client.close(reason_phrase="not started")
    client.receive_datagram(b"ignored", SERVER_ADDR, 0)
    assert client.next_event() is None
    assert client._stream_can_send(0)
    for operation in (
        lambda: client.reset_stream(0, 0),
        lambda: client.stop_stream(0, 0),
        lambda: client.send_datagram_frame(b"x"),
        lambda: client.send_ping(1),
        client.change_connection_id,
    ):
        with pytest.raises(AssertionError, match="not been started"):
            operation()
    with pytest.raises(AssertionError, match="before handshake"):
        client.request_key_update()

    error = QuicConnectionError(1, None, "bad")
    assert str(error) == "Error: 1, reason: bad"
    assert str(QuicConnectionError(2, 3, "worse")).endswith("frame_type: 3")


def test_native_preconnect_stream_staging_and_connect_validation() -> None:
    client = make_client()
    client.send_stream_data(0, b"first")
    client.send_stream_data(0, b"second", end_stream=True)
    client.send_stream_data(2, b"uni")
    assert client._pre_handshake_streams == [(0, False), (2, True)]
    assert client._pre_handshake_writes == [
        (0, b"first", False),
        (0, b"second", True),
        (2, b"uni", False),
    ]
    assert client.get_next_available_stream_id() == 4
    assert client.get_next_available_stream_id(is_unidirectional=True) == 6

    client.connect(SERVER_ADDR, 1.0)
    with pytest.raises(AssertionError, match="single time"):
        client.connect(SERVER_ADDR, 2.0)

    _, server = make_pair()
    with pytest.raises(AssertionError, match="only be called for clients"):
        server.connect(CLIENT_ADDR, 1.0)


def test_native_core_idle_timer_is_anchored_before_tls_drain(monkeypatch) -> None:
    client = make_client()
    observed_timers = []
    monkeypatch.setattr(
        client, "_drain_tls", lambda: observed_timers.append(client.get_timer())
    )

    client.connect(SERVER_ADDR, 1000.0)

    assert observed_timers == [1030.0]


def test_native_batch_and_gro_fallback_before_handshake(monkeypatch) -> None:
    client = make_client()
    seen = []
    monkeypatch.setattr(
        client,
        "receive_datagram",
        lambda data, addr, now: seen.append((data, addr, now)),
    )
    client.receive_many_datagrams([], SERVER_ADDR, 1.0)
    client.receive_gro_buffer(b"abcdefg", 3, SERVER_ADDR, 2.0)
    assert [item[0] for item in seen] == [b"abc", b"def", b"g"]
    with pytest.raises(ValueError, match="positive"):
        client.receive_gro_buffer(b"x", 0, SERVER_ADDR, 3.0)

    client._core = object()
    seen.clear()
    client.receive_many_datagrams([b"one", b"two"], SERVER_ADDR, 4.0)
    client.receive_gro_buffer(b"aabb", 2, SERVER_ADDR, 5.0)
    assert [item[0] for item in seen] == [b"one", b"two", b"aa", b"bb"]


def test_native_server_rejects_non_initial_and_unsupported_initial() -> None:
    client, server = make_pair()
    version_negotiation = encode_quic_version_negotiation(
        source_cid=b"source",
        destination_cid=b"destination",
        supported_versions=[QuicProtocolVersion.VERSION_1],
    ).ljust(1200, b"\0")
    server.receive_datagram(version_negotiation, CLIENT_ADDR, 1.0)
    assert server._core is None

    client.connect(SERVER_ADDR, 1.0)
    initial = bytearray(client.datagrams_to_send(1.0)[0][0])
    initial[1:5] = (0x1A2A3A4A).to_bytes(4, "big")
    server.receive_datagram(bytes(initial), CLIENT_ADDR, 1.0)
    assert server._core is None


def test_native_malformed_header_after_connect_is_safely_consumed() -> None:
    client = make_client()
    client.connect(SERVER_ADDR, 1.0)
    client.datagrams_to_send(1.0)
    client.receive_datagram(b"\x80", SERVER_ADDR, 1.01)
    client._learn_remote_source_cid(b"\x80")


def test_native_single_item_batch_can_initialize_server() -> None:
    client, server = make_pair()
    client.connect(SERVER_ADDR, 1.0)
    initial = client.datagrams_to_send(1.0)[0][0]
    server.receive_many_datagrams([initial], CLIENT_ADDR, 1.0)
    assert server._core is not None


def test_native_core_event_translation_and_timer_paths() -> None:
    client = make_client()

    class EventCore:
        def __init__(self) -> None:
            self.events = iter(
                [
                    ("stream_reset", 1, 2),
                    ("stop_sending", 3, 4),
                    ("protocol_error", 5, 6, "protocol"),
                    ("peer_closed", 0, 7, 8, b"peer\xff"),
                    ("connection_terminated", 9, None, b"done\xff"),
                    None,
                ]
            )
            self.timer_calls = []
            self.ack_wait_calls = []

        def next_event(self):
            return next(self.events)

        def get_timer(self):
            return ("loss", 12.5)

        def handle_timer(self, now):
            self.timer_calls.append(now)

        def should_wait_for_ack(self, now):
            self.ack_wait_calls.append(now)
            return True

    core = EventCore()
    client._core = core
    assert client.get_timer() == 12.5
    assert client.should_wait_for_ack(12.25)
    assert core.ack_wait_calls == [12.25]
    client.handle_timer(12.5)
    assert core.timer_calls == [12.5]
    assert client.next_event() == events.StreamReset(2, 1)
    assert client.next_event() == events.StopSendingReceived(4, 3)
    assert client.next_event() == events.ConnectionTerminated(9, None, "done\ufffd")
    assert client.next_event() is None
    assert client._state == QuicConnectionState.TERMINATED


def test_native_stream_recording_and_replay_guards() -> None:
    client = make_client()

    class StreamCore:
        def __init__(self) -> None:
            self.reset = None

        def reset_stream(self, stream_id, error_code):
            self.reset = (stream_id, error_code)

        def open_stream(self, is_unidirectional):
            return 4

    core = StreamCore()
    client._core = core
    client.reset_stream(0, 7)
    assert core.reset == (0, 7)
    assert client._pre_handshake_streams == [(0, False)]

    client._pre_handshake_streams = [(0, False)]
    with pytest.raises(QuicConnectionError, match="allocation changed"):
        client._reopen_pre_handshake_streams("test")

    client._pre_handshake_state_replayed = True
    client._replay_pre_handshake_state("already replayed")


def test_native_version_negotiation_outcomes() -> None:
    client = make_client()
    client.configuration.supported_versions = [
        QuicProtocolVersion.VERSION_1,
        QuicProtocolVersion.VERSION_2,
    ]
    client.connect(SERVER_ADDR, 1.0)
    client.datagrams_to_send(1.0)
    original_core = client._core

    containing_current = encode_quic_version_negotiation(
        source_cid=client.original_destination_connection_id,
        destination_cid=client.host_cid,
        supported_versions=[QuicProtocolVersion.VERSION_1],
    )
    client.receive_datagram(containing_current, SERVER_ADDR, 1.01)
    assert client._core is original_core

    alternate = encode_quic_version_negotiation(
        source_cid=client.original_destination_connection_id,
        destination_cid=client.host_cid,
        supported_versions=[QuicProtocolVersion.VERSION_2],
    )
    client.receive_datagram(alternate, SERVER_ADDR, 1.02)
    assert client._version == QuicProtocolVersion.VERSION_2
    assert client._version_negotiated
    assert client._core is not original_core
    assert client.datagrams_to_send(1.02)

    failed = make_client()
    failed.connect(SERVER_ADDR, 1.0)
    no_common = encode_quic_version_negotiation(
        source_cid=failed.original_destination_connection_id,
        destination_cid=failed.host_cid,
        supported_versions=[0x1A2A3A4A],
    )
    failed.receive_datagram(no_common, SERVER_ADDR, 1.01)
    assert failed.next_event() == events.ConnectionTerminated(
        QuicErrorCode.INTERNAL_ERROR,
        None,
        "Could not find a common protocol version",
    )
    assert failed._state == QuicConnectionState.TERMINATED


def test_native_retry_wrong_fields_and_duplicate_are_ignored() -> None:
    client = make_client()
    client.connect(SERVER_ADDR, 1.0)
    client.datagrams_to_send(1.0)

    wrong_destination = encode_quic_retry(
        version=client._version,
        source_cid=b"retrycid",
        destination_cid=b"wrongcid",
        original_destination_cid=client.original_destination_connection_id,
        retry_token=b"token",
    )
    client.receive_datagram(wrong_destination, SERVER_ADDR, 1.01)
    assert client._retry_count == 0

    valid = encode_quic_retry(
        version=client._version,
        source_cid=b"retrycid",
        destination_cid=client.host_cid,
        original_destination_cid=client.original_destination_connection_id,
        retry_token=b"token",
    )
    client.receive_datagram(valid, SERVER_ADDR, 1.02)
    assert client._retry_count == 1
    retried_core = client._core
    client.receive_datagram(valid, SERVER_ADDR, 1.03)
    assert client._core is retried_core
    assert client._retry_count == 1


def test_native_qlog_drop_and_malformed_packet_branches() -> None:
    quic_logger = QuicLogger()
    configuration = QuicConfiguration(is_client=True, quic_logger=quic_logger)
    client = QuicConnection(configuration=configuration)
    trace = client._quic_logger
    client._log_packet("packet_received", b"\x80")
    client._log_packets("packet_sent", b"\x80")
    client._log_packet_dropped(b"ciphertext")
    names = [event["name"] for event in trace.to_dict()["events"]]
    assert names == ["transport:packet_dropped"]


def test_native_address_normalization_accepts_only_ip_addresses() -> None:
    client = make_client()
    assert client._normalize_address(("127.0.0.1", 443)) == ("127.0.0.1", 443)
    assert client._normalize_address(("::1", 443, 0, 0)) == ("::1", 443, 0, 0)
    with pytest.raises(OSError):
        client._normalize_address(("example.test", 443))


def make_resumption_pair(client_ticket, session_ticket_fetcher=None):
    client_configuration = QuicConfiguration(
        alpn_protocols=["h3"], is_client=True, server_name="localhost"
    )
    client_configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
    client_configuration.session_ticket = client_ticket
    client = QuicConnection(configuration=client_configuration)

    server_configuration = QuicConfiguration(alpn_protocols=["h3"], is_client=False)
    server_configuration.load_cert_chain(SERVER_CERTFILE, SERVER_KEYFILE)
    server = QuicConnection(
        configuration=server_configuration,
        original_destination_connection_id=client.original_destination_connection_id,
        session_ticket_fetcher=session_ticket_fetcher,
    )
    return client, server


def test_native_client_server_handshake() -> None:
    client, server = make_pair()
    client_events, server_events, _ = handshake(client, server)

    for connection_events in (client_events, server_events):
        assert events.ProtocolNegotiated("h3") in connection_events
        assert events.HandshakeCompleted("h3", False, False) in connection_events
    assert client.get_cipher() is not None
    assert client.get_peercert() is not None


def test_native_v1_v2_compatible_negotiation_handshake() -> None:
    client, server = make_pair()
    for connection in (client, server):
        connection.configuration.supported_versions = [
            QuicProtocolVersion.VERSION_2,
            QuicProtocolVersion.VERSION_1,
        ]
    client.configuration.original_version = QuicProtocolVersion.VERSION_1

    client_events, server_events, now = handshake(client, server)

    assert client._version == server._version == QuicProtocolVersion.VERSION_2
    assert client._core.version == server._core.version == QuicProtocolVersion.VERSION_2
    assert events.HandshakeCompleted("h3", False, False) in client_events
    assert events.HandshakeCompleted("h3", False, False) in server_events
    client.send_stream_data(0, b"negotiated v2", end_stream=True)
    transfer(client, server, CLIENT_ADDR, now)
    assert server.next_event() == events.StreamDataReceived(
        b"negotiated v2", True, 0
    )


def test_native_rejects_oversized_outbound_varints_transactionally() -> None:
    client, server = make_pair()
    _, _, now = handshake(client, server)
    oversized = 2**62

    with pytest.raises(ValueError, match="error code exceeds"):
        client.reset_stream(0, oversized)
    assert client.get_next_available_stream_id() == 0
    assert client.open_outbound_streams == 0

    with pytest.raises(ValueError, match="error code exceeds"):
        client.stop_stream(1, oversized)
    with pytest.raises(ValueError, match="error code exceeds"):
        client.close(oversized)
    assert client._close_event is None
    assert client._core.state == "connected"

    with pytest.raises(ValueError, match="CRYPTO end offset exceeds"):
        client._core.send_crypto(int(tls.Epoch.INITIAL), oversized - 1, b"xx")
    client.send_ping(123)
    assert transfer(client, server, CLIENT_ADDR, now) == 1


def test_native_datagram_limit_uses_encoded_size() -> None:
    client, server = make_pair()
    client.configuration.max_datagram_frame_size = 66
    server.configuration.max_datagram_frame_size = 66
    _, _, now = handshake(client, server)

    assert client._tls.remote_transport_parameters.max_datagram_frame_size == 66
    assert server._tls.remote_transport_parameters.max_datagram_frame_size == 66

    client.send_datagram_frame(b"a" * 63)
    transfer(client, server, CLIENT_ADDR, now)
    assert server.next_event() == events.DatagramFrameReceived(b"a" * 63)

    # A 64-byte payload needs a two-byte length varint, making the complete
    # DATAGRAM frame 67 bytes rather than 66.
    with pytest.raises(ValueError, match="datagram is too large"):
        client.send_datagram_frame(b"a" * 64)

    # Simulate a peer violating the advertised limit to exercise receive-side
    # enforcement independently of the sender check.
    client._core.apply_peer_transport_parameters(
        client.configuration.max_data,
        client.configuration.max_stream_data,
        client.configuration.max_stream_data,
        client.configuration.max_stream_data,
        100,
        103,
        3,
        0.025,
        client.configuration.idle_timeout,
        1200,
    )
    client.send_datagram_frame(b"a" * 64)
    transfer(client, server, CLIENT_ADDR, now + 0.01)
    assert server._core.local_error == (
        10,
        int(QuicFrameType.DATAGRAM_WITH_LENGTH),
        "DATAGRAM frame exceeds the advertised maximum",
    )


def test_native_facade_uses_batch_and_gro_core_entrypoints_after_handshake() -> None:
    client, _ = make_pair()

    class RecordingCore:
        def __init__(self) -> None:
            self.many = None
            self.gro = None

        def receive_many_datagrams(self, datagrams, addr, now):
            self.many = (datagrams, addr, now)

        def receive_gro_buffer(self, buffer, segment_size, addr, now):
            self.gro = (buffer, segment_size, addr, now)

        def next_event(self):
            return None

    core = RecordingCore()
    client._core = core
    client._handshake_complete = True
    client.receive_many_datagrams([b"one", b"two"], SERVER_ADDR, 1.0)
    client.receive_gro_buffer(b"aaabbb", 3, SERVER_ADDR, 2.0)

    assert core.many == ([b"one", b"two"], SERVER_ADDR, 1.0)
    assert core.gro == (b"aaabbb", 3, SERVER_ADDR, 2.0)


def test_native_client_retains_new_token() -> None:
    client, _ = make_pair()

    class TokenCore:
        def __init__(self) -> None:
            self.events = iter([("new_token", b"future initial"), None])

        def next_event(self):
            return next(self.events)

    client._core = TokenCore()
    client._drain_core()

    assert client._peer_token == b"future initial"


def test_native_zero_rtt_accepted() -> None:
    client_ticket, store = issue_session_ticket()
    client, server = make_resumption_pair(client_ticket, store.pop)
    now = 2.0
    client.connect(SERVER_ADDR, now)
    client.send_stream_data(0, b"early request", end_stream=True)

    # The quantum-readiness transport parameter makes ClientHello span two
    # padded Initial datagrams; the third datagram carries the 0-RTT packet.
    assert transfer(client, server, CLIENT_ADDR, now) == 3
    early_events = drain_events(server)
    assert events.StreamDataReceived(b"early request", True, 0) in early_events

    client_events, server_events, _ = handshake(client, server)
    assert events.HandshakeCompleted("h3", True, True) in client_events
    assert events.HandshakeCompleted("h3", True, True) in server_events
    assert not any(
        isinstance(event, events.StreamDataReceived) for event in server_events
    )


def test_native_zero_rtt_rejected_and_replayed_once() -> None:
    client_ticket, _ = issue_session_ticket()
    client, server = make_resumption_pair(client_ticket)
    now = 2.0
    client.connect(SERVER_ADDR, now)
    client.send_stream_data(0, b"replay me", end_stream=True)

    assert transfer(client, server, CLIENT_ADDR, now) == 3
    assert not any(
        isinstance(event, events.StreamDataReceived) for event in drain_events(server)
    )
    early_packets = client._core.outstanding_application_packets
    assert early_packets and early_packets[0][0] == 0

    assert transfer(server, client, SERVER_ADDR, now + 0.01) > 0
    client_events = drain_events(client)
    replay = client.datagrams_to_send(now + 0.01)
    assert replay
    replay_packets = client._core.outstanding_application_packets
    assert replay_packets and min(packet[0] for packet in replay_packets) > 0
    for data, _ in replay:
        server.receive_datagram(data, CLIENT_ADDR, now + 0.01)

    remaining_client_events, server_events, _ = handshake(client, server)
    client_events.extend(remaining_client_events)
    assert events.HandshakeCompleted("h3", False, False) in client_events
    stream_events = [
        event for event in server_events if isinstance(event, events.StreamDataReceived)
    ]
    assert stream_events == [events.StreamDataReceived(b"replay me", True, 0)]


def test_native_qlog_lifecycle_and_h3_logging() -> None:
    client_logger = CountingQuicLogger()
    server_logger = CountingQuicLogger()
    client, server = make_pair()
    client.configuration.quic_logger = client_logger
    server.configuration.quic_logger = server_logger

    # Traces are started by construction, as they are for the legacy connection.
    client = QuicConnection(configuration=client.configuration)
    server = QuicConnection(
        configuration=server.configuration,
        original_destination_connection_id=client.original_destination_connection_id,
    )
    client_trace = client._quic_logger
    server_trace = server._quic_logger
    assert client_trace is not None
    assert server_trace is not None

    _, _, now = handshake(client, server)
    h3 = H3Connection(client)
    h3.send_headers(0, [(b":method", b"GET"), (b":path", b"/")])

    client_events = client_trace.to_dict()["events"]
    names = {event["name"] for event in client_events}
    assert {
        "http:frame_created",
        "security:key_updated",
        "transport:datagrams_received",
        "transport:datagrams_sent",
        "transport:packet_received",
        "transport:packet_sent",
        "transport:parameters_set",
    } <= names

    client.close(reason_phrase="finished")
    transfer(client, server, CLIENT_ADDR, now)
    for connection in (client, server):
        deadline = connection.get_timer()
        assert deadline is not None
        connection.handle_timer(deadline)
        connection.handle_timer(deadline + 1)

    assert client_logger.ended == [client_trace]
    assert server_logger.ended == [server_trace]
    assert client._quic_logger is None
    assert server._quic_logger is None
    assert client_trace.to_dict()["events"][-1]["name"] == (
        "connectivity:connection_closed"
    )


def test_native_issues_spare_connection_ids_and_rotates() -> None:
    client, server = make_pair()
    client_events, server_events, now = handshake(client, server)
    client_issued = [
        event.connection_id
        for event in client_events
        if isinstance(event, events.ConnectionIdIssued)
    ]
    server_issued = [
        event.connection_id
        for event in server_events
        if isinstance(event, events.ConnectionIdIssued)
    ]

    # The server advertises eight active IDs, while an omitted client limit
    # has the RFC default of two. The initial ID is already externally known.
    assert len(client_issued) == 7
    assert len(server_issued) == 1
    assert len(set(client_issued)) == len(client_issued)
    assert len(set(server_issued)) == len(server_issued)

    client.send_ping(99)
    before_rotation = client.datagrams_to_send(now)
    assert (
        pull_quic_header(before_rotation[0][0], 0, len(client.host_cid))[3]
        == server.host_cid
    )
    for data, _ in before_rotation:
        server.receive_datagram(data, CLIENT_ADDR, now)

    retired = server.host_cid
    client.change_connection_id()
    rotation = client.datagrams_to_send(now)
    assert (
        pull_quic_header(rotation[0][0], 0, len(client.host_cid))[3] == server_issued[0]
    )
    for data, _ in rotation:
        server.receive_datagram(data, CLIENT_ADDR, now)
    server_events = drain_events(server)
    assert events.ConnectionIdRetired(retired) in server_events
    assert any(isinstance(event, events.ConnectionIdIssued) for event in server_events)

    # Drop the replacement NEW_CONNECTION_ID. Its delivery action must put it
    # into a PTO probe, otherwise no second rotation is possible.
    assert server.datagrams_to_send(now + 0.001)
    deadline = server.get_timer()
    assert deadline is not None
    server.handle_timer(deadline)
    transfer(server, client, SERVER_ADDR, deadline)
    client.change_connection_id()


def test_native_validates_and_activates_rebound_path() -> None:
    client, server = make_pair()
    handshake(client, server)
    server._core.apply_peer_transport_parameters(
        0,
        0,
        0,
        0,
        100,
        100,
        3,
        0.025,
        None,
        None,
        disable_active_migration=True,
    )
    now = 2.0
    assert server._core.active_path[2] == CLIENT_ADDR

    client.send_ping(123)
    outbound = client.datagrams_to_send(now)
    assert outbound
    for data, _ in outbound:
        server.receive_datagram(data, REBOUND_CLIENT_ADDR, now)

    challenge = server.datagrams_to_send(now + 0.001)
    assert challenge
    assert all(address == REBOUND_CLIENT_ADDR for _, address in challenge)
    for data, _ in challenge:
        client.receive_datagram(data, SERVER_ADDR, now + 0.001)

    response = client.datagrams_to_send(now + 0.002)
    assert response
    for data, _ in response:
        server.receive_datagram(data, REBOUND_CLIENT_ADDR, now + 0.002)

    assert server._core.active_path[2] == REBOUND_CLIENT_ADDR
    # RFC 9000 section 9.4 allows retaining recovery state for a port-only
    # change, which is the common NAT rebinding case.
    assert server._core.smoothed_rtt is not None

    # disable_active_migration forbids deliberate peer IP migration, but RFC
    # 9000 requires port-only NAT rebinding to remain eligible for validation.
    client.send_ping(124)
    for data, _ in client.datagrams_to_send(now + 0.01):
        server.receive_datagram(data, ("127.0.0.2", 54321), now + 0.01)
    assert server._core.active_path[2] == REBOUND_CLIENT_ADDR


def test_native_retransmits_lost_path_response() -> None:
    client, server = make_pair()
    client.configuration.probe_datagram_size = False
    _, _, now = handshake(client, server)

    client.send_ping(123)
    for data, _ in client.datagrams_to_send(now):
        server.receive_datagram(data, REBOUND_CLIENT_ADDR, now)
    for data, _ in server.datagrams_to_send(now + 0.001):
        client.receive_datagram(data, SERVER_ADDR, now + 0.001)

    assert client.datagrams_to_send(now + 0.002)  # Drop PATH_RESPONSE.
    deadline = client.get_timer()
    assert deadline is not None
    deadline = max(deadline, now + 0.002)
    client.handle_timer(deadline)
    transfer(client, server, REBOUND_CLIENT_ADDR, deadline)

    assert server._core.active_path[2] == REBOUND_CLIENT_ADDR


def test_native_server_drops_undersized_initial() -> None:
    client, server = make_pair()
    client.connect(SERVER_ADDR, 1.0)
    initial = client.datagrams_to_send(1.0)[0][0]
    assert len(initial) >= 1200

    server.receive_datagram(initial[:1199], CLIENT_ADDR, 1.0)

    assert server._core is None
    assert server.next_event() is None


def test_native_server_silently_drops_malformed_large_first_datagram() -> None:
    _, server = make_pair()
    server.receive_datagram(b"not a QUIC packet".ljust(1200, b"\0"), CLIENT_ADDR, 1.0)
    server.receive_datagram(b"\xff" * 1200, CLIENT_ADDR, 1.01)
    assert server._core is None
    assert server.next_event() is None


def test_native_stateless_reset_terminates_once() -> None:
    client, server = make_pair()
    _, _, now = handshake(client, server)
    token = server._tls.stateless_reset_token
    reset = bytes([0x40]) + os.urandom(24) + token

    client.receive_datagram(reset, SERVER_ADDR, now)
    client.receive_datagram(reset, SERVER_ADDR, now + 0.01)

    assert client.next_event() == events.ConnectionTerminated(0, None, "")
    assert client.next_event() is None
    assert client._core.state == "terminated"


@pytest.mark.parametrize(
    ("frame_type", "expected_frame_type"),
    [(None, None), (int(QuicFrameType.PING), int(QuicFrameType.PING))],
)
def test_native_close_semantics_and_single_terminal_event(
    frame_type: int | None, expected_frame_type: int | None
) -> None:
    client, server = make_pair()
    _, _, now = handshake(client, server)

    client.close(42, frame_type, "finished")
    client.close(99, int(QuicFrameType.CRYPTO), "ignored")
    with pytest.raises(QuicConnectionError, match="closed"):
        client.send_ping(1)
    transfer(client, server, CLIENT_ADDR, now)

    assert server._core.state == "draining"
    assert server.next_event() is None
    deadline = server.get_timer()
    assert deadline is not None
    server.handle_timer(deadline)
    assert server.next_event() == events.ConnectionTerminated(
        42, expected_frame_type, "finished"
    )
    assert server.next_event() is None


def test_native_close_is_retransmitted_after_authenticated_packet() -> None:
    client, server = make_pair()
    _, _, now = handshake(client, server)
    client.close(reason_phrase="bye")
    assert client.datagrams_to_send(now)
    assert client.datagrams_to_send(now) == []

    server.send_ping(1)
    transfer(server, client, SERVER_ADDR, now + 0.01)
    assert client.datagrams_to_send(now + 0.01)


def test_native_pmtu_probing_respects_configuration() -> None:
    client, server = make_pair()
    _, _, _ = handshake(client, server)
    assert client._core.active_path[5] == 1472
    assert server._core.active_path[5] == 1280

    client, server = make_pair()
    client.configuration.probe_datagram_size = False
    _, _, _ = handshake(client, server)
    assert client._core.active_path[5] == 1280


def test_native_peer_max_udp_payload_size_caps_datagrams_and_pmtu() -> None:
    client, server = make_pair()
    server.configuration.max_datagram_size = 2000
    _, _, now = handshake(client, server)
    assert server._tls.remote_transport_parameters.max_udp_payload_size == 1472

    server.send_stream_data(1, b"x" * 10_000, end_stream=True)
    datagrams = server.datagrams_to_send(now)
    assert datagrams
    assert max(len(data) for data, _ in datagrams) <= 1472
    assert server._core.active_path[5] <= 1472


def test_native_lost_pmtu_probe_does_not_reduce_congestion_window() -> None:
    client, server = make_pair()
    now = 1.0
    client.connect(SERVER_ADDR, now)
    dropped_probe = False

    for _ in range(200):
        for data, _ in client.datagrams_to_send(now):
            if client._handshake_confirmed and len(data) > 1200:
                dropped_probe = True
            else:
                server.receive_datagram(data, CLIENT_ADDR, now)
        transfer(server, client, SERVER_ADDR, now)
        now += 0.01
        if dropped_probe and client._core.get_timer()[0] == "pmtu":
            break
        for connection in (client, server):
            deadline = connection.get_timer()
            if deadline is not None and deadline <= now:
                connection.handle_timer(now)

    assert dropped_probe
    timer_kind, deadline = client._core.get_timer()
    assert timer_kind == "pmtu"
    congestion_window = client._core.congestion_window
    client.handle_timer(deadline)
    assert client._core.congestion_window == congestion_window
    assert client._core.active_path[5] == 1280


def test_native_datagram_is_not_retransmitted_on_pto() -> None:
    client, server = make_pair()
    client.configuration.probe_datagram_size = False
    _, _, now = handshake(client, server)
    client.configuration.max_datagram_frame_size = 1200
    server.configuration.max_datagram_frame_size = 1200
    client._core.apply_peer_transport_parameters(
        client.configuration.max_data,
        client.configuration.max_stream_data,
        client.configuration.max_stream_data,
        client.configuration.max_stream_data,
        100,
        103,
        3,
        0.025,
        client.configuration.idle_timeout,
        1200,
    )

    client.send_datagram_frame(b"not reliable")
    assert client.datagrams_to_send(now)
    deadline = client.get_timer()
    assert deadline is not None
    client.handle_timer(deadline)
    transfer(client, server, CLIENT_ADDR, deadline)

    assert not any(
        isinstance(event, events.DatagramFrameReceived)
        for event in drain_events(server)
    )


def test_native_acknowledges_every_second_application_packet() -> None:
    client, server = make_pair()
    client.configuration.probe_datagram_size = False
    _, _, now = handshake(client, server)

    client.send_ping(1)
    transfer(client, server, CLIENT_ADDR, now)
    assert server.datagrams_to_send(now) == []

    client.send_ping(2)
    transfer(client, server, CLIENT_ADDR, now + 0.001)
    assert server.datagrams_to_send(now + 0.001)


def test_native_preferred_address_remains_explicitly_disabled() -> None:
    client, server = make_pair()
    _, _, _ = handshake(client, server)
    original_path = client._core.active_path
    parameters = client._tls.remote_transport_parameters
    parameters.preferred_address = QuicPreferredAddress(
        ipv4_address=("127.0.0.2", 4444),
        ipv6_address=None,
        connection_id=b"preferred",
        stateless_reset_token=b"0" * 16,
    )
    client._applied_transport_parameters = None

    client._drain_tls()

    assert client._core.active_path == original_path


def test_native_stream_roundtrip() -> None:
    client, server = make_pair()
    _, _, now = handshake(client, server)

    stream_id = client.get_next_available_stream_id()
    client.send_stream_data(stream_id, b"request", end_stream=True)
    transfer(client, server, CLIENT_ADDR, now)
    assert server.next_event() == events.StreamDataReceived(
        data=b"request", end_stream=True, stream_id=stream_id
    )

    server.send_stream_data(stream_id, b"response", end_stream=True)
    transfer(server, client, SERVER_ADDR, now + 0.01)
    assert client.next_event() == events.StreamDataReceived(
        data=b"response", end_stream=True, stream_id=stream_id
    )
    assert client.open_outbound_streams == 0
    assert stream_id not in client._created_local_stream_ids
    assert client.max_concurrent_bidi_streams >= 100

    client.send_ping(42)
    transfer(client, server, CLIENT_ADDR, now + 0.02)
    timer = server.get_timer()
    assert timer is not None
    server.handle_timer(timer)
    transfer(server, client, SERVER_ADDR, timer)
    assert client.next_event() == events.PingAcknowledged(uid=42)


def test_native_stream_id_is_a_lazy_peek_before_and_after_connect() -> None:
    client, server = make_pair()
    assert client.get_next_available_stream_id() == 0
    assert client.get_next_available_stream_id() == 0

    _, _, now = handshake(client, server)
    assert client.get_next_available_stream_id() == 0
    assert client.get_next_available_stream_id() == 0
    client.send_stream_data(0, b"first", end_stream=True)
    assert client.get_next_available_stream_id() == 4
    client.send_stream_data(4, b"second", end_stream=True)
    assert client.get_next_available_stream_id() == 8
    assert client.open_outbound_streams == 2
    transfer(client, server, CLIENT_ADDR, now)


def test_native_stream_data_queued_before_connect_is_delivered_once() -> None:
    client, server = make_pair()
    client.send_stream_data(0, b"queued before connect", end_stream=True)

    assert client.datagrams_to_send(1.0) == []
    assert client.get_timer() is None

    _, server_events, _ = handshake(client, server)
    stream_events = [
        event for event in server_events if isinstance(event, events.StreamDataReceived)
    ]
    assert stream_events == [
        events.StreamDataReceived(b"queued before connect", True, 0)
    ]


def test_native_stream_api_rejects_wrong_direction_and_unknown_peer_streams() -> None:
    client, server = make_pair()
    _, _, _ = handshake(client, server)

    with pytest.raises(ValueError, match="peer-initiated unidirectional"):
        client.send_stream_data(3, b"invalid")
    with pytest.raises(ValueError, match="unknown peer-initiated"):
        client.reset_stream(1, 1)
    with pytest.raises(ValueError, match="unknown stream"):
        client.stop_stream(1, 1)

    stream_id = client.get_next_available_stream_id(is_unidirectional=True)
    client.send_stream_data(stream_id, b"created")
    with pytest.raises(ValueError, match="local-initiated unidirectional"):
        client.stop_stream(stream_id, 1)


def test_native_replenishes_stream_credit_for_sequential_requests() -> None:
    client, server = make_pair()
    _, _, now = handshake(client, server)
    initial_limit = client.max_concurrent_bidi_streams

    for index in range(initial_limit + 2):
        stream_id = client.get_next_available_stream_id()
        client.send_stream_data(stream_id, b"request", end_stream=True)
        transfer(client, server, CLIENT_ADDR, now)
        assert server.next_event() == events.StreamDataReceived(
            data=b"request", end_stream=True, stream_id=stream_id
        )

        server.send_stream_data(stream_id, b"response", end_stream=True)
        transfer(server, client, SERVER_ADDR, now + 0.001)
        assert client.next_event() == events.StreamDataReceived(
            data=b"response", end_stream=True, stream_id=stream_id
        )

        client.send_ping(index)
        transfer(client, server, CLIENT_ADDR, now + 0.002)
        transfer(server, client, SERVER_ADDR, now + 0.003)
        while client.next_event() is not None:
            pass
        now += 0.01

    assert client.max_concurrent_bidi_streams > initial_limit
    assert client.open_outbound_streams == 0


def test_native_retransmits_lost_max_streams_update() -> None:
    client, server = make_pair()
    _, _, now = handshake(client, server)
    initial_limit = client.max_concurrent_bidi_streams
    stream_id = client.get_next_available_stream_id()
    client.send_stream_data(stream_id, b"request", end_stream=True)
    transfer(client, server, CLIENT_ADDR, now)
    assert server.next_event() is not None
    server.send_stream_data(stream_id, b"response", end_stream=True)
    transfer(server, client, SERVER_ADDR, now + 0.001)
    assert client.next_event() is not None

    client.send_ping(1)
    transfer(client, server, CLIENT_ADDR, now + 0.002)
    assert server.datagrams_to_send(now + 0.003)  # Drop MAX_STREAMS.
    deadline = server.get_timer()
    assert deadline is not None
    server.handle_timer(deadline)
    transfer(server, client, SERVER_ADDR, deadline)

    assert client.max_concurrent_bidi_streams == initial_limit + 1


def test_native_retransmits_lost_flow_control_updates() -> None:
    client, server = make_pair()
    client.configuration.probe_datagram_size = False
    server.configuration.max_data = 10
    server.configuration.max_stream_data = 10
    _, _, now = handshake(client, server)

    client.send_stream_data(0, b"a" * 10)
    transfer(client, server, CLIENT_ADDR, now)
    assert server.next_event() == events.StreamDataReceived(b"a" * 10, False, 0)

    # Drop the packet carrying MAX_DATA and MAX_STREAM_DATA, then let the
    # delivery actions recreate both frames in the PTO probe.
    assert server.datagrams_to_send(now + 0.001)
    deadline = server.get_timer()
    assert deadline is not None
    deadline = max(deadline, now + 0.001)
    server.handle_timer(deadline)
    transfer(server, client, SERVER_ADDR, deadline)

    client.send_stream_data(0, b"b" * 10, end_stream=True)
    transfer(client, server, CLIENT_ADDR, deadline + 0.001)
    assert server.next_event() == events.StreamDataReceived(b"b" * 10, True, 0)


def test_native_reset_final_sizes_replenish_connection_credit() -> None:
    client, server = make_pair()
    server.configuration.max_data = 10
    server.configuration.max_stream_data = 10
    _, _, now = handshake(client, server)

    for index in range(3):
        stream_id = client.get_next_available_stream_id()
        client.send_stream_data(stream_id, b"x" * 10)
        assert client.datagrams_to_send(now)  # Drop the STREAM packet.
        client.reset_stream(stream_id, index)
        transfer(client, server, CLIENT_ADDR, now + 0.001)
        assert server.next_event() == events.StreamReset(index, stream_id)

        # Polling StreamReset consumes its final size and emits fresh MAX_DATA.
        transfer(server, client, SERVER_ADDR, now + 0.002)
        now += 0.01


def test_native_retransmits_lost_handshake_done() -> None:
    client, server = make_pair()
    client.configuration.probe_datagram_size = False
    now = 1.0
    client.connect(SERVER_ADDR, now)

    for _ in range(100):
        transfer(client, server, CLIENT_ADDR, now)
        if server._handshake_complete:
            assert server.datagrams_to_send(now)  # Drop HANDSHAKE_DONE.
            break
        transfer(server, client, SERVER_ADDR, now)
        now += 0.01

    assert server._handshake_complete
    assert not client._handshake_confirmed
    for _ in range(20):
        deadline = server.get_timer()
        assert deadline is not None
        now = max(deadline, now)
        server.handle_timer(now)
        transfer(server, client, SERVER_ADDR, now)
        if client._handshake_confirmed:
            break
        now += 0.001
    assert client._handshake_confirmed


def test_native_handshake_retransmits_lost_crypto() -> None:
    client, server = make_pair()
    now = 1.0
    client.connect(SERVER_ADDR, now)
    assert transfer(client, server, CLIENT_ADDR, now) > 0

    # Drop the server's complete first flight, then fire its PTO.
    assert server.datagrams_to_send(now)
    timer = server.get_timer()
    assert timer is not None
    server.handle_timer(timer)
    assert transfer(server, client, SERVER_ADDR, timer) > 0

    now = timer + 0.01
    for _ in range(100):
        sent = transfer(client, server, CLIENT_ADDR, now)
        sent += transfer(server, client, SERVER_ADDR, now)
        now += 0.01
        for connection in (client, server):
            deadline = connection.get_timer()
            if deadline is not None and deadline <= now:
                connection.handle_timer(now)
        if client._handshake_complete and server._handshake_complete and not sent:
            break

    assert client._handshake_complete
    assert server._handshake_complete


def test_native_initial_falls_back_from_1280_to_1200_on_pto() -> None:
    client = make_client()
    now = 1.0
    client.connect(SERVER_ADDR, now)

    first_flight = client.datagrams_to_send(now)
    assert first_flight
    assert all(len(data) == 1280 for data, _ in first_flight)
    assert client._core.active_path[5] == 1280

    deadline = client.get_timer()
    assert deadline is not None
    client.handle_timer(deadline)

    retransmission = client.datagrams_to_send(deadline)
    assert retransmission
    assert all(len(data) == 1200 for data, _ in retransmission)
    assert client._core.active_path[5] == 1200


def test_native_client_restarts_after_retry() -> None:
    configuration = QuicConfiguration(
        alpn_protocols=["h3"], is_client=True, server_name="localhost"
    )
    client = QuicConnection(configuration=configuration)
    client.connect(SERVER_ADDR, 1.0)
    first_uni = client.get_next_available_stream_id(is_unidirectional=True)
    second_uni = client.get_next_available_stream_id(is_unidirectional=True)
    assert first_uni == second_uni
    assert client.datagrams_to_send(1.0)

    retry_source_cid = b"retrycid"
    retry_token = b"authenticated retry token"
    retry = encode_quic_retry(
        version=client._version,
        source_cid=retry_source_cid,
        destination_cid=client.host_cid,
        original_destination_cid=client.original_destination_connection_id,
        retry_token=retry_token,
    )
    client.receive_datagram(retry, SERVER_ADDR, 1.01)

    retried = client.datagrams_to_send(1.01)
    assert retried
    header = pull_quic_header(retried[0][0], 0, len(client.host_cid))
    assert header[3] == retry_source_cid
    assert header[5] == retry_token
    assert client._retry_source_connection_id == retry_source_cid
    assert client.get_next_available_stream_id(is_unidirectional=True) == first_uni


def test_native_client_ignores_invalid_retry() -> None:
    configuration = QuicConfiguration(is_client=True, server_name="localhost")
    client = QuicConnection(configuration=configuration)
    client.connect(SERVER_ADDR, 1.0)
    client.datagrams_to_send(1.0)
    core = client._core

    retry = bytearray(
        encode_quic_retry(
            version=client._version,
            source_cid=b"retrycid",
            destination_cid=client.host_cid,
            original_destination_cid=client.original_destination_connection_id,
            retry_token=b"token",
        )
    )
    retry[-1] ^= 1
    client.receive_datagram(bytes(retry), SERVER_ADDR, 1.01)

    assert client._core is core
    assert client._retry_count == 0
    assert client.datagrams_to_send(1.01) == []


@pytest.mark.parametrize("forged", ["destination", "source"])
def test_native_client_ignores_version_negotiation_with_forged_cid(forged) -> None:
    client, _ = make_pair()
    client.configuration.supported_versions.insert(0, 0x1A2A3A4A)
    client.connect(SERVER_ADDR, 1.0)
    core = client._core
    packet = encode_quic_version_negotiation(
        source_cid=(
            b"forged"
            if forged == "source"
            else client.original_destination_connection_id
        ),
        destination_cid=b"forged" if forged == "destination" else client.host_cid,
        supported_versions=[QuicProtocolVersion.VERSION_1],
    )
    client.receive_datagram(packet, SERVER_ADDR, 1.01)
    assert client._core is core
    assert not client._version_negotiated


def test_native_client_ignores_version_negotiation_after_authenticated_packet() -> None:
    client, server = make_pair()
    client.connect(SERVER_ADDR, 1.0)
    transfer(client, server, CLIENT_ADDR, 1.0)
    first_server_flight = server.datagrams_to_send(1.01)
    assert first_server_flight
    client.receive_datagram(first_server_flight[0][0], SERVER_ADDR, 1.01)
    assert client._core.received_authenticated_packet
    core = client._core

    packet = encode_quic_version_negotiation(
        source_cid=client.original_destination_connection_id,
        destination_cid=client.host_cid,
        supported_versions=[QuicProtocolVersion.VERSION_1],
    )
    client.receive_datagram(packet, SERVER_ADDR, 1.02)
    assert client._core is core
    assert not client._version_negotiated


def test_native_client_rejects_retry_after_authenticated_server_packet() -> None:
    client, server = make_pair()
    _, _, now = handshake(client, server)
    core = client._core
    retry = encode_quic_retry(
        version=client._version,
        source_cid=b"latecid1",
        destination_cid=client.host_cid,
        original_destination_cid=client.original_destination_connection_id,
        retry_token=b"late retry",
    )

    client.receive_datagram(retry, SERVER_ADDR, now)

    assert client._core is core
    assert client._retry_count == 0
    assert client.next_event() is None


def test_native_one_rtt_key_update_roundtrip() -> None:
    client, server = make_pair()
    _, _, now = handshake(client, server)
    assert client._handshake_confirmed
    assert server._handshake_confirmed
    assert client._core.send_key_phase == server._core.receive_key_phase == 0

    client.request_key_update()
    with pytest.raises(ValueError, match="invalid key phase"):
        client.request_key_update()
    assert client._core.send_key_phase == client._core.receive_key_phase == 1
    client.send_ping(1)
    assert transfer(client, server, CLIENT_ADDR, now) == 1
    assert server._core.send_key_phase == server._core.receive_key_phase == 1

    server.send_ping(2)
    assert transfer(server, client, SERVER_ADDR, now + 0.01) == 1
    assert client._core.send_key_phase == server._core.receive_key_phase == 1

    timer = client.get_timer()
    assert timer is not None
    client.handle_timer(timer)
    transfer(client, server, CLIENT_ADDR, timer)

    server.request_key_update()
    server.send_ping(3)
    assert transfer(server, client, SERVER_ADDR, now + 0.02) == 1
    assert client._core.send_key_phase == client._core.receive_key_phase == 0
    assert server._core.send_key_phase == server._core.receive_key_phase == 0


def test_native_key_update_accepts_reordered_old_phase_packet() -> None:
    client, server = make_pair()
    _, _, now = handshake(client, server)

    client.send_ping(10)
    old_datagrams = client.datagrams_to_send(now)
    assert len(old_datagrams) == 1

    client.request_key_update()
    client.send_ping(11)
    new_datagrams = client.datagrams_to_send(now + 0.01)
    assert len(new_datagrams) == 1

    server.receive_datagram(new_datagrams[0][0], CLIENT_ADDR, now + 0.01)
    assert server._core.receive_key_phase == 1
    server.receive_datagram(old_datagrams[0][0], CLIENT_ADDR, now + 0.02)
    assert server._core.receive_key_phase == 1

    timer = server.get_timer()
    assert timer is not None
    timer = max(timer, now + 0.02)
    server.handle_timer(timer)
    transfer(server, client, SERVER_ADDR, timer)
    acknowledged = [client.next_event(), client.next_event()]
    assert {event.uid for event in acknowledged} == {10, 11}


@pytest.mark.asyncio
async def test_native_asyncio_connect_and_serve(monkeypatch) -> None:
    monkeypatch.setattr(asyncio_client, "QuicConnection", QuicConnection)
    monkeypatch.setattr(asyncio_server, "QuicConnection", QuicConnection)

    handler_tasks = []

    def handle_stream(reader, writer) -> None:
        async def respond() -> None:
            data = await reader.read()
            writer.write(data[::-1])
            writer.write_eof()

        handler_tasks.append(asyncio.create_task(respond()))

    async def exchange() -> None:
        server_configuration = QuicConfiguration(is_client=False)
        server_configuration.load_cert_chain(SERVER_CERTFILE, SERVER_KEYFILE)
        server = await asyncio_server.serve(
            "127.0.0.1",
            0,
            configuration=server_configuration,
            stream_handler=handle_stream,
        )
        port = server._transport.get_extra_info("sockname")[1]

        client_configuration = QuicConfiguration(
            is_client=True, server_name="localhost"
        )
        client_configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
        try:
            async with asyncio_client.connect(
                "127.0.0.1", port, configuration=client_configuration
            ) as client:
                reader, writer = await client.create_stream()
                writer.write(b"ping")
                writer.write_eof()
                assert await reader.read() == b"gnip"
                assert client._stream_readers == {}
                assert client._stream_readers_done == {0}
        finally:
            server.close()
            if handler_tasks:
                await asyncio.gather(*handler_tasks)

    await asyncio.wait_for(exchange(), timeout=10)


@pytest.mark.asyncio
@pytest.mark.parametrize("retry", [False, True])
async def test_native_address_validation_allows_large_response_to_tiny_request(
    monkeypatch, retry
) -> None:
    monkeypatch.setattr(asyncio_client, "QuicConnection", QuicConnection)
    monkeypatch.setattr(asyncio_server, "QuicConnection", QuicConnection)
    tasks = []

    def handle_stream(reader, writer) -> None:
        async def respond() -> None:
            assert await reader.read() == b"x"
            writer.write(b"y" * 16_000)
            writer.write_eof()

        tasks.append(asyncio.create_task(respond()))

    configuration = QuicConfiguration(is_client=False)
    configuration.load_cert_chain(SERVER_CERTFILE, SERVER_KEYFILE)
    server = await asyncio_server.serve(
        "127.0.0.1",
        0,
        configuration=configuration,
        retry=retry,
        stream_handler=handle_stream,
    )
    port = server._transport.get_extra_info("sockname")[1]
    client_configuration = QuicConfiguration(is_client=True, server_name="localhost")
    client_configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
    try:
        async with asyncio_client.connect(
            "127.0.0.1", port, configuration=client_configuration
        ) as client:
            reader, writer = await client.create_stream()
            writer.write(b"x")
            writer.write_eof()
            assert await reader.read() == b"y" * 16_000
    finally:
        server.close()
        await asyncio.gather(*tasks)


@pytest.mark.asyncio
async def test_native_asyncio_certificate_failure_does_not_hang(monkeypatch) -> None:
    monkeypatch.setattr(asyncio_client, "QuicConnection", QuicConnection)
    monkeypatch.setattr(asyncio_server, "QuicConnection", QuicConnection)

    server_configuration = QuicConfiguration(is_client=False)
    server_configuration.load_cert_chain(SERVER_CERTFILE, SERVER_KEYFILE)
    server = await asyncio_server.serve(
        "127.0.0.1", 0, configuration=server_configuration
    )
    port = server._transport.get_extra_info("sockname")[1]

    async def connect_once() -> None:
        async with asyncio_client.connect("127.0.0.1", port):
            pass

    try:
        with pytest.raises(ConnectionError):
            await asyncio.wait_for(connect_once(), timeout=5)
    finally:
        server.close()
