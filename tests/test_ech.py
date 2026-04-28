from __future__ import annotations

import asyncio
import socket
from collections import deque

import pytest

import dns.resolver

from qh3.asyncio.client import connect
from qh3.asyncio.protocol import QuicConnectionProtocol
from qh3.h3.connection import H3Connection
from qh3.h3.events import DataReceived, H3Event, HeadersReceived
from qh3.quic.configuration import QuicConfiguration
from qh3.quic.events import QuicEvent


_PROBE_HOST = "cloudflare.com"
_PROBE_PORT = 443
_PROBE_TIMEOUT_S = 2

# research.cloudflare.com publishes an ECH config whose public_name is
# "cloudflare-ech.com". This gives us a real test where:
#   - outer (cleartext) SNI  = cloudflare-ech.com   (public_name from ECHConfig)
#   - inner (encrypted) SNI  = research.cloudflare.com  (the actual target)
_ECH_HOST = "encryptedsni.com"
_ECH_PORT = 443


def _network_available() -> bool:
    try:
        sock = socket.create_connection(
            (_PROBE_HOST, _PROBE_PORT), timeout=_PROBE_TIMEOUT_S
        )
        sock.close()
        return True
    except OSError:
        return False


def _fetch_ech_config_list(domain: str) -> bytes:
    """Query DNS HTTPS record for *domain* and return the raw ECHConfigList bytes."""
    answers = dns.resolver.resolve(domain, "HTTPS")
    for rdata in answers:
        # params is a dict-like; key 5 is the ECH SvcParamKey
        if hasattr(rdata, "params") and 5 in rdata.params:
            return rdata.params[5].ech
    raise RuntimeError(f"No ECH config found in HTTPS record for {domain}")


requires_network = pytest.fixture(scope="session")(
    lambda: pytest.skip("Network is unreachable") if not _network_available() else None
)


class _H3Client(QuicConnectionProtocol):
    """Minimal HTTP/3 client protocol for testing."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._request_events: dict[int, deque[H3Event]] = {}
        self._request_waiter: dict[int, asyncio.Future[deque[H3Event]]] = {}

    def quic_event_received(self, event: QuicEvent) -> None:
        for h3_event in self._http.handle_event(event):
            if isinstance(h3_event, (HeadersReceived, DataReceived)):
                stream_id = h3_event.stream_id
                if stream_id in self._request_events:
                    self._request_events[stream_id].append(h3_event)
                    if h3_event.stream_ended:
                        self._request_waiter.pop(stream_id).set_result(
                            self._request_events.pop(stream_id)
                        )

    async def get(self, authority: str, path: str = "/") -> deque[H3Event]:
        stream_id = self._quic.get_next_available_stream_id()
        self._http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", authority.encode()),
                (b":path", path.encode()),
            ],
            end_stream=True,
        )
        waiter = asyncio.get_running_loop().create_future()
        self._request_events[stream_id] = deque()
        self._request_waiter[stream_id] = waiter
        self.transmit()
        return await asyncio.shield(waiter)


@pytest.mark.asyncio
async def test_ech_accepted(requires_network):
    """Connect to research.cloudflare.com with ECH, perform an HTTP/3 GET,
    and verify both ECH acceptance and that the response is the real page.

    The ECH config's public_name is "cloudflare-ech.com", so the outer
    ClientHello SNI is cloudflare-ech.com while the real server name
    (research.cloudflare.com) is encrypted in the inner ClientHello.
    """
    ech_config_list = _fetch_ech_config_list(_ECH_HOST)

    configuration = QuicConfiguration(is_client=True)
    configuration.ech_config_list = ech_config_list
    configuration.alpn_protocols = ["h3"]

    async with connect(
        _ECH_HOST,
        _ECH_PORT,
        configuration=configuration,
        create_protocol=_H3Client,
    ) as client:
        assert client._quic.ech_accepted is True

        events = await client.get(_ECH_HOST)

        # Verify we got a 200 response
        headers = {}
        body = b""
        for event in events:
            if isinstance(event, HeadersReceived):
                headers = dict(event.headers)
            elif isinstance(event, DataReceived):
                body += event.data

        assert headers[b":status"] == b"301"

        html = body.decode()

        assert not html


@pytest.mark.asyncio
async def test_grease_ech_no_rejection(requires_network):
    """Connect without ECH config (GREASE only) — server should ignore it and
    the handshake should succeed, but ech_accepted must be False."""
    configuration = QuicConfiguration(is_client=True)
    configuration.alpn_protocols = ["h3"]

    async with connect(
        _ECH_HOST,
        _ECH_PORT,
        configuration=configuration,
        create_protocol=_H3Client,
    ) as client:
        assert client._quic.ech_accepted is False

        events = await client.get(_ECH_HOST)

        # Verify we got a 200 response
        headers = {}
        body = b""

        for event in events:
            if isinstance(event, HeadersReceived):
                headers = dict(event.headers)
            elif isinstance(event, DataReceived):
                body += event.data

        assert headers[b":status"] == b"301"
        html = body.decode()

        assert not html
