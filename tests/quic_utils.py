from __future__ import annotations

import contextlib
import time
from collections.abc import Callable, Iterator
from typing import Any

from qh3.quic.configuration import QuicConfiguration
from qh3.quic.connection import NetworkAddress, QuicConnection
from qh3.quic.logger import QuicLogger

from .utils import SERVER_CACERTFILE, SERVER_CERTFILE, SERVER_KEYFILE

CLIENT_ADDR = ("1.2.3.4", 1234)
SERVER_ADDR = ("2.3.4.5", 4433)
_now = time.time()


def _next_time() -> float:
    global _now
    _now += 0.05
    return _now


def transfer(sender: QuicConnection, receiver: QuicConnection) -> int:
    """Transfer all currently available datagrams between two connections."""
    datagrams = 0
    source: NetworkAddress = CLIENT_ADDR if sender.configuration.is_client else SERVER_ADDR
    now = _next_time()
    for data, _ in sender.datagrams_to_send(now=now):
        datagrams += 1
        receiver.receive_datagram(data, source, now=now)
    return datagrams


@contextlib.contextmanager
def client_and_server(
    client_kwargs: dict[str, Any] | None = None,
    client_options: dict[str, Any] | None = None,
    client_patch: Callable[[QuicConnection], None] | None = None,
    handshake: bool = True,
    server_kwargs: dict[str, Any] | None = None,
    server_certfile: str = SERVER_CERTFILE,
    server_keyfile: str = SERVER_KEYFILE,
    server_options: dict[str, Any] | None = None,
    server_patch: Callable[[QuicConnection], None] | None = None,
) -> Iterator[tuple[QuicConnection, QuicConnection]]:
    client_configuration = QuicConfiguration(
        is_client=True,
        quic_logger=QuicLogger(),
        probe_datagram_size=False,
        **(client_options or {}),
    )
    client_configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
    client = QuicConnection(configuration=client_configuration, **(client_kwargs or {}))
    if client_patch is not None:
        client_patch(client)

    server_configuration = QuicConfiguration(
        is_client=False,
        quic_logger=QuicLogger(),
        **(server_options or {}),
    )
    server_configuration.load_cert_chain(server_certfile, server_keyfile)
    server = QuicConnection(
        configuration=server_configuration,
        original_destination_connection_id=client.original_destination_connection_id,
        **(server_kwargs or {}),
    )
    if server_patch is not None:
        server_patch(server)

    if handshake:
        client.connect(SERVER_ADDR, now=_next_time())
        for _ in range(100):
            sent = transfer(client, server) + transfer(server, client)
            now = _next_time()
            for connection in (client, server):
                timer = connection.get_timer()
                if timer is not None and timer <= now:
                    connection.handle_timer(now)
            if client._handshake_complete and server._handshake_complete and not sent:
                break

    try:
        yield client, server
    finally:
        client.close()
        server.close()
