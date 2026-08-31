# Asyncio Guide

The asyncio layer owns UDP I/O, timer scheduling, and connection cleanup. Use
it unless an application already has its own networking abstraction.

## Connection lifecycle

Use `connect()` as an asynchronous context manager:

```python
from qh3 import QuicConfiguration, connect

configuration = QuicConfiguration(is_client=True, alpn_protocols=["h3"])

async with connect("example.com", 443, configuration=configuration) as protocol:
    await protocol.wait_connected()
    await protocol.ping()
```

`connect()` waits for the handshake by default. Pass `wait_connected=False`
only when the caller is prepared to manage connection establishment itself.

## Streams

`create_stream()` returns an `asyncio.StreamReader` and
`asyncio.StreamWriter`. Bidirectional streams are created by default:

```python
reader, writer = await protocol.create_stream()
writer.write(b"hello")
writer.write_eof()
reply = await reader.read()
```

For a unidirectional stream:

```python
reader, writer = await protocol.create_stream(is_unidirectional=True)
```

The reader is useful only when the stream direction permits receiving.

## Receiving events

Subclass `QuicConnectionProtocol` and override `quic_event_received()` when an
application needs direct event handling:

```python
from qh3 import QuicConnectionProtocol, quic_events


class Protocol(QuicConnectionProtocol):
    def quic_event_received(self, event: quic_events.QuicEvent) -> None:
        if isinstance(event, quic_events.DatagramFrameReceived):
            print(event.data)
```

Pass the subclass through `create_protocol`:

```python
async with connect(
    "example.com",
    443,
    configuration=configuration,
    create_protocol=Protocol,
) as protocol:
    ...
```

## Server callbacks

`serve()` accepts a `stream_handler` called with a reader and writer whenever
a peer creates a stream. It also accepts `create_protocol` for applications
that need custom event handling.

The returned server handle supports `close()`. Direct construction or
subclassing of the server implementation is not part of the public API.
