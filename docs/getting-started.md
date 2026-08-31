# Getting Started

## Installation

Install the latest stable release from PyPI:

```bash
python -m pip install qh3
```

## Connect with asyncio

`connect()` is an asynchronous context manager. The connection is closed when
the context exits.

```python
import asyncio

from qh3 import QuicConfiguration, connect


async def main() -> None:
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=["h3"],
    )

    async with connect("example.com", 443, configuration=configuration) as client:
        await client.ping()


asyncio.run(main())
```

Certificate verification and hostname verification are enabled by default.
Use `QuicConfiguration.load_verify_locations()` when connecting to a service
whose certificate is issued by a private CA.

## Create a stream

The asyncio protocol exposes QUIC streams as standard `asyncio` readers and
writers:

```python
async with connect("example.com", 443, configuration=configuration) as client:
    reader, writer = await client.create_stream()
    writer.write(b"request")
    writer.write_eof()
    response = await reader.read()
```

This is a QUIC byte stream, not an HTTP request. Use `H3Connection` when you
need HTTP/3 semantics.

## Serve QUIC

Servers require a certificate and private key:

```python
import asyncio

from qh3 import QuicConfiguration, serve


async def main() -> None:
    configuration = QuicConfiguration(is_client=False, alpn_protocols=["my-protocol"])
    configuration.load_cert_chain("certificate.pem", "private-key.pem")

    server = await serve("::", 4433, configuration=configuration)
    try:
        await asyncio.Future()
    finally:
        server.close()


asyncio.run(main())
```

For complete HTTP/3 client and server implementations, see the
[examples directory](https://github.com/jawah/qh3/tree/main/examples).

## Next steps

- [Asyncio guide](guides/asyncio.md)
- [Sans-I/O guide](guides/sans-io.md)
- [Configuration reference](api/configuration.md)
- [Public API policy](api-stability.md)
