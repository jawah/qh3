# qh3

**QUIC and HTTP/3 for Python, with a native Rust transport core.**

[![PyPI version](https://img.shields.io/pypi/v/qh3.svg)](https://pypi.org/project/qh3/)
[![Python versions](https://img.shields.io/pypi/pyversions/qh3.svg)](https://pypi.org/project/qh3/)
[![License](https://img.shields.io/pypi/l/qh3.svg)](license.md)

qh3 is a maintained fork of aioquic for applications that need a focused,
high-performance QUIC and HTTP/3 implementation. It provides:

- a convenient `asyncio` client and server API;
- sans-I/O QUIC and HTTP/3 APIs for custom event loops and transports;
- QUIC v1 and v2, TLS 1.3, IPv4 and IPv6, connection migration, QLOG,
  datagrams, server push, WebTransport streams, ECH, and post-quantum key
  exchange;
- native packet processing and UDP batching implemented in Rust.

## Install

```bash
python -m pip install qh3
```

qh3 supports CPython and PyPy 3.7 or newer.

## Choose an API

| Goal | Start here |
| --- | --- |
| Open or serve QUIC connections with `asyncio` | [Asyncio guide](guides/asyncio.md) |
| Integrate QUIC into another I/O framework | [Sans-I/O guide](guides/sans-io.md) |
| Send HTTP/3 headers, data, or datagrams | [HTTP/3 API](api/http3.md) |
| Configure TLS, certificates, limits, or versions | [Configuration](api/configuration.md) |

## API policy

Only interfaces listed in the [public API reference](api/index.md) are part of
the supported API. In particular, `qh3._hazmat` and underscore-prefixed modules
are implementation details and may change without notice.

qh3 is low-level infrastructure. Applications looking for a complete HTTP
client should generally use [Niquests](https://github.com/jawah/niquests) or
[urllib3.future](https://github.com/jawah/urllib3.future).

[Get started](getting-started.md){ .md-button .md-button--primary }
[Browse the API](api/index.md){ .md-button }
