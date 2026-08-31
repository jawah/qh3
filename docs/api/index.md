# Public API

This reference is the supported qh3 API. Prefer imports from `qh3` where a
top-level name is available.

## Entry points

| Import | Purpose |
| --- | --- |
| `qh3.connect` | Open an asyncio QUIC connection |
| `qh3.serve` | Start an asyncio QUIC server |
| `qh3.QuicConnectionProtocol` | Customize asyncio connection behavior |
| `qh3.QuicConnection` | Drive a sans-I/O QUIC connection |
| `qh3.H3Connection` | Encode and decode HTTP/3 over QUIC |
| `qh3.QuicConfiguration` | Configure QUIC and TLS |

## Supporting types

| Import | Purpose |
| --- | --- |
| `qh3.QuicConnectionError` | Public QUIC operation error |
| `qh3.H3Error` | Base public HTTP/3 exception |
| `qh3.NoAvailablePushIDError` | Server push limit error |
| `qh3.QuicProtocolVersion` | Supported QUIC version values |
| `qh3.QuicLogger` | In-memory QLOG collection |
| `qh3.QuicFileLogger` | QLOG file output |
| `qh3.CipherSuite` | Supported TLS cipher-suite values |
| `qh3.SessionTicket` | TLS resumption ticket |
| `qh3.quic_events` | QUIC event classes |
| `qh3.h3_events` | HTTP/3 event classes |

## Stability boundary

Only names documented in this reference are supported as public API. An object
being importable does not make it public. See [API stability](../api-stability.md)
for the complete policy.
