# Design

## Sans-I/O protocol layers

The QUIC and HTTP/3 layers perform no socket I/O. This keeps protocol state
independent of an event loop and allows qh3 to integrate with asyncio or another
networking framework.

The layers are intentionally separate:

1. An I/O integration receives UDP datagrams and tracks time.
2. `QuicConnection` handles QUIC transport state, packet protection, recovery,
   streams, and connection events.
3. `H3Connection` consumes QUIC events and produces HTTP/3 events.
4. The application handles HTTP semantics.

## Native core

The authoritative QUIC packet and recovery state machine is implemented in
Rust. The Python facade retains configuration, TLS policy, event translation,
and integration APIs. `qh3._hazmat` is the private binding between those layers;
applications must not use it directly.

## TLS

qh3 includes a minimal TLS 1.3 implementation tailored to QUIC. QUIC requires
access to handshake messages and traffic secrets without the TLS record layer,
which is not exposed by common high-level TLS APIs.

Cryptographic primitives and packet protection use AWS-LC through Rust.

## Standards

- [RFC 9000: QUIC](https://datatracker.ietf.org/doc/html/rfc9000)
- [RFC 9001: Using TLS to Secure QUIC](https://datatracker.ietf.org/doc/html/rfc9001)
- [RFC 9002: QUIC Loss Detection and Congestion Control](https://datatracker.ietf.org/doc/html/rfc9002)
- [RFC 9114: HTTP/3](https://datatracker.ietf.org/doc/html/rfc9114)
- [RFC 9369: QUIC Version 2](https://datatracker.ietf.org/doc/html/rfc9369)
