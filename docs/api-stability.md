# API Stability

qh3 follows semantic versioning for the API documented in this site.

## Supported surface

The supported public API consists of:

- the names listed in the [public API reference](api/index.md);
- the explicitly listed methods and properties on those classes;
- the event fields shown in the [events reference](api/events.md).

Prefer top-level imports such as `from qh3 import QuicConnection`. Module paths
shown by the generated reference remain valid where they are necessary for
event classes or type annotations.

## Internal surface

The following are not covered by compatibility guarantees:

- `qh3._hazmat`;
- underscore-prefixed modules, attributes, and methods;
- `qh3.quic.crypto`, `qh3.quic.retry`, and `qh3.quic.tls_bridge`;
- packet and frame parsing or encoding helpers;
- native Rust modules and error types;
- QLOG trace encoders;
- symbols used only by tests, benchmarks, or examples.

`qh3._hazmat` is intentionally importable so the typed Python facade can use
the native extension. It is not an advanced public API. Its signatures,
exceptions, and behavior may change in any release.

## Extension points

The supported customization points are deliberately small:

- pass `create_protocol` to `connect()` or `serve()`;
- subclass `QuicConnectionProtocol` and override `quic_event_received()`;
- use `QuicConnection` and `H3Connection` through their documented methods for
  a custom sans-I/O integration.

Depending on internal connection state, monkey-patching private attributes, or
subclassing undocumented implementation classes is unsupported.
