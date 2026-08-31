# TLS Types

qh3 owns the TLS 1.3 handshake used by QUIC. The handshake state machine and
wire codecs are internal; applications normally interact only with cipher-suite
selection and session tickets.

## Cipher suites

::: qh3.tls.CipherSuite
    options:
      show_root_heading: true
      members: false

Use `qh3.CipherSuite` as the canonical import.

The configurable cipher suites are `AES_128_GCM_SHA256`,
`AES_256_GCM_SHA384`, and `CHACHA20_POLY1305_SHA256`.

## Session tickets

::: qh3.tls.SessionTicket
    options:
      show_root_heading: true
      members:
        - is_valid
        - obfuscated_age

Use `qh3.SessionTicket` as the canonical import. Store tickets as sensitive
credentials and provide them through `QuicConfiguration.session_ticket` only
to the server name that issued them.
