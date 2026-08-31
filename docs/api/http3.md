# HTTP/3 API

`H3Connection` translates between QUIC events and HTTP/3 events. It relies on a
`QuicConnection` for transport and performs no I/O itself.

```python
from qh3 import H3Connection, quic_events

h3 = H3Connection(quic)

while (event := quic.next_event()) is not None:
    for http_event in h3.handle_event(event):
        handle_http_event(http_event)

stream_id = quic.get_next_available_stream_id()
h3.send_headers(
    stream_id,
    [
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b"example.com"),
        (b":path", b"/"),
    ],
    end_stream=True,
)
```

::: qh3.h3.connection.H3Connection
    options:
      show_root_heading: true
      members:
        - create_webtransport_stream
        - handle_event
        - send_datagram
        - send_push_promise
        - send_data
        - send_headers
        - received_settings
        - sent_settings

## Exceptions

::: qh3.h3.exceptions.H3Error
    options:
      show_root_heading: true
      members: false

::: qh3.h3.exceptions.NoAvailablePushIDError
    options:
      show_root_heading: true
      members: false

HTTP/3 parser exceptions and wire-level constants are implementation details.
Protocol errors encountered by `handle_event()` close the QUIC connection and
are not raised to the application.
