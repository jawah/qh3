# Events

Import event classes through `qh3.quic_events` and `qh3.h3_events`.

## QUIC events

::: qh3.quic.events.QuicEvent
    options:
      show_root_heading: true
      members: false

::: qh3.quic.events.ConnectionIdIssued
    options:
      show_root_heading: true

::: qh3.quic.events.ConnectionIdRetired
    options:
      show_root_heading: true

::: qh3.quic.events.ConnectionTerminated
    options:
      show_root_heading: true

::: qh3.quic.events.DatagramFrameReceived
    options:
      show_root_heading: true

::: qh3.quic.events.HandshakeCompleted
    options:
      show_root_heading: true

::: qh3.quic.events.PingAcknowledged
    options:
      show_root_heading: true

::: qh3.quic.events.ProtocolNegotiated
    options:
      show_root_heading: true

::: qh3.quic.events.StopSendingReceived
    options:
      show_root_heading: true

::: qh3.quic.events.StreamDataReceived
    options:
      show_root_heading: true

::: qh3.quic.events.StreamReset
    options:
      show_root_heading: true

## HTTP/3 events

::: qh3.h3.events.H3Event
    options:
      show_root_heading: true
      members: false

::: qh3.h3.events.DataReceived
    options:
      show_root_heading: true

::: qh3.h3.events.DatagramReceived
    options:
      show_root_heading: true

::: qh3.h3.events.InformationalHeadersReceived
    options:
      show_root_heading: true

::: qh3.h3.events.HeadersReceived
    options:
      show_root_heading: true

::: qh3.h3.events.PushPromiseReceived
    options:
      show_root_heading: true

::: qh3.h3.events.GoawayReceived
    options:
      show_root_heading: true

::: qh3.h3.events.WebTransportStreamDataReceived
    options:
      show_root_heading: true

::: qh3.h3.events.StreamReset
    options:
      show_root_heading: true

::: qh3.h3.events.StopSending
    options:
      show_root_heading: true
