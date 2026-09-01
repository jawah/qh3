# QUIC API

`QuicConnection` is the supported sans-I/O QUIC facade. It does not read from
or write to sockets.

## Connection

::: qh3.quic.connection.QuicConnection
    options:
      show_root_heading: true
      members:
        - configuration
        - original_destination_connection_id
        - open_outbound_streams
        - max_concurrent_bidi_streams
        - max_concurrent_uni_streams
        - ech_accepted
        - ech_retry_configs
        - get_cipher
        - get_peercert
        - get_issuercerts
        - connect
        - receive_datagram
        - receive_many_datagrams
        - receive_gro_buffer
        - datagrams_to_send
        - get_timer
        - handle_timer
        - should_wait_for_ack
        - next_event
        - get_next_available_stream_id
        - send_stream_data
        - reset_stream
        - stop_stream
        - send_datagram_frame
        - send_ping
        - request_key_update
        - change_connection_id
        - close

## Errors

::: qh3.quic.connection.QuicConnectionError
    options:
      show_root_heading: true
      members: false

## Protocol versions

::: qh3.quic.packet.QuicProtocolVersion
    options:
      show_root_heading: true
      members: true

Use `qh3.QuicProtocolVersion` as the canonical import.
