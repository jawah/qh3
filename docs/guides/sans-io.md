# Sans-I/O Guide

`QuicConnection` implements QUIC state without performing network I/O. The
caller supplies received datagrams, sends generated datagrams, and drives the
timer.

## Event-loop contract

Use one monotonic clock for every `now` value:

```python
import time

from qh3 import QuicConfiguration, QuicConnection

configuration = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
connection = QuicConnection(configuration=configuration)

now = time.monotonic()
connection.connect(("203.0.113.10", 443), now=now)

for data, address in connection.datagrams_to_send(now=time.monotonic()):
    udp_socket.sendto(data, address)
```

For each incoming UDP datagram:

```python
data, address = udp_socket.recvfrom(65536)
connection.receive_datagram(data, address, now=time.monotonic())
```

After receiving data or handling a timer, drain both outgoing datagrams and
events.

## Timers

`get_timer()` returns an absolute timestamp in the same clock domain supplied
to the connection. When it expires, call `handle_timer()` and transmit any new
datagrams:

```python
deadline = connection.get_timer()
if deadline is not None and deadline <= time.monotonic():
    connection.handle_timer(now=time.monotonic())
```

## Events

Call `next_event()` until it returns `None`:

```python
while (event := connection.next_event()) is not None:
    handle_quic_event(event)
```

Pass each event to `H3Connection.handle_event()` when HTTP/3 is in use.

## Batched UDP

`receive_many_datagrams()` and `receive_gro_buffer()` are optional optimized
entry points. Start with `receive_datagram()` unless the surrounding I/O layer
already exposes batching or GRO metadata.

## Closing

`close()` starts QUIC closing. Continue servicing timers and sending generated
datagrams until a `ConnectionTerminated` event is received or the integration
discards the connection after its own shutdown deadline.
