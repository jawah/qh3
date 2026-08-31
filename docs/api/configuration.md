# Configuration

Create one configuration per connection role. Set `is_client=False` for a
server and load its certificate before calling `serve()`.

```python
from qh3 import QuicConfiguration, QuicProtocolVersion

configuration = QuicConfiguration(
    is_client=True,
    alpn_protocols=["h3"],
    idle_timeout=30.0,
    supported_versions=[
        QuicProtocolVersion.VERSION_1,
        QuicProtocolVersion.VERSION_2,
    ],
)
```

## Supported options

| Option | Meaning |
| --- | --- |
| `is_client` | Select client or server behavior |
| `alpn_protocols` | Ordered ALPN protocol names |
| `server_name` | TLS server name used by clients |
| `idle_timeout` | Idle timeout in seconds |
| `connection_id_length` | Length of locally generated connection IDs |
| `max_data` | Connection receive flow-control limit |
| `max_stream_data` | Per-stream receive flow-control limit |
| `max_datagram_size` | Maximum sent QUIC datagram payload size |
| `max_datagram_frame_size` | Enable QUIC DATAGRAM and set its receive limit |
| `active_connection_id_limit` | Client connection-ID limit override |
| `initial_rtt` | Initial RTT estimate in seconds |
| `probe_datagram_size` | Enable client path-MTU discovery |
| `supported_versions` | Ordered QUIC versions to advertise and accept |
| `session_ticket` | TLS ticket used for session resumption and 0-RTT |
| `verify_mode` | TLS certificate verification mode |
| `verify_hostname` | Enable server hostname verification |
| `hostname_checks_common_name` | Permit common-name hostname fallback |
| `quic_logger` | QLOG collector |
| `secrets_log_file` | File-like destination for TLS traffic secrets |
| `ech_config_list` | Wire-format ECHConfigList obtained from HTTPS/SVCB DNS |

Certificate objects, private-key objects, custom signature lists, and other
low-level fields are implementation escape hatches. Use the loading methods
below instead of constructing native certificate or key objects.

::: qh3.quic.configuration.QuicConfiguration
    options:
      show_root_heading: true
      show_signature: false
      members:
        - load_cert_chain
        - load_verify_locations
