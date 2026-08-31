# Logging

qh3 can collect [QLOG](https://www.rfc-editor.org/rfc/rfc9462.html) events in
memory or write one JSON trace per connection to a directory.

```python
from qh3 import QuicConfiguration, QuicFileLogger

configuration = QuicConfiguration(
    is_client=True,
    quic_logger=QuicFileLogger("qlog"),
)
```

Traffic secrets can be written separately by assigning an open text file to
`QuicConfiguration.secrets_log_file`. Treat that file as sensitive.

::: qh3.quic.logger.QuicLogger
    options:
      show_root_heading: true
      members:
        - to_dict

::: qh3.quic.logger.QuicFileLogger
    options:
      show_root_heading: true
      members: false

`QuicLoggerTrace` and its encoding helpers are internal implementation details.
