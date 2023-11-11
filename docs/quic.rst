QUIC API
========

The QUIC API performs no I/O on its own, leaving this to the API user.
This allows you to integrate QUIC in any Python application, regardless of
the concurrency model you are using.

Connection
----------

.. automodule:: qh3.quic.connection

    .. autoclass:: QuicConnection
        :members:


Configuration
-------------

.. automodule:: qh3.quic.configuration

    .. autoclass:: QuicConfiguration
        :members:

.. automodule:: qh3.quic.logger

    .. autoclass:: QuicLogger
        :members:

Events
------

.. automodule:: qh3.quic.events

    .. autoclass:: QuicEvent
        :members:

    .. autoclass:: ConnectionTerminated
        :members:

    .. autoclass:: HandshakeCompleted
        :members:

    .. autoclass:: PingAcknowledged
        :members:

    .. autoclass:: StopSendingReceived
        :members:

    .. autoclass:: StreamDataReceived
        :members:

    .. autoclass:: StreamReset
        :members:
