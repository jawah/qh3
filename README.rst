qh3
===

|pypi-version| |python-versions| |license|

``qh3`` is a fast QUIC and HTTP/3 implementation for Python, backed by a
native Rust transport core. It is a maintained fork of ``aioquic`` and is not
a drop-in replacement.

It provides:

* a convenient ``asyncio`` client and server API;
* sans-I/O QUIC and HTTP/3 APIs for custom integrations;
* QUIC v1 and v2, TLS 1.3, IPv4 and IPv6, migration, QLOG, datagrams,
  server push, WebTransport streams, ECH, and post-quantum key exchange;
* support for CPython and PyPy 3.7 or newer.

Installation
------------

.. code-block:: console

   python -m pip install qh3

Documentation
-------------

Read the `qh3 documentation`_ for the getting-started guide, asyncio and
sans-I/O integration guides, and the supported public API reference.

Only interfaces listed in the public API reference are covered by API
compatibility guarantees. In particular, ``qh3._hazmat`` and
underscore-prefixed modules are implementation details.

Complete examples are available in the `examples directory`_. Applications
looking for a complete HTTP client should generally use `Niquests`_ or
`urllib3.future`_.

Standards
---------

* `RFC 9000`_: QUIC
* `RFC 9001`_: Using TLS to Secure QUIC
* `RFC 9002`_: QUIC Loss Detection and Congestion Control
* `RFC 9114`_: HTTP/3
* `RFC 9369`_: QUIC Version 2

License
-------

``qh3`` is distributed under the `BSD 3-Clause License`_.

.. |pypi-version| image:: https://img.shields.io/pypi/v/qh3.svg
   :target: https://pypi.org/project/qh3/
   :alt: PyPI version

.. |python-versions| image:: https://img.shields.io/pypi/pyversions/qh3.svg
   :target: https://pypi.org/project/qh3/
   :alt: Supported Python versions

.. |license| image:: https://img.shields.io/pypi/l/qh3.svg
   :target: https://github.com/jawah/qh3/blob/main/LICENSE
   :alt: License

.. _qh3 documentation: https://qh3.readthedocs.io/
.. _examples directory: https://github.com/jawah/qh3/tree/main/examples
.. _Niquests: https://github.com/jawah/niquests
.. _urllib3.future: https://github.com/jawah/urllib3.future
.. _RFC 9000: https://datatracker.ietf.org/doc/html/rfc9000
.. _RFC 9001: https://datatracker.ietf.org/doc/html/rfc9001
.. _RFC 9002: https://datatracker.ietf.org/doc/html/rfc9002
.. _RFC 9114: https://datatracker.ietf.org/doc/html/rfc9114
.. _RFC 9369: https://datatracker.ietf.org/doc/html/rfc9369
.. _BSD 3-Clause License: https://github.com/jawah/qh3/blob/main/LICENSE
