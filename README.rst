qh3
===

|rtd| |pypi-v| |pypi-pyversions| |pypi-l| |codecov|

.. |rtd| image:: https://readthedocs.org/projects/aioquic/badge/?version=latest
    :target: https://aioquic.readthedocs.io/

.. |pypi-v| image:: https://img.shields.io/pypi/v/qh3.svg
    :target: https://pypi.python.org/pypi/qh3

.. |pypi-pyversions| image:: https://img.shields.io/pypi/pyversions/qh3.svg
    :target: https://pypi.python.org/pypi/qh3

.. |pypi-l| image:: https://img.shields.io/pypi/l/qh3.svg
    :target: https://pypi.python.org/pypi/qh3

.. |codecov| image:: https://img.shields.io/codecov/c/github/Ousret/qh3.svg
    :target: https://codecov.io/gh/aiortc/aioquic

What is ``qh3``?
----------------

``qh3`` is a fork of the awesome ``aioquic`` library pending its author return.
Important changes/improvements are:

- Made abi3 compatible, no need to build the wheel all over again on each interpreter version.
- Only one dependency left! Cryptography will remain as long as Python does not ship with proper QUIC implementation.
- Mitigated deprecated match_hostname.
- Mimic load_default_certs SSL context from native Python.
- Remove the need for OpenSSL development headers.

``aioquic`` is a library for the QUIC network protocol in Python. It features
a minimal TLS 1.3 implementation, a QUIC stack and an HTTP/3 stack.

QUIC was standardised in `RFC 9000`_ and HTTP/3 in `RFC 9114`_.
``aioquic`` is regularly tested for interoperability against other
`QUIC implementations`_.

To learn more about ``aioquic`` please `read the documentation`_.

Why should I use ``aioquic``?
-----------------------------

``aioquic`` has been designed to be embedded into Python client and server
libraries wishing to support QUIC and / or HTTP/3. The goal is to provide a
common codebase for Python libraries in the hope of avoiding duplicated effort.

Both the QUIC and the HTTP/3 APIs follow the "bring your own I/O" pattern,
leaving actual I/O operations to the API user. This approach has a number of
advantages including making the code testable and allowing integration with
different concurrency models.

Features
--------

- QUIC stack conforming with `RFC 9000`_
- HTTP/3 stack conforming with `RFC 9114`_
- minimal TLS 1.3 implementation conforming with `RFC 8446`_
- IPv4 and IPv6 support
- connection migration and NAT rebinding
- logging TLS traffic secrets
- logging QUIC events in QLOG format
- HTTP/3 server push support

Requirements
------------

``aioquic`` requires Python 3.7 or greater.

Running the examples
--------------------

`aioquic` comes with a number of examples illustrating various QUIC usecases.

You can browse these examples here: https://github.com/aiortc/aioquic/tree/main/examples

License
-------

``aioquic`` is released under the `BSD license`_.

.. _read the documentation: https://aioquic.readthedocs.io/en/latest/
.. _QUIC implementations: https://github.com/quicwg/base-drafts/wiki/Implementations
.. _cryptography: https://cryptography.io/
.. _Chocolatey: https://chocolatey.org/
.. _BSD license: https://aioquic.readthedocs.io/en/latest/license.html
.. _RFC 8446: https://datatracker.ietf.org/doc/html/rfc8446
.. _RFC 9000: https://datatracker.ietf.org/doc/html/rfc9000
.. _RFC 9114: https://datatracker.ietf.org/doc/html/rfc9114
