qh3
===

|pypi-v| |pypi-pyversions| |pypi-l| |codecov|

.. |pypi-v| image:: https://img.shields.io/pypi/v/qh3.svg
    :target: https://pypi.python.org/pypi/qh3

.. |pypi-pyversions| image:: https://img.shields.io/pypi/pyversions/qh3.svg
    :target: https://pypi.python.org/pypi/qh3

.. |pypi-l| image:: https://img.shields.io/pypi/l/qh3.svg
    :target: https://pypi.python.org/pypi/qh3

.. |codecov| image:: https://img.shields.io/codecov/c/github/Ousret/qh3.svg
    :target: https://codecov.io/gh/Ousret/qh3

What is ``qh3``?
----------------

``qh3`` is a maintained fork of the ``aioquic`` library.
It is lighter, and more adapted to mass usage.
Regularly improved and expect a better time to initial response in issues and PRs.

``qh3`` is a library for the QUIC network protocol in Python. It features
a minimal TLS 1.3 implementation, a QUIC stack, and an HTTP/3 stack.

QUIC was standardized in `RFC 9000`_ and HTTP/3 in `RFC 9114`_.
``qh3`` is regularly tested for interoperability against other
`QUIC implementations`_.

To learn more about ``qh3`` please `read the documentation`_.

Why should I use ``qh3``?
-----------------------------

``qh3`` has been designed to be embedded into Python client and server
libraries wishing to support QUIC and/or HTTP/3. The goal is to provide a
common codebase for Python libraries in the hope of avoiding duplicated effort.

Both the QUIC and the HTTP/3 APIs follow the "bring your own I/O" pattern,
leaving actual I/O operations to the API user. This approach has a number of
advantages including making the code testable and allowing integration with
different concurrency models.

This library is the lowest level you can find for handling QUIC and HTTP/3. Here are higher libraries:

- mid-way: `urllib3.future`_
- highest and easiest: `niquests`_ (Recommended!)

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

``qh3`` requires Python 3.7 or greater.

Running the examples
--------------------

`qh3` comes with a number of examples illustrating various QUIC use cases.

You can browse these examples here: https://github.com/Ousret/qh3/tree/main/examples

License
-------

``qh3`` is released under the `BSD license`_.

.. _read the documentation: https://aioquic.readthedocs.io/en/latest/
.. _QUIC implementations: https://github.com/quicwg/base-drafts/wiki/Implementations
.. _cryptography: https://cryptography.io/
.. _Chocolatey: https://chocolatey.org/
.. _BSD license: https://aioquic.readthedocs.io/en/latest/license.html
.. _RFC 8446: https://datatracker.ietf.org/doc/html/rfc8446
.. _RFC 9000: https://datatracker.ietf.org/doc/html/rfc9000
.. _RFC 9114: https://datatracker.ietf.org/doc/html/rfc9114
.. _niquests: https://github.com/jawah/niquests
.. _urllib3.future: https://github.com/jawah/urllib3.future
