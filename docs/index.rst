qh3
====

|pypi-v| |pypi-pyversions| |pypi-l|

.. |pypi-v| image:: https://img.shields.io/pypi/v/qh3.svg
    :target: https://pypi.python.org/pypi/aioquic

.. |pypi-pyversions| image:: https://img.shields.io/pypi/pyversions/qh3.svg
    :target: https://pypi.python.org/pypi/aioquic

.. |pypi-l| image:: https://img.shields.io/pypi/l/aioquic.svg
    :target: https://pypi.python.org/pypi/aioquic

``qh3`` is a library for the QUIC network protocol in Python. It is a maintained fork of the ``aioquic`` library.
``aioquic`` is still maintained, but we decided to diverge as qh3 took a path that is in opposition to their wishes.

It is lighter, and a bit faster, and more adapted to a broader audience as this package has no external dependency
and does not rely on mainstream OpenSSL.

While it is a compatible fork, it is not a drop-in replacement since the first major. See the CHANGELOG for details.

It features several APIs:

- a QUIC API following the "bring your own I/O" pattern, suitable for
  embedding in any framework,

- an HTTP/3 API which also follows the "bring your own I/O" pattern,

- a QUIC convenience API built on top of :mod:`asyncio`, Python's standard asynchronous
  I/O framework.

.. toctree::
   :maxdepth: 2

   design
   quic
   h3
   asyncio
   license
