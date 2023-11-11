0.14.0 (2023-11-11)
===================

**Changed**
- Converted our ``Buffer`` implementation to native Python instead of C as performance are plain better thanks to CPython internal optimisations

**Fixed**
- Addressed performance concerns when attributing new stream ids
- The retry token was based on a weak key

**Added**
- ``StopSendingReceived`` event
- Property ``open_outbound_streams`` in ``QuicConnection``
- Property ``max_concurrent_bidi_streams`` in ``QuicConnection``
- Property ``max_concurrent_uni_streams`` in ``QuicConnection``
- Method ``get_cipher`` in ``QuicConnection``
- Method ``get_peercert`` in ``QuicConnection``
- Method ``get_issuercerts`` in ``QuicConnection``

0.13.0 (2023-10-27)
===================

**Added**
- Support for in-memory certificates (client/intermediary) via ``Configuration.load_cert_chain(..)``

**Removed**
- (internal) Unused code in private ``_vendor.OpenSSL``

0.12.0 (2023-10-08)
===================

**Changed**
- All **INFO** logs entries are downgraded to **DEBUG**

**Removed**
- Certifi will no longer be used if present in the environment. Use jawah/wassima as a super replacement.

**Deprecated**
- ``H0Connection`` will be removed in the 1.0 milestone. Use HTTP Client Niquests instead.

0.11.5 (2023-09-05)
===================

**Fixed**
- **QuicConnection** ignored ``verify_hostname`` context option  (PR #16 by @doronz88)

0.11.4 (2023-09-03)
===================

**Added**
- Support for QUIC mTLS on the client side (PR #13 by @doronz88)

0.11.3 (2023-07-20)
===================

**Added**
- Toggle for hostname verification in Configuration

**Changed**
- Hostname verification can be done independently of certificate verification

0.11.2 (2023-07-15)
===================

**Added**
- Support for certificate fingerprint matching

**Fixed**
- datetime.utcnow deprecation

**Changed**
- commonName is no longer checked by default

0.11.1 (2023-06-18)
===================

**Added**
- Support for "IP Address" as subject alt name in certificate verifications

0.11.0 (2023-06-18)
===================

**Removed**
- Dependency on OpenSSL development headers

**Changed**
- Crypto module relies on ``cryptography`` OpenSSL binding instead of our own copy

**Added**
- Explicit support for PyPy


0.10.0 (2023-06-16)
===================

**Removed**

- Dependency on pyOpenSSL
- Dependency on certifi
- Dependency on pylsqpack

**Changed**

- Vendored pyOpenSSL.crypto for the certificate verification chain (X590Store)
- Vendored pylsqpack, use v1.0.3 from upstream and make module abi3 compatible
- The module _crypto and _buffer are abi3 compatible
- The whole package is abi3 ready
- certifi ca bundle is loaded only if present in the current environment (behavior will be removed in v1.0.0)

**Fixed**

- Mitigate ssl.match_hostname deprecation by porting urllib3 match_hostname
- Mimic ssl load_default_cert into the certification chain verification

