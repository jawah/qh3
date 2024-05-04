1.0.5 (2024-05-04)
=====================

**Fixed**
- Qpack encoder / decoder failure due to unfed stream data.

1.0.4 (2024-04-23)
=====================

**Changed**
- Buffer management has been migrated over to Rust in order to improve the overall performance.

1.0.3 (2024-04-20)
=====================

**Fixed**
- setting assert_hostname to False triggered an error when the peer certificate contained at least one IP in subject alt names.

1.0.2 (2024-04-20)
=====================

**Fixed**
- qpack encoder/decoder blocking state in a rare condition.
- missing (a default) NullHandler for ``quic`` and ``http3`` loggers causing a StreamHandler to write into stderr.
- setting assert_hostname to False did not disable hostname verification / match with given certificate.

**Changed**
- Updated rustls to v0.23.5

1.0.1 (2024-04-19)
=====================

**Fixed**
- PyO3 unsendable classes constraint has been relaxed. qh3 is not thread-safe and you should take appropriate measures in a concurrent environment.

**Added**
- Exposed ``CipherSuite`` and ``SessionTicket`` classes in the top-level import.

**Misc**
- Exposed a x509 helper to make for ``cryptography`` dependency removal, solely for Niquests usage.

1.0.0 (2024-04-18)
=====================

**Removed**
- **Breaking:** Dependency on ``cryptography`` along with the indirect dependencies on cffi and pycparser.
- **Breaking:** ``H0Connection`` class that was previously deprecated. Use either urllib3-future or niquests instead.
- **Breaking:** Draft support for QUIC and H3 protocols.
- **Breaking:** ``RSA_PKCS1_SHA1`` signature algorithm due to its inherent risk dealing with the unsafe SHA1.
- **Breaking:** ED448/X448 signature and private key are no longer supported due to its absence in aws-lc-rs.
- **Breaking:** You may no longer pass certificates (along with private keys) as object that comes from ``cryptography``. You have to encode them into PEM format.

**Changed**
- ls-qpack binding integration upgraded to v2.5.4 and migrated to Rust.
- cryptographic bindings are rewritten in Rust using the PyO3 SDK, the underlying crypto library is aws-lc-rs 1.6.4
- certificate chain control with dns name matching is delegated to rustls instead of previously half-vendored (py)OpenSSL (X509Store).

**Added**
- Exposed a public API for ``qh3`` (top-level import).
- SECP384R1 key exchange algorithm as a supported group by default to make for the X448 removal.
- SECP521R1 key exchange algorithm is also supported but not enabled by default per standards (NSA Suite B) recommendations.

**Misc**
- Noticeable performance improvement and memory safety thanks to the Rust migration. We tried to leverage pure Rust binding whenever we could do it safely.
- Example scripts are adapted for this major version.
- Using ``maturin`` as the build backend.
- Published new compatible architectures for pre-built wheels.
- Initial MSRV 1.75+

If you rely on one aspect of enumerated breaking changes, please pin qh3 to
exclude this major (eg. ``>=0.15,<1``) and inform us on how this release affected your program(s).
We will listen.

The semantic versioning will be respected excepted for the hazardous materials.

0.15.1 (2024-03-21)
===================

**Fixed**
- Improved stream write scheduling. (upstream patch https://github.com/aiortc/aioquic/pull/475)

**Misc**
- CI now prepare a complete sdist with required vendors
- aarch64 linux is now served

0.15.0 (2023-02-01)
===================

**Changed**
- Highly simplified ``_crypto`` module based on upstream work https://github.com/aiortc/aioquic/pull/457
- Bump upper bound ``cryptography`` version to 42.x

**Fixed**
- Mitigate deprecation originating from ``cryptography`` about datetime naïve timezone.

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
