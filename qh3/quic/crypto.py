from __future__ import annotations

from ..tls import CipherSuite, cipher_suite_hash, hkdf_expand_label
from .packet import QuicProtocolVersion

CIPHER_SUITES = {
    CipherSuite.AES_128_GCM_SHA256: (b"aes-128-ecb", b"aes-128-gcm"),
    CipherSuite.CHACHA20_POLY1305_SHA256: (b"chacha20", b"chacha20-poly1305"),
    CipherSuite.AES_256_GCM_SHA384: (b"aes-256-ecb", b"aes-256-gcm"),
}


def derive_key_iv_hp(
    *, cipher_suite: CipherSuite, secret: bytes, version: int
) -> tuple[bytes, bytes, bytes]:
    algorithm = cipher_suite_hash(cipher_suite)

    if cipher_suite in [
        CipherSuite.AES_256_GCM_SHA384,
        CipherSuite.CHACHA20_POLY1305_SHA256,
    ]:
        key_size = 32
    else:
        key_size = 16

    if version == QuicProtocolVersion.VERSION_2:
        return (
            hkdf_expand_label(algorithm, secret, b"quicv2 key", b"", key_size),
            hkdf_expand_label(algorithm, secret, b"quicv2 iv", b"", 12),
            hkdf_expand_label(algorithm, secret, b"quicv2 hp", b"", key_size),
        )
    return (
        hkdf_expand_label(algorithm, secret, b"quic key", b"", key_size),
        hkdf_expand_label(algorithm, secret, b"quic iv", b"", 12),
        hkdf_expand_label(algorithm, secret, b"quic hp", b"", key_size),
    )
