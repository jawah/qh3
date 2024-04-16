from __future__ import annotations

import struct

from ._hazmat import (
    AeadAes128Gcm,
    AeadAes256Gcm,
    AeadChaCha20Poly1305,
    CryptoError,
    QUICHeaderProtection,
)

AEAD_NONCE_LENGTH = 12
AEAD_TAG_LENGTH = 16

CHACHA20_ZEROS = bytes(5)
PACKET_NUMBER_LENGTH_MAX = 4
SAMPLE_LENGTH = 16
AEAD_KEY_LENGTH_MAX = 32


class AEAD:
    def __init__(self, cipher_name: bytes, key: bytes, iv: bytes):
        if cipher_name not in (b"aes-128-gcm", b"aes-256-gcm", b"chacha20-poly1305"):
            raise CryptoError(f"Invalid cipher name: {cipher_name.decode()}")

        # check and store key and iv
        if len(key) > AEAD_KEY_LENGTH_MAX:
            raise CryptoError("Invalid key length")

        if len(iv) != AEAD_NONCE_LENGTH:
            raise CryptoError("Invalid iv length")

        self._aead: AeadAes256Gcm | AeadAes128Gcm | AeadChaCha20Poly1305

        if cipher_name == b"chacha20-poly1305":
            self._aead = AeadChaCha20Poly1305(key)
        else:
            if cipher_name == b"aes-256-gcm":
                self._aead = AeadAes256Gcm(key)
            else:
                self._aead = AeadAes128Gcm(key)

        self._iv = iv

    def decrypt(self, data: bytes, associated_data: bytes, packet_number: int) -> bytes:
        return self._aead.decrypt(
            self._nonce(packet_number),
            data,
            associated_data,
        )

    def encrypt(self, data: bytes, associated_data: bytes, packet_number: int) -> bytes:
        return self._aead.encrypt(
            self._nonce(packet_number),
            data,
            associated_data,
        )

    def _nonce(self, packet_number: int) -> bytes:
        return self._iv[0:4] + struct.pack(
            ">Q", struct.unpack(">Q", self._iv[4:12])[0] ^ packet_number
        )


class HeaderProtection:
    def __init__(self, cipher_name: bytes, key: bytes):
        if cipher_name not in (b"aes-128-ecb", b"aes-256-ecb", b"chacha20"):
            raise CryptoError(f"Invalid cipher name: {cipher_name.decode()}")

        if len(key) > AEAD_KEY_LENGTH_MAX:
            raise CryptoError("Invalid key length")

        if cipher_name == b"chacha20":
            self._qhp = QUICHeaderProtection(key, 20)
        else:
            if len(key) == 16:
                self._qhp = QUICHeaderProtection(key, 128)
            elif len(key) == 32:
                self._qhp = QUICHeaderProtection(key, 256)
            else:
                raise CryptoError(
                    f"No AES algorithm available for given key length "
                    f"(given {len(key)}, expected one of 16 or 32)"
                )

    def apply(self, plain_header: bytes, protected_payload: bytes) -> bytes:
        pn_length = (plain_header[0] & 0x03) + 1
        pn_offset = len(plain_header) - pn_length
        sample_offset = PACKET_NUMBER_LENGTH_MAX - pn_length
        mask = self._mask(
            protected_payload[sample_offset : sample_offset + SAMPLE_LENGTH]
        )

        buffer = bytearray(plain_header + protected_payload)
        if buffer[0] & 0x80:
            buffer[0] ^= mask[0] & 0x0F
        else:
            buffer[0] ^= mask[0] & 0x1F

        for i in range(pn_length):
            buffer[pn_offset + i] ^= mask[1 + i]

        return bytes(buffer)

    def remove(self, packet: bytes, pn_offset: int) -> tuple[bytes, int]:
        sample_offset = pn_offset + PACKET_NUMBER_LENGTH_MAX
        mask = self._mask(packet[sample_offset : sample_offset + SAMPLE_LENGTH])

        buffer = bytearray(packet)
        if buffer[0] & 0x80:
            buffer[0] ^= mask[0] & 0x0F
        else:
            buffer[0] ^= mask[0] & 0x1F

        pn_length = (buffer[0] & 0x03) + 1
        pn_truncated = 0
        for i in range(pn_length):
            buffer[pn_offset + i] ^= mask[1 + i]
            pn_truncated = buffer[pn_offset + i] | (pn_truncated << 8)

        return bytes(buffer[: pn_offset + pn_length]), pn_truncated

    def _mask(self, sample: bytes) -> bytes:
        return self._qhp.mask(sample)
